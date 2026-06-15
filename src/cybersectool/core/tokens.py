"""API token üretimi ve doğrulaması.

Token formatı: ``cst_<rastgele>``. Veritabanına yalnızca SHA-256 **hash**'i yazılır;
ham token kullanıcıya bir kez gösterilir.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.models import ApiToken, User

TOKEN_PREFIX = "cst_"


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_token() -> tuple[str, str]:
    """(ham_token, hash) döndürür."""
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return raw, _hash_token(raw)


async def create_api_token(
    session: AsyncSession,
    user_id: int,
    name: str,
    expires_at: datetime | None = None,
) -> tuple[ApiToken, str]:
    """Yeni token oluşturur; (kayıt, ham_token) döndürür. Ham token bir kez gösterilir."""
    raw, token_hash = generate_token()
    token = ApiToken(user_id=user_id, name=name, token_hash=token_hash, expires_at=expires_at)
    session.add(token)
    await session.commit()
    await session.refresh(token)
    return token, raw


async def list_user_tokens(session: AsyncSession, user_id: int) -> list[ApiToken]:
    """Bir kullanıcının kendi token'larını (yenisi üstte) listeler."""
    result = await session.execute(
        select(ApiToken).where(ApiToken.user_id == user_id).order_by(ApiToken.id.desc())
    )
    return list(result.scalars().all())


async def revoke_user_token(session: AsyncSession, token_id: int, user_id: int) -> bool:
    """Token'ı iptal eder — yalnızca sahibi iptal edebilir. Başarılıysa True."""
    token = await session.get(ApiToken, token_id)
    if token is None or token.user_id != user_id:
        return False
    token.revoked = True
    await session.commit()
    return True


async def user_from_token(session: AsyncSession, raw: str) -> User | None:
    """Ham Bearer token'ı geçerli, aktif bir kullanıcıya çözer; aksi halde None."""
    if not raw.startswith(TOKEN_PREFIX):
        return None
    result = await session.execute(select(ApiToken).where(ApiToken.token_hash == _hash_token(raw)))
    token = result.scalar_one_or_none()
    if token is None or token.revoked:
        return None
    if token.expires_at is not None:
        expires = token.expires_at
        if expires.tzinfo is None:  # SQLite naive değerleri için UTC varsay
            expires = expires.replace(tzinfo=UTC)
        if expires < datetime.now(UTC):
            return None
    user = await session.get(User, token.user_id)
    if user is None or not user.is_active:
        return None
    token.last_used_at = datetime.now(UTC)
    await session.commit()
    return user
