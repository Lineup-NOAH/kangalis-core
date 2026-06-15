"""API token yönetimi uçları (oturumlu kullanıcı kendi token'larını yönetir)."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict

from cybersectool.api.deps import CurrentUser, SessionDep
from cybersectool.core.models import ApiToken
from cybersectool.core.tokens import create_api_token, list_user_tokens, revoke_user_token

router = APIRouter(prefix="/auth/tokens", tags=["tokens"])


class TokenCreateIn(BaseModel):
    name: str
    expires_at: datetime | None = None


class TokenOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    revoked: bool
    expires_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime


class TokenCreatedOut(TokenOut):
    token: str  # ham token — yalnızca oluşturma anında döner


@router.post("", response_model=TokenCreatedOut)
async def create_token(
    data: TokenCreateIn, user: CurrentUser, session: SessionDep
) -> TokenCreatedOut:
    token, raw = await create_api_token(session, user.id, data.name, data.expires_at)
    return TokenCreatedOut(
        id=token.id,
        name=token.name,
        revoked=token.revoked,
        expires_at=token.expires_at,
        last_used_at=token.last_used_at,
        created_at=token.created_at,
        token=raw,
    )


@router.get("", response_model=list[TokenOut])
async def list_tokens(user: CurrentUser, session: SessionDep) -> list[ApiToken]:
    return await list_user_tokens(session, user.id)


@router.delete("/{token_id}")
async def revoke_token(token_id: int, user: CurrentUser, session: SessionDep) -> dict[str, str]:
    if not await revoke_user_token(session, token_id, user.id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Token bulunamadı")
    return {"status": "revoked"}
