"""FastAPI bağımlılıkları: kimlik doğrulama (session + API token) ve yetki (RBAC)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.db import get_session
from cybersectool.core.models import Role, User
from cybersectool.core.session_guard import session_idle_expired, touch_session
from cybersectool.core.tokens import user_from_token
from cybersectool.core.users import get_user_by_id

SessionDep = Annotated[AsyncSession, Depends(get_session)]


async def get_current_user(
    request: Request,
    session: SessionDep,
    authorization: Annotated[str | None, Header()] = None,
) -> User:
    """Geçerli kullanıcıyı çözer: önce ``Bearer`` API token, yoksa session cookie."""
    if authorization and authorization.startswith("Bearer "):
        raw = authorization.removeprefix("Bearer ").strip()
        user = await user_from_token(session, raw)
        if user is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Geçersiz token")
        return user

    user_id = request.session.get("user_id")
    if user_id is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Giriş gerekli")
    # Idle zaman aşımı: süre dolduysa oturumu düşür.
    if session_idle_expired(request.session):
        request.session.clear()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Oturum zaman aşımına uğradı")
    user = await get_user_by_id(session, int(user_id))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Geçersiz oturum")
    touch_session(request.session)
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_role(*roles: Role) -> Callable[[User], User]:
    """Belirtilen rollerden birine sahip olmayı zorunlu kılan bağımlılık üretir."""

    def checker(user: CurrentUser) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Yetki yok")
        return user

    return checker
