"""Kimlik doğrulama uçları: login / logout / me."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from cybersectool.api.deps import CurrentUser, SessionDep
from cybersectool.core.app_settings import get_settings
from cybersectool.core.audit import log_action
from cybersectool.core.login_guard import (
    clear_login_failures,
    login_lockout_remaining,
    record_login_failure,
)
from cybersectool.core.models import AuthSource, Role, User
from cybersectool.core.session_guard import start_session_timeout
from cybersectool.core.users import authenticate_user

router = APIRouter(prefix="/auth", tags=["auth"])

_LOCKED_MSG = "Çok fazla başarısız deneme. Hesap geçici olarak kilitlendi; sonra tekrar deneyin."


class LoginIn(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str | None
    role: Role
    auth_source: AuthSource


@router.post("/login", response_model=UserOut)
async def login(data: LoginIn, request: Request, session: SessionDep) -> User:
    settings_row = await get_settings(session)
    # Hesap kilitliyse doğru parola bile reddedilir (kaba-kuvvet koruması).
    if await login_lockout_remaining(settings_row, data.username):
        await log_action(session, "login_locked", target=data.username[:120])
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, _LOCKED_MSG)
    user = await authenticate_user(session, data.username, data.password)
    if user is None:
        locked = await record_login_failure(settings_row, data.username)
        await log_action(session, "login_failed", target=data.username[:120])
        if locked:
            await log_action(session, "login_locked", target=data.username[:120])
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, _LOCKED_MSG)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Kullanıcı adı veya parola hatalı")
    # MFA bypass koruması: MFA etkin hesaplar bu JSON ucundan parolayla oturum AÇAMAZ.
    # İkinci doğrulama yalnızca web arayüzünde (/login/mfa) yapılır; programatik erişim
    # için MFA ile web'den girip API token (Bearer) oluşturulmalıdır.
    if user.mfa_enabled:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Bu hesapta MFA etkin; web arayüzünden giriş yapın ya da API token kullanın.",
        )
    await clear_login_failures(data.username)
    request.session["user_id"] = user.id
    # Sorumluluk reddi kapısı bu bayrağı okur (gate middleware — DB sorgusu yok).
    request.session["disclaimer_ok"] = user.disclaimer_accepted_at is not None
    start_session_timeout(request.session, settings_row.session_timeout_min)
    return user


@router.post("/logout")
async def logout(request: Request) -> dict[str, str]:
    request.session.clear()
    return {"status": "logged_out"}


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser) -> User:
    return user
