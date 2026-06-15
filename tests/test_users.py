"""Kullanıcı yönetimi servis testleri (rol/aktiflik/silme)."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Role
from cybersectool.core.users import (
    create_user,
    delete_user,
    get_user_by_username,
    list_users,
    set_user_active,
    set_user_role,
)


async def test_user_management(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        user = await create_user(session, "alice", "pw", role=Role.viewer)
        assert user.role == Role.viewer and user.is_active is True
        assert await get_user_by_username(session, "alice") is not None

        # Rol değiştir
        assert await set_user_role(session, user.id, Role.analyst) is True
        fetched = await get_user_by_username(session, "alice")
        assert fetched is not None and fetched.role == Role.analyst

        # Pasifleştir
        assert await set_user_active(session, user.id, False) is True
        fetched = await get_user_by_username(session, "alice")
        assert fetched is not None and fetched.is_active is False

        # Sil
        assert await delete_user(session, user.id) is True
        assert await delete_user(session, user.id) is False
        assert await list_users(session) == []
