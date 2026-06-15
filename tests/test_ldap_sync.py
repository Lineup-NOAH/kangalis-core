"""LDAP periyodik senkron (X-6): due-zamanlama (saf) + ayar kaydı + çekme testleri."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.app_settings import get_settings, save_ldap_sync_settings
from cybersectool.core.ldap_sync import is_ldap_sync_due, sync_ldap_users

NOW = datetime(2026, 6, 8, 3, 30, 0)  # yerel saat 03:30


def test_due_hourly() -> None:
    # Hiç çalışmadı → saatlikte hemen.
    assert is_ldap_sync_due("hourly", 3, None, NOW) is True
    # 30 dk önce → henüz değil.
    assert is_ldap_sync_due("hourly", 3, NOW - timedelta(minutes=30), NOW) is False
    # 61 dk önce → zamanı geldi.
    assert is_ldap_sync_due("hourly", 3, NOW - timedelta(minutes=61), NOW) is True


def test_due_daily_hour_window() -> None:
    # Hiç çalışmadı + yerel saat == yapılandırılan saat (3) → zamanı.
    assert is_ldap_sync_due("daily", 3, None, NOW) is True
    # Hiç çalışmadı ama saat eşleşmiyor → değil.
    assert is_ldap_sync_due("daily", 9, None, NOW) is False
    # 25 saat önce + saat eşleşiyor → zamanı.
    assert is_ldap_sync_due("daily", 3, NOW - timedelta(hours=25), NOW) is True
    # 25 saat önce ama saat eşleşmiyor → değil (yanlış saatte tetiklenmez).
    assert is_ldap_sync_due("daily", 9, NOW - timedelta(hours=25), NOW) is False
    # Yeterli süre geçmedi (2 saat) → değil.
    assert is_ldap_sync_due("daily", 3, NOW - timedelta(hours=2), NOW) is False


def test_due_weekly_and_invalid() -> None:
    assert is_ldap_sync_due("weekly", 3, NOW - timedelta(days=8), NOW) is True
    assert is_ldap_sync_due("weekly", 3, NOW - timedelta(days=2), NOW) is False
    assert is_ldap_sync_due("bogus", 3, None, NOW) is False


async def test_save_ldap_sync_settings_clamps(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        row = await save_ldap_sync_settings(session, enabled=True, period="weekly", hour=99)
        assert row.ldap_sync_enabled is True
        assert row.ldap_sync_period == "weekly"
        assert row.ldap_sync_hour == 23  # 0-23'e kırpıldı
        # Geçersiz period → daily'ye düşer.
        row2 = await save_ldap_sync_settings(session, enabled=False, period="zzz", hour=5)
        assert row2.ldap_sync_period == "daily"
        assert row2.ldap_sync_hour == 5
        assert (await get_settings(session)).ldap_sync_enabled is False


async def test_sync_ldap_users_imports_inactive(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LDAP'tan çekilen yeni üyeler PASİF oluşur; var olanların durumu korunur."""
    from cybersectool.core import ldap_sync as ldap_sync_mod
    from cybersectool.core.ldap import LdapUser
    from cybersectool.core.ldap_config import save_ldap_config
    from cybersectool.core.users import get_user_by_username

    async with session_factory() as session:
        await save_ldap_config(
            session,
            server_uri="ldap://x:389",
            use_ssl=False,
            bind_dn="",
            base_dn="dc=x",
            user_filter="(objectClass=person)",
            attr_username="uid",
            attr_email="mail",
            attr_display_name="cn",
            default_role="viewer",
            bind_password=None,
        )

    async def fake_search(*a: object, **k: object) -> list[LdapUser]:
        return [
            LdapUser("carol", "c@x", "Carol", "uid=carol,dc=x"),
            LdapUser("dave", None, None, "uid=dave,dc=x"),
        ]

    monkeypatch.setattr(ldap_sync_mod, "ldap_search_users", fake_search)
    async with session_factory() as session:
        result = await sync_ldap_users(session)
        assert result["skipped"] is False
        assert result["created"] == 2
    async with session_factory() as session:
        carol = await get_user_by_username(session, "carol")
        assert carol is not None and carol.is_active is False  # pasif geldi


async def test_run_ldap_sync_ignores_env_flag(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Periyodik senkron ortam bayrağına (LDAP_ENABLED) BAKMAZ: UI ayarı + DB bağlantısı yeter.

    Regresyon: eski kod settings.ldap_enabled kapalıyken hemen 'ldap_disabled' dönüp hiç
    senkron yapmıyordu (UI'dan kurulan senkron çalışmıyordu).
    """
    from cybersectool.core import ldap_sync as core_mod
    from cybersectool.core.ldap import LdapUser
    from cybersectool.core.ldap_config import save_ldap_config
    from cybersectool.tasks import ldap_sync as task_mod

    # LDAP_ENABLED açıkça KAPALI olsa bile senkron çalışmalı.
    monkeypatch.setattr(task_mod.settings, "ldap_enabled", False)

    async def fake_search(*a: object, **k: object) -> list[LdapUser]:
        return [LdapUser("erin", "e@x", "Erin", "uid=erin,dc=x")]

    monkeypatch.setattr(core_mod, "ldap_search_users", fake_search)

    async with session_factory() as session:
        await save_ldap_config(
            session,
            server_uri="ldap://x:389",
            use_ssl=False,
            bind_dn="",
            base_dn="dc=x",
            user_filter="(objectClass=person)",
            attr_username="uid",
            attr_email="mail",
            attr_display_name="cn",
            default_role="viewer",
            bind_password=None,
        )
        await save_ldap_sync_settings(session, enabled=True, period="hourly", hour=0)
        # ldap_sync_last None + hourly → hemen due; env bayrağına bakmadan senkronlamalı.
        res = await task_mod.run_ldap_sync(session)
        assert res.startswith("synced") and "created=1" in res
        assert (await get_settings(session)).ldap_sync_last is not None

    # UI ayarı kapalıyken sync_disabled döner (env'den bağımsız).
    async with session_factory() as session:
        await save_ldap_sync_settings(session, enabled=False, period="hourly", hour=0)
        assert await task_mod.run_ldap_sync(session) == "sync_disabled"
