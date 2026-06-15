"""LDAP periyodik kullanıcı senkronu (X-6) — zamanlama (saf) + çekme.

Beat saatlik çalışır; ``is_ldap_sync_due`` period + saat + son-senkrona bakıp tetikleyip
tetiklemeyeceğine SAF olarak karar verir (test edilebilir). ``sync_ldap_users`` LDAP'tan
tüm kullanıcıları çekip içe aktarır — **YENİ üyeler pasif gelir, VAR OLANLARIN rol/aktifliği
KORUNUR** (import_ldap_users deseni; admin sonradan etkinleştirir).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.app_settings import get_settings
from cybersectool.core.ldap import ldap_search_users
from cybersectool.core.ldap_config import get_bind_password, get_ldap_config
from cybersectool.core.models import Role
from cybersectool.core.users import import_ldap_users

LDAP_SYNC_PERIODS: tuple[str, ...] = ("hourly", "daily", "weekly")
_PERIOD_SECONDS: dict[str, int] = {"hourly": 3600, "daily": 86_400, "weekly": 604_800}
# Beat saatlik koştuğu için bir periyot-süresinden ~1 saat slack düşülür (kaçırma önlemi).
_SLACK_SECONDS = 3600


def is_ldap_sync_due(
    period: str, hour: int, last_local: datetime | None, now_local: datetime
) -> bool:
    """Periyodik LDAP senkronunun zamanı geldi mi? (saf — YEREL saatler verilir).

    - ``hourly``: son senkrondan ~1 saat geçtiyse.
    - ``daily``/``weekly``: yeterli süre geçti VE yerel saat yapılandırılan ``hour`` ise
      (beat saatlik koştuğundan o saat penceresinde bir kez tetiklenir).
    Hiç senkron yapılmadıysa (last_local=None): hourly hemen, daily/weekly o saatte.
    """
    if period not in LDAP_SYNC_PERIODS:
        return False
    if last_local is None:
        return period == "hourly" or now_local.hour == hour
    elapsed = (now_local - last_local).total_seconds()
    if period == "hourly":
        return elapsed >= _PERIOD_SECONDS["hourly"] - 60
    threshold = _PERIOD_SECONDS[period] - _SLACK_SECONDS
    return elapsed >= threshold and now_local.hour == hour


def _safe_role(value: str) -> Role:
    """Yapılandırmadaki varsayılan rol dizesini Role'e çevirir (geçersizse viewer)."""
    try:
        return Role(value)
    except ValueError:
        return Role.viewer


async def sync_ldap_users(session: AsyncSession) -> dict[str, int | bool]:
    """LDAP'tan tüm kullanıcıları çekip içe aktarır (yeni=pasif, var olan KORUNUR).

    LDAP yapılandırılmamışsa ``skipped=True`` döner. Aksi halde
    ``{created, existing, skipped=False}``.
    """
    config = await get_ldap_config(session)
    if config is None or not config.server_uri or not config.base_dn:
        return {"created": 0, "existing": 0, "skipped": True}
    app_row = await get_settings(session)
    users = await ldap_search_users(
        config,
        get_bind_password(config),
        "",
        verify_cert=app_row.ldaps_verify_cert,
        ca_cert=app_row.ldaps_ca_cert,
    )
    members = [(u.username, u.email) for u in users if u.username]
    created, existing = await import_ldap_users(
        session, members, _safe_role(config.default_role), active=False
    )
    return {"created": created, "existing": existing, "skipped": False}
