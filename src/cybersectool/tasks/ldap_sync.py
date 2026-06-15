"""LDAP periyodik kullanıcı senkronu beat görevi (X-6).

Saatlik koşar; senkron etkin (UI ayarı) + (period/saat'e göre) zamanı geldiyse DB'deki
LDAP bağlantısından (LdapConfig) kullanıcıları çeker (yeni=pasif, var olan korunur) ve
``ldap_sync_last``'ı günceller. **Ortam değişkeni LDAP_ENABLED'a BAKMAZ** — o yalnız LDAP
*ile giriş* (kimlik doğrulama) içindir; periyodik kullanıcı senkronu tamamen UI'dan
yönetilen DB bağlantısını kullanır. Bağlantı yoksa/erişilemezse sessiz geçer (en iyi çaba).
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime, tzinfo
from zoneinfo import ZoneInfo

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from cybersectool.config import settings
from cybersectool.core.app_settings import get_settings
from cybersectool.core.audit import log_action
from cybersectool.core.ldap_sync import is_ldap_sync_due, sync_ldap_users
from cybersectool.tasks.celery_app import celery_app


def _local(dt: datetime, tz_name: str) -> datetime:
    """UTC datetime'ı verilen IANA dilimine çevirir (geçersiz dilimde UTC'ye düşer)."""
    tz: tzinfo
    try:
        tz = ZoneInfo(tz_name)
    except Exception:  # noqa: BLE001
        tz = UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(tz)


async def run_ldap_sync(session: AsyncSession, *, now: datetime | None = None) -> str:
    """Senkron kararını verip (zamanı geldiyse) LDAP'tan kullanıcıları çeker.

    Ortam değişkeni ``LDAP_ENABLED``'a BAKMAZ — yalnız UI ayarı (``ldap_sync_enabled``),
    zamanlama (``is_ldap_sync_due``) ve DB'deki ``LdapConfig`` belirleyicidir. ``now``
    test için enjekte edilebilir (verilmezse UTC şimdi).
    """
    row = await get_settings(session)
    if not row.ldap_sync_enabled:
        return "sync_disabled"
    now_utc = now or datetime.now(UTC)
    now_local = _local(now_utc, row.timezone)
    last_local = _local(row.ldap_sync_last, row.timezone) if row.ldap_sync_last else None
    if not is_ldap_sync_due(row.ldap_sync_period, row.ldap_sync_hour, last_local, now_local):
        return "not_due"
    result = await sync_ldap_users(session)
    if result.get("skipped"):
        return "ldap_not_configured"  # DB'de LDAP bağlantısı yok → çekme yapılmadı
    row.ldap_sync_last = datetime.now(UTC)
    await session.commit()
    with contextlib.suppress(Exception):
        await log_action(
            session,
            "ldap_sync",
            target=f"yeni={result['created']} mevcut={result['existing']}",
        )
    return f"synced created={result['created']} existing={result['existing']}"


async def _run() -> str:
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            return await run_ldap_sync(session)
    finally:
        await engine.dispose()


@celery_app.task(name="ldap_sync")
def ldap_sync_task() -> str:
    return asyncio.run(_run())
