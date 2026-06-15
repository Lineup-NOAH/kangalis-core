"""Denetim günlüğü (audit log) servis fonksiyonları.

Her eylem tipinin stabil bir ``event_id`` kodu vardır (Windows Event ID benzeri)
— loglama/SIEM tarafında filtrelemeyi kolaylaştırır. Eylem→event_id/kategori/anlamlı
mesaj eşlemesi tek kaynaktan (:mod:`cybersectool.core.audit_events`) gelir. Zaman
dilimi (günlük/haftalık/aylık), tarih aralığı, anahtar kelime ve event_id filtreleri
ile CSV/JSON dışa aktarma desteklenir.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.app_settings import get_settings
from cybersectool.core.audit_events import (
    AUDIT_EVENTS,
    UNKNOWN_EVENT_ID,
    category_for,
    event_id_for,
    render_message,
)
from cybersectool.core.models import AuditLog
from cybersectool.core.syslog_forward import forward_audit

# Geriye dönük uyumluluk: eylem → stabil event_id (tek kaynak audit_events).
ACTION_EVENT_IDS: dict[str, int] = {a: m.event_id for a, m in AUDIT_EVENTS.items()}

__all__ = [
    "ACTION_EVENT_IDS",
    "UNKNOWN_EVENT_ID",
    "category_for",
    "event_id_for",
    "export_audit_logs",
    "list_audit_logs",
    "log_action",
    "query_audit_logs",
    "range_since",
    "render_message",
]

# UI zaman dilimi → gün sayısı (None = tümü).
RANGE_DAYS: dict[str, int] = {"day": 1, "week": 7, "month": 30}


def range_since(range_key: str, now: datetime | None = None) -> datetime | None:
    """Zaman dilimi anahtarından başlangıç zamanı (None = sınırsız/tümü)."""
    days = RANGE_DAYS.get(range_key)
    if days is None:
        return None
    return (now or datetime.now(UTC)) - timedelta(days=days)


async def log_action(
    session: AsyncSession,
    action: str,
    user_id: int | None = None,
    target: str | None = None,
) -> AuditLog:
    """Bir eylemi denetim günlüğüne yazar (kim, neyi, event_id ile) ve syslog'a iletir."""
    entry = AuditLog(action=action, user_id=user_id, target=target, event_id=event_id_for(action))
    session.add(entry)
    await session.commit()
    await session.refresh(entry)
    # SIEM forward (best-effort): yapılandırılmışsa syslog'a ilet; hata audit'i bozmaz.
    with contextlib.suppress(Exception):
        settings_row = await get_settings(session)
        if settings_row.syslog_enabled:
            await forward_audit(settings_row, entry)
    return entry


async def list_audit_logs(
    session: AsyncSession, limit: int = 100, since: datetime | None = None
) -> list[AuditLog]:
    """Denetim kayıtlarını (en yeni önce) döndürür; since verilirse o andan itibaren."""
    stmt = select(AuditLog).order_by(AuditLog.id.desc())
    if since is not None:
        stmt = stmt.where(AuditLog.created_at >= since)
    stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def export_audit_logs(
    session: AsyncSession, since: datetime | None = None, max_rows: int = 100000
) -> list[AuditLog]:
    """Dışa aktarma için kayıtları (eski→yeni) döndürür; since verilirse o aralık."""
    stmt = select(AuditLog).order_by(AuditLog.id.asc())
    if since is not None:
        stmt = stmt.where(AuditLog.created_at >= since)
    result = await session.execute(stmt.limit(max_rows))
    return list(result.scalars().all())


async def query_audit_logs(
    session: AsyncSession,
    *,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    keyword: str | None = None,
    event_id: int | None = None,
    matched_user_ids: list[int] | None = None,
    limit: int = 500,
) -> list[AuditLog]:
    """Denetim kayıtlarını birden çok ölçüte göre filtreli döndürür (en yeni önce).

    * ``date_from`` / ``date_to`` — tarih/zaman aralığı (dahil).
    * ``keyword`` — ``action``/``target`` (büyük-küçük harf duyarsız) içinde geçer; ek
      olarak ``matched_user_ids`` verilirse o kullanıcı id'lerini de eşler (kullanıcı
      adıyla arama için, çağıran uçta çözülür).
    * ``event_id`` — tam event_id eşleşmesi.
    """
    stmt = select(AuditLog).order_by(AuditLog.id.desc())
    if date_from is not None:
        stmt = stmt.where(AuditLog.created_at >= date_from)
    if date_to is not None:
        stmt = stmt.where(AuditLog.created_at <= date_to)
    if event_id is not None:
        stmt = stmt.where(AuditLog.event_id == event_id)
    if keyword:
        like = f"%{keyword.strip()}%"
        clauses = [AuditLog.action.ilike(like), AuditLog.target.ilike(like)]
        if matched_user_ids:
            clauses.append(AuditLog.user_id.in_(matched_user_ids))
        stmt = stmt.where(or_(*clauses))
    stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    return list(result.scalars().all())
