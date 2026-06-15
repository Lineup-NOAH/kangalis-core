"""Yerel AI üretim önbelleği (#183) — aynı içerik tekrar üretilmez (CPU pahalı).

``cache_key`` üretimin neyi açıkladığını belirler (bkz. ``AIExplanation``). Per-bulgu açıklama
CVE'ler arasında paylaşılır (aynı CVE farklı host'larda tek üretilir). Önbellek-hit anında
döner; miss'te route generate edip ``store`` eder.
"""

from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.models import AIExplanation


def digest(text: str) -> str:
    """Önbellek anahtarı için kararlı kısa özet (sha256 ilk 32 hex = 128-bit).

    Çakışmaya-dayanıklı; TÜM AI önbellek hash'leri (finding/exploit-diagnose/trend) bunu
    tek noktadan kullanır — eski sha1[:16] (64-bit) yerine.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def finding_cache_key(*, cve_id: str | None, title: str) -> str:
    """Bir bulgu için önbellek anahtarı: CVE varsa ``cve:<id>``, yoksa ``finding:<slug>``.

    CVE'li bulgular CVE üzerinden paylaşılır (host bağımsız). CVE'siz bulgular (zayıf
    kimlik/açık servis) başlığın kararlı kısa-hash'iyle anahtarlanır.
    """
    if cve_id:
        return f"cve:{cve_id.strip().upper()}"
    return f"finding:{digest(title.strip().lower())}"


async def get_cached(session: AsyncSession, cache_key: str) -> AIExplanation | None:
    """Önbellekten üretimi getir (yoksa None)."""
    result = await session.execute(
        select(AIExplanation).where(AIExplanation.cache_key == cache_key)
    )
    return result.scalar_one_or_none()


async def get_many(session: AsyncSession, cache_keys: list[str]) -> dict[str, AIExplanation]:
    """Birden çok anahtarı tek sorguda getir (rapor ön-yüklemesi). {cache_key: satır}."""
    if not cache_keys:
        return {}
    result = await session.execute(
        select(AIExplanation).where(AIExplanation.cache_key.in_(cache_keys))
    )
    return {row.cache_key: row for row in result.scalars()}


async def store(
    session: AsyncSession, cache_key: str, content: str, *, model: str
) -> AIExplanation:
    """Üretimi önbelleğe yaz (varsa içeriği tazele). Tekil ``cache_key`` korunur."""
    row = await get_cached(session, cache_key)
    if row is None:
        row = AIExplanation(cache_key=cache_key, content=content, model=model)
        session.add(row)
    else:
        row.content = content
        row.model = model
    await session.commit()
    await session.refresh(row)
    return row
