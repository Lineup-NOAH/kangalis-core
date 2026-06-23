"""Çalışma-anı bileşen sürümlerini toplar — Güncelleme sayfası (``/update``) için.

Ürünün kendi sürümü (``cybersectool.__version__``) + harici/altyapı bileşenleri
(nmap, Python, PostgreSQL, Redis, yerel AI modeli). Her probe **HATA-YUTAR**: bir
sorgu başarısız olursa ``None`` döner (sayfa asla çökmez), UI "bilinmiyor" gösterir.

nmap/Python süreç-ömrü boyunca sabittir → ``lru_cache``'lenir; DB/Redis sürümü ucuz
sorgudur, canlı okunur. nmap probe'u ayrı süreç çağrısı olduğundan ``gather_versions``
onu ``asyncio.to_thread`` ile koşar (event loop'u bloklamaz).
"""

from __future__ import annotations

import asyncio
import platform
import re
import shutil
import subprocess

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool import __version__
from cybersectool.config import settings
from cybersectool.core.models import AppSettings


def app_version() -> str:
    """Kangalis ürün sürümü (tek kaynak: ``cybersectool.__version__``)."""
    return __version__


def python_version() -> str:
    """Çalışan Python yorumlayıcı sürümü (ör. ``3.12.7``)."""
    return platform.python_version()


def nmap_version() -> str | None:
    """Kurulu nmap ikilisinin sürümü (``Nmap version X.YZ`` ilk satırından).

    nmap yoksa / çalışmazsa ``None`` (UI "bilinmiyor" + Eklentiler'e yönlendirir).
    KABUK YOK (argv listesi), kullanıcı girdisi geçmez (sabit komut) → enjeksiyon riski yok.
    """
    exe = shutil.which("nmap")
    if not exe:
        return None
    try:
        out = subprocess.run(  # noqa: S603 (sabit argv, kabuk yok, kullanıcı girdisi yok)
            [exe, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"Nmap version\s+(\S+)", out.stdout or "")
    return match.group(1) if match else None


async def postgres_version(session: AsyncSession) -> str | None:
    """PostgreSQL sunucu sürümü (``SELECT version()`` → "PostgreSQL X.Y" çıkarımı)."""
    try:
        result = await session.execute(text("SELECT version()"))
        raw = (result.scalar_one_or_none() or "").strip()
    except Exception:
        return None
    match = re.search(r"PostgreSQL\s+(\S+)", raw)
    return match.group(1) if match else (raw[:40] or None)


async def redis_version() -> str | None:
    """Redis sunucu sürümü (``INFO server`` → ``redis_version``). Erişilemezse ``None``."""
    try:
        import redis.asyncio as aioredis

        client = aioredis.from_url(  # type: ignore[no-untyped-call]
            settings.redis_url, socket_connect_timeout=2, socket_timeout=2
        )
        try:
            info = await client.info("server")
        finally:
            await client.aclose()
    except Exception:
        return None
    if isinstance(info, dict):
        value = info.get("redis_version")
        return str(value) if value else None
    return None


def _ai_model_label(row: AppSettings) -> str | None:
    """Yapılandırılan yerel AI modeli (AI etkinse). Kapalıysa ``None`` (satır gizlenir)."""
    if not row.ai_enabled:
        return None
    return (row.ai_model_name or "").strip() or "qwen3:8b"


async def gather_versions(session: AsyncSession, row: AppSettings) -> dict[str, str | None]:
    """Tüm bileşen sürümlerini tek sözlükte toplar (Güncelleme sayfası için).

    nmap + Python (süreç çağrısı/CPU) ``asyncio.to_thread`` ile koşulur; PostgreSQL/Redis
    canlı sorgulanır; hepsi hata-yutar (probe patlarsa ilgili değer ``None``).
    """
    nmap, py = await asyncio.to_thread(lambda: (nmap_version(), python_version()))
    return {
        "app": app_version(),
        "nmap": nmap,
        "python": py,
        "postgres": await postgres_version(session),
        "redis": await redis_version(),
        "ai": _ai_model_label(row),
    }
