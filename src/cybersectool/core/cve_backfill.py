"""NVD geçmiş-yükleme (backfill) ilerleme + iptal durumu — Redis tabanlı.

Geçmiş CVE/CPE backfill'i uzun sürer (anahtarsız onlarca dakika). Bu modül çalışan backfill
görevinin ilerlemesini (pencere X/Y, eklenen CVE sayısı, geçerli aralık) Redis'te tutar;
Ayarlar sayfası bunu HTMX ile canlı gösterir. Ayrıca kooperatif **iptal** bayrağı: görev her
pencere arasında bunu yoklar, set'liyse temiz durur (o ana dek yazılan veri korunur).

Tasarım — login_guard ile aynı desen: tek lazy async Redis istemcisi, tüm erişimler
``contextlib.suppress`` ile fail-safe (Redis yoksa ilerleme görünmez ama ana akış bozulmaz).
Celery worker'ı her görevi ``asyncio.run`` ile YENİ event loop'ta çalıştırdığından, backfill
görevi başında ``reset_client()`` çağırıp taze istemci kurar, sonunda ``aclose()`` ile kapatır;
web tarafı sabit loop'ta tek istemciyle çalışır.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as aioredis

from cybersectool.config import settings as app_config

# Tek hash anahtarı; alanlar: status/windows_total/windows_done/cves/cpe_total/current/
# years/started_at/updated_at/error/cancel. Terminal/atıl durum 24s sonra kendini siler.
_KEY = "kg:nvd:backfill"
_LOCK = "kg:nvd:backfill:lock"  # tek-koşu atomik kilidi (worker tarafı; çift backfill engeli)
_LOCK_TTL = 7200  # 2s; worker çökerse kilit en geç bu sürede serbest kalır
_TTL = 86400
_ACTIVE = ("running", "queued")

_client: aioredis.Redis | None = None


def _redis() -> aioredis.Redis:
    """Süreç-ömrü boyunca tek async Redis istemcisi (lazy)."""
    global _client
    if _client is None:
        _client = aioredis.from_url(  # type: ignore[no-untyped-call]
            app_config.redis_url, decode_responses=True
        )
    return _client


def reset_client() -> None:
    """Singleton'ı bırakır (worker yeni event loop'ta taze istemci kursun)."""
    global _client
    _client = None


async def aclose() -> None:
    """İstemciyi kapatır + bırakır (worker görev sonunda bağlantıları sızdırmasın)."""
    global _client
    if _client is not None:
        with contextlib.suppress(Exception):
            await _client.aclose()
        _client = None


def _now() -> str:
    return datetime.now(UTC).isoformat()


async def mark_queued(*, years: int) -> None:
    """Görev kuyruğa alındı (worker henüz başlamadı) — UI hemen 'başlatılıyor' göstersin."""
    now = _now()
    with contextlib.suppress(Exception):
        r = _redis()
        await r.delete(_KEY)
        await r.hset(  # type: ignore[misc]
            _KEY,
            mapping={
                "status": "queued",
                "windows_total": "0",
                "windows_done": "0",
                "cves": "0",
                "cpe_total": "0",
                "current": "",
                "years": str(years),
                "started_at": now,
                "updated_at": now,
                "error": "",
                "cancel": "0",
            },
        )
        await r.expire(_KEY, _TTL)


async def begin(*, windows_total: int, years: int) -> None:
    """Backfill başlangıcı: status=running, sayaçlar sıfır.

    Kuyruk anı (``mark_queued``) ile bu çağrı arasında basılmış olabilecek iptal isteğini KORUR;
    aksi halde queued penceresinde verilen iptal silinir ve yükleme yine de tam koşardı.
    """
    now = _now()
    with contextlib.suppress(Exception):
        r = _redis()
        pending_cancel = await r.hget(_KEY, "cancel")  # type: ignore[misc]
        await r.delete(_KEY)
        await r.hset(  # type: ignore[misc]
            _KEY,
            mapping={
                "status": "running",
                "windows_total": str(max(windows_total, 0)),
                "windows_done": "0",
                "cves": "0",
                "cpe_total": "0",
                "current": "",
                "years": str(years),
                "started_at": now,
                "updated_at": now,
                "error": "",
                "cancel": "1" if pending_cancel == "1" else "0",
            },
        )
        await r.expire(_KEY, _TTL)


async def update(*, windows_done: int, cves: int, cpe_total: int, current: str) -> None:
    """Bir pencere bittiğinde ilerlemeyi günceller."""
    with contextlib.suppress(Exception):
        r = _redis()
        await r.hset(  # type: ignore[misc]
            _KEY,
            mapping={
                "windows_done": str(windows_done),
                "cves": str(cves),
                "cpe_total": str(cpe_total),
                "current": current,
                "updated_at": _now(),
            },
        )
        await r.expire(_KEY, _TTL)


async def finish(*, status: str, cves: int, cpe_total: int, error: str = "") -> None:
    """Terminal durum (done/cancelled/error) yazar."""
    with contextlib.suppress(Exception):
        r = _redis()
        await r.hset(  # type: ignore[misc]
            _KEY,
            mapping={
                "status": status,
                "cves": str(cves),
                "cpe_total": str(cpe_total),
                "error": error,
                "updated_at": _now(),
            },
        )
        await r.expire(_KEY, _TTL)


async def request_cancel() -> bool:
    """Çalışan/kuyruktaki backfill için iptal bayrağını set eder. Döner: işaretlendi mi."""
    with contextlib.suppress(Exception):
        r = _redis()
        if (await r.hget(_KEY, "status")) in _ACTIVE:  # type: ignore[misc]
            await r.hset(_KEY, "cancel", "1")  # type: ignore[misc]
            await r.expire(_KEY, _TTL)
            return True
    return False


async def acquire() -> bool:
    """Atomik tek-koşu kilidini al (worker tarafı). Aynı anda yalnız bir backfill koşar.

    ``SET NX`` atomiktir → iki görev yarışsa bile yalnız biri kazanır; öteki erken çıkar.
    Redis erişilemezse **fail-OPEN** (True): ilerleme/kilit görünmez ama çekirdek iş yine koşar.
    """
    with contextlib.suppress(Exception):
        return bool(await _redis().set(_LOCK, "1", nx=True, ex=_LOCK_TTL))
    return True


async def release() -> None:
    """Tek-koşu kilidini bırakır (worker görev sonunda)."""
    with contextlib.suppress(Exception):
        await _redis().delete(_LOCK)


async def is_cancelled() -> bool:
    """Görev bu bayrağı pencere aralarında yoklar."""
    with contextlib.suppress(Exception):
        flag: str | None = await _redis().hget(_KEY, "cancel")  # type: ignore[misc]
        return flag == "1"
    return False


async def is_active() -> bool:
    """Backfill kuyrukta ya da çalışıyor mu (ikinci başlatmayı engellemek için)."""
    with contextlib.suppress(Exception):
        return (await _redis().hget(_KEY, "status")) in _ACTIVE  # type: ignore[misc]
    return False


async def state() -> dict[str, Any] | None:
    """UI için tüm durum (yoksa None). ``percent`` türetilir."""
    with contextlib.suppress(Exception):
        raw: dict[str, str] = await _redis().hgetall(_KEY)  # type: ignore[misc]
        if not raw:
            return None
        total = int(raw.get("windows_total", "0") or 0)
        done = int(raw.get("windows_done", "0") or 0)
        out: dict[str, Any] = {}
        out.update(raw)
        if total > 0:
            out["percent"] = min(100, int(done * 100 / total))
        else:
            out["percent"] = 100 if raw.get("status") == "done" else 0
        return out
    return None
