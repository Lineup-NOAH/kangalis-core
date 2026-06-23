"""Yeni sürüm denetimi — GitHub Releases'i sorgulayıp en güncel sürümü saklar.

Günlük beat görevi (``tasks/update_check.py``) + admin "Şimdi denetle" butonu bunu
çağırır. Sonuç ``AppSettings``'e yazılır (``latest_version`` + son-denetim zamanı +
durum); UI bunu gösterir. Sayfa yüklenişi denetim TETİKLEMEZ (egress yapmaz) — yalnız
saklı sonucu okur (``stored_status``).

**DIŞ-ERİŞİM (egress) UYARISI:** yalnız bu denetim internete çıkar. ``update_check_enabled``
ile kapatılabilir (air-gap/sıfır-egress), URL ``update_check_url`` ile değiştirilebilir
(kendi ayna/sürüm sunucusu). Uygulamanın geri kalanı tamamen yereldir.

**ASLA istisna fırlatmaz:** ağ/parse hatası → durum ``unreachable``/``error``; uygulama
akışı etkilenmez (fail-soft). Sürüm karşılaştırması kaba ama sağlam semver (ön-sürüm
ekleri yok sayılır).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool import __version__
from cybersectool.core.app_settings import get_settings
from cybersectool.core.models import AppSettings
from cybersectool.core.net_guard import is_blocked_url

# AppSettings.update_check_url server_default ile AYNI tutulur (oradaki literal = buradaki).
DEFAULT_UPDATE_CHECK_URL = "https://api.github.com/repos/Lineup-NOAH/kangalis-core/releases/latest"


def parse_version(value: str) -> tuple[int, int, int]:
    """``v1.2.3`` / ``1.2.3-rc1`` → ``(1, 2, 3)``. Sayısal olmayan ekler atılır; eksik 0.

    Kıyas için kaba ama sağlam: baştaki sayısal nokta-ayrık parçaları alır, 3 bileşene
    doldurur (``1.2`` → ``(1,2,0)``); ön-sürüm/build eki yok sayılır (``1.2.0-rc1`` ~
    ``1.2.0``). Geçersiz/boş → ``(0, 0, 0)``.
    """
    parts: list[int] = []
    for token in (value or "").strip().lstrip("vV").split("."):
        match = re.match(r"\d+", token.strip())
        if not match:
            break
        parts.append(int(match.group(0)))
        if len(parts) == 3:
            break
    while len(parts) < 3:
        parts.append(0)
    return (parts[0], parts[1], parts[2])


def is_newer(latest: str, current: str) -> bool:
    """``latest`` sürümü ``current``'tan yeni mi (boş/eşit/küçük → False)."""
    if not latest:
        return False
    return parse_version(latest) > parse_version(current)


@dataclass(frozen=True)
class UpdateStatus:
    """Güncelleme durumu (görüntüleme için; asla istisna taşımaz)."""

    current: str
    latest: str
    available: bool
    last_checked: datetime | None
    # ok | unreachable | no_release | error | disabled | never
    status: str


def stored_status(row: AppSettings) -> UpdateStatus:
    """DB'deki SON denetim sonucundan durum üretir — EGRESS YOK (sayfa yüklenişi bunu kullanır)."""
    current = __version__
    latest = (row.latest_version or "").strip()
    last = row.update_last_checked
    status = (row.update_last_status or "").strip() or ("never" if last is None else "ok")
    return UpdateStatus(
        current=current,
        latest=latest,
        available=is_newer(latest, current),
        last_checked=last,
        status=status,
    )


async def run_update_check(session: AsyncSession, *, force: bool = False) -> UpdateStatus:
    """En güncel sürümü uzaktan (GitHub Releases) sorgular + sonucu DB'ye yazar.

    ``force=False`` (günlük beat): ``update_check_enabled`` kapalıysa egress yapmaz, saklı
    durumu ``disabled`` ile döner. ``force=True`` (admin "Şimdi denetle"): toggle'ı yok sayar
    (admin açıkça istedi). Her hata yutulur → durum alanı dürüstçe yansıtır.
    """
    row = await get_settings(session)
    current = __version__

    if not row.update_check_enabled and not force:
        return UpdateStatus(
            current=current,
            latest=(row.latest_version or "").strip(),
            available=is_newer(row.latest_version or "", current),
            last_checked=row.update_last_checked,
            status="disabled",
        )

    url = (row.update_check_url or "").strip() or DEFAULT_UPDATE_CHECK_URL
    # SSRF/şema koruması: admin-ayarlı URL http(s) DEĞİLSE (file://, gopher:// vb.) VEYA link-local/
    # bulut-metadata literal IP'sine (169.254.x) gidiyorsa güvenli varsayılana (GitHub) döner. Meşru
    # şirket-içi ayna (RFC1918/hostname) korunur; yalnız asla-meşru-olmayan hedefler elenir.
    if not url.lower().startswith(("http://", "https://")) or is_blocked_url(url):
        url = DEFAULT_UPDATE_CHECK_URL

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"Kangalis/{current}",
    }
    # Opsiyonel token (yalnız özel repo testi için; üretimde repo public → gereksiz).
    token = os.getenv("KANGALIS_UPDATE_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    status = "ok"
    latest = (row.latest_version or "").strip()
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
        if resp.status_code == 404:
            # Yayınlanmış release yok ya da repo henüz public değil (anonim 404).
            status = "no_release"
        elif resp.status_code >= 400:
            status = "error"
        else:
            data = resp.json()
            tag = str(data.get("tag_name") or data.get("name") or "").strip()
            if tag:
                latest = tag.lstrip("vV")
            else:
                status = "no_release"
    except (httpx.HTTPError, ValueError):
        # Ağ hatası / JSON parse hatası → erişilemedi (fail-soft).
        status = "unreachable"

    now = datetime.now(UTC)
    row.update_last_checked = now
    row.update_last_status = status
    if status == "ok" and latest:
        row.latest_version = latest
    await session.commit()

    return UpdateStatus(
        current=current,
        latest=(row.latest_version or "").strip(),
        available=is_newer(row.latest_version or "", current),
        last_checked=now,
        status=status,
    )
