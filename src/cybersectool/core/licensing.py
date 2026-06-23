"""Çevrimdışı, imza-temelli ticari LİSANS doğrulama — ``exploit`` özelliğini açar.

Satıcı KENDİ özel anahtarıyla (Ed25519) lisans kodları üretip (ayrı, harici imzalama aracı)
müşteriye dağıtır. Çekirdek YALNIZ satıcının açık anahtarıyla (``LICENSE_PUBLIC_KEY``)
imzayı doğrular — sunucuya/internete ihtiyaç YOK (air-gap dostu). Lisans kodu kendi-kendine
imzalı bir token'dır; kurcalanırsa ya da süresi dolduysa geçersiz sayılır.

LİSANS KODU BİÇİMİ::

    base64url(payload_json) + "." + base64url(signature)

  ``payload_json``  — kompakt JSON (imzalanan ham baytlar):
      {"customer": str, "issued": "YYYY-MM-DD", "expires": "YYYY-MM-DD"|null,
       "features": ["exploit", ...]}
  ``signature``     — Ed25519 imzası (64 ham bayt) ``payload_json`` baytları üzerinde.
  base64url padding ('=') ATILIR; çözerken yeniden eklenir (env/tek-satır dostu).

İKİ KAPI: ``exploit`` sömürüsü için HEM geçerli lisans HEM de ayrı ticari eklenti
(``cybersectool.exploit``) GEREKİR — biri eksikse sömürü atlanır (bkz. ``exploit_unlocked``).
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import date

from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.config import settings as app_config
from cybersectool.core.app_settings import get_settings
from cybersectool.core.exploit_seam import exploit_plugin_available


@dataclass(frozen=True)
class LicenseInfo:
    """Doğrulanmış lisans durumu (görüntüleme + kapı kararı için, asla istisna fırlatmaz)."""

    status: str  # "valid" | "expired" | "invalid" | "none" | "disabled"
    customer: str = ""
    expires: str | None = None
    features: tuple[str, ...] = ()

    @property
    def is_valid(self) -> bool:
        """Lisans şu an geçerli mi (yalnızca status == 'valid')."""
        return self.status == "valid"


def _b64url_decode(data: str) -> bytes:
    """base64url metnini çözer; eksik '=' dolgusunu yeniden ekler."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def verify_license(license_str: str, *, public_key: str | None = None) -> LicenseInfo:
    """Lisans kodunu Ed25519 imzasıyla doğrular — ASLA istisna fırlatmaz.

    Açık anahtar çözümü: ``public_key`` verilmiş (ve boş değil) ise o kullanılır (DB'den
    gelen değer, Lisans sekmesinden girilir); aksi hâlde config.license_public_key (env
    ``LICENSE_PUBLIC_KEY``) fallback olur. Böylece açık anahtar .env'e dokunmadan UI'dan
    yönetilebilir, ama env yine de çalışır.

    Akış: boş lisans → "none"; açık anahtar (DB+env) hiç yok → "disabled"; imza/biçim/çözme
    hatası → "invalid"; geçerli imza ama süresi dolmuş → "expired" (yine de müşteri/özellik
    görüntü için döner); aksi → "valid".
    """
    if not license_str or not license_str.strip():
        return LicenseInfo(status="none")

    # DB değeri (UI'dan) önceliklidir; boşsa env'e düş.
    public_key_b64 = (public_key or "").strip() or app_config.license_public_key.strip()
    if not public_key_b64:
        # Lisanslama yapılandırılmamış (patron açık anahtarı koymamış) → özellik kilitli kalır.
        return LicenseInfo(status="disabled")

    try:
        # NOT: yerel değişken adı parametre 'public_key' (str) ile çakışmasın diye '_obj' soneki.
        public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(_b64url_decode(public_key_b64))
        payload_b64, sig_b64 = license_str.strip().split(".", 1)
        payload_bytes = _b64url_decode(payload_b64)
        signature = _b64url_decode(sig_b64)
        # İmzayı ham payload baytları üzerinde doğrula (InvalidSignature → geçersiz).
        public_key_obj.verify(signature, payload_bytes)
    except Exception:
        # Her hata (kötü biçim/çözme/imza ya da beklenmedik) → kilit-tarafa düş: "invalid".
        # Modül ASLA istisna fırlatmamalı; çağıranlar lisansı güven kararı olarak kullanır.
        return LicenseInfo(status="invalid")

    try:
        payload = json.loads(payload_bytes)
        # İmzalı ama nesne-olmayan payload (liste/sayı/null) → ".get" AttributeError fırlatırdı;
        # "asla istisna fırlatmaz" sözleşmesini korumak için açık tip-kapısı (kilit-tarafa düş).
        if not isinstance(payload, dict):
            return LicenseInfo(status="invalid")
        customer = str(payload.get("customer", ""))
        expires = payload.get("expires")
        expires_str = str(expires) if expires else None
        features = tuple(str(f) for f in payload.get("features", []))
    except (ValueError, TypeError):
        return LicenseInfo(status="invalid")

    # Süre kontrolü: ISO tarih string'leri (datetime.date.fromisoformat). Bu modül uygulama
    # tarafından import edilir → date.today() burada uygundur (iş-akışı betiği DEĞİL).
    if expires_str:
        try:
            if date.fromisoformat(expires_str) < date.today():
                return LicenseInfo(
                    status="expired",
                    customer=customer,
                    expires=expires_str,
                    features=features,
                )
        except ValueError:
            return LicenseInfo(status="invalid")

    return LicenseInfo(
        status="valid",
        customer=customer,
        expires=expires_str,
        features=features,
    )


async def active_license(session: AsyncSession) -> LicenseInfo:
    """DB'deki lisans kodunu, yine DB'deki açık anahtarla (yoksa env) doğrular.

    Açık anahtar ``AppSettings.license_public_key``'ten okunur (Lisans sekmesinden girilir);
    boşsa ``verify_license`` config/env fallback'ine düşer.
    """
    row = await get_settings(session)
    return verify_license(row.license_key, public_key=row.license_public_key)


async def feature_licensed(session: AsyncSession, feature: str) -> bool:
    """Lisans geçerli VE istenen özelliği içeriyor mu."""
    info = await active_license(session)
    return info.is_valid and feature in info.features


async def exploit_unlocked(session: AsyncSession) -> bool:
    """Sömürü kullanılabilir mi — HEM lisans HEM eklenti gerekir.

    ``exploit`` sömürüsü için İKİ koşul birden sağlanmalı: (1) ticari eklenti
    (``cybersectool.exploit``) kurulu, (2) geçerli ``exploit`` lisansı var. Biri eksikse
    sömürü atlanır (tespit/rapor yine tam çalışır).
    """
    return exploit_plugin_available() and await feature_licensed(session, "exploit")
