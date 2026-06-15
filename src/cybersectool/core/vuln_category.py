"""Zafiyet kategorisi türetimi (saf; ağ/DB gerektirmez).

Bir Vulnerability'yi başlık + tarama türü + CVE'ye bakarak kaba bir kategoriye atar.
Zafiyetler sayfası bu kategoriye göre filtre/rozet gösterir. ``weak_credential`` en
yüksek önceliklidir — brute force ve VI-12 varsayılan-kimlik denetiminin ürettiği
"zayıf/varsayılan kimlik" bulguları (CVE'siz, kritik) bu kategoriye düşer.
"""

from __future__ import annotations

from cybersectool.core.models import ScanType

# Kategori değerleri (Vulnerability.category kolonunda saklanır).
WEAK_CREDENTIAL = "weak_credential"
OS_PACKAGE = "os_package"
CVE = "cve"
WEB = "web"
CONFIG = "config"
SCA = "sca"
OTHER = "other"

VULN_CATEGORIES: tuple[str, ...] = (WEAK_CREDENTIAL, OS_PACKAGE, CVE, WEB, CONFIG, SCA, OTHER)

# Zayıf/varsayılan kimlik bulgularının başlık önekleri (küçük harf).
# Kaynaklar: brute force (scanners/bruteforce.py) + VI-12 varsayılan kimlik
# (scanners/default_creds.py + tasks/network_scan.py). Yeni kaynak eklenirse buraya ekle.
_WEAK_CRED_PREFIXES: tuple[str, ...] = (
    "zayıf/varsayılan kimlik bulundu",
    "varsayılan ssh kimliği",
    "varsayılan kimlik",
)


def is_weak_credential_title(title: str) -> bool:
    """Başlık bir zayıf/varsayılan kimlik bulgusuna mı ait?"""
    low = title.strip().lower()
    return any(low.startswith(prefix) for prefix in _WEAK_CRED_PREFIXES)


def is_os_package_title(title: str) -> bool:
    """Başlık kimlikli taramanın OS-paket zafiyet bulgusuna mı ait? (OSPKG #196)

    ``store_credentialed`` bu bulguları ``"Zafiyetli paket: <ad> <sürüm> (<CVE>)"``
    başlığıyla yazar (kaynak: OSV.dev). CVE'leri olsa da ayrı bir kategori/rozet alır
    ki "kimlikli tarama paket açığı buldu" net görünsün.
    """
    return title.strip().lower().startswith("zafiyetli paket")


def derive_vuln_category(title: str, scan_type: ScanType, cve_id: str | None) -> str:
    """Zafiyeti kategoriye atar (öncelik: weak_credential > os_package > cve > web/sca/config)."""
    if is_weak_credential_title(title):
        return WEAK_CREDENTIAL
    if is_os_package_title(title):
        return OS_PACKAGE  # OSV.dev paket bulgusu (CVE'si olsa da ayrı kategori)
    if cve_id:
        return CVE
    if scan_type == ScanType.web:
        return WEB
    if scan_type == ScanType.sca:
        return SCA
    if scan_type in (ScanType.credentialed, ScanType.hardening):
        return CONFIG
    return OTHER
