"""SNMP salt-okunur envanter + güvenlik denetimi (VII-2b) — yalnız GET (okuma).

Standart MIB-2 sistem grubu OID'lerini okuyup cihaz envanteri (sysDescr/sysName/…)
çıkarır ve **zayıf/varsayılan topluluk dizesi** (wordlist — ``public``/``private``/…)
erişimini tespit eder — klasik SNMP yanlış yapılandırması (Nessus "SNMP Agent Default
Community Names" / OpenVAS "SNMP Default Community" dengi). ``evaluate_snmp`` ve yardımcıları SAFtır
(ağ gerektirmez, birim testi edilebilir); ağ erişimi ``scanners/snmp.py`` içindedir
ve gerçek SNMP agent'ına karşı doğrulanır.

YAZMA YAPMAZ: yalnızca SNMP GET denenir; SET/değiştirme hiçbir zaman gönderilmez.
"""

from __future__ import annotations

from dataclasses import dataclass

from cybersectool.core.models import Severity

# Standart MIB-2 sistem grubu OID'leri (RFC 1213 system group).
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

# Envanter için tek GET çağrısında istenen OID → SnmpInfo alan adı.
SYSTEM_OIDS: dict[str, str] = {
    OID_SYS_DESCR: "sys_descr",
    OID_SYS_OBJECT_ID: "sys_object_id",
    OID_SYS_UPTIME: "sys_uptime",
    OID_SYS_CONTACT: "sys_contact",
    OID_SYS_NAME: "sys_name",
    OID_SYS_LOCATION: "sys_location",
}

# Şifresiz / topluluk-tabanlı (kimlik+şifreleme yok) SNMP sürümleri.
PLAINTEXT_VERSIONS: tuple[str, ...] = ("v1", "v2c")


@dataclass
class SnmpInfo:
    """SNMP sistem grubu envanteri (okunabildiği kadarıyla)."""

    sys_descr: str = ""
    sys_object_id: str = ""
    sys_uptime: str = ""
    sys_contact: str = ""
    sys_name: str = ""
    sys_location: str = ""

    @property
    def has_data(self) -> bool:
        """En az bir tanımlayıcı alan okunabildi mi?"""
        return bool(self.sys_descr or self.sys_name or self.sys_object_id)

    def summary(self) -> str:
        """Kısa tek satır özet (sysName — sysDescr)."""
        parts = [p for p in (self.sys_name, self.sys_descr) if p]
        return " — ".join(parts) or "bilinmiyor"


@dataclass
class SnmpFinding:
    """SNMP denetiminden bir güvenlik bulgusu."""

    title: str
    severity: Severity
    detail: str


def info_from_oids(values: dict[str, str]) -> SnmpInfo:
    """GET sonucundaki OID→değer eşlemesini SnmpInfo'ya çevirir (saf)."""
    fields = {SYSTEM_OIDS[oid]: value for oid, value in values.items() if oid in SYSTEM_OIDS}
    return SnmpInfo(**fields)


def eval_weak_community(community: str) -> SnmpFinding:
    """Zayıf/wordlist topluluğu erişilebilir → bulgu (private=yüksek, public=orta, diğer=orta).

    Yalnızca wordlist'teki (bilinen/tahmin edilebilir) topluluklar için çağrılır;
    kullanıcının verdiği özel topluluk için ÇAĞRILMAZ (beklenen yapılandırma).
    """
    name = community.strip().lower()
    if name == "private":
        return SnmpFinding(
            "SNMP varsayılan 'private' topluluğu erişilebilir",
            Severity.high,
            "Cihaz 'private' varsayılan topluluğuyla okunabiliyor; bu topluluk genelde "
            "yazma yetkilidir ve ağdaki herkes konfigürasyonu değiştirebilir. "
            "Topluluğu değiştirin/kaldırın ve mümkünse SNMPv3 (authPriv) kullanın.",
        )
    if name == "public":
        return SnmpFinding(
            "SNMP varsayılan 'public' topluluğu erişilebilir",
            Severity.medium,
            "Cihaz 'public' varsayılan topluluğuyla okunabiliyor; ağdaki herkes cihaz "
            "envanteri ve konfigürasyon bilgisini okuyabilir. Topluluğu benzersiz bir "
            "değerle değiştirin veya SNMPv3'e geçin.",
        )
    return SnmpFinding(
        f"SNMP zayıf/tahmin edilebilir topluluk '{community}' erişilebilir",
        Severity.medium,
        f"Cihaz iyi bilinen '{community}' topluluğuyla okunabiliyor (yaygın varsayılan/"
        "tahmin listesinde). Ağdaki herkes bu dizeyi deneyerek erişebilir. Benzersiz bir "
        "topluluk belirleyin veya SNMPv3 (authPriv) kullanın.",
    )


def eval_snmp_version(version: str, *, any_accessible: bool) -> SnmpFinding | None:
    """Cihaz şifresiz (v1/v2c) yanıt veriyorsa hardening notu (düşük önem)."""
    if any_accessible and version.strip().lower() in PLAINTEXT_VERSIONS:
        return SnmpFinding(
            f"SNMP {version} şifresiz (topluluk-tabanlı) kullanımda",
            Severity.low,
            f"Cihaz SNMP {version} ile yanıt veriyor; topluluk dizesi ağ üzerinde düz "
            "metin gider ve kimlik doğrulama/şifreleme yoktur. Hassas ortamlarda "
            "SNMPv3 (authPriv) önerilir.",
        )
    return None


def evaluate_snmp(accessible: list[tuple[str, str]], weak: set[str]) -> list[SnmpFinding]:
    """Erişilebilen (topluluk, sürüm) çiftlerinden bulguları üretir (saf, ağ yok).

    ``accessible``: yanıt veren (community, version) çiftleri. ``weak``: zayıf sayılan
    topluluklar (küçük harf; wordlist). Yalnızca wordlist'teki topluluklar bulgu üretir;
    kullanıcının verdiği özel topluluk beklenen yapılandırmadır, bulgu sayılmaz (düşük FP).
    Erişilen her şifresiz sürüm (v1/v2c) için ayrıca düşük önemli sürüm notu eklenir.
    """
    findings: list[SnmpFinding] = []
    seen: set[str] = set()
    for community, _version in accessible:
        key = community.strip().lower()
        if key in seen or key not in weak:
            continue  # tekrar / wordlist dışı (özel) topluluk → bulgu yok
        seen.add(key)
        findings.append(eval_weak_community(community))
    for version in sorted({v for _community, v in accessible}):
        note = eval_snmp_version(version, any_accessible=True)
        if note is not None:
            findings.append(note)
    return findings
