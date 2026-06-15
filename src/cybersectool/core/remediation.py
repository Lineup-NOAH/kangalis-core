"""Çözüm (remediation) önerisi üretimi — şablon metin + CVE referansları/KEV/EPSS.

Saf (yan etkisiz) mantık: bir bulgu (+ varsa CVE ve servis) için
- **neden** (etkilenen servis/CVE),
- **çözüm** şablon metni (başlık anahtar kelimelerine göre; CVE varsa yama şablonu),
- **referanslar** (NVD linki + CVE'nin referans URL'leri),
- **KEV/EPSS** sömürülebilirlik sinyalleri
üretir. Rapor (HTML ve PDF) bu çıktıyı gösterir.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cybersectool.core.models import CVE, Finding, Service

# (anahtar kelimeler, çözüm şablonu) — başlıkta eşleşen ilk kural uygulanır.
_RULES: list[tuple[tuple[str, ...], str]] = [
    (
        ("smbv1", "smb1", "ms17", "eternalblue"),
        "SMBv1 protokolünü devre dışı bırakın; SMBv2/3'e geçin ve 445/tcp erişimini "
        "ağ segmentasyonuyla kısıtlayın.",
    ),
    (
        ("tls", "ssl", "cipher", "sslv", "weak protocol", "zayıf"),
        "Zayıf TLS/SSL sürüm ve şifre takımlarını kapatın; TLS 1.2+ ve güçlü cipher'lar "
        "kullanın, geçerli bir sertifika ile yapılandırın.",
    ),
    (
        ("rdp", "nla", "remote desktop"),
        "RDP için NLA (Ağ Düzeyinde Kimlik Doğrulama) zorunlu kılın; RDP'yi yalnızca "
        "VPN/iç ağdan erişilebilir hale getirin.",
    ),
    (
        ("autologon", "autoadminlogon", "otomatik oturum"),
        "AutoLogon'u kapatın ve kayıtlı düz-metin parolayı kaldırın.",
    ),
    (
        ("world-writable", "world writable", "dünya-yaz", "0777"),
        "Dünya-yazılabilir dosya/dizin izinlerini kaldırın (chmod o-w) ve kritik "
        "dizinlerde doğru sahiplik uygulayın.",
    ),
    (
        ("nopasswd", "sudo", "ayrıcalık"),
        "Parolasız (NOPASSWD) sudo kurallarını kaldırın; ayrıcalıkları en az yetki "
        "ilkesine göre sınırlayın.",
    ),
    (
        ("pending update", "bekleyen", "outdated", "out-of-date", "patch", "yama", "güncelleme"),
        "Bekleyen güvenlik güncellemelerini uygulayın ve otomatik yama yönetimini devreye alın.",
    ),
    (
        ("default credential", "default password", "weak password", "zayıf parola", "anonymous"),
        "Varsayılan/zayıf kimlik bilgilerini değiştirin; güçlü parola politikası ve "
        "çok faktörlü kimlik doğrulama (MFA) uygulayın.",
    ),
    (
        ("firewall", "güvenlik duvarı", "exposed", "open port", "açık port"),
        "Gereksiz açık portları kapatın; servisi güvenlik duvarı ve ağ segmentasyonu "
        "ile sınırlayın.",
    ),
    (
        ("defender", "antivirus", "av kapalı"),
        "Uç nokta korumasını (Defender/AV) etkinleştirin ve imzaları güncel tutun.",
    ),
]

# CVE'li bulgular için (kurala uymayan) genel yama şablonu.
_CVE_TEMPLATE = (
    "Satıcının güvenlik yamasını uygulayın ve etkilenen bileşeni güncel sürüme "
    "yükseltin. Yama yoksa servisi ağdan izole edin, erişimi kısıtlayın ve telafi "
    "edici kontroller uygulayın."
)
# Hiçbir kural ve CVE yoksa genel öneri.
_GENERIC = (
    "Etkilenen bileşeni güncelleyin/yapılandırmayı sıkılaştırın ve erişimi en az "
    "yetki ilkesine göre kısıtlayın."
)

# Servis/CVE bağlanmamış bulgular için başlık-anahtarına göre "neden" (NEDEN) metni.
# Amaç: rapor/detayda NEDEN alanının boş ("—") kalmaması (özellikle zayıf-kimlik bulguları).
_CAUSE_RULES: list[tuple[tuple[str, ...], str]] = [
    (
        (
            "varsayılan",
            "default credential",
            "default password",
            "weak password",
            "zayıf parola",
            "zayıf kimlik",
            "brute",
            "anonymous",
            "anonim",
        ),
        "Zayıf ya da varsayılan kimlik bilgisi tahmin edilebilir; saldırgan uzaktan oturum "
        "açıp yetkisiz erişim veya hesap ele geçirme gerçekleştirebilir.",
    ),
    (
        ("smbv1", "smb1", "ms17", "eternalblue"),
        "Eski/güvensiz SMBv1 protokolü uzaktan kod çalıştırma (ör. EternalBlue) için bilinen "
        "ve aktif istismar edilen bir saldırı yüzeyidir.",
    ),
    (
        (
            "hassas yol",
            "bulunan yol",
            ".git",
            ".env",
            "backup",
            "yedek",
            "ifşa",
            "disclosure",
            "phpinfo",
            "server-status",
        ),
        "Hassas dosya/dizin kimlik doğrulaması olmadan erişilebilir; yapılandırma, kaynak "
        "kod veya kimlik bilgisi sızıntısına yol açabilir.",
    ),
    (
        ("güvenlik başlığı", "header", "csp", "hsts", "x-frame", "çerez", "cookie", "cors"),
        "Eksik/zayıf güvenlik yapılandırması istemci tarafı saldırılara (XSS, clickjacking, "
        "oturum çalma) karşı korumayı zayıflatır.",
    ),
    (
        ("tls", "ssl", "cipher", "sertifika", "certificate"),
        "Zayıf TLS/SSL yapılandırması trafiğin araya girilip dinlenmesine veya "
        "değiştirilmesine (MITM) imkân verir.",
    ),
    (
        ("açık port", "open port", "exposed", "firewall", "güvenlik duvarı"),
        "Gereksiz açık servis saldırı yüzeyini genişletir ve istismar için giriş noktası sunar.",
    ),
]
# Hiçbir kurala uymayan, servis/CVE'siz bulgular için genel neden (asla boş bırakma).
_CAUSE_GENERIC = (
    "Bu durum bir güvenlik zafiyeti oluşturur ve saldırı yüzeyini artırır; istismar edilirse "
    "gizlilik, bütünlük veya erişilebilirlik etkilenebilir."
)


def _cause_for(title: str) -> str:
    """Servis/CVE bağlanmamış bir bulgu için başlık-anahtarına göre 'neden' metni döndürür."""
    low = title.lower()
    for keywords, text in _CAUSE_RULES:
        if any(k in low for k in keywords):
            return text
    return _CAUSE_GENERIC


@dataclass
class Remediation:
    """Bir bulgu için neden + çözüm + referanslar + sömürülebilirlik sinyalleri."""

    cause: str
    summary: str
    references: list[str] = field(default_factory=list)
    kev: bool = False
    epss: float | None = None

    @property
    def epss_pct(self) -> str | None:
        """EPSS skorunu yüzde olarak biçimlendirir (ör. 0.97 → '%97')."""
        if self.epss is None:
            return None
        return f"%{round(self.epss * 100)}"


def _nvd_url(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def _template_for(title: str, has_cve: bool) -> str:
    low = title.lower()
    for keywords, text in _RULES:
        if any(k in low for k in keywords):
            return text
    return _CVE_TEMPLATE if has_cve else _GENERIC


def remediation_for(
    finding: Finding, cve: CVE | None = None, service: Service | None = None
) -> Remediation:
    """Bir bulgu (+ varsa CVE ve servis) için çözüm önerisi üretir."""
    has_cve = bool(finding.cve_id)
    summary = _template_for(finding.title or "", has_cve)

    kev = bool(cve.kev_flag) if cve is not None else False
    epss = cve.epss_score if cve is not None else None
    if kev:
        summary = "ACİL — CISA KEV (aktif sömürü altında): " + summary

    # Referanslar: NVD linki + CVE'nin referans URL'leri (tekilleştir, sınırla).
    references: list[str] = []
    if finding.cve_id:
        references.append(_nvd_url(finding.cve_id))
    if cve is not None and cve.references:
        for ref in cve.references:
            if ref and ref not in references:
                references.append(ref)
    references = references[:6]

    # Neden: etkilenen servis (ürün/sürüm/port) + CVE.
    cause_parts: list[str] = []
    if service is not None:
        label = service.product or service.service_name
        if label:
            ver = f" {service.version}" if service.version else ""
            cause_parts.append(f"{label}{ver} ({service.port}/{service.protocol})")
    if finding.cve_id:
        cause_parts.append(finding.cve_id)
    # Servis/CVE bağlıysa onu göster; değilse başlık-anahtarına göre anlamlı 'neden' (boş bırakma).
    cause = " · ".join(cause_parts) if cause_parts else _cause_for(finding.title or "")

    return Remediation(cause=cause, summary=summary, references=references, kev=kev, epss=epss)
