"""CVE → uyum/mevzuat eşlemesi (IX-10) — SAF heuristik (ağ/DB gerektirmez).

Bir CVE'nin hangi düzenleyici çerçeve(ler) için önemli olduğunu başlık + kategori +
kritiklik sinyallerinden tahmin eder. Kesin değildir (CWE persist edilmediği için
anahtar kelime tabanlıdır) ama kullanıcıya "bu zafiyet PCI-DSS / KVKK için önemli"
yönünde rehberlik eder. Exploit DB sayfası ve tarama raporlarında rozet gösterilir.

Tasarım: çekirdek çerçeveler (KVKK/ISO 27001/PCI-DSS) ciddi (kritik/yüksek/KEV/CVSS>=7)
her zaman eklenir; anahtar kelime/kategori kuralları ek çerçeveleri (GDPR/NIST/5651) ekler.
"""

from __future__ import annotations

from collections.abc import Sequence

# Desteklenen çerçeveler — gösterim sırası (TR + uluslararası).
FRAMEWORKS: tuple[str, ...] = ("KVKK", "ISO 27001", "PCI-DSS", "GDPR", "NIST CSF", "5651")

# Ciddi zafiyetlerde (kritik/yüksek/KEV/CVSS>=7) her zaman ilgili çekirdek çerçeveler.
_CORE: tuple[str, ...] = ("KVKK", "ISO 27001", "PCI-DSS")
_SERIOUS_SEVERITIES = frozenset({"critical", "high"})

# (anahtar kelimeler) → ilgili çerçeveler. Başlık + kategori metninde aranır.
# Yanlış pozitifi azaltmak için çoğunlukla çok-kelimeli/ayırt edici terimler seçildi.
_RULES: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    # Şifreleme / aktarımda gizlilik
    (
        ("tls", "ssl", "cipher", "crypto", "certificate", "heartbleed", "poodle", "encryption"),
        ("PCI-DSS", "ISO 27001", "KVKK", "GDPR"),
    ),
    # Kimlik doğrulama / erişim kontrolü / yetki
    (
        (
            "authentication",
            "credential",
            "password",
            "privilege escalation",
            "kerberos",
            "ntlm",
            "authentication bypass",
            "access control",
            "unauthenticated",
            "auth bypass",
        ),
        ("PCI-DSS", "ISO 27001", "KVKK", "GDPR"),
    ),
    # Enjeksiyon / uzaktan kod çalıştırma
    (
        (
            "sql injection",
            "remote code execution",
            "command injection",
            "code execution",
            "deserialization",
            "arbitrary code",
            "arbitrary command",
        ),
        ("PCI-DSS", "ISO 27001", "KVKK", "NIST CSF"),
    ),
    # Web uygulaması zafiyetleri
    (
        (
            "cross-site scripting",
            "xss",
            "csrf",
            "ssrf",
            "open redirect",
            "directory traversal",
            "path traversal",
            "file inclusion",
            "file upload",
        ),
        ("PCI-DSS", "KVKK", "GDPR"),
    ),
    # Kayıt tutma / denetim izi (TR 5651 log yükümlülüğü)
    (
        ("audit log", "logging", "insufficient logging", "log injection"),
        ("PCI-DSS", "5651", "ISO 27001"),
    ),
    # Hizmet dışı bırakma / erişilebilirlik
    (
        ("denial of service", "denial-of-service", "resource exhaustion"),
        ("ISO 27001", "NIST CSF"),
    ),
    # Bilgi ifşası / kişisel veri
    (
        (
            "information disclosure",
            "information leak",
            "data exposure",
            "sensitive information",
            "memory disclosure",
        ),
        ("KVKK", "GDPR", "ISO 27001"),
    ),
)

# Exploit kategorisi → çerçeveler.
_CATEGORY_FRAMEWORKS: dict[str, tuple[str, ...]] = {
    "database": ("PCI-DSS", "KVKK", "GDPR"),
    "web": ("PCI-DSS", "KVKK"),
    "network": ("PCI-DSS", "ISO 27001"),
}


def framework_db_signals(framework: str) -> tuple[list[str], list[str], bool]:
    """Bir çerçeve için DB ön-filtresi sinyalleri: (başlık/metin anahtar kelimeleri,
    kategoriler, çekirdek_mi).

    ``_frameworks_for_exploit`` (yalnız title + severity + categories kullanır) ile BİREBİR
    aynı veri yapılarından (``_RULES`` + ``_CATEGORY_FRAMEWORKS`` + ``_CORE``) türetilir →
    exploit DB filtresi ile gösterilen rozet ASLA çelişmez (drift yok). Çekirdek çerçeveler
    ayrıca ciddi (kritik/yüksek) her exploit'e eklenir (severity sinyali çağıran tarafta).
    """
    keywords: list[str] = []
    for kws, fws in _RULES:
        if framework in fws:
            keywords.extend(kws)
    categories = [cat for cat, fws in _CATEGORY_FRAMEWORKS.items() if framework in fws]
    return keywords, categories, framework in _CORE


def frameworks_for_cve(
    *,
    title: str = "",
    cvss_score: float | None = None,
    severity: str | None = None,
    categories: Sequence[str] = (),
    kev: bool = False,
) -> list[str]:
    """CVE sinyallerinden ilgili mevzuat çerçevelerini döndürür (FRAMEWORKS sırasında, tekrarsız).

    Hiçbir kural eşleşmez ve zafiyet ciddi değilse boş liste döner (rozet gösterilmez).
    """
    matched: set[str] = set()
    haystack = f" {title.lower()} {' '.join(c.lower() for c in categories)} "
    for keywords, frameworks in _RULES:
        if any(kw in haystack for kw in keywords):
            matched.update(frameworks)
    for category in categories:
        matched.update(_CATEGORY_FRAMEWORKS.get(category.strip().lower(), ()))
    is_serious = (
        kev or (severity or "").strip().lower() in _SERIOUS_SEVERITIES or (cvss_score or 0.0) >= 7.0
    )
    if is_serious:
        matched.update(_CORE)
    return [fw for fw in FRAMEWORKS if fw in matched]
