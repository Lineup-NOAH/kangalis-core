"""CPE (Common Platform Enumeration) ayrıştırma + sürüm aralığı eşleştirme.

Tamamı **saf** (ağsız, DB'siz) fonksiyonlar — birim testi edilebilir. NVD CVE
yanıtındaki ``configurations`` bloklarından CPE eşleşme ölçütlerini çıkarır ve
bir servisin sürümünün bu ölçütlere (aralıklar dahil) uyup uymadığını hesaplar.

İki CPE biçimi de desteklenir:
* CPE 2.3 formatlı dize: ``cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*``
* CPE 2.2 URI (nmap çıktısı): ``cpe:/a:apache:http_server:2.4.49``
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_WILDCARDS = {"", "*", "-"}


@dataclass(frozen=True)
class ParsedCpe:
    """Bir CPE dizesinin ayrıştırılmış bileşenleri (vendor/product küçük harf)."""

    part: str  # a (uygulama) / o (işletim sistemi) / h (donanım)
    vendor: str
    product: str
    version: str  # "*" veya "-" olabilir (sürümsüz)


@dataclass
class CpeMatchData:
    """NVD configurations içindeki tek bir ``cpeMatch`` ölçütü."""

    criteria: str
    part: str
    vendor: str
    product: str
    version: str
    vulnerable: bool = True
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None


def _unescape(value: str) -> str:
    """CPE kaçışlarını (``\\:`` vb.) çözer ve alt çizgileri korur."""
    return re.sub(r"\\(.)", r"\1", value)


def parse_cpe(uri: str | None) -> ParsedCpe | None:
    """CPE 2.3 ya da 2.2 dizesini :class:`ParsedCpe`'e çevirir; geçersizse None."""
    if not uri:
        return None
    uri = uri.strip()
    if uri.startswith("cpe:2.3:"):
        # cpe:2.3:part:vendor:product:version:...
        fields = _split_23(uri[len("cpe:2.3:") :])
        if len(fields) < 4:
            return None
        part, vendor, product, version = fields[0], fields[1], fields[2], fields[3]
    elif uri.startswith("cpe:/"):
        # cpe:/part:vendor:product:version:...
        fields = uri[len("cpe:/") :].split(":")
        if len(fields) < 3:
            return None
        part = fields[0]
        vendor = fields[1]
        product = fields[2]
        version = fields[3] if len(fields) > 3 else "*"
    else:
        return None
    return ParsedCpe(
        part=part.lower(),
        vendor=_unescape(vendor).lower(),
        product=_unescape(product).lower(),
        version=_unescape(version),
    )


def _split_23(body: str) -> list[str]:
    """CPE 2.3 gövdesini ``:`` ile böler ama kaçışlı ``\\:`` ayraçlarını korur."""
    return re.split(r"(?<!\\):", body)


# --- Sürüm karşılaştırma ---


def _version_tokens(version: str) -> list[tuple[int, int, str]]:
    """Sürümü karşılaştırılabilir token listesine çevirir.

    Her token (tür, sayı, metin): aynı pozisyonda sayısal parça (1, n, "")
    metin parçasından (0, 0, s) büyüktür. Eksik son parçanın anlamı
    ``compare_versions``ta ele alınır (sayısal sıfıra eşit ama harf-sonekten
    küçük). Mantık gevşek ama iç ağ servislerinin sürümleri için yeterlidir.
    """
    tokens: list[tuple[int, int, str]] = []
    for chunk in re.split(r"[._\-+~]", version):
        for match in re.finditer(r"\d+|[A-Za-z]+", chunk):
            tok = match.group(0)
            if tok.isdigit():
                tokens.append((1, int(tok), ""))
            else:
                tokens.append((0, 0, tok.lower()))
    return tokens


def _is_numeric_zero(tok: tuple[int, int, str]) -> bool:
    """Token sayısal sıfır mı? (eksik son parçayı ``.0`` ile eşitlemek için: 2.4 == 2.4.0)."""
    return tok[0] == 1 and tok[1] == 0


def compare_versions(a: str, b: str) -> int:
    """``a`` ile ``b`` sürümlerini karşılaştırır: -1 / 0 / 1.

    Eksik son parça SAYISAL sıfıra eşittir (``2.4 == 2.4.0``) ama bir HARF
    sonekinden KÜÇÜKtür (``1.0.1 < 1.0.1g``; harf-sonek sonraki yamadır →
    ``2.4.49a > 2.4.49``). Bu, OpenSSL/Apache tipi harf-yamalı sürümlerin
    aralık + tam eşleşmesini doğru yapar (eskiden eksik parça harften büyük
    sayılıyor, taban sürüm ``1.0.1`` ``1.0.1g``'den büyük çıkıp KAÇIYORDU).
    """
    ta = _version_tokens(a)
    tb = _version_tokens(b)
    for i in range(max(len(ta), len(tb))):
        x = ta[i] if i < len(ta) else None
        y = tb[i] if i < len(tb) else None
        if x is None:
            # ``a`` tükendi: kalan y sayısal sıfırsa bu pozisyon eşit (devam); pozitif
            # sayı VEYA harf ise a daha küçük.
            if y is not None and _is_numeric_zero(y):
                continue
            return -1
        if y is None:
            if _is_numeric_zero(x):
                continue
            return 1
        if x < y:
            return -1
        if x > y:
            return 1
    return 0


def _has_bounds(m: CpeMatchData) -> bool:
    return any(
        (
            m.version_start_including,
            m.version_start_excluding,
            m.version_end_including,
            m.version_end_excluding,
        )
    )


def cpe_match_applies(service_version: str | None, m: CpeMatchData) -> bool:
    """Bir servisin sürümü, verilen CPE ölçütüne (aralıklar dahil) uyuyor mu?"""
    sv = (service_version or "").strip()
    cv = (m.version or "").strip()

    if sv in _WILDCARDS:
        # Servis sürümü bilinmiyor: yalnızca ölçüt de sürümsüz ve aralıksızsa
        # (ürünün tüm sürümleri zafiyetli) eşleştir.
        return cv in _WILDCARDS and not _has_bounds(m)

    if cv not in _WILDCARDS:
        # Ölçüt belirli bir sürüm: tam eşleşme gerekir.
        return compare_versions(sv, cv) == 0

    # Ölçüt sürümsüz (*) → aralık sınırlarına bak.
    if not _has_bounds(m):
        return True  # ürünün tüm sürümleri zafiyetli
    results: list[bool] = []
    if m.version_start_including:
        results.append(compare_versions(sv, m.version_start_including) >= 0)
    if m.version_start_excluding:
        results.append(compare_versions(sv, m.version_start_excluding) > 0)
    if m.version_end_including:
        results.append(compare_versions(sv, m.version_end_including) <= 0)
    if m.version_end_excluding:
        results.append(compare_versions(sv, m.version_end_excluding) < 0)
    return all(results)


# --- Vendor/ürün alias eşleştirme (COV-4b) ---
#
# nmap'in raporladığı servis/ürün adı NVD CPE'sindeki vendor:product ile her
# zaman birebir TUTMAZ; tam-eşleşme bu yüzden bazı CVE'leri KAÇIRIR:
#   * redis  → NVD vendor "redislabs" (eski kayıtlar) / "redis" (yeni)
#   * OpenSSH → NVD vendor "openbsd"
#   * IIS    → "microsoft:internet_information_services"
# Bu el-küratörlü harita, bir ürün/servis adını OLASI (vendor, product)
# adaylarına çevirir. Anahtarlar yalnız iyi-bilinen, AYIRT-EDİCİ tokenlerdir;
# genel "httpd"/"server"/"http" gibi tokenler ASLA anahtar değildir → yanlış
# ürünle çapraz-eşleşme olmaz. Üstelik her aday yine sürüm-kapısından
# (``cpe_match_applies``) geçtiği için yanlış bir aday pratikte bulgu üretemez
# (servisin sürümü o ürünün zafiyet aralığına düşmez).
_VENDOR_PRODUCT_ALIASES: dict[str, list[tuple[str, str]]] = {
    "redis": [("redislabs", "redis"), ("redis", "redis")],
    "openssh": [("openbsd", "openssh"), ("openssh", "openssh")],
    "apache": [("apache", "http_server")],
    "nginx": [("nginx", "nginx"), ("f5", "nginx")],
    "tomcat": [("apache", "tomcat")],
    "coyote": [("apache", "tomcat")],
    "mysql": [("oracle", "mysql"), ("mysql", "mysql")],
    "mariadb": [("mariadb", "mariadb")],
    "postgresql": [("postgresql", "postgresql")],
    "postgres": [("postgresql", "postgresql")],
    "mongodb": [("mongodb", "mongodb")],
    "memcached": [("memcached", "memcached")],
    "elasticsearch": [("elastic", "elasticsearch"), ("elasticsearch", "elasticsearch")],
    "vsftpd": [("vsftpd_project", "vsftpd"), ("beasts", "vsftpd")],
    "proftpd": [("proftpd", "proftpd"), ("proftpd_project", "proftpd")],
    "samba": [("samba", "samba")],
    "smbd": [("samba", "samba")],
    "openssl": [("openssl", "openssl")],
    "exim": [("exim", "exim")],
    "postfix": [("postfix", "postfix")],
    "dovecot": [("dovecot", "dovecot")],
    "bind": [("isc", "bind")],
    "named": [("isc", "bind")],
    "lighttpd": [("lighttpd", "lighttpd")],
    "haproxy": [("haproxy", "haproxy")],
    "iis": [
        ("microsoft", "internet_information_services"),
        ("microsoft", "internet_information_server"),
    ],
    "php": [("php", "php")],
    "jetty": [("eclipse", "jetty"), ("mortbay", "jetty")],
    "jenkins": [("jenkins", "jenkins")],
    "grafana": [("grafana", "grafana")],
}

# Anahtar olarak KULLANILMAYACAK genel tokenler (ürün ayırt etmez → FP riski).
_ALIAS_STOPWORDS = frozenset(
    {
        "http",
        "https",
        "httpd",
        "server",
        "daemon",
        "service",
        "ssl",
        "tls",
        "key",
        "value",
        "store",
        "db",
        "the",
        "of",
        "and",
        "for",
    }
)


def _alias_keys(*names: str | None) -> list[str]:
    """Ürün/servis adlarından olası alias anahtarlarını üretir.

    Hem tam-normalize dize hem de tek tek kelimeler (genel stopword'ler hariç)
    anahtar adayıdır. Sıra korunur, tekrar yoktur.
    """
    keys: list[str] = []
    for raw in names:
        norm = re.sub(r"\s+", " ", (raw or "").strip().lower())
        if not norm:
            continue
        if norm not in keys:
            keys.append(norm)
        for word in re.split(r"[\s/_-]+", norm):
            if word and word not in _ALIAS_STOPWORDS and word not in keys:
                keys.append(word)
    return keys


def alias_candidates(
    vendor: str | None, product: str | None, *names: str | None
) -> list[tuple[str, str]]:
    """Bir servis için denenecek (vendor, product) adaylarını sıralı + benzersiz döndürür.

    Önce (varsa) CPE'den gelen birebir (vendor, product), ardından ürün/servis
    adından el-küratörlü harita ile türetilen adaylar. CPE hiç yoksa yalnız alias
    adayları döner → "CPE-yoksa fallback". Hiç aday yoksa boş liste.
    """
    out: list[tuple[str, str]] = []

    def _add(v: str | None, p: str | None) -> None:
        if not v or not p:
            return
        pair = (v.lower(), p.lower())
        if pair not in out:
            out.append(pair)

    _add(vendor, product)
    for key in _alias_keys(product, *names):
        for cand_vendor, cand_product in _VENDOR_PRODUCT_ALIASES.get(key, []):
            _add(cand_vendor, cand_product)
    return out


# --- NVD configurations çıkarımı ---


def _walk_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Bir konfigürasyon ağacındaki tüm cpeMatch girdilerini düz liste yapar."""
    out: list[dict[str, Any]] = []
    for node in nodes:
        out.extend(node.get("cpeMatch", []))
        children = node.get("children") or node.get("nodes")
        if children:
            out.extend(_walk_nodes(children))
    return out


def extract_cpe_matches(cve: dict[str, Any]) -> list[CpeMatchData]:
    """Tek bir NVD CVE nesnesinden CPE eşleşme ölçütlerini çıkarır."""
    matches: list[CpeMatchData] = []
    for config in cve.get("configurations", []):
        for entry in _walk_nodes(config.get("nodes", [])):
            criteria = entry.get("criteria") or entry.get("cpe23Uri")
            if not criteria:
                continue
            parsed = parse_cpe(criteria)
            if parsed is None:
                continue
            matches.append(
                CpeMatchData(
                    criteria=criteria,
                    part=parsed.part,
                    vendor=parsed.vendor,
                    product=parsed.product,
                    version=parsed.version,
                    vulnerable=bool(entry.get("vulnerable", True)),
                    version_start_including=entry.get("versionStartIncluding"),
                    version_start_excluding=entry.get("versionStartExcluding"),
                    version_end_including=entry.get("versionEndIncluding"),
                    version_end_excluding=entry.get("versionEndExcluding"),
                )
            )
    return matches
