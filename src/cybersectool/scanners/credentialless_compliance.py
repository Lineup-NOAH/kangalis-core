"""Kimliksiz (credentialless) uyum denetimi (roadmap #E) — kimlik bilgisi GEREKTİRMEZ.

Kimlikli (credentialed) sertleştirme denetimleri host'a SSH/WinRM ile girip config okur;
bu modül ise YALNIZ ağ/web taramasının zaten ürettiği veriden (Finding + Service) uyum
sonucu türetir. Böylece kimlik bilgisi olmayan taramalar da KVKK/ISO/PCI tablosuna katkı verir.

12 denetim 4 grupta:
  * TLS (4): zayıf sürüm, zayıf cipher, self-signed sertifika, süresi dolmuş/yakın sertifika.
  * Açık servis (6): kimliksiz Redis/Elasticsearch/Docker-API/kubelet/Kubernetes-API + anonim FTP.
  * Yönetim portu (1): SSH/RDP/WinRM tarama kapsamında erişilebilir.
  * HTTP/HSTS (1): 80/HTTP açık ya da HSTS başlığı yok.

``eval_*`` yardımcıları SAF (DB'siz, birim testi edilebilir); ``run_credentialless_compliance``
taramanın bulgu+servis verisini sorgulayıp bunları çalıştırır ve ``ComplianceResult`` döner.
Sonuçlar mevcut ``store_compliance`` ile AYNI ``ComplianceCheck`` tablosuna yazılır → var olan
uyum arayüzü/raporu (KVKK/ISO/PCI) değişiklik gerekmeden gösterir.

Karar kuralı: bir denetim ilgili servis/port KAPSAMDA YOKSA atlanır (absent servis için sahte
'pass' seli üretilmez); servis VARSA güvenliyse PASS, açıksa FAIL emit edilir.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.compliance import ComplianceResult
from cybersectool.core.models import Finding, Service, Severity

# Çerçeve etiketi (rapor/PDF'te ham gösterilir; i18n aramaz — diğer çerçeveler gibi).
FRAMEWORK = "Ağ/TLS (kimliksiz)"

# Yönetim portları (uzaktan yönetim yüzeyi) → port: protokol etiketi.
MANAGEMENT_PORTS: dict[int, str] = {22: "SSH", 3389: "RDP", 5985: "WinRM", 5986: "WinRM (HTTPS)"}

# Açık-servis bulgu başlığı öneki → (control_id, başlık). exposed_services.py'deki üretimle
# eşleşir; başlık önekleri orada değişirse burası da güncellenmeli (tek-kaynak bağı).
_EXPOSED_PREFIXES: tuple[tuple[str, str, str], ...] = (
    ("Kimlik doğrulamasız Redis", "N-EXP.1", "Redis kimlik doğrulamasız erişime kapalı olmalı"),
    (
        "Kimlik doğrulamasız Elasticsearch",
        "N-EXP.2",
        "Elasticsearch kimlik doğrulamasız erişime kapalı olmalı",
    ),
    (
        "Kimlik doğrulamasız Docker API",
        "N-EXP.3",
        "Docker Engine API kimlik doğrulamasız/TLS'siz dışa açık olmamalı",
    ),
    ("Anonim kubelet erişimi", "N-EXP.4", "kubelet API anonim erişime kapalı olmalı"),
    ("Anonim FTP erişimi", "N-EXP.5", "FTP anonim girişe kapalı olmalı"),
    (
        "Kimlik doğrulamasız Kubernetes API",
        "N-EXP.6",
        "kube-apiserver kimlik doğrulamasız erişime kapalı olmalı",
    ),
)

# TLS bulgu başlığı imzaları → (control_id, başlık). web.py check_tls/_check_cert üretimiyle eşli.
_TLS_WEAK_VERSION = ("Zayıf TLS sürümü", "Zayıf TLS protokolü ETKİN")
_TLS_WEAK_CIPHER = "Zayıf TLS şifre paketi"
_TLS_SELF_SIGNED = "Kendinden imzalı (self-signed) TLS sertifikası"
_HSTS_MISSING = "Eksik güvenlik başlığı: Strict-Transport-Security (HSTS)"
# El sıkışma başarısız olursa check_tls bu başlıkla TEK bulgu döner (web.py) → TLS posture
# bilinemez. Bu başlık "TLS" içerdiğinden 'denetlendi' sanılıp sahte PASS üretmemeli.
_TLS_CONN_ERROR = "TLS/SSL bağlantı hatası"


def _result(
    control_id: str, title: str, status: str, sev: Severity | None, detail: str | None
) -> ComplianceResult:
    return ComplianceResult(FRAMEWORK, control_id, title, status, sev, detail)


def eval_exposed_services(finding_titles: list[str]) -> list[ComplianceResult]:
    """Açık-servis bulgularına (6 denetim) göre FAIL üretir (saf).

    Her exposed-servis denetimi yalnız ilgili bulgu VARSA emit edilir (FAIL). Bulgu yoksa,
    servisin kapsamda olup olmadığını tek başına bilemeyiz → atlanır (yanlış 'pass' üretilmez;
    açık-port-bazlı PASS'ler yönetim-portu denetiminde ayrı ele alınır).
    """
    results: list[ComplianceResult] = []
    for prefix, control_id, title in _EXPOSED_PREFIXES:
        match = next((t for t in finding_titles if t.startswith(prefix)), None)
        if match is not None:
            results.append(_result(control_id, title, "fail", Severity.critical, match))
    return results


def eval_tls(finding_titles: list[str], *, https_present: bool) -> list[ComplianceResult]:
    """TLS bulgularına göre 4 denetim üretir (saf).

    ``https_present``: TLS GERÇEKTEN denetlendi mi (check_tls çalıştı ve el sıkışma başarılı).
    Yalnız açık 443 portu yeterli DEĞİL — ağ taraması el sıkışma yapmaz; çağıran bu ayrımı
    ``run_credentialless_compliance(tls_checked=...)`` ile yapar. Denetlenmediyse atlanır
    (absent → ne pass ne fail; sahte 'pass' yok). Denetlendiyse: zayıflık bulgusu varsa FAIL,
    yoksa PASS (TLS var ve güçlü → mevzuat skoruna olumlu katkı).
    """
    if not https_present:
        return []
    titles = finding_titles

    def has(*needles: str) -> str | None:
        for t in titles:
            if all(n in t for n in needles):
                return t
        return None

    results: list[ComplianceResult] = []
    # 1) Zayıf TLS sürümü/protokolü (TLS1.0/1.1)
    hit = next((t for t in titles if t.startswith(_TLS_WEAK_VERSION)), None)
    results.append(
        _result(
            "N-TLS.1",
            "Yalnız TLS 1.2+ kullanılmalı (zayıf sürüm devre dışı)",
            "fail" if hit else "pass",
            Severity.medium if hit else None,
            hit,
        )
    )
    # 2) Zayıf cipher
    cipher = next((t for t in titles if t.startswith(_TLS_WEAK_CIPHER)), None)
    results.append(
        _result(
            "N-TLS.2",
            "Güçlü şifre paketleri kullanılmalı (zayıf cipher yok)",
            "fail" if cipher else "pass",
            Severity.medium if cipher else None,
            cipher,
        )
    )
    # 3) Self-signed sertifika
    ss = next((t for t in titles if t == _TLS_SELF_SIGNED), None)
    results.append(
        _result(
            "N-TLS.3",
            "Güvenilir CA imzalı sertifika kullanılmalı (self-signed değil)",
            "fail" if ss else "pass",
            Severity.medium if ss else None,
            ss,
        )
    )
    # 4) Süresi dolmuş / yakında dolacak sertifika
    exp = has("TLS sertifikası süresi dolmuş") or has("TLS sertifikası", "gün içinde dolacak")
    results.append(
        _result(
            "N-TLS.4",
            "Sertifika geçerli olmalı (süresi dolmamış/yakın değil)",
            "fail" if exp else "pass",
            Severity.high if exp else None,
            exp,
        )
    )
    return results


def eval_management_ports(open_ports: set[int]) -> ComplianceResult | None:
    """Yönetim portu (SSH/RDP/WinRM) tarama kapsamında erişilebilir mi (saf).

    Kapsamda hiç yönetim portu yoksa atlanır (None). Varsa: uzaktan yönetim yüzeyi açık →
    bilgilendirici FAIL (iç ağda beklenebilir ama maruziyet azaltma için raporlanmalı).
    """
    exposed = sorted(p for p in open_ports if p in MANAGEMENT_PORTS)
    if not exposed:
        return None
    labels = ", ".join(f"{MANAGEMENT_PORTS[p]}({p})" for p in exposed)
    return _result(
        "N-MGT.1",
        "Uzaktan yönetim portları (SSH/RDP/WinRM) ağa kapatılmalı/sınırlandırılmalı",
        "fail",
        Severity.low,
        f"Erişilebilir yönetim portu: {labels}",
    )


def eval_http_hsts(
    open_ports: set[int], finding_titles: list[str], *, https_present: bool
) -> ComplianceResult | None:
    """HTTP (80) açık ya da HSTS başlığı yok mu (saf).

    Web yüzeyi yoksa (ne 80 açık ne HTTPS denetlendi ne HSTS bulgusu) atlanır. HTTP açık
    ya da HSTS eksik → FAIL; HTTPS denetlendi ve HSTS eksik bulgusu YOK → PASS.
    """
    http_open = 80 in open_ports
    hsts_missing = _HSTS_MISSING in finding_titles
    if not http_open and not https_present and not hsts_missing:
        return None
    if http_open or hsts_missing:
        why = []
        if http_open:
            why.append("80/HTTP açık (HTTPS'e yönlendirme garanti değil)")
        if hsts_missing:
            why.append("HSTS (Strict-Transport-Security) başlığı yok")
        return _result(
            "N-HTTP.1",
            "HTTP yerine HTTPS zorlanmalı ve HSTS gönderilmeli",
            "fail",
            Severity.medium,
            "; ".join(why),
        )
    return _result(
        "N-HTTP.1",
        "HTTP yerine HTTPS zorlanmalı ve HSTS gönderilmeli",
        "pass",
        None,
        None,
    )


async def _scan_findings(session: AsyncSession, scan_id: int) -> list[str]:
    rows = await session.execute(select(Finding.title).where(Finding.scan_id == scan_id))
    return [str(t) for t in rows.scalars().all()]


async def _scan_open_ports(
    session: AsyncSession, scan_id: int, services: list[Service] | None
) -> set[int]:
    """Tarama kapsamındaki açık portlar. ``services`` verilirse (işleme anındaki bellek-içi
    Service listesi) onu kullanır; yoksa bu taramada bulgusu olan varlıkların servislerini sorgular.
    """
    if services is not None:
        return {s.port for s in services if s.port}
    asset_rows = await session.execute(
        select(Finding.asset_id).where(Finding.scan_id == scan_id, Finding.asset_id.is_not(None))
    )
    asset_ids = {int(a) for a in asset_rows.scalars().all() if a is not None}
    if not asset_ids:
        return set()
    svc_rows = await session.execute(select(Service.port).where(Service.asset_id.in_(asset_ids)))
    return {int(p) for p in svc_rows.scalars().all() if p}


async def run_credentialless_compliance(
    session: AsyncSession,
    scan_id: int,
    *,
    services: list[Service] | None = None,
    tls_checked: bool = False,
) -> list[ComplianceResult]:
    """Taramanın kimliksiz verisinden (bulgu + servis) uyum sonuçları türetir (12 denetim).

    ``services`` ağ taraması işleme yolunda bellek-içi Service listesini geçirmek için (port
    bilgisi en doğru oradadır). Verilmezse bulgulu varlıkların servisleri sorgulanır.

    ``tls_checked``: çağıran yolda ``check_tls`` GERÇEKTEN çalıştı mı (web/ESXi). Ağ taraması
    ``check_tls`` çağırmaz → varsayılan False; bu durumda 443 açık olsa bile TLS DENETLENMEMİŞ
    sayılır ve TLS denetimleri atlanır (sahte 'pass' üretilmez). El sıkışma başarısızsa (bağlantı
    hatası bulgusu) yine TLS denetlenmemiş sayılır.

    Sonuçlar çağıran tarafından ``store_compliance`` ile saklanır (çerçeve-başına idempotent).
    """
    titles = await _scan_findings(session, scan_id)
    open_ports = await _scan_open_ports(session, scan_id, services)
    # TLS GERÇEKTEN denetlendi mi: check_tls çalıştı (tls_checked) VE el sıkışma başarılı
    # (bağlantı-hatası bulgusu yok). 443 açık olması TEK BAŞINA TLS denetlendiği anlamına gelmez.
    tls_inspected = tls_checked and not any(_TLS_CONN_ERROR in t for t in titles)
    # HTTP/HSTS için web yüzeyi sinyali ayrıdır: 443 açık = HTTPS yüzeyi var (TLS denetiminden
    # bağımsız; salt port-tabanlı, sahte TLS-pass üretmez).
    https_open = 443 in open_ports

    results: list[ComplianceResult] = []
    results.extend(eval_tls(titles, https_present=tls_inspected))
    results.extend(eval_exposed_services(titles))
    mgmt = eval_management_ports(open_ports)
    if mgmt is not None:
        results.append(mgmt)
    http = eval_http_hsts(open_ports, titles, https_present=https_open)
    if http is not None:
        results.append(http)
    return results
