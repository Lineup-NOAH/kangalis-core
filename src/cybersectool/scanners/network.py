"""Ağ tarayıcı — nmap ile host keşfi, port ve servis/versiyon tespiti.

`run_nmap` nmap'i çalıştırıp ayrıştırır (e2e ile doğrulanır); `store_results` sonuçları
Asset/Service envanterine yazar (birim testi edilebilir, nmap gerektirmez).
"""

from __future__ import annotations

import contextlib
import os
import re
import shlex
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from typing import Any

# XXE/billion-laughs koruması: python-libnmap, ``defusedxml`` kuruluysa XML ayrıştırmada onu
# OTOMATİK kullanır (parser.py: ``try: import defusedxml.ElementTree``). defusedxml pyproject'te
# zorunlu bağımlılıktır; tests/test_security_hardening.py bu seçimi sabitler. Tarama hedefi banner
# vb. yoluyla nmap XML'ini etkileyebilse de güvenli ayrıştırılır.
from libnmap.parser import NmapParser
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.assets import prune_unseen_services, upsert_asset, upsert_service
from cybersectool.core.findings import create_finding
from cybersectool.core.models import Service, Severity
from cybersectool.core.scope import should_be_asset

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_RISK_RE = re.compile(r"Risk factor:\s*(\w+)", re.IGNORECASE)
_STATE_VULN_RE = re.compile(r"State:\s*VULNERABLE\b")
_VULN_HEADER_RE = re.compile(r"\bVULNERABLE:")
_RISK_MAP = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
}


@dataclass
class ServiceResult:
    port: int
    protocol: str
    name: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None


@dataclass
class NseFinding:
    """Agresif modda bir NSE vuln/exploit script'inin AKTİF doğruladığı zafiyet."""

    ip: str
    script_id: str
    title: str
    severity: Severity
    cve_id: str | None
    output: str


def _is_confirmed_vulnerable(output: str) -> bool:
    """NSE çıktısı zafiyeti KESİN doğruladı mı? (muhafazakâr: yalnız net pozitif).

    nmap vuln kütüphanesi pozitifte 'State: VULNERABLE', negatifte 'NOT VULNERABLE'
    yazar. 'LIKELY VULNERABLE' gibi belirsiz durumlar doğrulanmış SAYILMAZ.
    """
    if not output:
        return False
    if _STATE_VULN_RE.search(output):
        return True
    return bool(_VULN_HEADER_RE.search(output)) and "NOT VULNERABLE" not in output


def _severity_from_output(output: str) -> Severity:
    m = _RISK_RE.search(output)
    if m:
        return _RISK_MAP.get(m.group(1).lower(), Severity.high)
    return Severity.high


def parse_nse_findings(ip: str, script_results: list[dict[str, object]]) -> list[NseFinding]:
    """NSE script sonuçlarından AKTİF doğrulanmış zafiyetleri çıkarır (saf, test edilebilir).

    CVE'li script → her CVE için bir bulgu (çıkarım bulgularıyla fingerprint üzerinden
    tekilleşir, doğrulanmış olan yapışkanca kazanır). CVE'siz script → tek bulgu.
    """
    findings: list[NseFinding] = []
    for sr in script_results or []:
        output = str(sr.get("output") or "")
        if not _is_confirmed_vulnerable(output):
            continue
        script_id = str(sr.get("id") or "nse")
        sev = _severity_from_output(output)
        short = output.strip()[:1500]
        cves = sorted(set(_CVE_RE.findall(output)))
        if cves:
            for cve in cves:
                findings.append(
                    NseFinding(
                        ip, script_id, f"{script_id}: {cve} (NSE doğrulandı)", sev, cve, short
                    )
                )
        else:
            findings.append(
                NseFinding(
                    ip, script_id, f"{script_id}: doğrulanmış zafiyet (NSE)", sev, None, short
                )
            )
    return findings


def _extract_cpe(svc: object) -> str | None:
    """nmap servisinden CPE dizesini çıkarır; uygulama (a) CPE'sini tercih eder."""
    cpelist = getattr(svc, "cpelist", None) or []
    strings: list[str] = []
    for entry in cpelist:
        text = getattr(entry, "cpestring", None) or (entry if isinstance(entry, str) else None)
        if text:
            strings.append(str(text))
    for text in strings:
        if text.startswith("cpe:/a") or text.startswith("cpe:2.3:a"):
            return text
    return strings[0] if strings else None


@dataclass
class HostResult:
    ip: str
    hostname: str | None = None
    services: list[ServiceResult] = field(default_factory=list)
    nse_findings: list[NseFinding] = field(default_factory=list)


def _nmap_output_complete(xml: str) -> bool:
    """nmap XML çıktısı düzgün KAPANDI mı? nmap her koşmayı ``<runstats><finished .../>`` ile

    bitirir (0 host bile olsa). Bu işaret yoksa çıktı KESİK/EKSİK demektir (kill/OOM/okuma
    kopması) → tarama tamamlanmamıştır.
    """
    return "<finished" in xml


def _wait_or_cancel(proc: subprocess.Popen[str], cancel: threading.Event | None) -> bool:
    """nmap sürecini bekler; ``cancel`` set edilirse süreci ÖLDÜRÜR. Öldürüldüyse True döner.

    Saniyede bir ``cancel`` bayrağını yoklar (poll). İptal gelirse ``kill`` + kısa ``wait``
    (zombi/orphan bırakma). Normal bitişte False döner. nmap GEREKTİRMEZ — minimal proc
    arayüzüyle (``wait``/``kill``) çağrılabildiği için birim testi edilebilir (#160).
    """
    while True:
        try:
            proc.wait(timeout=1.0)
            return False
        except subprocess.TimeoutExpired:
            if cancel is not None and cancel.is_set():
                proc.kill()
                with contextlib.suppress(Exception):
                    proc.wait(timeout=5)
                return True


def _run_nmap_to_xml(
    target: str, options: str, cancel: threading.Event | None = None
) -> str | None:
    """nmap'i çalıştırır, XML çıktısını DOSYAYA yazar ve içeriğini (dize) döndürür.

    Neden dosya (stdout DEĞİL): libnmap'in ``NmapProcess``'i XML'i ``-oX -`` ile STDOUT
    borusundan okur; çok-bloklu/büyük hedeflerde (ör. LAN + lab BİRLİKTE) bu okuma çıktıyı
    ERKEN KESEBİLİYOR → 0 host parse edilir, tarama yanlışlıkla "tamamlandı, 0 sonuç" görünür
    (gerçekte başarısız). Dosya çıktısı bu kesilmeyi tamamen bypass eder.

    İptal (#160): ``cancel`` Event'i set edilirse çalışan nmap süreci ``kill`` edilir ve
    ``None`` döner (çağıran bunu boş sonuç sayar). Böylece kullanıcı "Taramayı Durdur" deyince
    arka planda ORPHAN nmap süreci KALMAZ — eskiden tarama 'cancelled' işaretleniyordu ama
    nmap koşmaya devam ediyordu (özellikle UDP taraması dakikalarca CPU/ağ yiyordu).

    Eksiklik denetimi: nmap çıktıyı ``<finished .../>`` ile kapatır. Yoksa çıktı kesik/eksik
    (kill/OOM/okuma kopması) → ``RuntimeError`` fırlatılır ki tarama 'başarısız' işaretlensin
    (sessizce boş tamamlanmasın). Argümanlar LİSTE ile geçer (shell YOK) → komut-enjeksiyonu
    yok; ``options`` scan_policy'den (kontrollü), ``target`` scope guard'dan geçmiştir.
    """
    fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="kg-nmap-")
    os.close(fd)
    efd, err_path = tempfile.mkstemp(suffix=".err", prefix="kg-nmap-")
    os.close(efd)
    try:
        args = ["nmap", *shlex.split(options), "-oX", xml_path, *target.split()]
        # stderr DOSYAYA yazılır (PIPE değil): iptal beklerken proc.wait yapıyoruz, dolu bir
        # stderr borusu nmap'i bloklayıp kilitlenmeye yol açabilirdi. Dosya bunu önler + tail'i
        # eksiklik hatasında korur.
        with open(err_path, "w", encoding="utf-8") as err_fh:
            proc = subprocess.Popen(  # noqa: S603
                args, stdout=subprocess.DEVNULL, stderr=err_fh, text=True
            )
            cancelled = _wait_or_cancel(proc, cancel)
        if cancelled:
            return None
        try:
            with open(xml_path, encoding="utf-8", errors="replace") as fh:
                xml = fh.read()
        except OSError:
            xml = ""
        if not _nmap_output_complete(xml):
            try:
                with open(err_path, encoding="utf-8", errors="replace") as efh:
                    tail = efh.read().strip()[-300:]
            except OSError:
                tail = ""
            raise RuntimeError(
                f"nmap çıktısı eksik/kesik (rc={proc.returncode}, {len(xml)} bayt) — "
                f"tarama tamamlanamadı. {tail}"
            )
        return xml
    finally:
        with contextlib.suppress(OSError):
            os.unlink(xml_path)
        with contextlib.suppress(OSError):
            os.unlink(err_path)


def run_nmap(
    target: str, options: str = "-sV -T4", cancel: threading.Event | None = None
) -> list[HostResult]:
    """nmap çalıştırıp açık host/servisleri `HostResult` listesine ayrıştırır.

    ``cancel`` (iptal bayrağı) set edilirse nmap öldürülür ve boş liste döner (#160).
    """
    xml = _run_nmap_to_xml(target, options, cancel=cancel)
    if xml is None:
        return []
    report = NmapParser.parse(xml)

    results: list[HostResult] = []
    for host in report.hosts:
        if not host.is_up():
            continue
        hostname = host.hostnames[0] if host.hostnames else None
        services: list[ServiceResult] = []
        script_results: list[dict[str, object]] = list(getattr(host, "scripts_results", None) or [])
        for svc in host.services:
            if svc.state != "open":
                continue
            script_results.extend(getattr(svc, "scripts_results", None) or [])
            banner = dict(svc.banner_dict or {})
            services.append(
                ServiceResult(
                    port=int(svc.port),
                    protocol=str(svc.protocol),
                    name=svc.service or None,
                    product=banner.get("product"),
                    version=banner.get("version"),
                    cpe=_extract_cpe(svc),
                )
            )
        nse = parse_nse_findings(str(host.address), script_results)
        results.append(
            HostResult(ip=str(host.address), hostname=hostname, services=services, nse_findings=nse)
        )
    return results


async def store_results(
    session: AsyncSession,
    results: list[HostResult],
    *,
    port_scope: dict[str, set[int] | None] | None = None,
) -> list[Service]:
    """Tarama sonuçlarını Asset/Service olarak yazar; yazılan Service kayıtlarını döndürür.

    ``port_scope`` verilirse (STALE-PRUNE, ``examined_port_scope`` çıktısı), her YANIT VEREN host
    için bu taramada görülmeyen eski servisler (taramanın kapsamı dahilinde) silinir → bir kez
    yazılan ``tcpwrapped`` ya da artık kapalı bir servis envanterde eskimeden kalmaz. ``None``
    ise eski davranış korunur (yalnız upsert, budama yok).
    """
    stored: list[Service] = []
    for host in results:
        # F1: yalnız varlık-kapsamı içindeki (iç) IP'ler envantere eklenir; dış/kapsam-dışı
        # hedeflere yapılan taramalar Varlıklar'ı kirletmez (servisleri de yazılmaz).
        if not await should_be_asset(session, host.ip):
            continue
        asset = await upsert_asset(session, host.ip, hostname=host.hostname, is_up=True)
        seen: set[tuple[int, str]] = set()
        for svc in host.services:
            service = await upsert_service(
                session,
                asset.id,
                svc.port,
                protocol=svc.protocol,
                service_name=svc.name,
                product=svc.product,
                version=svc.version,
                cpe=svc.cpe,
            )
            stored.append(service)
            seen.add((svc.port, svc.protocol))
        # Host yanıt verdi (sonuç listesinde) → bu taramada görülmeyen eski servisleri eskit/sil.
        # 0 servisli (hepsi filtered/closed) yanıt veren host'ta kapsamdaki tüm eski servisler
        # temizlenir — expire olmuş/kapanmış bir hedefin tcpwrapped kayıtları böyle gider.
        if port_scope is not None:
            await prune_unseen_services(session, asset.id, seen, port_scope)
    return stored


@dataclass
class DiscoveredHost:
    """Ping taramasında (host keşfi) AYAKTA bulunan bir host."""

    ip: str
    hostname: str | None = None


def run_ping_scan(
    target: str, options: str, cancel: threading.Event | None = None
) -> list[DiscoveredHost]:
    """nmap host keşfi (-sn) çalıştırır; AYAKTA olan hostları döner (port taraması YOK).

    ``run_nmap`` ile aynı dosya-çıktı/parser deseni (``_run_nmap_to_xml``); tek fark port
    taraması yapılmaz, yalnızca ``is_up()`` hostlar toplanır. nmap gerektirir → e2e doğrulanır.
    ``cancel`` set edilirse nmap öldürülür ve boş liste döner (#160).
    """
    xml = _run_nmap_to_xml(target, options, cancel=cancel)
    if xml is None:
        return []
    report = NmapParser.parse(xml)
    hosts: list[DiscoveredHost] = []
    for host in report.hosts:
        if not host.is_up():
            continue
        hostname = host.hostnames[0] if host.hostnames else None
        hosts.append(DiscoveredHost(ip=str(host.address), hostname=hostname))
    return hosts


def scan_block_hosts(
    block: str,
    port_options: str,
    discovery_options: str,
    discover: bool,
    cancel: threading.Event | None = None,
) -> list[HostResult]:
    """Tek bir bloğu/host kümesini tarar (fan-out child'ı için) → `HostResult` listesi.

    SCAN-NET Faz 2b: bir taramanın blokları worker'lara dağıtıldığında her child bunu çağırır.
    ``discover=True`` (CIDR blok): önce sertleştirilmiş ``-sn`` keşif (NAT boğulmasını + ACK
    sahte-up'ı önler), sonra YALNIZ canlı host'lara ``port_options`` (``-Pn`` içerir) ile derin
    tarama. ``discover=False`` (açıkça yazılan host listesi): doğrudan tarar (kullanıcı niyeti).
    ``cancel`` set edilirse nmap öldürülür → boş döner (#160). Faz 1 ``run_ping_scan``/``run_nmap``
    yeniden kullanılır; fark yalnızca işin tek bir bloğa ait olması.
    """
    if cancel is not None and cancel.is_set():
        return []
    if discover:
        live = [h.ip for h in run_ping_scan(block, discovery_options, cancel)]
        if not live:
            return []
        targets = " ".join(live)
    else:
        targets = block
    return run_nmap(targets, port_options, cancel)


def host_result_to_dict(host: HostResult) -> dict[str, Any]:
    """`HostResult`'ı JSON-güvenli dict'e çevirir (Celery chord ile worker'lar arası taşıma).

    Enum'lar (Severity) ``.value`` ile dizeye indirilir ki Celery'nin JSON serileştiricisi
    taşıyabilsin; ``host_result_from_dict`` ile birebir geri kurulur.
    """
    return {
        "ip": host.ip,
        "hostname": host.hostname,
        "services": [
            {
                "port": s.port,
                "protocol": s.protocol,
                "name": s.name,
                "product": s.product,
                "version": s.version,
                "cpe": s.cpe,
            }
            for s in host.services
        ],
        "nse_findings": [
            {
                "ip": n.ip,
                "script_id": n.script_id,
                "title": n.title,
                "severity": n.severity.value,
                "cve_id": n.cve_id,
                "output": n.output,
            }
            for n in host.nse_findings
        ],
    }


def host_result_from_dict(data: dict[str, Any]) -> HostResult:
    """`host_result_to_dict` çıktısını `HostResult`'a geri kurar (merge task'ı bunu kullanır)."""
    services = [
        ServiceResult(
            port=int(s["port"]),
            protocol=str(s["protocol"]),
            name=s.get("name"),
            product=s.get("product"),
            version=s.get("version"),
            cpe=s.get("cpe"),
        )
        for s in data.get("services", [])
    ]
    nse = [
        NseFinding(
            ip=str(n["ip"]),
            script_id=str(n["script_id"]),
            title=str(n["title"]),
            severity=Severity(n["severity"]),
            cve_id=n.get("cve_id"),
            output=str(n.get("output", "")),
        )
        for n in data.get("nse_findings", [])
    ]
    return HostResult(
        ip=str(data["ip"]),
        hostname=data.get("hostname"),
        services=services,
        nse_findings=nse,
    )


async def store_discovery(session: AsyncSession, scan_id: int, hosts: list[DiscoveredHost]) -> int:
    """Keşfedilen ayakta hostları Asset envanterine yazar + özet info bulgusu üretir.

    Ayakta host sayısını döner. Port/servis taranmadığından Service/Finding (info hariç)
    üretilmez — yalnız envanter (hangi IP'ler canlı) güncellenir.
    """
    for host in hosts:
        # F1: yalnız kapsam-içi (iç) IP'ler envantere; dış hedefler kirletmez (bulgu yine listeler).
        if await should_be_asset(session, host.ip):
            await upsert_asset(session, host.ip, hostname=host.hostname, is_up=True)
    if hosts:
        shown = ", ".join(f"{h.ip}{f' ({h.hostname})' if h.hostname else ''}" for h in hosts[:60])
        if len(hosts) > 60:
            shown += " …"
        await create_finding(
            session,
            scan_id,
            f"Ping taraması: {len(hosts)} ayakta host bulundu",
            severity=Severity.info,
            description=f"Yanıt veren (canlı) hostlar: {shown}",
        )
    else:
        await create_finding(
            session,
            scan_id,
            "Ping taraması: ayakta host bulunamadı",
            severity=Severity.info,
            description="Hedef aralığında yanıt veren host saptanmadı (kapalı ya da filtreli).",
        )
    return len(hosts)


async def store_nse_findings(
    session: AsyncSession, scan_id: int, results: list[HostResult]
) -> list[str]:
    """Aktif NSE doğrulanmış bulguları validated=True olarak yazar; CVE id'lerini döner.

    Bu bulgular agresif modda NSE vuln/exploit script'lerinin GERÇEKTEN doğruladığı
    zafiyetlerdir (versiyon-bazlı çıkarım değil) → ``validated=True`` (VI-13).
    """
    cve_ids: list[str] = []
    for host in results:
        if not host.nse_findings:
            continue
        # F1: kapsam-içi hedef → varlığa bağla; kapsam-dışı (dış) → asset yaratma ama
        # doğrulanmış bulgu yine raporlanır (asset_id=None; envanter kirlenmez).
        asset = (
            await upsert_asset(session, host.ip, hostname=host.hostname, is_up=True)
            if await should_be_asset(session, host.ip)
            else None
        )
        for nf in host.nse_findings:
            await create_finding(
                session,
                scan_id,
                nf.title,
                severity=nf.severity,
                asset_id=asset.id if asset else None,
                cve_id=nf.cve_id,
                description=nf.output,
                validated=True,
            )
            if nf.cve_id:
                cve_ids.append(nf.cve_id)
    return cve_ids
