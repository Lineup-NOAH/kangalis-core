"""Ağ tarayıcı sonuç-yazma + NSE doğrulama testi (nmap gerektirmez)."""

from __future__ import annotations

import subprocess
import threading

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.assets import count_assets, list_assets, services_for_target
from cybersectool.core.models import Severity
from cybersectool.scanners.network import (
    HostResult,
    NseFinding,
    ServiceResult,
    _nmap_output_complete,
    _wait_or_cancel,
    host_result_from_dict,
    host_result_to_dict,
    parse_nse_findings,
    store_nse_findings,
    store_results,
)


def test_nmap_output_complete() -> None:
    """nmap çıktısı <finished> ile kapanmalı; yoksa KESİK (sahte 'tamamlandı' önlenir).

    Gerçek-LAN + lab birlikte taranınca libnmap'in stdout okuması çıktıyı erken kesip 0 host
    döndürüyordu; XML dosyaya yazılır + bu kontrolle kesiklik 'başarısız' işaretlenir.
    """
    complete = '<nmaprun><host>...</host><runstats><finished elapsed="58" exit="success"/>'
    truncated = "<nmaprun><prescript>...</prescript>"  # host taraması başlamadan kesilmiş
    assert _nmap_output_complete(complete) is True
    assert _nmap_output_complete(truncated) is False
    assert _nmap_output_complete("") is False


class _FakeProc:
    """``_wait_or_cancel`` testi için minimal nmap süreci taklidi (gerçek nmap gerektirmez).

    ``finish_after`` kadar timeout sonra kendiliğinden biter; ``kill`` çağrılınca sonraki
    ``wait`` hemen döner (öldürülen süreç).
    """

    def __init__(self, finish_after: int = 0) -> None:
        self._waits = 0
        self._finish_after = finish_after
        self.killed = False
        self.returncode = 0

    def wait(self, timeout: float | None = None) -> int:
        if self.killed:
            return -9
        self._waits += 1
        if self._waits > self._finish_after:
            return 0
        raise subprocess.TimeoutExpired(cmd="nmap", timeout=timeout or 1.0)

    def kill(self) -> None:
        self.killed = True


def test_wait_or_cancel_normal_finish() -> None:
    """İptal yokken nmap kendiliğinden biter → False döner, süreç ÖLDÜRÜLMEZ."""
    proc = _FakeProc(finish_after=3)  # 3 timeout sonra biter
    cancelled = _wait_or_cancel(proc, threading.Event())  # event hiç set edilmez
    assert cancelled is False
    assert proc.killed is False


def test_wait_or_cancel_kills_on_cancel() -> None:
    """#160: ``cancel`` set ise çalışan nmap ÖLDÜRÜLÜR ve True döner (orphan kalmaz)."""
    proc = _FakeProc(finish_after=10_000)  # kendiliğinden bitmez
    cancel = threading.Event()
    cancel.set()
    cancelled = _wait_or_cancel(proc, cancel)
    assert cancelled is True
    assert proc.killed is True


def test_wait_or_cancel_none_event_never_kills() -> None:
    """``cancel=None`` (iptal desteği yok) → bayrak yoklanmaz, süreç bitene dek beklenir."""
    proc = _FakeProc(finish_after=1)
    assert _wait_or_cancel(proc, None) is False
    assert proc.killed is False


async def test_fanout_redis_client_fresh_per_call(monkeypatch: object) -> None:
    """Regression (fan-out): blok-sayacı Redis istemcisi ÇAĞRI BAŞINA yaratılıp kapatılmalı.

    Süreç-ömürlü önbelleğe-alınmış async istemci, worker'da 2. taramada "Event loop is closed"
    hatası verirdi (her Celery görevi ``asyncio.run`` ile YENİ event loop açar; cached istemci
    kapanmış loop'a bağlı kalır). Bu test cache'in geri gelmesini engeller.
    """
    from cybersectool.tasks import network_scan

    calls = {"from_url": 0, "aclose": 0}

    class _FakeRedis:
        async def incr(self, key: str) -> int:
            return 1

        async def expire(self, key: str, ttl: int) -> bool:
            return True

        async def delete(self, key: str) -> int:
            return 1

        async def aclose(self) -> None:
            calls["aclose"] += 1

    def _fake_from_url(*args: object, **kwargs: object) -> _FakeRedis:
        calls["from_url"] += 1
        return _FakeRedis()

    monkeypatch.setattr(network_scan.aioredis, "from_url", _fake_from_url)  # type: ignore[attr-defined]
    await network_scan._incr_blocks_done(1)
    await network_scan._incr_blocks_done(1)
    await network_scan._reset_blocks_done(1)
    assert calls["from_url"] == 3  # cached DEĞİL → her çağrıda yeni istemci (geçerli loop'a bağlı)
    assert calls["aclose"] == 3  # her istemci kapatıldı (bağlantı sızıntısı yok)


def test_host_result_dict_roundtrip() -> None:
    """SCAN-NET Faz 2b: HostResult ↔ JSON-dict gidiş-dönüş (fan-out chord) bilgi kaybetmez."""
    original = HostResult(
        ip="10.0.0.9",
        hostname="h1",
        services=[
            ServiceResult(port=22, protocol="tcp", name="ssh", product="OpenSSH", version="8.9"),
            ServiceResult(port=80, protocol="tcp", name="http"),
        ],
        nse_findings=[
            NseFinding(
                ip="10.0.0.9",
                script_id="ssl-heartbleed",
                title="CVE-2014-0160",
                severity=Severity.high,
                cve_id="CVE-2014-0160",
                output="VULNERABLE",
            )
        ],
    )
    # to_dict çıktısı JSON-güvenli olmalı (Celery JSON serileştiricisi taşıyabilsin).
    import json

    encoded = json.loads(json.dumps(host_result_to_dict(original)))
    restored = host_result_from_dict(encoded)
    assert restored.ip == original.ip
    assert restored.hostname == original.hostname
    assert [(s.port, s.name, s.product, s.version) for s in restored.services] == [
        (22, "ssh", "OpenSSH", "8.9"),
        (80, "http", None, None),
    ]
    assert len(restored.nse_findings) == 1
    nf = restored.nse_findings[0]
    assert nf.cve_id == "CVE-2014-0160"
    assert nf.severity == Severity.high  # enum .value → str → enum geri kuruldu


async def test_store_results_writes_inventory(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    results = [
        HostResult(
            ip="10.0.0.9",
            hostname="h1",
            services=[
                ServiceResult(port=22, protocol="tcp", name="ssh", version="8.9"),
                ServiceResult(port=80, protocol="tcp", name="http"),
            ],
        )
    ]
    async with session_factory() as session:
        written = await store_results(session, results)
        assert len(written) == 2
        assert await count_assets(session) == 1
        assets = await list_assets(session)
        assert assets[0].ip == "10.0.0.9"
        assert assets[0].hostname == "h1"


async def test_store_results_skips_out_of_scope_ip(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """F1: varlık-kapsamı dışındaki (dış/public) IP envantere eklenmez (servisleri de yazılmaz).

    İç IP (10.x) asset olur; dış IP (8.8.8.8) varsayılan kapsam (RFC1918) dışında → atlanır.
    """
    results = [
        HostResult(
            ip="10.0.0.9",
            hostname="ic",
            services=[ServiceResult(port=22, protocol="tcp", name="ssh")],
        ),
        HostResult(
            ip="8.8.8.8",
            hostname="dis",
            services=[ServiceResult(port=443, protocol="tcp", name="https")],
        ),
    ]
    async with session_factory() as session:
        written = await store_results(session, results)
        assert len(written) == 1  # yalnız iç host'un servisi yazıldı
        assert await count_assets(session) == 1  # dış IP asset olmadı
        assets = await list_assets(session)
        assert [a.ip for a in assets] == ["10.0.0.9"]


async def test_store_results_prunes_stale_services(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """STALE-PRUNE: yanıt veren host'ta bu taramada görülmeyen eski servis (tcpwrapped) silinir."""
    first = [
        HostResult(
            ip="10.0.0.50",
            services=[
                ServiceResult(port=22, protocol="tcp", name="ssh"),
                ServiceResult(port=445, protocol="tcp", name="tcpwrapped"),
            ],
        )
    ]
    async with session_factory() as session:
        await store_results(session, first, port_scope={"tcp": None})
        assert {s.port for s in await services_for_target(session, "10.0.0.50")} == {22, 445}
        # İkinci tarama: host yanıt veriyor ama 445 artık açık değil → sonuç listesinde yok.
        second = [
            HostResult(
                ip="10.0.0.50", services=[ServiceResult(port=22, protocol="tcp", name="ssh")]
            )
        ]
        await store_results(session, second, port_scope={"tcp": None})
        ports = {s.port for s in await services_for_target(session, "10.0.0.50")}
        assert ports == {22}  # 445/tcpwrapped budandı (artık açık değil)


async def test_store_results_prune_respects_scope(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """STALE-PRUNE kapsam dışı portu ve incelenmeyen protokolü KORUR (hedefli/kısmi tarama)."""
    first = [
        HostResult(
            ip="10.0.0.51",
            services=[
                ServiceResult(port=80, protocol="tcp", name="http"),
                ServiceResult(port=9999, protocol="tcp", name="custom"),
                ServiceResult(port=161, protocol="udp", name="snmp"),
            ],
        )
    ]
    async with session_factory() as session:
        await store_results(session, first, port_scope={"tcp": None})
        # Hedefli TCP taraması: yalnız 80 incelendi, açık değil. 9999 (kapsam dışı port) + 161/udp
        # (protokol hiç incelenmedi) KORUNUR; yalnız 80 budanır.
        second = [HostResult(ip="10.0.0.51", services=[])]
        await store_results(session, second, port_scope={"tcp": {80}})
        keys = {(s.port, s.protocol) for s in await services_for_target(session, "10.0.0.51")}
        assert (80, "tcp") not in keys  # kapsamda + görülmedi → budandı
        assert (9999, "tcp") in keys  # kapsam dışı port → korundu
        assert (161, "udp") in keys  # udp incelenmedi → korundu


async def test_store_results_no_prune_without_scope(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """port_scope=None → eski davranış: budama YOK (yalnız upsert), envanter korunur."""
    async with session_factory() as session:
        await store_results(
            session,
            [
                HostResult(
                    ip="10.0.0.52",
                    services=[ServiceResult(port=445, protocol="tcp", name="tcpwrapped")],
                )
            ],
        )
        # İkinci tarama 445'i görmüyor ama port_scope verilmedi → 445 korunur (geriye uyum).
        await store_results(session, [HostResult(ip="10.0.0.52", services=[])])
        ports = {s.port for s in await services_for_target(session, "10.0.0.52")}
        assert ports == {445}


# --- VI-13: NSE doğrulama ayrıştırma ---
_HEARTBLEED_OUTPUT = """
| ssl-heartbleed:
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability...
|     State: VULNERABLE
|     Risk factor: High
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
"""

_NOT_VULN_OUTPUT = """
| ssl-heartbleed:
|     State: NOT VULNERABLE
"""

_LIKELY_OUTPUT = "| http-something:\n|   State: LIKELY VULNERABLE\n"


def test_parse_nse_confirmed_with_cve() -> None:
    """State: VULNERABLE + CVE → doğrulanmış bulgu; severity Risk factor'dan."""
    findings = parse_nse_findings(
        "10.0.0.5", [{"id": "ssl-heartbleed", "output": _HEARTBLEED_OUTPUT}]
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.cve_id == "CVE-2014-0160"
    assert f.severity == Severity.high
    assert f.script_id == "ssl-heartbleed"


def test_parse_nse_not_vulnerable_excluded() -> None:
    """NOT VULNERABLE ve LIKELY VULNERABLE → doğrulanmış SAYILMAZ (muhafazakâr)."""
    assert parse_nse_findings("10.0.0.5", [{"id": "x", "output": _NOT_VULN_OUTPUT}]) == []
    assert parse_nse_findings("10.0.0.5", [{"id": "y", "output": _LIKELY_OUTPUT}]) == []
    assert parse_nse_findings("10.0.0.5", [{"id": "z", "output": ""}]) == []


def test_parse_nse_no_cve_single_finding() -> None:
    """CVE'siz ama State: VULNERABLE → tek (CVE'siz) doğrulanmış bulgu."""
    out = "|   State: VULNERABLE\n|   Risk factor: Critical\n"
    findings = parse_nse_findings("10.0.0.5", [{"id": "custom-vuln", "output": out}])
    assert len(findings) == 1
    assert findings[0].cve_id is None
    assert findings[0].severity == Severity.critical


async def test_store_nse_findings_validated(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """store_nse_findings validated=True bulgu yazar + CVE id'lerini döner."""
    from cybersectool.core.findings import list_findings
    from cybersectool.core.models import ScanType
    from cybersectool.core.scans import create_scan

    results = [
        HostResult(
            ip="10.0.0.5",
            nse_findings=parse_nse_findings(
                "10.0.0.5", [{"id": "ssl-heartbleed", "output": _HEARTBLEED_OUTPUT}]
            ),
        )
    ]
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.5")
        cve_ids = await store_nse_findings(session, scan.id, results)
        assert cve_ids == ["CVE-2014-0160"]
        findings = await list_findings(session)
        assert len(findings) == 1
        assert findings[0].validated is True
        assert findings[0].cve_id == "CVE-2014-0160"


def test_merge_host_results_dedups_same_ip() -> None:
    """PORT-fanout: aynı IP için N HostResult tek HostResult'a birleşir (servisler dedup edilir).

    Bu olmadan store_results aynı IP'yi ayrı host sanıp her blokta prune ile öncekini siler+patlar.
    """
    from cybersectool.tasks.network_scan import _merge_host_results

    results = [
        HostResult(ip="10.0.0.5", services=[ServiceResult(port=80, protocol="tcp", name="http")]),
        HostResult(ip="10.0.0.5", services=[ServiceResult(port=135, protocol="tcp", name="msrpc")]),
        HostResult(ip="10.0.0.5", services=[ServiceResult(port=80, protocol="tcp", name="http")]),
        HostResult(ip="10.0.0.6", services=[ServiceResult(port=22, protocol="tcp", name="ssh")]),
    ]
    merged = _merge_host_results(results)
    by_ip = {h.ip: h for h in merged}
    assert set(by_ip) == {"10.0.0.5", "10.0.0.6"}
    assert {s.port for s in by_ip["10.0.0.5"].services} == {80, 135}  # 3 girdi → 2 (80 dedup)
    assert {s.port for s in by_ip["10.0.0.6"].services} == {22}


# --- #168 RPC-PROBE: SMB/RPC açık host'ta PrintNightmare adayı bulgusu (audit_rpc monkeypatch) ---


async def test_rpc_probe_findings_writes_cve_findings(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: object,
) -> None:
    """445 açık host → audit_rpc çağrılır; PrintNightmare CVE bulguları asset_id ile yazılır.

    Gerçek bind ağ/Windows gerektirdiğinden ``audit_rpc`` monkeypatch'lenir (ajan canlı bind
    ATEŞLEMEZ — saf mantık + kablolama doğrulanır). Bulgu asset'e bağlanmalı (Zafiyetler'e akması
    için) ve dönen CVE id'leri matched_ids'e girecek şekilde toplanmalı.
    """
    from cybersectool.core.findings import list_findings
    from cybersectool.core.models import ScanType
    from cybersectool.core.scans import create_scan
    from cybersectool.scanners.rpc_probe import RpcInfo, evaluate_rpc
    from cybersectool.tasks import network_scan

    async def fake_audit_rpc(host: str, **kw: object) -> object:
        info = RpcInfo(spooler_reachable=True, spooler_confirm="bind")
        return info, evaluate_rpc(info)

    monkeypatch.setattr(network_scan, "audit_rpc", fake_audit_rpc)  # type: ignore[attr-defined]

    results = [
        HostResult(
            ip="10.0.0.7",
            services=[ServiceResult(port=445, protocol="tcp", name="microsoft-ds")],
        ),
        # 445/139/135 yok → probe atlanır (audit_rpc çağrılmaz).
        HostResult(ip="10.0.0.8", services=[ServiceResult(port=80, protocol="tcp", name="http")]),
    ]
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.7 10.0.0.8")
        await store_results(session, results)  # asset'leri oluştur (asset_id çözülsün)
        cve_ids = await network_scan._rpc_probe_findings(session, scan.id, results)
        assert sorted(set(cve_ids)) == ["CVE-2021-1675", "CVE-2021-34527"]
        findings = await list_findings(session)
        pn = [f for f in findings if f.cve_id in ("CVE-2021-1675", "CVE-2021-34527")]
        assert len(pn) == 2
        assets = {a.ip: a.id for a in await list_assets(session)}
        for f in pn:
            assert f.asset_id == assets["10.0.0.7"]  # Zafiyetler'e akması için asset'e bağlı
            assert f.validated is False  # erişilebilirlik aday — kesin-doğrulanmış değil


async def test_rpc_probe_findings_skips_hosts_without_rpc_ports(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: object,
) -> None:
    """SMB/RPC portu (445/139/135) yoksa audit_rpc HİÇ çağrılmaz (gereksiz probe yok)."""
    from cybersectool.core.models import ScanType
    from cybersectool.core.scans import create_scan
    from cybersectool.tasks import network_scan

    called: list[str] = []

    async def spy_audit_rpc(host: str, **kw: object) -> object:
        called.append(host)
        from cybersectool.scanners.rpc_probe import RpcInfo

        return RpcInfo(), []

    monkeypatch.setattr(network_scan, "audit_rpc", spy_audit_rpc)  # type: ignore[attr-defined]
    results = [
        HostResult(ip="10.0.0.9", services=[ServiceResult(port=80, protocol="tcp", name="http")])
    ]
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.9")
        cve_ids = await network_scan._rpc_probe_findings(session, scan.id, results)
        assert cve_ids == []
        assert called == []  # 445/139/135 yok → probe tetiklenmedi


# --- Birleşik Tarama Dispatcher'ı (#173): Faz 1 keşif → Faz 2 host-queue/port-queue yönlendirme ---


async def test_unified_dispatcher_phase2_routing(monkeypatch: object) -> None:
    """Birleşik Dispatcher Faz 2: keşif sonrası canlı host'lar host-queue/port-queue/boş yönlenir.

    Karar moddan değil **hedef şekli + port sayısından** türer: (a) host ≥ worker → HOST-QUEUE;
    (b) az host + çok port → PORT-QUEUE; (c) az host + az port → HOST-QUEUE (tiny); canlı host yok
    → boş sonuç işlenir (chord yok). _discover_hosts_chunked + iki dağıtıcı + _process_results
    sahtelenir → hangi dalın seçildiği yakalanır (gerçek nmap/Celery/DB gerekmez).
    """
    from cybersectool.core.models import ScanMode
    from cybersectool.tasks import network_scan

    calls: dict[str, object] = {}

    async def noop(*a: object, **k: object) -> None:
        return None

    async def fake_get_scan(session: object, scan_id: int) -> None:
        return None  # is_vuln=False; boş-dal None'a tolere

    async def fake_process(
        session: object, scan_id: int, target: str, mode: object, results: list, **k: object
    ) -> str:
        calls["branch"] = "empty"
        calls["results"] = results
        return "empty_processed"

    async def fake_host_queue(
        session: object,
        scan_id: int,
        target: str,
        mode: object,
        hosts: list,
        port_options: str,
        workers: int,
    ) -> str:
        calls["branch"] = "host_queue"
        calls["hosts"] = list(hosts)
        return "host_queue"

    async def fake_port_fanout(
        session: object, scan_id: int, target: str, scan_target: str, *a: object
    ) -> str:
        calls["branch"] = "port_queue"
        calls["scan_target"] = scan_target
        return "port_queue"

    monkeypatch.setattr(network_scan, "set_scan_progress", noop)  # type: ignore[attr-defined]
    monkeypatch.setattr(network_scan, "log_action", noop)  # type: ignore[attr-defined]
    monkeypatch.setattr(network_scan, "get_scan", fake_get_scan)  # type: ignore[attr-defined]
    monkeypatch.setattr(network_scan, "_process_results", fake_process)  # type: ignore[attr-defined]
    monkeypatch.setattr(network_scan, "_dispatch_host_queue", fake_host_queue)  # type: ignore[attr-defined]
    monkeypatch.setattr(network_scan, "_dispatch_port_fanout", fake_port_fanout)  # type: ignore[attr-defined]

    async def run(live: list[str], explicit: list[str], ports: str | None, workers: int) -> str:
        calls.clear()

        async def fake_discover(
            session: object, scan_id: int, blocks: list, disc: str, **kw: object
        ) -> list[str]:
            return list(live)

        monkeypatch.setattr(network_scan, "_discover_hosts_chunked", fake_discover)  # type: ignore[attr-defined]
        await network_scan._dispatch_fanout(
            object(),
            1,
            "10.0.0.0/24",
            ScanMode.safe,
            ["10.0.0.0/27"],
            explicit,
            "-sV -Pn",
            "-sn",
            ports=ports,
            want_udp=False,
            dns_opts="",
            exclude_opt="",
            speed_opts="",
            workers=workers,
        )
        return str(calls["branch"])

    # Canlı host yok + explicit yok → boş sonuç işlenir (tarama tamamlanır, chord kurulmaz).
    assert await run([], [], None, 16) == "empty"
    assert calls["results"] == []
    # Bol canlı host (20 ≥ worker=4) → HOST-QUEUE (host boyutu havuzu doldurur).
    assert await run([f"10.0.0.{i}" for i in range(1, 21)], [], None, 4) == "host_queue"
    assert len(calls["hosts"]) == 20  # type: ignore[arg-type]
    # Az host (2 < worker=16) ama çok port (varsayılan top-1000) → PORT-QUEUE.
    assert await run(["10.0.0.5", "10.0.0.6"], [], None, 16) == "port_queue"
    assert calls["scan_target"] == "10.0.0.5 10.0.0.6"  # canlı host'lar port-fanout hedefi
    # Az host + az port (-p 80,443 < worker) → HOST-QUEUE (host başına tiny child, port bölme yok).
    assert await run(["10.0.0.5"], [], "80,443", 16) == "host_queue"
    # Explicit hedef keşif boş olsa da deep_targets'a girer → derin taranır (kaçırılmaz).
    assert await run([], ["192.168.1.1"], "80,443", 16) == "host_queue"
    assert calls["hosts"] == ["192.168.1.1"]


async def test_dispatch_host_queue_builds_children(monkeypatch: object) -> None:
    """HOST-QUEUE: canlı host'lar discover=False child'lara round-robin bölünür (keşif bitti)."""
    from cybersectool.core.models import ScanMode
    from cybersectool.tasks import network_scan

    captured: dict[str, object] = {}

    def fake_chord(children: object) -> object:
        captured["children"] = list(children)  # type: ignore[arg-type]

        def _apply(callback: object) -> None:
            captured["callback"] = callback

        return _apply

    async def noop(*a: object, **k: object) -> None:
        return None

    monkeypatch.setattr(network_scan, "chord", fake_chord)  # type: ignore[attr-defined]
    monkeypatch.setattr(network_scan, "set_scan_progress", noop)  # type: ignore[attr-defined]
    monkeypatch.setattr(network_scan, "log_action", noop)  # type: ignore[attr-defined]
    monkeypatch.setattr(network_scan, "_reset_blocks_done", noop)  # type: ignore[attr-defined]

    hosts = [f"10.0.0.{i}" for i in range(1, 13)]  # 12 host
    result = await network_scan._dispatch_host_queue(
        object(), 1, "10.0.0.0/24", ScanMode.safe, hosts, "-sV -Pn", 4
    )
    # 4 worker × hafif(3) = 12 ama host=12 → 12 parti (her host bir child).
    children = captured["children"]
    assert isinstance(children, list)
    assert len(children) == 12
    assert result == "host_queue:12"
    # Her child keşifsiz (discover=False, args[4]) + port_options -Pn içerir (args[2]).
    first = children[0]
    assert first.args[4] is False  # discover bayrağı kapalı (keşif Faz 1'de bitti)
    assert "-Pn" in first.args[2]  # derin tarama -Pn ile (canlı host kesin)
    assert first.args[3] == ""  # discovery_options boş (keşif yapılmaz)
    # Tüm host'lar child'lara dağıldı (kayıp yok).
    spread = sorted(h for c in children for h in str(c.args[1]).split())
    assert spread == sorted(hosts)
