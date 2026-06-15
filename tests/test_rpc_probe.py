"""RPC probe (#168) saf-mantık testleri — ağ/impacket gerektirmez.

``evaluate_rpc`` + hata sınıflandırma SAFtır; gerçek bind/EPM ağ erişimi gerektirdiğinden
(gerçek bir Windows hedefi) burada test EDİLMEZ — onlar canlı/lab ile doğrulanır.
"""

from __future__ import annotations

from cybersectool.core.models import Severity
from cybersectool.scanners.rpc_probe import (
    PRINTNIGHTMARE_CVES,
    RpcInfo,
    _confirm_label,
    _is_access_denied,
    evaluate_rpc,
)


def test_evaluate_rpc_not_reachable_no_findings() -> None:
    """Spooler erişilemezse bulgu YOK (yanlış-pozitif üretmez)."""
    assert evaluate_rpc(RpcInfo()) == []
    assert evaluate_rpc(RpcInfo(spooler_reachable=False, reached_rpc=True)) == []


def test_evaluate_rpc_reachable_yields_both_printnightmare_cves() -> None:
    """Spooler erişilebilirse PrintNightmare çift-CVE'sinin İKİSİ için de aday bulgu üretilir."""
    findings = evaluate_rpc(RpcInfo(spooler_reachable=True, spooler_confirm="bind"))
    assert len(findings) == 2
    cves = [f.cve_id for f in findings]
    assert cves == list(PRINTNIGHTMARE_CVES)
    assert set(cves) == {"CVE-2021-1675", "CVE-2021-34527"}
    for f in findings:
        assert f.severity == Severity.high  # erişilebilirlik aday → high (kesin-doğrulanmış değil)
        assert f.cve_id is not None and f.cve_id in f.title  # CVE başlıkta görünür
        assert "PrintNightmare" in f.title
        assert "Spooler" in f.detail and "MS-RPRN" in f.detail


def test_evaluate_rpc_confirm_method_in_detail() -> None:
    """Erişilebilirliğin NASIL doğrulandığı (bind/access_denied/epm) bulgu açıklamasına yansır."""
    for confirm, marker in (
        ("bind", "anonim RPC bind"),
        ("access_denied", "yetki gerekti"),
        ("epm", "endpoint mapper"),
    ):
        findings = evaluate_rpc(RpcInfo(spooler_reachable=True, spooler_confirm=confirm))
        assert marker in findings[0].detail


def test_confirm_label_known_and_unknown() -> None:
    """``_confirm_label`` bilinen kodları çevirir; bilinmeyen kod ham/yedek metne düşer."""
    assert "bind" in _confirm_label("bind")
    assert _confirm_label("") == "erişilebilir"
    assert _confirm_label("garip-kod") == "garip-kod"


def test_is_access_denied_distinguishes_present_pipe_from_unreachable() -> None:
    """ACCESS_DENIED = pipe var (aday); bağlantı reddi/timeout = erişilemez (aday DEĞİL)."""
    assert _is_access_denied(Exception("SMB SessionError: STATUS_ACCESS_DENIED(...)")) is True
    assert _is_access_denied(Exception("rpc_s_access_denied")) is True
    assert _is_access_denied(Exception("nca_s_fault 0xC0000022")) is True
    # Bağlantı kurulamadı → erişilemez (Spooler aday sayılmaz).
    assert _is_access_denied(Exception("[Errno 111] Connection refused")) is False
    assert _is_access_denied(TimeoutError("timed out")) is False
