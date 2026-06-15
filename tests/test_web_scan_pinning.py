"""Web tarama scope IP-pinning testleri (bug #12 — TOCTOU/DNS-rebinding)."""

from __future__ import annotations

from cybersectool.tasks.web_scan import pinned_url


def test_pinned_url_uses_validated_ip() -> None:
    """Hostname hedefi doğrulanan ip'ye sabitlenir; şema/port/path/query korunur."""
    assert pinned_url("http://example.com/admin", "10.0.0.5") == "http://10.0.0.5:80/admin"
    assert pinned_url("https://h:8443/x?y=1", "1.2.3.4") == "https://1.2.3.4:8443/x?y=1"
    # şemasız host → http varsayılan + 80
    assert pinned_url("example.com", "10.0.0.7") == "http://10.0.0.7:80"
    # https şemasında varsayılan port 443
    assert pinned_url("https://svc.local", "10.0.0.9") == "https://10.0.0.9:443"


def test_pinned_url_noop_when_target_is_ip() -> None:
    """Hedef zaten IP ise (host==ip) bağlanılan adres değişmez (no-op)."""
    assert pinned_url("http://10.0.0.5:8080/p", "10.0.0.5") == "http://10.0.0.5:8080/p"
