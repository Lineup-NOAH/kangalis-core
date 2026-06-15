"""COV-1: Kimliksiz exposed-servis denetimleri (Redis/Elasticsearch) — saf parse + dispatch."""

from __future__ import annotations

import pytest

from cybersectool.core.models import Severity
from cybersectool.scanners.exposed_services import (
    parse_docker_unauth,
    parse_elastic_unauth,
    parse_ftp_anonymous,
    parse_k8s_api_unauth,
    parse_kubelet_unauth,
    parse_redis_unauth,
    scan_exposed_services,
)


def test_parse_redis_unauth() -> None:
    # Kimliksiz: INFO çıktısı geldi.
    assert parse_redis_unauth("# Server\r\nredis_version:7.0.5\r\n") is True
    assert parse_redis_unauth("+PONG\r\n") is True
    # Korumalı: AUTH gerekiyor.
    assert parse_redis_unauth("-NOAUTH Authentication required.\r\n") is False
    assert parse_redis_unauth("-ERR Client sent AUTH, but no password is set") is False
    assert parse_redis_unauth("") is False


def test_parse_elastic_unauth() -> None:
    body = '{"name":"node1","cluster_name":"prod","tagline":"You Know, for Search"}'
    assert parse_elastic_unauth(200, body) is True
    # 401 → kimlik doğrulama açık.
    assert parse_elastic_unauth(401, body) is False
    # 200 ama beklenen alan yok → eşleşme yok.
    assert parse_elastic_unauth(200, "<html>not elastic</html>") is False


def test_parse_docker_unauth() -> None:
    """#148: Docker /version 200 + ApiVersion/GoVersion → kimliksiz açık daemon."""
    body = '{"Version":"24.0.5","ApiVersion":"1.43","GoVersion":"go1.20.6","Os":"linux"}'
    assert parse_docker_unauth(200, body) is True
    assert parse_docker_unauth(401, body) is False  # kimlik gerekiyor
    assert parse_docker_unauth(200, "<html>nginx</html>") is False  # Docker değil


def test_parse_kubelet_unauth() -> None:
    """#148: kubelet /pods 200 + PodList → anonim erişim."""
    body = '{"kind":"PodList","apiVersion":"v1","items":[]}'
    assert parse_kubelet_unauth(200, body) is True
    assert parse_kubelet_unauth(401, body) is False
    assert parse_kubelet_unauth(403, '{"kind":"Status","status":"Failure"}') is False


def test_parse_k8s_api_unauth() -> None:
    """#148: kube-apiserver /version 200 + gitVersion → kimliksiz bilgi sızıntısı."""
    body = '{"major":"1","minor":"28","gitVersion":"v1.28.2","buildDate":"2023-09-13"}'
    assert parse_k8s_api_unauth(200, body) is True
    assert parse_k8s_api_unauth(401, body) is False
    assert parse_k8s_api_unauth(200, '{"paths":["/api"]}') is False  # /version değil


def test_parse_ftp_anonymous() -> None:
    """#148: PASS sonrası 230 = anonim kabul; 530 = reddedildi."""
    assert parse_ftp_anonymous("230 Login successful.\r\n") is True
    assert parse_ftp_anonymous("530 Login incorrect.\r\n") is False
    assert parse_ftp_anonymous("421 Service not available.\r\n") is False
    # Çok-satırlı yanıtta ilk anlamlı koda bakılır.
    assert parse_ftp_anonymous("230-Welcome\r\n230 OK\r\n") is True
    assert parse_ftp_anonymous("") is False


async def test_scan_exposed_services_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Açık porta göre doğru denetim çağrılır; kapalı portta çağrılmaz."""
    from cybersectool.scanners import exposed_services as mod
    from cybersectool.scanners.exposed_services import ExposedFinding

    async def fake_redis(host: str, port: int = 6379, *, timeout: float = 4.0) -> list:
        return [ExposedFinding("redis unauth", Severity.critical)]

    async def fake_elastic(host: str, port: int = 9200, *, timeout: float = 6.0) -> list:
        raise AssertionError("9200 kapalıyken elastic çağrılmamalı")

    async def fake_ftp(host: str, port: int = 21, *, timeout: float = 5.0) -> list:
        return [ExposedFinding("ftp anon", Severity.high)]

    monkeypatch.setattr(mod, "check_redis", fake_redis)
    monkeypatch.setattr(mod, "check_elasticsearch", fake_elastic)
    monkeypatch.setattr(mod, "check_ftp_anonymous", fake_ftp)

    out = await scan_exposed_services("10.0.0.5", {6379, 22})
    assert len(out) == 1
    assert out[0].title == "redis unauth"
    # 21 açık → FTP denetimi çağrılır (yeni servis dispatch'i).
    ftp_out = await scan_exposed_services("10.0.0.5", {21})
    assert [f.title for f in ftp_out] == ["ftp anon"]
    # Hiç ilgili port yok → boş.
    assert await scan_exposed_services("10.0.0.5", {22, 80}) == []
