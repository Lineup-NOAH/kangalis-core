"""/health ucunun calistigini dogrular (veritabani gerektirmez)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from cybersectool.api.app import app

client = TestClient(app)


def test_health_ok() -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body
