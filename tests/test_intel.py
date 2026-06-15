"""CISA KEV + EPSS ayrıştırma ve zenginleştirme testleri."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core import vuln
from cybersectool.core.models import CVE
from cybersectool.intel import epss as epss_mod
from cybersectool.intel.epss import parse_epss
from cybersectool.intel.kev import parse_kev


def test_parse_kev() -> None:
    data = {"vulnerabilities": [{"cveID": "CVE-2021-1"}, {"cveID": "CVE-2021-2"}, {"x": "y"}]}
    assert parse_kev(data) == {"CVE-2021-1", "CVE-2021-2"}


async def test_fetch_epss_batches_over_100(monkeypatch: pytest.MonkeyPatch) -> None:
    """#144: 100'den fazla CVE → tüm liste 100'lük partilerde çekilir (sessiz kırpma yok)."""
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        cves = request.url.params.get("cve", "").split(",")
        calls.append(len(cves))
        return httpx.Response(200, json={"data": [{"cve": c, "epss": "0.5"} for c in cves]})

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs.pop("transport", None)
        return real_client(*args, transport=transport, **kwargs)

    monkeypatch.setattr(epss_mod.httpx, "AsyncClient", factory)
    ids = [f"CVE-2024-{i}" for i in range(250)]
    out = await epss_mod.fetch_epss(ids)
    assert calls == [100, 100, 50]  # 250 CVE → 3 parti
    assert len(out) == 250  # hepsi döndü (eskiden 100'de kırpılırdı)


def test_parse_epss() -> None:
    data = {"data": [{"cve": "CVE-2021-1", "epss": "0.97"}, {"cve": "CVE-2021-2", "epss": "0.01"}]}
    result = parse_epss(data)
    assert result["CVE-2021-1"] == 0.97
    assert result["CVE-2021-2"] == 0.01


async def test_enrich_cves(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_kev() -> set[str]:
        return {"CVE-2021-1"}

    async def fake_epss(cve_ids: list[str]) -> dict[str, float]:
        return {"CVE-2021-1": 0.9, "CVE-2021-2": 0.1}

    monkeypatch.setattr(vuln, "fetch_kev_set", fake_kev)
    monkeypatch.setattr(vuln, "fetch_epss", fake_epss)

    async with session_factory() as session:
        session.add(CVE(cve_id="CVE-2021-1"))
        session.add(CVE(cve_id="CVE-2021-2"))
        await session.commit()

        await vuln.enrich_cves(session, ["CVE-2021-1", "CVE-2021-2"])

        c1 = await session.get(CVE, "CVE-2021-1")
        c2 = await session.get(CVE, "CVE-2021-2")
        assert c1 is not None and c2 is not None
        assert c1.kev_flag is True
        assert c1.epss_score == 0.9
        assert c2.kev_flag is False
        assert c2.epss_score == 0.1
