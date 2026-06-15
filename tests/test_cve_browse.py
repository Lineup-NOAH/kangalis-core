"""CVE/CPE bilgi bankası gezgini (CVE-BROWSER): filtre/sayfalama + sayfa render."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.cve_browse import (
    count_cves_filtered,
    cpe_counts_for_cves,
    list_cves_page,
)
from cybersectool.core.models import CVE, CpeMatch, Exploit, ExploitSource, Role, Severity
from cybersectool.core.users import create_user


async def _seed(session: AsyncSession) -> None:
    session.add_all(
        [
            CVE(
                cve_id="CVE-2021-44228",
                description="log4j remote code execution",
                severity=Severity.critical,
                cvss_score=10.0,
                kev_flag=True,
                epss_score=0.97,
                category="web",
            ),
            CVE(
                cve_id="CVE-2020-0001",
                description="openssl certificate flaw",
                severity=Severity.medium,
                cvss_score=5.0,
                category="linux",
            ),
            CVE(
                cve_id="CVE-2019-9999",
                description="minor info disclosure",
                severity=Severity.low,
            ),
        ]
    )
    session.add(
        CpeMatch(
            cve_id="CVE-2021-44228",
            vendor="apache",
            product="log4j",
            criteria="cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
        )
    )
    session.add(
        CpeMatch(
            cve_id="CVE-2021-44228",
            vendor="apache",
            product="log4j-core",
            criteria="cpe:2.3:a:apache:log4j-core:*:*:*:*:*:*:*:*",
        )
    )
    await session.commit()


async def test_count_and_filters(session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as session:
        await _seed(session)
        assert await count_cves_filtered(session) == 3
        assert await count_cves_filtered(session, severity=Severity.critical) == 1
        assert await count_cves_filtered(session, q="openssl") == 1  # açıklamada
        assert await count_cves_filtered(session, q="44228") == 1  # CVE id'de
        assert await count_cves_filtered(session, kev_only=True) == 1


async def test_list_order_and_pagination(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        await _seed(session)
        page = await list_cves_page(session, page=1, per=10)
        assert page[0].cve_id == "CVE-2021-44228"  # KEV → en üstte
        # Sayfalama: 2'şerli iki sayfa → 2 + 1
        assert len(await list_cves_page(session, page=1, per=2)) == 2
        assert len(await list_cves_page(session, page=2, per=2)) == 1


async def test_framework_filter(session_factory: async_sessionmaker[AsyncSession]) -> None:
    """Uyum çerçevesi filtresi (exploit DB ile birebir) — alt küme döndürür."""
    async with session_factory() as session:
        await _seed(session)
        total = await count_cves_filtered(session)
        # log4j (critical RCE) + openssl ('certificate' kelimesi) PCI-DSS'e girer;
        # düşük 'minor info' girmez → sonuç toplamdan AZ.
        pci = await count_cves_filtered(session, framework="PCI-DSS")
        assert 1 <= pci < total
        # Geçersiz/bilinmeyen çerçeve filtre uygulanmaz (None) gibi davranır → filtreden geçince
        # sadece geçerli çerçeveler route'ta kabul edilir; burada doğrudan boş sonuç beklenmez.
        page = await list_cves_page(session, framework="PCI-DSS", per=10)
        assert all(c.cve_id != "CVE-2019-9999" for c in page)  # düşük + kelime yok → dışarıda


async def test_category_filter_and_counts(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """CVE-CATEGORY: kategori sayımları (GROUP BY) + filtre (exploit DB paritesi)."""
    from cybersectool.core.cve_browse import category_counts

    async with session_factory() as session:
        await _seed(session)
        counts = await category_counts(session)
        assert counts == {"web": 1, "linux": 1}  # NULL kategori (minor info) sayılmaz
        assert await count_cves_filtered(session, category="web") == 1
        page = await list_cves_page(session, category="web", per=10)
        assert len(page) == 1 and page[0].cve_id == "CVE-2021-44228"


async def test_cpe_counts(session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as session:
        await _seed(session)
        counts = await cpe_counts_for_cves(session, ["CVE-2021-44228", "CVE-2020-0001"])
        assert counts.get("CVE-2021-44228") == 2
        assert "CVE-2020-0001" not in counts  # CPE eşleşmesi yok
        assert await cpe_counts_for_cves(session, []) == {}


async def test_cve_db_page_renders(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        await _seed(session)
        await create_user(session, "viewer1", "pass1234", role=Role.viewer)
    await client.post("/auth/login", json={"username": "viewer1", "password": "pass1234"})
    resp = await client.get("/cve-db")
    assert resp.status_code == 200
    assert "CVE-2021-44228" in resp.text
    # Filtre: yalnız critical → log4j görünür, openssl görünmez
    resp2 = await client.get("/cve-db?severity=critical")
    assert "CVE-2021-44228" in resp2.text
    assert "CVE-2020-0001" not in resp2.text


async def test_cve_db_page_requires_login(client: AsyncClient) -> None:
    resp = await client.get("/cve-db", follow_redirects=False)
    assert resp.status_code in (302, 303)


async def test_cve_db_page_shows_exploit_badge(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """EXPLOIT-MSF-BRIDGE: Metasploit modülü olan CVE 'MSF' rozetiyle gösterilir."""
    async with session_factory() as session:
        await _seed(session)
        session.add(
            Exploit(
                source=ExploitSource.metasploit,
                external_id="exploit/multi/http/log4shell",
                title="Log4Shell RCE",
                cve_ids=["CVE-2021-44228"],
                cve_text="CVE-2021-44228",
            )
        )
        await session.commit()
        await create_user(session, "viewer2", "pass1234", role=Role.viewer)
    await client.post("/auth/login", json={"username": "viewer2", "password": "pass1234"})
    resp = await client.get("/cve-db")
    assert resp.status_code == 200
    assert "MSF" in resp.text  # log4shell MSF modülü → sömürülebilir rozeti


async def test_cve_db_sync_admin_enqueues(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CVE-FRESHNESS: admin Güncelle → cpe_sync arka plan görevi kuyruğa girer."""
    from cybersectool.web import routes

    called = {"n": 0}
    monkeypatch.setattr(routes.cpe_sync_task, "delay", lambda *a, **k: called.__setitem__("n", 1))
    async with session_factory() as session:
        await create_user(session, "admC", "pass1234", role=Role.admin)
    await client.post("/auth/login", json={"username": "admC", "password": "pass1234"})
    resp = await client.post("/cve-db/sync", follow_redirects=False)
    assert resp.status_code == 303
    assert called["n"] == 1


async def test_cve_db_sync_non_admin_forbidden(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Analist CVE senkronu tetikleyemez (görev kuyruğa GİRMEZ)."""
    from cybersectool.web import routes

    called = {"n": 0}
    monkeypatch.setattr(routes.cpe_sync_task, "delay", lambda *a, **k: called.__setitem__("n", 1))
    async with session_factory() as session:
        await create_user(session, "vC", "pass1234", role=Role.viewer)
    await client.post("/auth/login", json={"username": "vC", "password": "pass1234"})
    resp = await client.post("/cve-db/sync", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/cve-db"
    assert called["n"] == 0
