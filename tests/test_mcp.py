"""MCP sunucusu payload yardımcıları + araç kaydı testleri."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.assets import upsert_asset, upsert_service
from cybersectool.core.exploits import ExploitRecord, sync_exploits
from cybersectool.core.models import ExploitSource, ScanType
from cybersectool.core.scans import create_scan
from cybersectool.core.zones import create_zone
from cybersectool.mcp import server


async def test_assets_payload(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.5", hostname="h1")
        await upsert_service(session, asset.id, 22, service_name="ssh", version="8.9")
        payload = await server.assets_payload(session)
        assert len(payload) == 1
        assert payload[0]["ip"] == "10.0.0.5"
        assert payload[0]["services"][0]["port"] == 22


async def test_scan_payload(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.0/24")
        payload = await server.scan_payload(session, scan.id)
        assert payload["scan_id"] == scan.id
        assert payload["status"] == "pending"
        # Zenginleştirilmiş alanlar (web UI ile aynı) MCP'de de görünür.
        assert payload["progress"] == 0
        assert "phase" in payload
        assert "error_reason" in payload
        assert "resolved_ip" in payload
        assert "error" in await server.scan_payload(session, 9999)


async def test_start_scan_payload_scope_denied(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        # Scope politikası yok → reddedilmeli (Celery'ye gitmeden)
        result = await server.start_scan_payload(session, "10.0.0.0/24")
        assert "error" in result


async def test_start_scan_payload_rejects_intrusive_mode(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """MCP müdahaleci modları başlatamaz: scope'tan ÖNCE mod reddedilir."""
    async with session_factory() as session:
        for bad in ("aggressive", "web", "brute", "credentialed"):
            result = await server.start_scan_payload(session, "10.0.0.5", bad)
            assert "error" in result
            assert "mod" in result["error"].lower()


async def test_wordlists_payload(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    from cybersectool.core.models import WordlistKind
    from cybersectool.core.wordlists import create_wordlist

    async with session_factory() as session:
        await create_wordlist(session, "wl1", WordlistKind.web_dir, ["admin", "login"])
        payload = await server.wordlists_payload(session)
        assert payload[0]["name"] == "wl1"
        assert payload[0]["kind"] == "web_dir"
        assert payload[0]["entry_count"] == 2


async def test_scans_payload(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        await create_scan(session, ScanType.network, "10.0.0.1")
        await create_scan(session, ScanType.ping, "10.0.0.2")
        payload = await server.scans_payload(session, limit=10)
        assert len(payload) == 2
        # En yeni önce (list_scans id DESC).
        assert payload[0]["target"] == "10.0.0.2"
        assert "progress" in payload[0]


async def test_exploits_payload_and_for_cve(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        await sync_exploits(
            session,
            [
                ExploitRecord(
                    ExploitSource.metasploit,
                    "m/1",
                    "Windows SMB RCE",
                    type="exploit",
                    platform="windows",
                    cve_ids=["CVE-2017-0144"],
                ),
            ],
        )
        rows = await server.exploits_payload(session, "smb", "windows", None, 10)
        assert len(rows) == 1 and rows[0]["id"] == "m/1"
        hit = await server.exploits_for_cve_payload(session, "CVE-2017-0144")
        assert hit["exploit_count"] == 1 and hit["metasploit"] is True


async def test_zones_payload(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        await create_zone(session, "z1", ["10.0.0.0/24"])
        payload = await server.zones_payload(session)
        assert payload[0]["name"] == "z1" and payload[0]["cidrs"] == ["10.0.0.0/24"]


async def test_tools_registered() -> None:
    tools = await server.mcp.list_tools()
    names = {tool.name for tool in tools}
    expected = {
        "list_assets",
        "list_vulnerabilities",
        "lookup_cve",
        "scan_status",
        "start_scan",
        "search_exploits",
        "exploits_for_cve",
        "exploit_db_stats",
        "list_ip_zones",
        "list_wordlists",
        "list_scans",
    }
    assert expected <= names
