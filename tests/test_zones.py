"""Zone (tarama bölgesi) servis + dağıtım testleri."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool import dispatch
from cybersectool.core.models import ScanMode, ScopePolicy
from cybersectool.core.zones import (
    create_zone,
    get_zone,
    is_url_entry,
    list_zones,
    parse_cidr_input,
    update_zone,
    validate_cidrs,
)


def test_parse_cidr_input() -> None:
    assert parse_cidr_input("10.0.0.0/24\n192.168.1.1") == ["10.0.0.0/24", "192.168.1.1"]
    # Virgül de ayraç; baştaki/sondaki boşluklar ve boş satırlar atılır.
    assert parse_cidr_input("10.0.0.0/24, 192.168.1.1 , ") == ["10.0.0.0/24", "192.168.1.1"]
    assert parse_cidr_input("  \n  ") == []


def test_validate_cidrs() -> None:
    assert validate_cidrs(["10.0.0.0/24", "192.168.1.5"]) == ["10.0.0.0/24", "192.168.1.5"]
    with pytest.raises(ValueError):
        validate_cidrs([])
    with pytest.raises(ValueError):
        validate_cidrs(["10.0.0.0/24", "notanip"])


def test_is_url_entry() -> None:
    assert is_url_entry("http://192.168.1.50:8080") is True
    assert is_url_entry("https://web.kangalis.local/app") is True
    assert is_url_entry("10.0.0.0/24") is False
    assert is_url_entry("192.168.1.5") is False
    assert is_url_entry("ftp://x") is False  # yalnız http(s)
    assert is_url_entry("notaurl") is False


def test_validate_cidrs_accepts_urls() -> None:
    # Zone artık IP/CIDR + http(s) URL karışık tutabilir (URL-zone).
    entries = ["10.0.0.0/24", "http://192.168.1.50:8080", "https://web.local"]
    assert validate_cidrs(entries) == entries
    # Geçersiz URL/IP yine reddedilir.
    with pytest.raises(ValueError):
        validate_cidrs(["http://192.168.1.50", "ftp://nope", "garbage"])


async def test_create_and_list_zone(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        zone = await create_zone(session, "DMZ", ["10.0.0.0/24"], "test bölgesi")
        assert zone.id is not None
        zones = await list_zones(session)
        assert len(zones) == 1
        assert zones[0].name == "DMZ"
        fetched = await get_zone(session, zone.id)
        assert fetched is not None
        assert fetched.cidrs == ["10.0.0.0/24"]


async def test_update_zone(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        zone = await create_zone(session, "DMZ", ["10.0.0.0/24"], "ilk")
        updated = await update_zone(session, zone.id, "DMZ-2", ["10.0.0.0/25", "10.0.1.5"], "yeni")
        assert updated is not None
        assert updated.name == "DMZ-2"
        assert updated.cidrs == ["10.0.0.0/25", "10.0.1.5"]
        assert updated.description == "yeni"
        # Geçersiz CIDR → ValueError
        with pytest.raises(ValueError):
            await update_zone(session, zone.id, "DMZ-2", ["notanip"])
        # Olmayan zone → None
        assert await update_zone(session, 9999, "x", ["10.0.0.0/24"]) is None


async def test_dispatch_zone_scan_filters_out_of_scope(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    enqueued: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        dispatch.network_scan_task, "delay", lambda *args, **kwargs: enqueued.append(args)
    )
    async with session_factory() as session:
        session.add(
            ScopePolicy(
                name="scope", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True
            )
        )
        await session.commit()
        zone = await create_zone(session, "karisik", ["10.0.0.0/24", "192.168.99.0/24"])

        result = await dispatch.dispatch_zone_scan(session, zone, ScanMode.safe, user_id=1)

        # Yalnızca kapsam içindeki blok taranır; diğeri atlanır.
        assert result.scanned == ["10.0.0.0/24"]
        assert result.skipped == ["192.168.99.0/24"]
        assert len(result.scans) == 1
        assert len(enqueued) == 1


async def test_dispatch_zone_credentialed(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    from cybersectool.scanners.credentialed import HostFacts

    async def fake_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
        return port == 22  # her host'ta yalnızca SSH portu açık (Linux)

    async def fake_scan(
        host: str, port: int, username: str, password: str, *, attempt_privesc: bool = False
    ) -> tuple[HostFacts, list[object]]:
        if host == "10.0.0.5":
            return HostFacts(os="Ubuntu", kernel="6.0", package_count=10), []
        raise OSError("connection refused")  # 10.0.0.6 → SSH hatası

    monkeypatch.setattr(dispatch, "_port_open", fake_port_open)
    monkeypatch.setattr(dispatch, "run_credentialed_scan", fake_scan)
    async with session_factory() as session:
        session.add(
            ScopePolicy(
                name="scope", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True
            )
        )
        await session.commit()
        zone = await create_zone(session, "hostlar", ["10.0.0.5", "10.0.0.6", "192.168.1.1"])

        result = await dispatch.dispatch_zone_credentialed(session, zone, 22, "u", "p", user_id=1)

        assert result.scanned == ["10.0.0.5"]  # SSH başarılı
        assert result.methods == {"10.0.0.5": "SSH"}
        assert result.failed == ["10.0.0.6"]  # SSH hatası, Windows portu yok
        assert result.skipped == ["192.168.1.1"]  # kapsam dışı


async def test_dispatch_inline_credentialed_winrm_fallback(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """SSH portu kapalı + Windows portu açık host → WinRM (NTLM) ile denetlenir."""
    from cybersectool.scanners.winrm import WindowsFacts

    async def fake_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
        return port in (3389, 5985)  # yalnızca Windows portları açık (SSH yok)

    async def fake_winrm(
        host: str, port: int, username: str, password: str
    ) -> tuple[WindowsFacts, list[object]]:
        return WindowsFacts(os="Windows Server 2022", version="10.0", hotfix_count=5), []

    monkeypatch.setattr(dispatch, "_port_open", fake_port_open)
    monkeypatch.setattr(dispatch, "run_winrm_scan", fake_winrm)
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        result = await dispatch.dispatch_inline_credentialed(
            session, ["10.0.0.9"], 22, "Administrator", "pw", user_id=1
        )
        assert result.scanned == ["10.0.0.9"]
        assert result.methods == {"10.0.0.9": "WinRM"}
        assert result.failed == []


async def test_dispatch_target_list_scan(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    enqueued: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        dispatch.network_scan_task, "delay", lambda *args, **kwargs: enqueued.append(args)
    )
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        result = await dispatch.dispatch_target_list_scan(
            session, ["10.0.0.5", "192.168.99.1"], ScanMode.safe, user_id=1
        )
        # Yalnızca kapsam içindeki hedef taranır; diğeri atlanır (zone'suz hızlı tarama).
        assert result.scanned == ["10.0.0.5"]
        assert result.skipped == ["192.168.99.1"]
        assert len(enqueued) == 1


async def test_dispatch_zones_scan_aggregates(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Birden çok IP zone tek seferde taranır; scanned/skipped birleşir."""
    enqueued: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        dispatch.network_scan_task, "delay", lambda *args, **kwargs: enqueued.append(args)
    )
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        z1 = await create_zone(session, "Z1", ["10.0.0.0/24"])
        z2 = await create_zone(session, "Z2", ["10.0.0.0/25", "192.168.5.0/24"])

        result = await dispatch.dispatch_zones_scan(session, [z1, z2], ScanMode.safe, user_id=1)

        assert result.scanned == ["10.0.0.0/24", "10.0.0.0/25"]  # iki zone'dan kapsam içi
        assert result.skipped == ["192.168.5.0/24"]  # kapsam dışı
        assert len(enqueued) == 2


async def test_dispatch_credential_zones_scan_aggregates(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Birden çok IP zone aynı kimlik kümesiyle taranır; sonuçlar birleşir."""
    from cybersectool.core.credentials import create_credential
    from cybersectool.core.models import CredentialType
    from cybersectool.scanners.credentialed import HostFacts

    async def fake_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
        return port == 22

    async def fake_scan(
        host: str, port: int, username: str, password: str, *, attempt_privesc: bool = False
    ) -> tuple[HostFacts, list[object]]:
        return HostFacts(os="Ubuntu", kernel="6.0", package_count=5), []

    monkeypatch.setattr(dispatch, "_port_open", fake_port_open)
    monkeypatch.setattr(dispatch, "run_credentialed_scan", fake_scan)
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        cred = await create_credential(session, "linux", CredentialType.ssh, "root", "pw")
        z1 = await create_zone(session, "h1", ["10.0.0.5"])
        z2 = await create_zone(session, "h2", ["10.0.0.6", "192.168.1.1"])

        result = await dispatch.dispatch_credential_zones_scan(session, [z1, z2], [cred], user_id=1)

        assert result.matched.get("10.0.0.5") == "linux"
        assert result.matched.get("10.0.0.6") == "linux"
        assert result.skipped == ["192.168.1.1"]  # kapsam dışı


async def test_dispatch_credential_zone_scan(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    from cybersectool.core.credentials import create_credential
    from cybersectool.core.models import CredentialType
    from cybersectool.scanners.credentialed import HostFacts

    async def fake_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
        return port == 22  # yalnızca SSH portu açık (Linux)

    async def fake_scan(
        host: str, port: int, username: str, password: str, *, attempt_privesc: bool = False
    ) -> tuple[HostFacts, list[object]]:
        return HostFacts(os="Ubuntu", kernel="6.0", package_count=5), []

    monkeypatch.setattr(dispatch, "_port_open", fake_port_open)
    monkeypatch.setattr(dispatch, "run_credentialed_scan", fake_scan)
    async with session_factory() as session:
        session.add(
            ScopePolicy(
                name="scope", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True
            )
        )
        await session.commit()
        cred = await create_credential(session, "linux", CredentialType.ssh, "root", "pw")
        ipzone = await create_zone(session, "hosts", ["10.0.0.5", "192.168.1.1"])  # 2. kapsam dışı

        result = await dispatch.dispatch_credential_zone_scan(session, ipzone, [cred], user_id=1)

        assert result.matched.get("10.0.0.5") == "linux"  # SSH kimliği tuttu
        assert result.skipped == ["192.168.1.1"]  # kapsam dışı
