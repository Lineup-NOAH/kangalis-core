"""WinRM Windows credentialed tarama testleri (saf eval + dispatch entegrasyonu)."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool import dispatch
from cybersectool.core.findings import count_open_findings
from cybersectool.core.models import Severity
from cybersectool.scanners import winrm
from cybersectool.scanners.winrm import (
    WindowsFacts,
    WinRMScanError,
    eval_autologon,
    eval_defender_rtp,
    eval_firewall,
    eval_local_admins,
    eval_rdp_nla,
    eval_smb1,
    parse_windows_facts,
    run_winrm_scan,
)

# --- saf ayrıştırma / eval ---


def test_parse_windows_facts() -> None:
    out = "OS=Windows Server 2019\nVERSION=10.0.17763\nHOSTNAME=WIN-DC01\nHOTFIX_COUNT=42"
    facts = parse_windows_facts(out)
    assert facts.os == "Windows Server 2019"
    assert facts.version == "10.0.17763"
    assert facts.hostname == "WIN-DC01"
    assert facts.hotfix_count == 42


def test_eval_smb1() -> None:
    assert eval_smb1("True")[0] == Severity.high  # type: ignore[index]
    assert eval_smb1("False") is None


def test_eval_defender_rtp() -> None:
    assert eval_defender_rtp("False")[0] == Severity.high  # type: ignore[index]
    assert eval_defender_rtp("True") is None


def test_eval_firewall() -> None:
    out = "Domain=True\nPrivate=True\nPublic=False"
    verdict = eval_firewall(out)
    assert verdict is not None and verdict[0] == Severity.high
    assert "Public" in verdict[1]
    assert eval_firewall("Domain=True\nPrivate=True\nPublic=True") is None


def test_eval_rdp_nla() -> None:
    assert eval_rdp_nla("0")[0] == Severity.medium  # type: ignore[index]
    assert eval_rdp_nla("1") is None


def test_eval_autologon() -> None:
    assert eval_autologon("Hunter2")[0] == Severity.high  # type: ignore[index]
    assert eval_autologon("") is None


def test_eval_local_admins() -> None:
    assert eval_local_admins("9")[0] == Severity.medium  # type: ignore[index]
    assert eval_local_admins("3") is None
    assert eval_local_admins("") is None


# --- run_winrm_scan (backend monkeypatch'li) ---


async def test_run_winrm_scan_success(monkeypatch: pytest.MonkeyPatch) -> None:
    facts_out = "OS=Windows 11\nVERSION=10.0.22000\nHOSTNAME=PC1\nHOTFIX_COUNT=10"
    # WIN_CHECKS: SMB1, Defender, Firewall, RDP-NLA, AutoLogon, LocalAdmins
    # + WIN_PRIVESC_CHECKS (VIII-3a): whoami /priv, AlwaysInstallElevated, tırnaksız servis
    outputs = [
        "True",
        "True",
        "Domain=True\nPublic=False",
        "1",
        "",
        "2",  # CIS
        "SeChangeNotifyPrivilege Enabled",
        "HKLM=\nHKCU=",
        "",  # priv-esc (zararsız)
    ]

    def fake_collect(host: str, port: int, user: str, pw: str, transport: str) -> object:
        return facts_out, outputs

    monkeypatch.setattr(winrm, "_winrm_collect", fake_collect)
    facts, findings = await run_winrm_scan("10.0.0.9", 5985, "administrator", "pw")
    assert facts.os == "Windows 11"
    # SMB1 (True) ve Firewall (Public=False) bulgu üretir; priv-esc çıktıları zararsız.
    titles = {f.title for f in findings}
    assert "SMBv1 protokolü" in titles
    assert "Güvenlik duvarı profilleri" in titles
    assert len(findings) == 2


async def test_run_winrm_scan_surfaces_privesc(monkeypatch: pytest.MonkeyPatch) -> None:
    """VIII-3a: tehlikeli token ayrıcalığı + AlwaysInstallElevated priv-esc bulgusu üretir."""
    facts_out = "OS=Windows Server 2019\nVERSION=10.0.17763\nHOSTNAME=SRV\nHOTFIX_COUNT=5"
    outputs = [
        "False",
        "True",
        "Domain=True",
        "1",
        "",
        "1",  # CIS (bulgu yok)
        "SeImpersonatePrivilege Enabled",
        "HKLM=1\nHKCU=1",
        "Svc|C:\\Program Files\\a b\\x.exe",
    ]

    def fake_collect(host: str, port: int, user: str, pw: str, transport: str) -> object:
        return facts_out, outputs

    monkeypatch.setattr(winrm, "_winrm_collect", fake_collect)
    _, findings = await run_winrm_scan("10.0.0.9", 5985, "administrator", "pw")
    titles = {f.title for f in findings}
    assert "Yetki yükseltme: tehlikeli ayrıcalıklar" in titles
    assert "Yetki yükseltme: AlwaysInstallElevated" in titles
    assert "Yetki yükseltme: tırnaksız servis yolları" in titles


async def test_run_winrm_scan_wraps_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(host: str, port: int, user: str, pw: str, transport: str) -> object:
        raise ConnectionError("unreachable")

    monkeypatch.setattr(winrm, "_winrm_collect", boom)
    with pytest.raises(WinRMScanError):
        await run_winrm_scan("10.0.0.9", 5985, "u", "p")


# --- dispatch: OS önceliği ile Windows host'ta WinRM ---


async def test_dispatch_winrm_windows_host(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    from cybersectool.core.credentials import create_credential
    from cybersectool.core.models import CredentialType, ScopePolicy
    from cybersectool.core.zones import create_zone
    from cybersectool.scanners.hardening import HardeningFinding

    async def fake_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
        return port == 5985  # yalnızca WinRM portu açık (Windows)

    async def fake_winrm(
        host: str, port: int, username: str, password: str, *, transport: str = "ntlm"
    ) -> tuple[WindowsFacts, list[HardeningFinding]]:
        return (
            WindowsFacts(os="Windows Server 2022", version="10.0", hotfix_count=5),
            [HardeningFinding("SMBv1 protokolü", Severity.high, "etkin")],
        )

    monkeypatch.setattr(dispatch, "_port_open", fake_port_open)
    monkeypatch.setattr(dispatch, "run_winrm_scan", fake_winrm)
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        cred = await create_credential(
            session, "win-adm", CredentialType.winrm, "administrator", "pw", domain="CORP"
        )
        ipzone = await create_zone(session, "wins", ["10.0.0.9"])

        result = await dispatch.dispatch_credential_zone_scan(session, ipzone, [cred], user_id=1)

        assert result.matched.get("10.0.0.9") == "win-adm"  # WinRM kimliği tuttu
        assert result.windows_reachable == []
        # envanter + 1 bulgu kaydedildi
        assert await count_open_findings(session) >= 2


async def test_dispatch_winrm_reachable_but_auth_fails(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    from cybersectool.core.credentials import create_credential
    from cybersectool.core.models import CredentialType, ScopePolicy
    from cybersectool.core.zones import create_zone

    async def fake_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
        return port == 5985

    async def fail_winrm(*args: object, **kwargs: object) -> object:
        raise WinRMScanError("bad credentials")

    monkeypatch.setattr(dispatch, "_port_open", fake_port_open)
    monkeypatch.setattr(dispatch, "run_winrm_scan", fail_winrm)
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        cred = await create_credential(
            session, "win-adm", CredentialType.winrm, "administrator", "pw"
        )
        ipzone = await create_zone(session, "wins", ["10.0.0.9"])

        result = await dispatch.dispatch_credential_zone_scan(session, ipzone, [cred], user_id=1)

        assert result.matched == {}
        assert result.windows_reachable == ["10.0.0.9"]  # port açık ama auth tutmadı
