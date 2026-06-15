"""Telnet/Cisco CLI güvenlik denetimi testleri (IX-7c)."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.credentials import create_credential
from cybersectool.core.models import CredentialType, Role, Severity
from cybersectool.core.users import create_user
from cybersectool.scanners.telnet_audit import (
    CISCO_CONFIG_TITLES,
    TELNET_BANNER_TITLE,
    TELNET_OPEN_TITLE,
    TelnetInfo,
    _clean_text,
    _process_iac,
    _prompt_hostname,
    eval_cisco_enable_secret,
    eval_cisco_http_server,
    eval_cisco_password_encryption,
    eval_cisco_vty_transport,
    eval_telnet_open,
    eval_telnet_warning_banner,
    evaluate_telnet,
    ran_titles_for,
)

WEAK_CONFIG = """Building configuration...
!
version 15.1
hostname Router
!
enable password cisco123
!
no service password-encryption
!
ip http server
!
line vty 0 4
 transport input telnet
!
end
"""

SECURE_CONFIG = """Building configuration...
!
version 15.1
hostname Router
!
enable secret 9 $9$abcdef
service password-encryption
!
no ip http server
ip http secure-server
!
line vty 0 4
 transport input ssh
!
end
"""


def test_eval_telnet_open() -> None:
    assert eval_telnet_open(False) is None
    verdict = eval_telnet_open(True)
    assert verdict is not None and verdict.severity == Severity.high


def test_eval_telnet_warning_banner() -> None:
    verdict = eval_telnet_warning_banner("Router login:")
    assert verdict is not None and verdict.severity == Severity.low
    assert eval_telnet_warning_banner("WARNING: unauthorized access prohibited") is None
    assert eval_telnet_warning_banner("Yetkisiz erişim yasaktır") is None


def test_eval_cisco_password_encryption() -> None:
    assert eval_cisco_password_encryption("service password-encryption\n") is None
    # 'no service password-encryption' kontrolü tetikler (satır başı 'service' eşleşmez).
    assert eval_cisco_password_encryption("no service password-encryption\n") is not None
    assert eval_cisco_password_encryption("") is not None


def test_eval_cisco_enable_secret() -> None:
    weak = "enable password cisco\n"
    verdict = eval_cisco_enable_secret(weak)
    assert verdict is not None and verdict.severity == Severity.high
    assert eval_cisco_enable_secret("enable secret 9 $9$x\n") is None
    # Hem secret hem password varsa → secret mevcut, bulgu yok.
    assert eval_cisco_enable_secret("enable secret 9 $9$x\nenable password y\n") is None


def test_eval_cisco_vty_and_http() -> None:
    assert eval_cisco_vty_transport(" transport input telnet\n") is not None
    assert eval_cisco_vty_transport(" transport input ssh\n") is None
    assert eval_cisco_http_server("ip http server\n") is not None
    assert eval_cisco_http_server("no ip http server\n") is None


def test_evaluate_telnet_weak_vs_secure() -> None:
    """Telnet açık + zayıf config → 6 bulgu; Telnet kapalı → bulgu yok."""
    weak = TelnetInfo(telnet_open=True, banner="Router login:", running_config=WEAK_CONFIG)
    findings = evaluate_telnet(weak)
    titles = {f.title for f in findings}
    assert TELNET_OPEN_TITLE in titles
    assert TELNET_BANNER_TITLE in titles
    assert set(CISCO_CONFIG_TITLES) <= titles
    assert len(findings) == 6
    # Telnet kapalı + config yok → tamamen temiz.
    assert evaluate_telnet(TelnetInfo(telnet_open=False)) == []
    # Telnet açık ama iyi banner + güvenli config → yalnız Telnet açıklığı (1).
    good = TelnetInfo(
        telnet_open=True,
        banner="WARNING unauthorized access prohibited",
        running_config=SECURE_CONFIG,
    )
    good_findings = evaluate_telnet(good)
    assert [f.title for f in good_findings] == [TELNET_OPEN_TITLE]


def test_ran_titles_dynamic() -> None:
    # Telnet kapalı → yalnız açıklık kontrolü.
    assert ran_titles_for(TelnetInfo(telnet_open=False)) == [TELNET_OPEN_TITLE]
    # Telnet açık, config yok → açıklık + banner.
    assert ran_titles_for(TelnetInfo(telnet_open=True)) == [TELNET_OPEN_TITLE, TELNET_BANNER_TITLE]
    # Telnet açık + config okundu → 6 kontrol.
    full = TelnetInfo(telnet_open=True, running_config=WEAK_CONFIG)
    assert len(ran_titles_for(full)) == 2 + len(CISCO_CONFIG_TITLES)


def test_process_iac_strips_options() -> None:
    """IAC DO ECHO + veri + IAC WILL SGA → temiz veri + ret (WONT/DONT) + kalan boş."""
    data = bytes([255, 253, 1]) + b"hello" + bytes([255, 251, 3])
    clean, resp, rem = _process_iac(data)
    assert clean == b"hello"
    # DO ECHO → WONT ECHO (255,252,1); WILL SGA → DONT SGA (255,254,3)
    assert resp == bytes([255, 252, 1, 255, 254, 3])
    assert rem == b""


def test_process_iac_partial_sequence_carried() -> None:
    """Sınırda yarım kalan IAC dizisi atılmaz; 'kalan ham' döner, sonraki chunk'a eklenir."""
    # chunk1 'A' + yarım IAC DO (opsiyon baytı eksik) → kalan = IAC DO
    clean1, resp1, rem1 = _process_iac(bytes([65, 255, 253]))
    assert clean1 == b"A"
    assert resp1 == b""
    assert rem1 == bytes([255, 253])
    # kalan + sonraki chunk birleşince tam dizi işlenir: IAC DO ECHO + 'B'
    clean2, resp2, rem2 = _process_iac(rem1 + bytes([1]) + b"B")
    assert clean2 == b"B"
    assert resp2 == bytes([255, 252, 1])  # WONT ECHO
    assert rem2 == b""


def test_prompt_hostname_rejects_banner() -> None:
    """#4: süslü banner ('####'/'>>>') gerçek CLI prompt'u sayılmamalı (sahte logged_in önlenir)."""
    assert _prompt_hostname("Router#") == "Router"
    assert _prompt_hostname("\r\nsw-core-1>") == "sw-core-1"
    assert _prompt_hostname("########") == ""  # banner → hostname yok
    assert _prompt_hostname(">>> uyari >>>") == ""
    assert _prompt_hostname("Username:") == ""


def test_clean_text_strips_ansi_and_control() -> None:
    """#8: ANSI CSI dizileri + DEL/C1 + lone ESC ayıklanır."""
    assert _clean_text("Router#\x1b[0m x") == "Router# x"
    assert _clean_text("A" + chr(0x7F) + chr(0x9B) + "B") == "AB"
    assert _clean_text("\x1b[2Jclean") == "clean"


def test_telnet_controls_mapped_to_cis() -> None:
    """IX-7c: tüm Telnet/Cisco başlıkları CIS Cisco kontrolüne + düzenleyiciye eşlenmiş olmalı."""
    from cybersectool.core.compliance import HARDENING_TO_CONTROL, REGULATION_MAP

    for title in (TELNET_OPEN_TITLE, TELNET_BANNER_TITLE, *CISCO_CONFIG_TITLES):
        assert title in HARDENING_TO_CONTROL
        control = HARDENING_TO_CONTROL[title]
        assert control.framework == "CIS Cisco"
        assert control.control_id in REGULATION_MAP


async def test_telnet_audit_route_non_admin_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as s:
        await create_user(s, "an_tel", "pass1234", role=Role.analyst)
    await client.post(
        "/login", data={"username": "an_tel", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post("/scans/telnet", data={"host": "10.0.0.60"}, follow_redirects=False)
    assert resp.status_code == 403


async def test_telnet_audit_route_wrong_cred_type(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """SSH tipi kimlikle Telnet denetimi → 400 (telnet bekleniyor)."""
    async with session_factory() as s:
        await create_user(s, "adm_tel", "pass1234", role=Role.admin)
        cred = await create_credential(s, "ssh-for-tel", CredentialType.ssh, "root", "x")
        cred_id = cred.id
    await client.post(
        "/login", data={"username": "adm_tel", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post(
        "/scans/telnet",
        data={"host": "10.0.0.60", "credential_id": str(cred_id)},
        follow_redirects=False,
    )
    assert resp.status_code == 400


async def test_telnet_audit_route_anonymous_scope_denied(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Kimliksiz Telnet denetimi + kapsam dışı host → 303 (scope guard durdurur, çökmez)."""
    async with session_factory() as s:
        await create_user(s, "adm_tel2", "pass1234", role=Role.admin)
    await client.post(
        "/login", data={"username": "adm_tel2", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post("/scans/telnet", data={"host": "10.0.0.60"}, follow_redirects=False)
    assert resp.status_code == 303


async def test_telnet_audit_route_telnet_cred_scope_denied(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Telnet kimliği + kapsam dışı host → 303 (scope guard içeride durdurur, çökmez)."""
    async with session_factory() as s:
        await create_user(s, "adm_tel3", "pass1234", role=Role.admin)
        cred = await create_credential(s, "tel-cred", CredentialType.telnet, "cisco", "cisco")
        cred_id = cred.id
    await client.post(
        "/login", data={"username": "adm_tel3", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post(
        "/scans/telnet",
        data={"host": "10.0.0.60", "credential_id": str(cred_id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303
