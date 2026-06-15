"""Cisco IOS SSH güvenlik denetimi testleri (VII-2d)."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.credentials import create_credential
from cybersectool.core.models import CredentialType, Role, Severity
from cybersectool.core.users import create_user
from cybersectool.scanners.cisco_ios_audit import (
    AAA_TITLE,
    CISCO_IOS_CONFIG_TITLES,
    SNMP_COMMUNITY_TITLE,
    SSH_VERSION_TITLE,
    CiscoIosInfo,
    _config_is_complete,
    _first_lines,
    _hostname_from_config,
    _looks_like_config,
    eval_cisco_aaa,
    eval_cisco_snmp_community,
    eval_cisco_ssh_version,
    evaluate_cisco_ios,
    ran_titles_for,
)

# Telnet kapalı ama her config kontrolü KALAN (7 bulgu) bir IOS config'i.
WEAK_CONFIG = """Building configuration...
!
version 15.1
hostname Switch1
!
enable password cisco123
no service password-encryption
!
ip http server
!
snmp-server community public RO
!
line vty 0 4
 transport input telnet
!
end
"""

# Tüm kontrolleri GEÇEN sertleştirilmiş config (0 bulgu).
SECURE_CONFIG = """Building configuration...
!
version 15.1
hostname Switch1
!
aaa new-model
service password-encryption
enable secret 9 $9$abcdef
!
ip ssh version 2
no ip http server
ip http secure-server
!
snmp-server community 7h1sIsR4nd0m RO
!
line vty 0 4
 transport input ssh
!
end
"""


def test_eval_cisco_ssh_version() -> None:
    assert eval_cisco_ssh_version("ip ssh version 2\n") is None
    # Direktif yok → uyarı; modern IOS-XE yanlış-fail gürültüsünü azaltmak için LOW (#276 review).
    verdict = eval_cisco_ssh_version("hostname x\n")
    assert verdict is not None and verdict.severity == Severity.low


def test_eval_cisco_snmp_community() -> None:
    weak = eval_cisco_snmp_community("snmp-server community public RO\n")
    assert weak is not None and weak.severity == Severity.high
    assert eval_cisco_snmp_community("snmp-server community private RW\n") is not None
    # Tip göstergeli düz-metin (0 public) yakalanmalı (#276 review — eskiden kaçıyordu).
    assert eval_cisco_snmp_community("snmp-server community 0 public RO\n") is not None
    # Şifreli (tip 7) community config'ten doğrulanamaz → atla (#276 review).
    assert eval_cisco_snmp_community("snmp-server community 7 13061E010803 RO\n") is None
    # Tahmin-edilemez community → bulgu yok.
    assert eval_cisco_snmp_community("snmp-server community 7h1sIsR4nd0m RO\n") is None
    assert eval_cisco_snmp_community("") is None  # community tanımlı değil → kapsam dışı


def test_config_is_complete_guards_truncation() -> None:
    """Paging/truncate'e karşı: satır-başı 'end' yoksa config EKSİK sayılır (#276 review)."""
    assert _config_is_complete(WEAK_CONFIG) is True  # 'end' ile biter
    assert _config_is_complete(SECURE_CONFIG) is True
    # Sayfa sınırında kesilmiş config (snmp/transport satırlarına ulaşılmadan) → eksik.
    truncated = "Building configuration...\n!\nhostname Switch1\n!\nenable password x\n --More--"
    assert _config_is_complete(truncated) is False


def test_eval_cisco_aaa() -> None:
    assert eval_cisco_aaa("aaa new-model\n") is None
    verdict = eval_cisco_aaa("hostname x\n")
    assert verdict is not None and verdict.severity == Severity.medium


def test_evaluate_cisco_ios_weak_vs_secure() -> None:
    """Zayıf config → 7 bulgu (4 ortak + SSHv2 + SNMP + AAA); güvenli config → 0; config yok → 0."""
    weak = evaluate_cisco_ios(CiscoIosInfo(running_config=WEAK_CONFIG))
    titles = {f.title for f in weak}
    assert SSH_VERSION_TITLE in titles
    assert SNMP_COMMUNITY_TITLE in titles
    assert AAA_TITLE in titles
    assert len(weak) == len(CISCO_IOS_CONFIG_TITLES) == 7
    # Güvenli config → tamamen temiz.
    assert evaluate_cisco_ios(CiscoIosInfo(running_config=SECURE_CONFIG)) == []
    # Config okunamadı (yetki yetmedi) → değerlendirme yok (yanlış "eksik direktif" üretme).
    assert evaluate_cisco_ios(CiscoIosInfo(running_config="")) == []


def test_ran_titles_dynamic() -> None:
    assert ran_titles_for(CiscoIosInfo(running_config="")) == []
    assert ran_titles_for(CiscoIosInfo(running_config=WEAK_CONFIG)) == list(CISCO_IOS_CONFIG_TITLES)


def test_looks_like_config_rejects_error_output() -> None:
    """Yetki yetmeyince gelen hata/banner config sanılmamalı (sahte değerlendirme önlenir)."""
    assert _looks_like_config(WEAK_CONFIG) is True
    assert _looks_like_config("% Invalid input detected at '^' marker.") is False
    assert _looks_like_config("% Authorization failed.") is False


def test_hostname_and_first_lines() -> None:
    assert _hostname_from_config(WEAK_CONFIG) == "Switch1"
    assert _hostname_from_config("interface Gi0/0\n") == ""
    joined = _first_lines("Cisco IOS Software\n\nVersion 15.1\nuptime 3 days\n", count=2)
    assert joined == "Cisco IOS Software | Version 15.1"


def test_cisco_controls_mapped_to_cis() -> None:
    """VII-2d: tüm Cisco IOS başlıkları CIS Cisco kontrolüne + düzenleyiciye eşlenmiş olmalı."""
    from cybersectool.core.compliance import HARDENING_TO_CONTROL, REGULATION_MAP

    for title in CISCO_IOS_CONFIG_TITLES:
        assert title in HARDENING_TO_CONTROL
        control = HARDENING_TO_CONTROL[title]
        assert control.framework == "CIS Cisco"
        assert control.control_id in REGULATION_MAP


async def test_cisco_route_non_admin_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as s:
        await create_user(s, "an_cis", "pass1234", role=Role.analyst)
    await client.post(
        "/login", data={"username": "an_cis", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post("/scans/cisco", data={"host": "10.0.0.61"}, follow_redirects=False)
    assert resp.status_code == 403


async def test_cisco_route_requires_credential(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Cisco IOS SSH denetimi kimliksiz olamaz → 400."""
    async with session_factory() as s:
        await create_user(s, "adm_cis", "pass1234", role=Role.admin)
    await client.post(
        "/login", data={"username": "adm_cis", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post("/scans/cisco", data={"host": "10.0.0.61"}, follow_redirects=False)
    assert resp.status_code == 400


async def test_cisco_route_wrong_cred_type(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Telnet tipi kimlikle Cisco IOS SSH denetimi → 400 (ssh bekleniyor)."""
    async with session_factory() as s:
        await create_user(s, "adm_cis2", "pass1234", role=Role.admin)
        cred = await create_credential(s, "tel-for-cis", CredentialType.telnet, "cisco", "x")
        cred_id = cred.id
    await client.post(
        "/login", data={"username": "adm_cis2", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post(
        "/scans/cisco",
        data={"host": "10.0.0.61", "credential_id": str(cred_id)},
        follow_redirects=False,
    )
    assert resp.status_code == 400


async def test_cisco_route_ssh_cred_scope_denied(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """SSH kimliği + kapsam dışı host → 303 (scope guard içeride durdurur, ağa çıkmaz)."""
    async with session_factory() as s:
        await create_user(s, "adm_cis3", "pass1234", role=Role.admin)
        cred = await create_credential(s, "ssh-for-cis", CredentialType.ssh, "admin", "admin")
        cred_id = cred.id
    await client.post(
        "/login", data={"username": "adm_cis3", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post(
        "/scans/cisco",
        data={"host": "10.0.0.61", "credential_id": str(cred_id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303
