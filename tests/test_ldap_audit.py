"""LDAP/AD güvenlik denetimi testleri (IX-7b)."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.credentials import create_credential
from cybersectool.core.models import CredentialType, Role, Severity
from cybersectool.core.users import create_user
from cybersectool.scanners.ldap_audit import (
    LDAP_CORE_TITLES,
    LDAP_POLICY_TITLES,
    LdapInfo,
    eval_ldap_anonymous_bind,
    eval_ldap_anonymous_search,
    eval_ldap_encryption,
    eval_ldap_lockout,
    eval_ldap_min_password_length,
    evaluate_ldap,
    ran_titles_for,
)


def test_eval_ldap_anonymous_bind() -> None:
    assert eval_ldap_anonymous_bind(False) is None
    verdict = eval_ldap_anonymous_bind(True)
    assert verdict is not None and verdict.severity == Severity.high


def test_eval_ldap_anonymous_search() -> None:
    assert eval_ldap_anonymous_search(False) is None
    verdict = eval_ldap_anonymous_search(True)
    assert verdict is not None and verdict.severity == Severity.high


def test_eval_ldap_encryption() -> None:
    # Ne LDAPS ne StartTLS → bulgu; herhangi biri varsa bulgu yok.
    verdict = eval_ldap_encryption(False, False)
    assert verdict is not None and verdict.severity == Severity.medium
    assert eval_ldap_encryption(True, False) is None
    assert eval_ldap_encryption(False, True) is None
    assert eval_ldap_encryption(True, True) is None


def test_eval_ldap_min_password_length() -> None:
    verdict = eval_ldap_min_password_length(4)
    assert verdict is not None and verdict.severity == Severity.medium
    assert eval_ldap_min_password_length(8) is None
    assert eval_ldap_min_password_length(14) is None


def test_eval_ldap_lockout() -> None:
    verdict = eval_ldap_lockout(0)
    assert verdict is not None and verdict.severity == Severity.medium
    assert eval_ldap_lockout(5) is None


def test_evaluate_ldap_secure_vs_weak() -> None:
    """Güvenli duruş → bulgu yok; zayıf duruş → her kontrol için bulgu."""
    secure = LdapInfo(
        rootdse_read=True,
        anonymous_bind=False,
        anonymous_search=False,
        ldaps_available=True,
        starttls_supported=True,
        min_password_length=14,
        lockout_threshold=5,
    )
    assert evaluate_ldap(secure) == []
    weak = LdapInfo(
        rootdse_read=True,
        anonymous_bind=True,
        anonymous_search=True,
        ldaps_available=False,
        starttls_supported=False,
        min_password_length=4,
        lockout_threshold=0,
    )
    findings = evaluate_ldap(weak)
    assert len(findings) == 5
    assert {f.title for f in findings} == set(LDAP_CORE_TITLES) | set(LDAP_POLICY_TITLES)


def test_evaluate_ldap_encryption_skipped_when_rootdse_unread() -> None:
    """#3: rootDSE okunamadıysa şifreleme kararı güvenilmez → bulgu üretilmez."""
    from cybersectool.scanners.ldap_audit import ran_titles_for

    info = LdapInfo(
        rootdse_read=False,
        anonymous_bind=False,
        anonymous_search=False,
        ldaps_available=False,
        starttls_supported=False,
    )
    findings = evaluate_ldap(info)
    titles = {f.title for f in findings}
    assert "LDAP şifreleme" not in titles  # yanlış-pozitif yok
    assert "LDAP şifreleme" not in ran_titles_for(info)  # bulgu↔uyum tutarlı


def test_ran_titles_dynamic() -> None:
    """Şifreleme yalnız rootDSE okunduğunda; parola politikası yalnız öznitelik okunduğunda."""
    # rootDSE okunamadı + politika yok → yalnız anonim bind + anonim okuma (2).
    minimal = LdapInfo(rootdse_read=False)
    assert ran_titles_for(minimal) == ["LDAP anonim bind", "LDAP anonim dizin okuma"]
    # rootDSE okundu, politika yok → 3 çekirdek kontrol.
    core = LdapInfo(rootdse_read=True)
    assert ran_titles_for(core) == list(LDAP_CORE_TITLES)
    # rootDSE + politika okundu → 5 kontrol.
    full = LdapInfo(rootdse_read=True, min_password_length=8, lockout_threshold=3)
    assert set(ran_titles_for(full)) == set(LDAP_CORE_TITLES) | set(LDAP_POLICY_TITLES)


def test_ldap_controls_mapped_to_cis() -> None:
    """IX-7b: tüm LDAP denetim başlıkları CIS LDAP kontrolüne + düzenleyiciye eşlenmiş olmalı."""
    from cybersectool.core.compliance import HARDENING_TO_CONTROL, REGULATION_MAP

    for title in (*LDAP_CORE_TITLES, *LDAP_POLICY_TITLES):
        assert title in HARDENING_TO_CONTROL
        control = HARDENING_TO_CONTROL[title]
        assert control.framework == "CIS LDAP"
        assert control.control_id in REGULATION_MAP


async def test_ldap_audit_route_non_admin_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as s:
        await create_user(s, "an_ldap", "pass1234", role=Role.analyst)
    await client.post(
        "/login", data={"username": "an_ldap", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post("/scans/ldap", data={"host": "10.0.0.50"}, follow_redirects=False)
    assert resp.status_code == 403


async def test_ldap_audit_route_wrong_cred_type(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """SSH tipi kimlikle LDAP denetimi → 400 (ldap bekleniyor)."""
    async with session_factory() as s:
        await create_user(s, "adm_ldap", "pass1234", role=Role.admin)
        cred = await create_credential(s, "ssh-for-ldap", CredentialType.ssh, "root", "x")
        cred_id = cred.id
    await client.post(
        "/login", data={"username": "adm_ldap", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post(
        "/scans/ldap",
        data={"host": "10.0.0.50", "credential_id": str(cred_id)},
        follow_redirects=False,
    )
    assert resp.status_code == 400


async def test_ldap_audit_route_anonymous_scope_denied(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Kimliksiz LDAP denetimi + kapsam dışı host → 303 (scope guard durdurur, çökmez)."""
    async with session_factory() as s:
        await create_user(s, "adm_ldap2", "pass1234", role=Role.admin)
    await client.post(
        "/login", data={"username": "adm_ldap2", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post("/scans/ldap", data={"host": "10.0.0.50"}, follow_redirects=False)
    assert resp.status_code == 303


async def test_ldap_audit_route_ldap_cred_scope_denied(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """LDAP kimliği + kapsam dışı host → 303 (scope guard içeride durdurur, çökmez)."""
    async with session_factory() as s:
        await create_user(s, "adm_ldap3", "pass1234", role=Role.admin)
        cred = await create_credential(s, "ldap-cred", CredentialType.ldap, "cn=admin,dc=x", "x")
        cred_id = cred.id
    await client.post(
        "/login", data={"username": "adm_ldap3", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post(
        "/scans/ldap",
        data={"host": "10.0.0.50", "credential_id": str(cred_id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303
