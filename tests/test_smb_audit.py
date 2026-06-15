"""SMB paylaşım/güvenlik denetimi testleri (IX-7a)."""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.credentials import create_credential
from cybersectool.core.models import CredentialType, Role, Severity
from cybersectool.core.users import create_user
from cybersectool.scanners.smb_audit import (
    SMB_CHECK_TITLES,
    SMB_PROBED_SHARES_TITLE,
    SmbInfo,
    eval_smb_anon_shares,
    eval_smb_guest,
    eval_smb_null_session,
    eval_smb_probed_shares,
    eval_smb_signing,
    eval_smb_v1,
    evaluate_smb,
)


def test_eval_smb_signing() -> None:
    assert eval_smb_signing(True) is None  # imzalama zorunlu → iyi
    verdict = eval_smb_signing(False)
    assert verdict is not None and verdict.severity == Severity.medium


def test_eval_smb_v1() -> None:
    assert eval_smb_v1(False) is None
    verdict = eval_smb_v1(True)
    assert verdict is not None and verdict.severity == Severity.high


def test_probe_smb_guest_suppressed_when_null_open(monkeypatch: pytest.MonkeyPatch) -> None:
    """ORTA fix: null oturum AÇIKKEN guest erişimi ayrı (MEDIUM) bulgu olarak işaretlenmez —
    null'a izin veren sunucuda 'guest'/boş-parola da null oturuma maplenir (yanıltıcı çift bulgu).
    """
    from cybersectool.scanners import smb_audit as sa

    monkeypatch.setattr(sa, "_negotiate", lambda *a: ("SMB 3.1.1", True))
    monkeypatch.setattr(sa, "_smb_v1_supported", lambda *a: False)

    # null + guest İKİSİ de başarılı (null-permissive sunucu) → guest bastırılmalı.
    monkeypatch.setattr(
        sa, "_login_and_inspect", lambda host, port, user, pw, dom, to: (True, [], {})
    )
    info = sa._probe_smb("10.0.0.1", 445, "", "", "", 1.0, None)
    assert info.null_session is True
    assert info.guest_access is False  # null açık → guest bastırıldı (çift bulgu önlendi)

    # null KAPALI ama guest açık → genuine guest bulgusu KALIR.
    monkeypatch.setattr(
        sa, "_login_and_inspect", lambda host, port, user, pw, dom, to: (user == "guest", [], {})
    )
    info2 = sa._probe_smb("10.0.0.1", 445, "", "", "", 1.0, None)
    assert info2.null_session is False
    assert info2.guest_access is True


def test_eval_smb_null_session() -> None:
    assert eval_smb_null_session(False) is None
    verdict = eval_smb_null_session(True)
    assert verdict is not None and verdict.severity == Severity.high


def test_eval_smb_guest() -> None:
    assert eval_smb_guest(False) is None
    verdict = eval_smb_guest(True)
    assert verdict is not None and verdict.severity == Severity.medium


def test_eval_smb_anon_shares() -> None:
    assert eval_smb_anon_shares([]) is None
    assert eval_smb_anon_shares(["IPC$"]) is None  # yalnız IPC$ → bulgu sayılmaz
    verdict = eval_smb_anon_shares(["IPC$", "DATA", "backup"])
    assert verdict is not None and verdict.severity == Severity.high
    assert "DATA" in verdict.detail


def test_evaluate_smb_secure_vs_weak() -> None:
    """Güvenli duruş → bulgu yok; zayıf duruş → her kontrol için bulgu."""
    secure = SmbInfo(
        signing_required=True,
        smbv1_supported=False,
        null_session=False,
        guest_access=False,
        anon_shares=[],
    )
    assert evaluate_smb(secure) == []
    weak = SmbInfo(
        signing_required=False,
        smbv1_supported=True,
        null_session=True,
        guest_access=True,
        anon_shares=["DATA"],
    )
    findings = evaluate_smb(weak)
    assert len(findings) == len(SMB_CHECK_TITLES) == 5
    assert {f.title for f in findings} == set(SMB_CHECK_TITLES)


def test_guest_shares_not_flagged_anonymous() -> None:
    """#7: guest hesabıyla listelenen paylaşımlar 'anonim listeleme' (HIGH) sayılmamalı.

    anon_shares yalnız gerçek null oturumdan gelir; guest erişimi ayrı (medium) bulgudur.
    """
    info = SmbInfo(
        signing_required=True,
        smbv1_supported=False,
        null_session=False,
        guest_access=True,
        anon_shares=[],  # null oturum açılmadı → anonim paylaşım yok
        guest_shares=["DATA", "PUBLIC"],
    )
    findings = evaluate_smb(info)
    titles = {f.title for f in findings}
    assert "SMB anonim paylaşım listeleme" not in titles  # guest ≠ anonim, çift sayım yok
    assert "SMB misafir erişimi" in titles  # guest erişimi yine medium bulgu


def test_eval_smb_probed_shares() -> None:
    assert eval_smb_probed_shares([]) is None  # gizli paylaşım yok → bulgu yok
    verdict = eval_smb_probed_shares(["HIDDEN$", "secret"])
    assert verdict is not None
    assert verdict.title == SMB_PROBED_SHARES_TITLE
    assert verdict.severity == Severity.medium
    assert "HIDDEN$" in verdict.detail and "secret" in verdict.detail


def test_evaluate_smb_includes_probed_shares() -> None:
    """probed_shares dolu → evaluate_smb bulgu listesine gizli-paylaşım bulgusunu ekler."""
    info = SmbInfo(signing_required=True, smbv1_supported=False, probed_shares=["HIDDEN$"])
    titles = [f.title for f in evaluate_smb(info)]
    assert SMB_PROBED_SHARES_TITLE in titles
    # Gizli-paylaşım keşfi CIS 'her zaman çalışan' kontrol DEĞİLDİR (uyuma sayılmaz).
    assert SMB_PROBED_SHARES_TITLE not in SMB_CHECK_TITLES


def test_smb_controls_mapped_to_cis() -> None:
    """IX-7a: tüm SMB denetim başlıkları CIS Windows kontrolüne eşlenmiş olmalı."""
    from cybersectool.core.compliance import HARDENING_TO_CONTROL, REGULATION_MAP

    for title in SMB_CHECK_TITLES:
        assert title in HARDENING_TO_CONTROL
        control = HARDENING_TO_CONTROL[title]
        assert control.framework == "CIS Windows"
        # Her SMB kontrolü düzenleyici çerçevelere (KVKK/ISO/PCI) eşlenmiş olmalı.
        assert control.control_id in REGULATION_MAP


async def test_smb_audit_route_non_admin_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as s:
        await create_user(s, "an_smb", "pass1234", role=Role.analyst)
    await client.post(
        "/login", data={"username": "an_smb", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post("/scans/smb", data={"host": "10.0.0.40"}, follow_redirects=False)
    assert resp.status_code == 403


async def test_smb_audit_route_wrong_cred_type(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """SSH tipi kimlikle SMB denetimi → 400 (smb bekleniyor)."""
    async with session_factory() as s:
        await create_user(s, "adm_smb", "pass1234", role=Role.admin)
        cred = await create_credential(s, "ssh-for-smb", CredentialType.ssh, "root", "x")
        cred_id = cred.id
    await client.post(
        "/login", data={"username": "adm_smb", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post(
        "/scans/smb",
        data={"host": "10.0.0.40", "credential_id": str(cred_id)},
        follow_redirects=False,
    )
    assert resp.status_code == 400


async def test_smb_audit_route_anonymous_scope_denied(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Kimliksiz (anonim) SMB denetimi + kapsam dışı host → 303 (scope guard durdurur, çökmez)."""
    async with session_factory() as s:
        await create_user(s, "adm_smb2", "pass1234", role=Role.admin)
    await client.post(
        "/login", data={"username": "adm_smb2", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post("/scans/smb", data={"host": "10.0.0.40"}, follow_redirects=False)
    assert resp.status_code == 303


async def test_smb_audit_route_smb_cred_scope_denied(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """SMB kimliği + kapsam dışı host → 303 (scope guard içeride durdurur, çökmez)."""
    async with session_factory() as s:
        await create_user(s, "adm_smb3", "pass1234", role=Role.admin)
        cred = await create_credential(s, "smb-cred", CredentialType.smb, "auditor", "x")
        cred_id = cred.id
    await client.post(
        "/login", data={"username": "adm_smb3", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post(
        "/scans/smb",
        data={"host": "10.0.0.40", "credential_id": str(cred_id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303


async def test_smb_audit_route_passes_wordlist_as_share_names(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SMB denetiminde paylaşım kelime listesi seçilirse satırları share_names olarak geçer."""
    from cybersectool.core.models import WordlistKind
    from cybersectool.core.wordlists import create_wordlist
    from cybersectool.web import routes as routes_mod

    captured: dict[str, Any] = {}

    async def fake_dispatch(*args: Any, **kwargs: Any) -> list[Any]:
        captured["share_names"] = kwargs.get("share_names")
        return []

    monkeypatch.setattr(routes_mod, "dispatch_smb_audit_hosts", fake_dispatch)
    async with session_factory() as s:
        await create_user(s, "adm_smb_wl", "pass1234", role=Role.admin)
        wl = await create_wordlist(
            s, "smb-paylasimlar", WordlistKind.smb_share, ["ADMIN$", "secret$"]
        )
        wl_id = wl.id
    await client.post(
        "/login", data={"username": "adm_smb_wl", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post(
        "/scans/smb",
        data={"host": "10.0.0.40", "smb_wordlist_id": str(wl_id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert captured["share_names"] == ["ADMIN$", "secret$"]
