"""SNMP salt-okunur envanter + varsayılan-topluluk denetimi testleri (VII-2b)."""

from __future__ import annotations

from collections.abc import Sequence

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.findings import count_by_severity
from cybersectool.core.models import Role, ScanType, Severity
from cybersectool.core.scans import create_scan
from cybersectool.core.snmp_audit import (
    OID_SYS_DESCR,
    OID_SYS_NAME,
    SnmpFinding,
    SnmpInfo,
    eval_snmp_version,
    eval_weak_community,
    evaluate_snmp,
    info_from_oids,
)
from cybersectool.core.snmp_wordlist import SNMP_COMMUNITY_WORDLIST
from cybersectool.core.users import create_user
from cybersectool.scanners.snmp import access_summary, audit_snmp, store_snmp_audit


def test_eval_weak_community() -> None:
    """private=yüksek, public=orta, diğer wordlist topluluğu=orta (hepsi bulgu üretir)."""
    pub = eval_weak_community("public")
    assert pub.severity == Severity.medium
    priv = eval_weak_community("PRIVATE")
    assert priv.severity == Severity.high
    other = eval_weak_community("cisco")  # bilinen zayıf topluluk → orta
    assert other.severity == Severity.medium and "cisco" in other.title


def test_wordlist_lowercase_unique_has_defaults() -> None:
    """Wordlist küçük harf + benzersiz, public/private içerir (>=20 giriş)."""
    assert "public" in SNMP_COMMUNITY_WORDLIST and "private" in SNMP_COMMUNITY_WORDLIST
    assert all(c == c.lower() for c in SNMP_COMMUNITY_WORDLIST)
    assert len(SNMP_COMMUNITY_WORDLIST) == len(set(SNMP_COMMUNITY_WORDLIST))
    assert len(SNMP_COMMUNITY_WORDLIST) >= 20


def test_access_summary() -> None:
    """Erişim özeti topluluk başına sürümleri birleştirir (sıralı)."""
    assert access_summary([]) == ""
    assert access_summary([("public", "v2c"), ("public", "v1")]) == "public (v1/v2c)"
    out = access_summary([("public", "v2c"), ("cisco", "v1")])
    assert "public (v2c)" in out and "cisco (v1)" in out


def test_eval_snmp_version() -> None:
    """Erişim varken v1/v2c → düşük bulgu; erişim yoksa veya v3 → bulgu yok."""
    note = eval_snmp_version("v2c", any_accessible=True)
    assert note is not None and note.severity == Severity.low
    assert eval_snmp_version("v2c", any_accessible=False) is None  # yanıt yok → bulgu yok
    assert eval_snmp_version("v3", any_accessible=True) is None  # v3 şifreli → bulgu yok


def test_info_from_oids() -> None:
    info = info_from_oids({OID_SYS_NAME: "sw-core-1", OID_SYS_DESCR: "Cisco IOS 15.2"})
    assert info.sys_name == "sw-core-1"
    assert info.has_data
    assert "sw-core-1" in info.summary()
    assert not SnmpInfo().has_data  # boş envanter veri taşımaz


def test_evaluate_snmp_only_weak_flagged() -> None:
    """Yalnız wordlist toplulukları bulgu üretir; özel topluluk yalnız sürüm notu verir."""
    weak = set(SNMP_COMMUNITY_WORDLIST)
    # Özel (wordlist dışı) topluluk yanıt verdi → yalnız sürüm notu (düşük).
    only_version = evaluate_snmp([("corp-x9", "v2c")], weak)
    assert len(only_version) == 1 and only_version[0].severity == Severity.low
    # public erişilebilir → orta zayıf-topluluk bulgusu + düşük sürüm notu.
    findings = evaluate_snmp([("public", "v2c")], weak)
    severities = {f.severity for f in findings}
    assert Severity.medium in severities and Severity.low in severities
    # Hiç erişim yok → hiç bulgu yok (düşük FP).
    assert evaluate_snmp([], weak) == []
    # Aynı topluluk hem v1 hem v2c → tek topluluk bulgusu + iki sürüm notu (v1, v2c).
    both = evaluate_snmp([("public", "v2c"), ("public", "v1")], weak)
    assert sum(1 for f in both if "public" in f.title) == 1
    assert sum(1 for f in both if f.severity == Severity.low) == 2


async def test_audit_snmp_injected_getter() -> None:
    """audit_snmp sahte okuyucuyla: ilk yanıt veren toplulukla envanter, doğru bulgu."""

    async def fake_getter(
        host: str,
        port: int,
        community: str,
        oids: Sequence[str],
        *,
        version: str,
        timeout: float,
    ) -> dict[str, str]:
        if community == "public":
            return {OID_SYS_DESCR: "Linux test-router", OID_SYS_NAME: "node1"}
        return {}  # private/özel topluluk yanıt vermiyor

    info, accessible, findings = await audit_snmp(
        "10.0.0.5",
        communities=["public", "private"],
        weak_communities=["public", "private"],
        getter=fake_getter,
    )
    assert {c for c, _v in accessible} == {"public"}  # public her iki sürümde de yanıt verdi
    assert info.sys_name == "node1"
    titles = [f.title for f in findings]
    assert any("public" in t for t in titles)
    assert not any("private" in t for t in titles)  # private erişilemedi → bulgu yok


async def test_audit_snmp_custom_community_not_flagged() -> None:
    """Özel (varsayılan olmayan) topluluk erişilebilirse default-bulgu üretilmez."""

    async def fake_getter(
        host: str,
        port: int,
        community: str,
        oids: Sequence[str],
        *,
        version: str,
        timeout: float,
    ) -> dict[str, str]:
        if community == "corp-ro-7x":
            return {OID_SYS_NAME: "fw1"}
        return {}

    info, accessible, findings = await audit_snmp(
        "10.0.0.6",
        communities=["public", "private", "corp-ro-7x"],
        weak_communities=["public", "private"],  # corp-ro-7x zayıf sayılmaz (özel)
        getter=fake_getter,
    )
    assert {c for c, _v in accessible} == {"corp-ro-7x"}
    # Yalnız sürüm notları (düşük); zayıf-topluluk bulgusu yok (özel topluluk işaretlenmez).
    assert findings and all(f.severity == Severity.low for f in findings)


async def test_store_snmp_audit(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """store_snmp_audit envanter (info) + bulguları Finding olarak yazar."""
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.credentialed, "10.0.0.30")
        info = SnmpInfo(sys_name="sw1", sys_descr="Switch X")
        findings = [
            SnmpFinding("SNMP varsayılan 'public' topluluğu erişilebilir", Severity.medium, "x")
        ]
        await store_snmp_audit(session, scan.id, info, [("public", "v2c")], findings)
        counts = await count_by_severity(session, scan_id=scan.id)
        assert counts.get("info", 0) == 1  # envanter
        assert counts.get("medium", 0) == 1  # public bulgusu


async def test_store_snmp_audit_no_response(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Yanıt yoksa tek bir 'SNMP yanıt yok' info bulgusu yazılır."""
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.credentialed, "10.0.0.31")
        await store_snmp_audit(session, scan.id, SnmpInfo(), [], [])
        counts = await count_by_severity(session, scan_id=scan.id)
        assert counts.get("info", 0) == 1


async def _login(
    client: AsyncClient, fac: async_sessionmaker[AsyncSession], username: str, role: Role
) -> None:
    async with fac() as session:
        await create_user(session, username, "pass1234", role=role)
    await client.post(
        "/login", data={"username": username, "password": "pass1234"}, follow_redirects=False
    )


async def test_snmp_route_non_admin_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "an_snmp", Role.analyst)
    resp = await client.post("/scans/snmp", data={"host": "10.0.0.30"}, follow_redirects=False)
    assert resp.status_code == 403


async def test_snmp_route_scope_denied_defaults_only(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Kimliksiz (yalnız varsayılan) + kapsam dışı host → 303 (scope guard içeride durdurur)."""
    async with session_factory() as session:
        await create_user(session, "adm_snmp2", "pass1234", role=Role.admin)
    await client.post(
        "/login", data={"username": "adm_snmp2", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post("/scans/snmp", data={"host": "10.0.0.30"}, follow_redirects=False)
    assert resp.status_code == 303  # kapsam dışı → scan failed kaydı, çökme yok


async def test_snmp_route_ignores_removed_params(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SNMP-NOCRED: kimlik/community paramları kaldırıldı; gönderilse bile yoksayılır.

    Panel sadeleşti (host + IP zone). Eski ``credential_id``/``snmp_wordlist_id`` form
    alanları artık tanınmaz → dispatch'e daima ``credential=None`` + ``extra_communities=None``
    geçilir (gömülü community wordlist'i arka planda yine denenir, davranış korunur).
    """
    from typing import Any

    from cybersectool.web import routes as routes_mod

    captured: dict[str, Any] = {}

    async def fake_dispatch(*args: Any, **kwargs: Any) -> list[Any]:
        captured["credential"] = kwargs.get("credential")
        captured["extra"] = kwargs.get("extra_communities")
        return []

    monkeypatch.setattr(routes_mod, "dispatch_snmp_audit_hosts", fake_dispatch)
    async with session_factory() as session:
        await create_user(session, "adm_snmp_nc", "pass1234", role=Role.admin)
    await client.post(
        "/login", data={"username": "adm_snmp_nc", "password": "pass1234"}, follow_redirects=False
    )
    # Eski alanlar gönderilse bile yoksayılır (FastAPI tanımsız form alanlarını atar).
    resp = await client.post(
        "/scans/snmp",
        data={"host": "10.0.0.30", "credential_id": "5", "snmp_wordlist_id": "9"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert captured["credential"] is None
    assert captured["extra"] is None
