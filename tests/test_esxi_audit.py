"""VMware ESXi / vCenter kimliksiz HTTPS duruş denetimi testleri (VII-2c)."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Role, Severity
from cybersectool.core.users import create_user
from cybersectool.scanners.esxi_audit import (
    ESXI_CONFIG_TITLES,
    ESXI_MOB_TITLE,
    ESXI_TLS_TITLE,
    EsxiInfo,
    _is_weak_tls_finding,
    eval_esxi_mob,
    eval_esxi_tls,
    eval_esxi_version_disclosure,
    evaluate_esxi,
    extract_vim_version,
    identify_vmware,
    ran_titles_for,
)
from cybersectool.scanners.web import WebFinding

SDK_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<namespaces><namespace><name>urn:vim25</name>"
    "<version>6.7</version><version>7.0.3.0</version><version>8.0.1.0</version>"
    "</namespace></namespaces>"
)


def test_identify_vmware() -> None:
    assert identify_vmware("Server: VMware ESXi/7.0 welcome") == (True, "VMware ESXi")
    assert identify_vmware("<title>VMware vCenter</title>") == (True, "VMware vCenter")
    assert identify_vmware("urn:vim25 vSphere") == (True, "VMware vSphere")
    # VMware işareti yok → tanımlanmaz (yanlış etiketleme önlenir).
    assert identify_vmware("Apache httpd / nginx welcome") == (False, "")
    # Tek-başına 'vmware' kelimesi AYIRT ETMEZ → VMware değil (#277 review yanlış-pozitif).
    assert identify_vmware("Welcome — see our VMware migration guide") == (False, "")


def test_extract_vim_version() -> None:
    assert extract_vim_version(SDK_XML) == "8.0.1.0"  # en yüksek sürüm
    assert extract_vim_version("<html>no versions</html>") == ""


def test_eval_esxi_mob() -> None:
    # 401 = MOB endpoint mevcut/etkin (kimlik ister) → bulgu.
    verdict = eval_esxi_mob(EsxiInfo(mob_status=401))
    assert verdict is not None and verdict.severity == Severity.medium
    assert eval_esxi_mob(EsxiInfo(mob_status=200)) is not None
    # 404/503 = devre dışı; 403 = proxy yasakladı; None = denenmedi → hepsi bulgu YOK.
    assert eval_esxi_mob(EsxiInfo(mob_status=404)) is None
    assert eval_esxi_mob(EsxiInfo(mob_status=503)) is None
    assert eval_esxi_mob(EsxiInfo(mob_status=403)) is None  # #277 review: 403 ≠ MOB açık
    assert eval_esxi_mob(EsxiInfo(mob_status=None)) is None


def test_eval_esxi_tls_and_version() -> None:
    assert (
        eval_esxi_tls(EsxiInfo(tls_weaknesses=["Zayıf TLS protokolü ETKİN: TLSv1.0"])) is not None
    )
    assert eval_esxi_tls(EsxiInfo(tls_weaknesses=[])) is None
    assert eval_esxi_version_disclosure(EsxiInfo(version_banner="8.0.1.0")) is not None
    assert eval_esxi_version_disclosure(EsxiInfo(version_banner="")) is None


def test_is_weak_tls_finding_excludes_expected_selfsigned() -> None:
    """ESXi'de beklenen self-signed/expired TLS-zayıflık SAYILMAZ; protokol/şifre sayılır."""
    assert _is_weak_tls_finding(
        WebFinding("Zayıf TLS sürümü (görüşülen): TLSv1.1", Severity.medium)
    )
    assert _is_weak_tls_finding(WebFinding("Zayıf TLS protokolü ETKİN: TLSv1.0", Severity.high))
    assert not _is_weak_tls_finding(WebFinding("Kendinden imzalı sertifika", Severity.low))


def test_evaluate_esxi_vmware_vs_not() -> None:
    """VMware + zayıf duruş → 3 bulgu (sürüm + MOB + TLS); VMware değil → 0."""
    weak = EsxiInfo(
        is_vmware=True,
        product="VMware ESXi",
        version_banner="8.0.1.0",
        mob_status=401,
        tls_weaknesses=["Zayıf TLS protokolü ETKİN: TLSv1.0"],
    )
    titles = {f.title for f in evaluate_esxi(weak)}
    assert ESXI_MOB_TITLE in titles
    assert ESXI_TLS_TITLE in titles
    assert len(titles) == 3
    # 443 açık ama VMware değil → ESXi'ye özgü bulgu/uyum üretilmez.
    assert evaluate_esxi(EsxiInfo(is_vmware=False, mob_status=401)) == []


def test_ran_titles_dynamic() -> None:
    """#277 review: yalnız tamamlanan problar uyuma girer (başarısız prob → 'pass' değil)."""
    assert ran_titles_for(EsxiInfo(is_vmware=False)) == []
    # VMware ama hiçbir prob tamamlanmadı (mob None, tls_checked False) → hiçbir kontrol yok.
    assert ran_titles_for(EsxiInfo(is_vmware=True)) == []
    # Her iki prob tamamlandı → MOB + TLS.
    full = EsxiInfo(is_vmware=True, mob_status=401, tls_checked=True)
    assert ran_titles_for(full) == list(ESXI_CONFIG_TITLES)
    # MOB probu durum aldı (404 = devre dışı, yine 'çalıştı') ama TLS probu düştü → yalnız MOB.
    assert ran_titles_for(EsxiInfo(is_vmware=True, mob_status=404)) == [ESXI_MOB_TITLE]


def test_esxi_controls_mapped_to_cis() -> None:
    """VII-2c: ESXi uyum başlıkları CIS VMware kontrolüne + düzenleyiciye eşlenmiş olmalı."""
    from cybersectool.core.compliance import HARDENING_TO_CONTROL, REGULATION_MAP

    for title in ESXI_CONFIG_TITLES:
        assert title in HARDENING_TO_CONTROL
        control = HARDENING_TO_CONTROL[title]
        assert control.framework == "CIS VMware"
        assert control.control_id in REGULATION_MAP


async def test_esxi_route_non_admin_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as s:
        await create_user(s, "an_esxi", "pass1234", role=Role.analyst)
    await client.post(
        "/login", data={"username": "an_esxi", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post("/scans/esxi", data={"host": "10.0.0.100"}, follow_redirects=False)
    assert resp.status_code == 403


async def test_esxi_route_requires_target(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as s:
        await create_user(s, "adm_esxi", "pass1234", role=Role.admin)
    await client.post(
        "/login", data={"username": "adm_esxi", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post("/scans/esxi", data={"host": ""}, follow_redirects=False)
    assert resp.status_code == 400


async def test_esxi_route_scope_denied(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Kapsam dışı host → 303 (scope guard içeride durdurur, ağa çıkmaz)."""
    async with session_factory() as s:
        await create_user(s, "adm_esxi2", "pass1234", role=Role.admin)
    await client.post(
        "/login", data={"username": "adm_esxi2", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post("/scans/esxi", data={"host": "10.0.0.100"}, follow_redirects=False)
    assert resp.status_code == 303
