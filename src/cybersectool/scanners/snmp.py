"""SNMP ağ erişimi + denetim depolama (VII-2b) — yalnız GET (salt-okunur).

``snmp_get`` pysnmp ile gerçek bir SNMP agent'ından sistem grubu OID'lerini okur
(ağ hatasında boş sözlük döner — erişilemedi anlamında, düşük FP). ``audit_snmp``
varsayılan toplulukları + isteğe bağlı özel topluluğu sırayla dener, ilk yanıt
verenle envanter çıkarır ve saf ``evaluate_snmp`` ile bulguları üretir. ``getter``
enjekte edilebilir → birim testi ağ gerektirmez. Gerçek net-snmp agent'a karşı
doğrulanmıştır.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable, Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.findings import create_finding
from cybersectool.core.models import Severity
from cybersectool.core.snmp_audit import (
    SYSTEM_OIDS,
    SnmpFinding,
    SnmpInfo,
    evaluate_snmp,
    info_from_oids,
)

# (host, port, community, oids, *, version, timeout) -> {oid: value}
SnmpGetter = Callable[..., Awaitable[dict[str, str]]]

# Tek seferde denenen şifresiz SNMP sürümleri (kullanıcı seçmez — ikisi de denenir).
PROBE_VERSIONS: tuple[str, ...] = ("v2c", "v1")


async def snmp_get(
    host: str,
    port: int,
    community: str,
    oids: Sequence[str],
    *,
    version: str = "v2c",
    timeout: float = 3.0,
    retries: int = 1,
) -> dict[str, str]:
    """Bir SNMP agent'ından verilen OID'leri okur (salt-okunur GET).

    Yanıt yoksa, topluluk tutmazsa ya da ağ hatası olursa boş sözlük döner —
    "erişilemedi" anlamında (asla yanlış pozitif bulgu üretmez).
    """
    from pysnmp.error import PySnmpError
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        get_cmd,
    )
    from pysnmp.proto import rfc1905

    absent = (rfc1905.NoSuchObject, rfc1905.NoSuchInstance, rfc1905.EndOfMibView)
    mp_model = 0 if version.strip().lower() == "v1" else 1  # 0=v1, 1=v2c
    try:
        engine = SnmpEngine()
    except PySnmpError:
        return {}
    # SnmpEngine her GET'te bir UDP transport dispatcher (soket/fd) açar; pysnmp __del__
    # tanımlamadığı için GC otomatik kapatmaz → finally'de KAPAT (yoksa çağrı başına fd sızar).
    try:
        try:
            target = await UdpTransportTarget.create((host, port), timeout=timeout, retries=retries)
            objects = [ObjectType(ObjectIdentity(oid)) for oid in oids]
            error_indication, error_status, _, var_binds = await get_cmd(
                engine,
                CommunityData(community, mpModel=mp_model),
                target,
                ContextData(),
                *objects,
            )
        except (OSError, TimeoutError, PySnmpError):
            return {}
        if error_indication or error_status:
            return {}
        result: dict[str, str] = {}
        for requested, var_bind in zip(oids, var_binds, strict=False):
            value = var_bind[1]
            if isinstance(value, absent):
                continue
            result[requested] = value.prettyPrint()
        return result
    finally:
        with contextlib.suppress(Exception):
            engine.close_dispatcher()


async def audit_snmp(
    host: str,
    port: int = 161,
    *,
    communities: Sequence[str],
    weak_communities: Sequence[str] = (),
    timeout: float = 3.0,
    getter: SnmpGetter = snmp_get,
) -> tuple[SnmpInfo, list[tuple[str, str]], list[SnmpFinding]]:
    """Her topluluğu v1 VE v2c ile (eşzamanlı) dener; yanıt verenlerle envanter çıkarır.

    ``(envanter, erişilebilen (topluluk, sürüm) çiftleri, bulgular)`` döner. Versiyon
    KULLANICI tarafından SEÇİLMEZ — ikisi de denenir, hangisinin tuttuğu raporlanır.
    ``weak_communities`` zayıf sayılan (wordlist) topluluklardır; özel topluluk bulgu
    üretmez. ``getter`` enjekte edilebilir → birim testi ağ gerektirmez.
    """
    oids = list(SYSTEM_OIDS)
    weak = {c.strip().lower() for c in weak_communities}

    async def _probe(community: str, version: str) -> tuple[str, str, dict[str, str]]:
        values = await getter(host, port, community, oids, version=version, timeout=timeout)
        return community, version, values

    tasks = [_probe(c, v) for c in communities for v in PROBE_VERSIONS]
    results = await asyncio.gather(*tasks)
    accessible: list[tuple[str, str]] = []
    info = SnmpInfo()
    for community, version, values in results:
        if not values:
            continue
        accessible.append((community, version))
        if not info.has_data:
            info = info_from_oids(values)
    findings = evaluate_snmp(accessible, weak)
    return info, accessible, findings


def access_summary(accessible: list[tuple[str, str]]) -> str:
    """Erişilen (topluluk, sürüm) çiftlerini 'public (v1/v2c), cisco (v2c)' gibi özetler."""
    by_comm: dict[str, list[str]] = {}
    for community, version in accessible:
        by_comm.setdefault(community, [])
        if version not in by_comm[community]:
            by_comm[community].append(version)
    return ", ".join(f"{c} ({'/'.join(sorted(vs))})" for c, vs in by_comm.items())


async def store_snmp_audit(
    session: AsyncSession,
    scan_id: int,
    info: SnmpInfo,
    accessible: list[tuple[str, str]],
    findings: list[SnmpFinding],
) -> None:
    """SNMP envanteri (info) + erişim (sürüm/topluluk) + güvenlik bulgularını kaydeder."""
    access = access_summary(accessible)
    if info.has_data:
        await create_finding(
            session,
            scan_id,
            f"SNMP envanteri: {info.summary()[:160]}",
            severity=Severity.info,
            description=(
                f"sysName={info.sys_name or '—'} · sysDescr={info.sys_descr or '—'} · "
                f"konum={info.sys_location or '—'} · ilgili kişi={info.sys_contact or '—'} · "
                f"erişim={access or '—'}"
            ),
        )
    elif accessible:
        await create_finding(
            session,
            scan_id,
            "SNMP erişildi (sistem envanteri okunamadı)",
            severity=Severity.info,
            description=f"Yanıt veren topluluk/sürüm: {access}",
        )
    for finding in findings:
        await create_finding(
            session,
            scan_id,
            finding.title,
            severity=finding.severity,
            description=finding.detail,
        )
    if not accessible:
        await create_finding(
            session,
            scan_id,
            "SNMP yanıt yok",
            severity=Severity.info,
            description=(
                "Hedef denenen topluluk wordlist'i (v1+v2c) ile SNMP yanıtı vermedi "
                "(SNMP kapalı olabilir ya da özel bir topluluk dizesi kullanılıyor olabilir)."
            ),
        )
