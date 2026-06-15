"""FastAPI uygulaması: sağlık uçları, oturum yönetimi ve auth router'ı."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

import asyncssh
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import text
from starlette.middleware.sessions import SessionMiddleware

from cybersectool.api.auth import router as auth_router
from cybersectool.api.deps import CurrentUser, SessionDep, require_role
from cybersectool.api.tokens import router as tokens_router
from cybersectool.config import APP_NAME, VERSION, settings
from cybersectool.core.app_settings import get_settings
from cybersectool.core.audit import log_action
from cybersectool.core.credentials import (
    create_credential,
    create_credential_zone,
    delete_credential,
    delete_credential_zone,
    effective_port,
    list_credential_zones,
    list_credentials,
)
from cybersectool.core.db import SessionLocal, engine
from cybersectool.core.exploit_classify import CATEGORIES
from cybersectool.core.exploits import facet_counts, list_exploits
from cybersectool.core.findings import create_finding
from cybersectool.core.models import (
    CredentialType,
    ExploitSource,
    Role,
    ScanMode,
    ScanStatus,
    ScanType,
    Severity,
)
from cybersectool.core.notify import notify_if_critical
from cybersectool.core.scan_policy import (
    AggressiveScanNotAllowed,
    ensure_mode_allowed,
    is_aggressive,
)
from cybersectool.core.scans import create_scan, set_scan_status
from cybersectool.core.schedules import create_schedule, list_schedules
from cybersectool.core.scope import ScopeError, validate_target
from cybersectool.core.wordlists import seed_builtin_wordlists
from cybersectool.core.zones import create_zone, delete_zone, get_zone, list_zones
from cybersectool.dispatch import dispatch_zone_scan
from cybersectool.scanners.credentialed import run_credentialed_scan, store_credentialed
from cybersectool.scanners.hardening import run_hardening
from cybersectool.tasks.example import demo_task
from cybersectool.tasks.exploit_sync import sync_exploits_task
from cybersectool.tasks.network_scan import network_scan_task
from cybersectool.tasks.sca_scan import sca_scan_task
from cybersectool.tasks.web_scan import web_scan_task
from cybersectool.web.routes import router as web_router

_IS_PROD = settings.app_env.strip().lower() == "production"


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Açılışta: saat dilimi cache + yerleşik kelime listeleri seed (best-effort)."""
    with contextlib.suppress(Exception):
        async with SessionLocal() as session:
            await get_settings(session)
            await seed_builtin_wordlists(session)
    yield


app = FastAPI(title=APP_NAME, version=VERSION, lifespan=_lifespan)
# Oturum çerezi: HTTP-only (Starlette varsayılanı) + lax samesite (CSRF azaltma) +
# üretimde yalnızca HTTPS (https_only) — düz HTTP üzerinden sızmayı önler.
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    same_site="lax",
    https_only=_IS_PROD,
)


@app.middleware("http")
async def _security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Tıklama-hırsızlığı (clickjacking) + MIME-sniffing + referrer sızıntısı korumaları."""
    response = await call_next(request)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if _IS_PROD:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


app.mount(
    "/static",
    StaticFiles(directory=str(Path(__file__).parent.parent / "web" / "static")),
    name="static",
)
app.include_router(auth_router)
app.include_router(tokens_router)
app.include_router(web_router)


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness: uygulama ayakta mı? (veritabanına bağlı değil)."""
    return {"status": "ok", "version": VERSION}


@app.get("/ready")
async def ready() -> dict[str, str]:
    """Readiness: veritabanına bağlanılabiliyor mu?."""
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    return {"status": "ready"}


@app.get("/admin/ping", dependencies=[Depends(require_role(Role.admin))])
async def admin_ping() -> dict[str, str]:
    """Yalnızca admin: RBAC örneği."""
    return {"status": "admin-ok"}


@app.post("/admin/demo-scan", dependencies=[Depends(require_role(Role.admin))])
async def demo_scan(session: SessionDep) -> dict[str, str | int]:
    """Örnek: bir scan oluşturup Celery'ye gönderir (arka plan akışı testi)."""
    scan = await create_scan(session, ScanType.network, "demo-target")
    result = demo_task.delay(scan.id)
    return {"scan_id": scan.id, "task_id": result.id}


@app.get("/admin/scope/check", dependencies=[Depends(require_role(Role.admin))])
async def scope_check(target: str, session: SessionDep) -> dict[str, object]:
    """Bir hedefin yetkili kapsamda olup olmadığını döndürür."""
    try:
        await validate_target(session, target)
    except ScopeError as exc:
        return {"target": target, "allowed": False, "reason": str(exc)}
    return {"target": target, "allowed": True}


class ScanIn(BaseModel):
    target: str
    scan_type: ScanType = ScanType.network
    mode: ScanMode = ScanMode.safe


@app.post("/scans", dependencies=[Depends(require_role(Role.admin, Role.analyst))])
async def start_scan(data: ScanIn, user: CurrentUser, session: SessionDep) -> dict[str, object]:
    """Yeni tarama başlatır: scope kontrolünden geçer ve Celery'ye gönderilir."""
    if data.scan_type == ScanType.network:
        # Agresif (müdahaleci) tarama çift kilit: yalnızca admin + global ayar açık.
        if is_aggressive(data.mode):
            if user.role != Role.admin:
                raise HTTPException(
                    403, "Agresif (müdahaleci) tarama yalnızca admin rolü ile başlatılabilir."
                )
            try:
                ensure_mode_allowed(data.mode, allow_aggressive=settings.allow_aggressive_scans)
            except AggressiveScanNotAllowed as exc:
                raise HTTPException(403, str(exc)) from exc
        try:
            await validate_target(session, data.target)
        except ScopeError as exc:
            raise HTTPException(403, str(exc)) from exc
        scan = await create_scan(
            session, data.scan_type, data.target, created_by=user.id, mode=data.mode
        )
        action = "aggressive_scan_start" if is_aggressive(data.mode) else "scan_start"
        await log_action(session, action, user_id=user.id, target=f"{data.target} [{data.mode}]")
        network_scan_task.delay(scan.id, data.target, str(data.mode))
    elif data.scan_type == ScanType.web:
        scan = await create_scan(session, data.scan_type, data.target, created_by=user.id)
        await log_action(session, "scan_start", user_id=user.id, target=data.target)
        web_scan_task.delay(scan.id, data.target)
    else:
        raise HTTPException(400, "Desteklenmeyen tarama türü")
    return {"scan_id": scan.id, "status": scan.status, "target": data.target}


class ScaIn(BaseModel):
    ecosystem: str = "PyPI"
    content: str


@app.post("/sca", dependencies=[Depends(require_role(Role.admin, Role.analyst))])
async def start_sca(data: ScaIn, user: CurrentUser, session: SessionDep) -> dict[str, object]:
    """Bağımlılık manifesti (requirements.txt / package.json) zafiyet taraması başlatır."""
    scan = await create_scan(
        session, ScanType.sca, f"{data.ecosystem} manifest", created_by=user.id
    )
    await log_action(session, "sca_start", user_id=user.id, target=data.ecosystem)
    sca_scan_task.delay(scan.id, data.ecosystem, data.content)
    return {"scan_id": scan.id, "status": scan.status}


class HardeningIn(BaseModel):
    host: str
    port: int = 22
    username: str
    password: str


@app.post("/hardening", dependencies=[Depends(require_role(Role.admin))])
async def start_hardening(
    data: HardeningIn, user: CurrentUser, session: SessionDep
) -> dict[str, object]:
    """SSH ile host sıkılaştırma denetimi (kimlik bilgileri saklanmaz, anlık kullanılır)."""
    # Kapsam koruması: yetkili kapsam dışı host'a (admin dahi) bağlanılamaz.
    try:
        await validate_target(session, data.host)
    except ScopeError as exc:
        raise HTTPException(403, str(exc)) from exc
    scan = await create_scan(session, ScanType.hardening, data.host, created_by=user.id)
    await log_action(session, "hardening_start", user_id=user.id, target=data.host)
    await set_scan_status(session, scan.id, ScanStatus.running)
    try:
        findings = await run_hardening(data.host, data.port, data.username, data.password)
    except (OSError, asyncssh.Error) as exc:
        await set_scan_status(session, scan.id, ScanStatus.failed)
        raise HTTPException(502, f"SSH bağlantı hatası: {exc}") from exc
    for finding in findings:
        await create_finding(
            session, scan.id, finding.title, severity=finding.severity, description=finding.detail
        )
    await notify_if_critical(session, scan.id, data.host)
    await set_scan_status(session, scan.id, ScanStatus.completed)
    return {"scan_id": scan.id, "status": "completed", "bulgu": len(findings)}


class CredentialedIn(BaseModel):
    host: str
    port: int = 22
    username: str
    password: str


@app.post("/scans/credentialed", dependencies=[Depends(require_role(Role.admin))])
async def start_credentialed(
    data: CredentialedIn, user: CurrentUser, session: SessionDep
) -> dict[str, object]:
    """SSH ile kimlikli (authenticated) host taraması: içeriden envanter + denetim.

    Kimlik bilgileri yalnızca anlık kullanılır, saklanmaz; tarama inline çalışır.
    """
    # Kapsam koruması: yetkili kapsam dışı host'a (admin dahi) bağlanılamaz.
    try:
        await validate_target(session, data.host)
    except ScopeError as exc:
        raise HTTPException(403, str(exc)) from exc
    scan = await create_scan(session, ScanType.credentialed, data.host, created_by=user.id)
    await log_action(session, "credentialed_scan_start", user_id=user.id, target=data.host)
    await set_scan_status(session, scan.id, ScanStatus.running)
    try:
        facts, findings = await run_credentialed_scan(
            data.host, data.port, data.username, data.password
        )
    except (OSError, asyncssh.Error) as exc:
        await set_scan_status(session, scan.id, ScanStatus.failed)
        raise HTTPException(502, f"SSH bağlantı hatası: {exc}") from exc
    await store_credentialed(session, scan.id, facts, findings)
    await notify_if_critical(session, scan.id, data.host)
    await set_scan_status(session, scan.id, ScanStatus.completed)
    return {
        "scan_id": scan.id,
        "status": "completed",
        "os": facts.os,
        "kernel": facts.kernel,
        "package_count": facts.package_count,
        "bulgu": len(findings),
    }


class ZoneIn(BaseModel):
    name: str
    cidrs: list[str]
    description: str | None = None


class ZoneScanIn(BaseModel):
    mode: ScanMode = ScanMode.safe


@app.post("/api/zones", dependencies=[Depends(require_role(Role.admin))])
async def create_zone_ep(data: ZoneIn, user: CurrentUser, session: SessionDep) -> dict[str, object]:
    """Yeni tarama bölgesi (zone) oluşturur: isimli IP/CIDR blok grubu."""
    try:
        zone = await create_zone(session, data.name, data.cidrs, data.description)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    await log_action(session, "zone_create", user_id=user.id, target=data.name)
    return {"id": zone.id, "name": zone.name, "cidrs": zone.cidrs}


@app.get("/api/zones", dependencies=[Depends(require_role(Role.admin, Role.analyst))])
async def list_zones_ep(session: SessionDep) -> list[dict[str, object]]:
    return [
        {"id": z.id, "name": z.name, "description": z.description, "cidrs": z.cidrs}
        for z in await list_zones(session)
    ]


@app.post(
    "/api/zones/{zone_id}/scan", dependencies=[Depends(require_role(Role.admin, Role.analyst))]
)
async def scan_zone_ep(
    zone_id: int, data: ZoneScanIn, user: CurrentUser, session: SessionDep
) -> dict[str, object]:
    """Bir zone'daki tüm izinli blokları tarar (kapsam dışı bloklar atlanır)."""
    zone = await get_zone(session, zone_id)
    if zone is None:
        raise HTTPException(404, "Zone bulunamadı")
    # Agresif mod çift kilit (tekil taramadaki ile aynı): admin + global ayar.
    if is_aggressive(data.mode):
        if user.role != Role.admin:
            raise HTTPException(
                403, "Agresif (müdahaleci) tarama yalnızca admin rolü ile başlatılabilir."
            )
        try:
            ensure_mode_allowed(data.mode, allow_aggressive=settings.allow_aggressive_scans)
        except AggressiveScanNotAllowed as exc:
            raise HTTPException(403, str(exc)) from exc
    result = await dispatch_zone_scan(session, zone, data.mode, user.id)
    return {
        "zone": zone.name,
        "mode": str(data.mode),
        "scanned": result.scanned,
        "skipped": result.skipped,
        "scan_ids": [s.id for s in result.scans],
    }


@app.delete("/api/zones/{zone_id}", dependencies=[Depends(require_role(Role.admin))])
async def delete_zone_ep(zone_id: int, user: CurrentUser, session: SessionDep) -> dict[str, object]:
    if not await delete_zone(session, zone_id):
        raise HTTPException(404, "Zone bulunamadı")
    await log_action(session, "zone_delete", user_id=user.id, target=str(zone_id))
    return {"deleted": zone_id}


class CredentialIn(BaseModel):
    name: str
    cred_type: CredentialType
    username: str
    secret: str
    domain: str | None = None
    port: int | None = None
    description: str | None = None


@app.post("/api/credentials", dependencies=[Depends(require_role(Role.admin))])
async def create_credential_ep(
    data: CredentialIn, user: CurrentUser, session: SessionDep
) -> dict[str, object]:
    """Kimlik kasasına yeni bir giriş bilgisi ekler (parola şifreli saklanır)."""
    try:
        cred = await create_credential(
            session,
            data.name,
            data.cred_type,
            data.username,
            data.secret,
            domain=data.domain,
            port=data.port,
            description=data.description,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    await log_action(session, "credential_create", user_id=user.id, target=data.name)
    # Parola ASLA döndürülmez.
    return {
        "id": cred.id,
        "name": cred.name,
        "type": str(cred.cred_type),
        "username": cred.username,
        "port": effective_port(cred),
    }


@app.get("/api/credentials", dependencies=[Depends(require_role(Role.admin))])
async def list_credentials_ep(session: SessionDep) -> list[dict[str, object]]:
    """Kimlikleri listeler — parola ALANI hiçbir zaman dönmez."""
    return [
        {
            "id": c.id,
            "name": c.name,
            "type": str(c.cred_type),
            "username": c.username,
            "domain": c.domain,
            "port": effective_port(c),
        }
        for c in await list_credentials(session)
    ]


@app.delete("/api/credentials/{credential_id}", dependencies=[Depends(require_role(Role.admin))])
async def delete_credential_ep(
    credential_id: int, user: CurrentUser, session: SessionDep
) -> dict[str, object]:
    if not await delete_credential(session, credential_id):
        raise HTTPException(404, "Kimlik bulunamadı")
    await log_action(session, "credential_delete", user_id=user.id, target=str(credential_id))
    return {"deleted": credential_id}


class CredentialZoneIn(BaseModel):
    name: str
    credential_ids: list[int]
    description: str | None = None


@app.post("/api/credential-zones", dependencies=[Depends(require_role(Role.admin))])
async def create_credential_zone_ep(
    data: CredentialZoneIn, user: CurrentUser, session: SessionDep
) -> dict[str, object]:
    """Kimlik bölgesi (bir kimlik grubu) oluşturur."""
    try:
        zone = await create_credential_zone(
            session, data.name, data.credential_ids, data.description
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    await log_action(session, "credential_zone_create", user_id=user.id, target=data.name)
    return {"id": zone.id, "name": zone.name, "credential_ids": zone.credential_ids}


@app.get("/api/credential-zones", dependencies=[Depends(require_role(Role.admin))])
async def list_credential_zones_ep(session: SessionDep) -> list[dict[str, object]]:
    return [
        {
            "id": z.id,
            "name": z.name,
            "description": z.description,
            "credential_ids": z.credential_ids,
        }
        for z in await list_credential_zones(session)
    ]


@app.delete("/api/credential-zones/{zone_id}", dependencies=[Depends(require_role(Role.admin))])
async def delete_credential_zone_ep(
    zone_id: int, user: CurrentUser, session: SessionDep
) -> dict[str, object]:
    if not await delete_credential_zone(session, zone_id):
        raise HTTPException(404, "Kimlik bölgesi bulunamadı")
    await log_action(session, "credential_zone_delete", user_id=user.id, target=str(zone_id))
    return {"deleted": zone_id}


@app.get("/api/exploits", dependencies=[Depends(require_role(Role.admin, Role.analyst))])
async def list_exploits_ep(
    session: SessionDep,
    q: str | None = None,
    source: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    limit: int = 50,
) -> dict[str, object]:
    """Yerel zafiyet/exploit veritabanında arama (başlık/CVE/ID + kaynak/kategori/kritiklik)."""
    try:
        src = ExploitSource(source) if source else None
    except ValueError:
        src = None
    try:
        sev = Severity(severity) if severity else None
    except ValueError:
        sev = None
    cat = category if category in CATEGORIES else None
    rows = await list_exploits(
        session, query=q, source=src, category=cat, severity=sev, limit=min(limit, 200)
    )
    facets = await facet_counts(session, query=q, source=src, category=cat, severity=sev)
    return {
        "total": facets["total"],
        "by_source": facets["by_source"],
        "by_severity": facets["by_severity"],
        "by_category": facets["by_category"],
        "results": [
            {
                "source": str(e.source),
                "external_id": e.external_id,
                "title": e.title,
                "type": e.type,
                "platform": e.platform,
                "severity": (str(e.severity) if e.severity else None),
                "categories": e.categories,
                "date": e.date,
                "cve_ids": e.cve_ids,
                "url": e.url,
            }
            for e in rows
        ],
    }


@app.post("/api/exploits/sync", dependencies=[Depends(require_role(Role.admin))])
async def sync_exploits_ep(user: CurrentUser, session: SessionDep) -> dict[str, object]:
    """Exploit veritabanını Exploit-DB + Metasploit'ten güncellemeyi kuyruğa alır (arka plan)."""
    result = sync_exploits_task.delay()
    await log_action(session, "exploit_sync_start", user_id=user.id, target="exploitdb+metasploit")
    return {"status": "queued", "task_id": result.id}


class ScheduleIn(BaseModel):
    target: str
    scan_type: ScanType = ScanType.network
    # period: daily | weekly | monthly | once | interval (varsayılan interval — geriye uyum)
    period: str = "interval"
    interval_minutes: int = 1440
    start_at: datetime | None = None


@app.post("/schedules", dependencies=[Depends(require_role(Role.admin))])
async def create_schedule_ep(
    data: ScheduleIn, user: CurrentUser, session: SessionDep
) -> dict[str, object]:
    """Tekrarlı (zamanlanmış) tarama tanımlar (Celery beat çalıştırır)."""
    schedule = await create_schedule(
        session,
        data.scan_type,
        data.target,
        period=data.period,
        interval_minutes=data.interval_minutes,
        start_at=data.start_at,
    )
    await log_action(session, "schedule_create", user_id=user.id, target=data.target)
    return {
        "id": schedule.id,
        "target": schedule.target,
        "period": schedule.period,
        "interval_minutes": schedule.interval_minutes,
    }


@app.get("/schedules", dependencies=[Depends(require_role(Role.admin, Role.analyst))])
async def list_schedules_ep(session: SessionDep) -> list[dict[str, object]]:
    return [
        {
            "id": s.id,
            "type": str(s.scan_type),
            "target": s.target,
            "interval_minutes": s.interval_minutes,
            "is_active": s.is_active,
        }
        for s in await list_schedules(session)
    ]
