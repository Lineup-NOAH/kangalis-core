"""Kangalis MCP sunucusu — Claude'un platformu kullanması için araç katmanı.

stdio üzerinden çalışır. Araçlar web UI ile aynı core/service katmanını çağırır.
Çalıştırma: ``python -m cybersectool.mcp.server`` ya da ``cybersectool-mcp``.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from collections import defaultdict
from typing import Any

from mcp.server.fastmcp import FastMCP
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.applications import Starlette
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from cybersectool.core import assets as assets_svc
from cybersectool.core import scans as scans_svc
from cybersectool.core.audit import log_action
from cybersectool.core.db import SessionLocal
from cybersectool.core.exploit_classify import CATEGORIES
from cybersectool.core.exploits import (
    exploit_summary_for_cves,
    facet_counts,
    list_exploits,
)
from cybersectool.core.findings import list_findings_by_risk
from cybersectool.core.models import CVE, ScanMode, ScanType, Service, Severity, User
from cybersectool.core.scope import ScopeError, validate_target
from cybersectool.core.tokens import user_from_token
from cybersectool.core.users import authenticate_user
from cybersectool.core.vuln import cves_by_ids
from cybersectool.core.wordlists import list_wordlists as list_wordlists_svc
from cybersectool.core.zones import list_zones
from cybersectool.mcp.rbac import first_denied_tool
from cybersectool.tasks.network_scan import network_scan_task
from cybersectool.tasks.ping_scan import ping_scan_task

mcp = FastMCP("Kangalis")


# --- Test edilebilir payload yardımcıları (core servisleri çağırır) ---


async def assets_payload(session: AsyncSession) -> list[dict[str, Any]]:
    assets = await assets_svc.list_assets(session)
    services = await assets_svc.list_services(session)
    by_asset: defaultdict[int, list[Service]] = defaultdict(list)
    for svc in services:
        by_asset[svc.asset_id].append(svc)
    return [
        {
            "id": asset.id,
            "ip": asset.ip,
            "hostname": asset.hostname,
            "os": asset.os,
            "services": [
                {
                    "port": s.port,
                    "protocol": s.protocol,
                    "service": s.service_name,
                    "product": s.product,
                    "version": s.version,
                }
                for s in by_asset[asset.id]
            ],
        }
        for asset in assets
    ]


async def vulns_payload(
    session: AsyncSession, severity: str | None, limit: int
) -> list[dict[str, Any]]:
    sev: Severity | None = None
    if severity:
        try:
            sev = Severity(severity)
        except ValueError:
            sev = None
    findings = await list_findings_by_risk(session, severity=sev, limit=limit)
    cve_map = await cves_by_ids(session, [f.cve_id for f in findings if f.cve_id])
    out: list[dict[str, Any]] = []
    for f in findings:
        cve = cve_map.get(f.cve_id) if f.cve_id else None
        out.append(
            {
                "cve_id": f.cve_id,
                "severity": str(f.severity),
                "risk_score": f.risk_score,
                "cvss": cve.cvss_score if cve else None,
                "epss": cve.epss_score if cve else None,
                "kev": cve.kev_flag if cve else False,
                "title": f.title,
            }
        )
    return out


async def cve_payload(session: AsyncSession, cve_id: str) -> dict[str, Any]:
    cve = await session.get(CVE, cve_id)
    if cve is None:
        return {"error": f"CVE bulunamadı: {cve_id}"}
    return {
        "cve_id": cve.cve_id,
        "cvss": cve.cvss_score,
        "severity": str(cve.severity) if cve.severity else None,
        "epss": cve.epss_score,
        "kev": cve.kev_flag,
        "description": cve.description,
        "references": cve.references,
    }


async def scan_payload(session: AsyncSession, scan_id: int) -> dict[str, Any]:
    scan = await scans_svc.get_scan(session, scan_id)
    if scan is None:
        return {"error": f"Tarama bulunamadı: {scan_id}"}
    return {
        "scan_id": scan.id,
        "type": str(scan.scan_type),
        "target": scan.target,
        "status": str(scan.status),
        # Canlı ilerleme alanları (web UI ile aynı) — Claude tarama gidişatını görebilsin.
        "progress": scan.progress,
        "phase": scan.phase,
        "error_reason": scan.error_reason,
        "resolved_ip": scan.resolved_ip,  # web taramasında çözülen hedef IP (yoksa None)
    }


# MCP yalnız GÜVENLİ (müdahaleci olmayan) modları başlatabilir. Agresif CVE, web DAST,
# kimlikli denetim ve brute force MCP'den BAŞLATILAMAZ (operatör ürün akışından yapar).
_MCP_SCAN_MODES = ("network", "ping", "cve_safe")


async def start_scan_payload(
    session: AsyncSession, target: str, mode: str = "network"
) -> dict[str, Any]:
    if mode not in _MCP_SCAN_MODES:
        return {
            "error": (
                f"Geçersiz/izinsiz mod: {mode}. MCP yalnız güvenli modları başlatır: "
                f"{', '.join(_MCP_SCAN_MODES)} (agresif/web/kimlikli/brute force HARİÇ)."
            )
        }
    try:
        await validate_target(session, target)
    except ScopeError as exc:
        return {"error": str(exc)}
    if mode == "ping":
        scan = await scans_svc.create_scan(session, ScanType.ping, target, mode=ScanMode.safe)
        await log_action(session, "scan_start_mcp", target=f"{target} [ping]")
        ping_scan_task.delay(scan.id, target)
    else:
        # network → ağ taraması; cve_safe → ağ + güvenli CVE eşleştirme (tür=vuln).
        scan_type = ScanType.vuln if mode == "cve_safe" else ScanType.network
        scan = await scans_svc.create_scan(session, scan_type, target, mode=ScanMode.safe)
        await log_action(session, "scan_start_mcp", target=f"{target} [{mode}]")
        network_scan_task.delay(scan.id, target, str(ScanMode.safe))
    return {"scan_id": scan.id, "status": str(scan.status), "target": target, "mode": mode}


async def wordlists_payload(session: AsyncSession) -> list[dict[str, Any]]:
    """Tanımlı kelime listelerini (dizin/SMB/brute force kaynakları) özetler."""
    return [
        {
            "id": wl.id,
            "name": wl.name,
            "kind": str(wl.kind),
            "entry_count": len(wl.entries),
            "is_builtin": wl.is_builtin,
        }
        for wl in await list_wordlists_svc(session)
    ]


async def scans_payload(session: AsyncSession, limit: int) -> list[dict[str, Any]]:
    """Son taramaları (id/tür/hedef/durum/ilerleme) listeler — en yeni önce."""
    scans = await scans_svc.list_scans(session)
    return [
        {
            "scan_id": s.id,
            "type": str(s.scan_type),
            "target": s.target,
            "status": str(s.status),
            "progress": s.progress,
        }
        for s in scans[:limit]
    ]


async def exploits_payload(
    session: AsyncSession,
    query: str | None,
    category: str | None,
    severity: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    sev: Severity | None = None
    if severity:
        try:
            sev = Severity(severity)
        except ValueError:
            sev = None
    cat = category if category in CATEGORIES else None
    rows = await list_exploits(session, query=query, category=cat, severity=sev, limit=limit)
    return [
        {
            "source": str(e.source),
            "id": e.external_id,
            "title": e.title,
            "severity": str(e.severity) if e.severity else None,
            "categories": e.categories,
            "cve_ids": e.cve_ids,
            "url": e.url,
        }
        for e in rows
    ]


async def exploits_for_cve_payload(session: AsyncSession, cve_id: str) -> dict[str, Any]:
    summary = await exploit_summary_for_cves(session, [cve_id])
    hit = summary.get(cve_id)
    return {
        "cve_id": cve_id,
        "exploit_count": hit.count if hit else 0,
        "metasploit": hit.metasploit if hit else False,
    }


async def zones_payload(session: AsyncSession) -> list[dict[str, Any]]:
    return [{"id": z.id, "name": z.name, "cidrs": z.cidrs} for z in await list_zones(session)]


# --- MCP araçları (Claude'un çağırdığı fonksiyonlar) ---


@mcp.tool()
async def list_assets() -> list[dict[str, Any]]:
    """Keşfedilen host ve servisleri (envanter) listeler."""
    async with SessionLocal() as session:
        return await assets_payload(session)


@mcp.tool()
async def list_vulnerabilities(
    severity: str | None = None, limit: int = 50
) -> list[dict[str, Any]]:
    """Bulguları risk sırasına göre listeler. severity ops.: critical/high/medium/low/info."""
    async with SessionLocal() as session:
        return await vulns_payload(session, severity, limit)


@mcp.tool()
async def lookup_cve(cve_id: str) -> dict[str, Any]:
    """Bir CVE'nin detayını döndürür: CVSS, severity, EPSS olasılığı, KEV (aktif sömürü)."""
    async with SessionLocal() as session:
        return await cve_payload(session, cve_id)


@mcp.tool()
async def scan_status(scan_id: int) -> dict[str, Any]:
    """Bir taramanın durumunu (pending/running/completed/failed) döndürür."""
    async with SessionLocal() as session:
        return await scan_payload(session, scan_id)


@mcp.tool()
async def start_scan(target: str, mode: str = "network") -> dict[str, Any]:
    """Yetkili kapsamda (scope) bir tarama başlatır. Kapsam dışı hedef reddedilir.

    mode: ``network`` (varsayılan, güvenli ağ taraması) / ``ping`` (host keşfi) /
    ``cve_safe`` (ağ + güvenli CVE eşleştirme). Müdahaleci modlar (agresif CVE, web DAST,
    kimlikli denetim, brute force) MCP'den BAŞLATILAMAZ — operatör ürün akışından yapar.
    """
    async with SessionLocal() as session:
        return await start_scan_payload(session, target, mode)


@mcp.tool()
async def search_exploits(
    query: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Yerel exploit/CVE veritabanında arar. category: windows/linux/web/database/...;
    severity: critical/high/medium/low/info; query: başlık/CVE/ID."""
    async with SessionLocal() as session:
        return await exploits_payload(session, query, category, severity, limit)


@mcp.tool()
async def exploits_for_cve(cve_id: str) -> dict[str, Any]:
    """Bir CVE için yerel depodaki exploit sayısı + Metasploit modülü var mı döndürür."""
    async with SessionLocal() as session:
        return await exploits_for_cve_payload(session, cve_id)


@mcp.tool()
async def exploit_db_stats() -> dict[str, Any]:
    """Exploit veritabanı sayıları: toplam + kaynak/kritiklik/kategori dağılımı."""
    async with SessionLocal() as session:
        return await facet_counts(session)


@mcp.tool()
async def list_ip_zones() -> list[dict[str, Any]]:
    """Tanımlı IP zone'larını (tarama bölgeleri) ve CIDR bloklarını listeler."""
    async with SessionLocal() as session:
        return await zones_payload(session)


@mcp.tool()
async def list_wordlists() -> list[dict[str, Any]]:
    """Kelime listelerini (dizin/SMB/brute force kaynakları) ad + tür + satır sayısıyla listeler."""
    async with SessionLocal() as session:
        return await wordlists_payload(session)


@mcp.tool()
async def list_scans(limit: int = 20) -> list[dict[str, Any]]:
    """Son taramaları (id/tür/hedef/durum/ilerleme) listeler — en yeni önce."""
    async with SessionLocal() as session:
        return await scans_payload(session, limit)


async def _authenticate_request(auth_header: str) -> User | None:
    """Authorization başlığından kullanıcıyı çözer (iki şema desteklenir).

    - ``Bearer cst_...``  → API token (programatik erişim).
    - ``Basic base64(kullanıcı:parola)`` → yerel **veya** LDAP kullanıcısı
      (authenticate_user üzerinden; LDAP kullanıcısı ilk girişte oluşturulur).
    """
    scheme, _, rest = auth_header.partition(" ")
    scheme = scheme.lower()
    rest = rest.strip()
    if scheme == "bearer" and rest:
        async with SessionLocal() as session:
            return await user_from_token(session, rest)
    if scheme == "basic" and rest:
        try:
            decoded = base64.b64decode(rest, validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return None
        username, sep, password = decoded.partition(":")
        if not sep:
            return None
        async with SessionLocal() as session:
            return await authenticate_user(session, username, password)
    return None


async def _send_json(send: Send, status: int, payload: dict[str, Any]) -> None:
    """ASGI üzerinden JSON gövdeli bir HTTP yanıtı gönderir."""
    body = json.dumps(payload).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class TokenAuthASGIMiddleware:
    """Pure ASGI middleware: kimlik doğrulama + araç bazlı rol kontrolü (RBAC).

    Kimlik: ``Authorization: Bearer cst_...`` (API token) **veya** ``Basic
    base64(kullanıcı:parola)`` (yerel/LDAP kullanıcısı). BaseHTTPMiddleware
    contextvar'ları bozduğundan ve gövdeyi okumayı zorlaştırdığından pure ASGI
    kullanılır. JSON-RPC gövdesi tampona alınır, ``tools/call`` çağrısının aracı
    kullanıcının rolüyle karşılaştırılır; yetersizse 403 döner. Yetkiliyse gövde
    aynen tekrar oynatılarak alt uygulamaya iletilir.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"").decode("latin-1")
        user = await _authenticate_request(auth)
        if user is None:
            await _send_json(
                send,
                401,
                {
                    "error": "Kimlik doğrulama gerekli: Authorization "
                    "'Bearer cst_...' (token) ya da 'Basic' (kullanıcı:parola)"
                },
            )
            return

        # Gövdeyi tampona al (tools/call RBAC kontrolü için), sonra tekrar oynat.
        buffered: list[Message] = []
        body = b""
        while True:
            message = await receive()
            buffered.append(message)
            if message["type"] == "http.request":
                body += message.get("body", b"")
                if not message.get("more_body", False):
                    break
            else:  # http.disconnect
                break

        denied = first_denied_tool(user.role, body)
        if denied is not None:
            async with SessionLocal() as session:
                await log_action(
                    session,
                    "mcp_rbac_denied",
                    user_id=user.id,
                    target=f"{user.username} -> {denied} (rol={user.role.value})",
                )
            await _send_json(
                send,
                403,
                {"error": f"'{denied}' aracı için yetersiz yetki (rol: {user.role.value})"},
            )
            return

        iterator = iter(buffered)

        async def replay() -> Message:
            try:
                return next(iterator)
            except StopIteration:
                return await receive()

        await self.app(scope, replay, send)


def http_app() -> Starlette:
    """Token + RBAC korumalı HTTP (streamable) MCP uygulaması."""
    app = mcp.streamable_http_app()
    app.add_middleware(TokenAuthASGIMiddleware)
    return app


def main() -> None:
    """MCP_TRANSPORT=http ise token korumalı HTTP sunucusu, değilse stdio."""
    if os.environ.get("MCP_TRANSPORT", "stdio") == "http":
        import uvicorn

        uvicorn.run(http_app(), host="0.0.0.0", port=8001)
    else:
        mcp.run()


if __name__ == "__main__":
    main()
