"""SCA (bağımlılık) tarama Celery görevi — manifest → OSV → findings."""

from __future__ import annotations

import asyncio
import contextlib

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from cybersectool.config import settings
from cybersectool.core.audit import log_action
from cybersectool.core.findings import create_finding
from cybersectool.core.models import ScanStatus, Severity
from cybersectool.core.notify import notify_if_critical
from cybersectool.core.scans import set_scan_progress, set_scan_status
from cybersectool.intel.osv import query_osv
from cybersectool.scanners.sca import parse_package_json, parse_requirements
from cybersectool.tasks.celery_app import celery_app


async def _run(scan_id: int, ecosystem: str, content: str) -> str:
    is_npm = ecosystem.lower() in ("npm", "node")
    osv_ecosystem = "npm" if is_npm else "PyPI"
    deps = parse_package_json(content) if is_npm else parse_requirements(content)

    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            await set_scan_status(session, scan_id, ScanStatus.running)
            total = len(deps)
            await set_scan_progress(
                session, scan_id, 10, phase=f"{osv_ecosystem}: {total} bağımlılık taranıyor"
            )
            count = 0
            for idx, (name, version) in enumerate(deps):
                for vuln in await query_osv(name, version, osv_ecosystem):
                    await create_finding(
                        session,
                        scan_id,
                        title=f"{vuln.id}: {name} {version}",
                        severity=vuln.severity,
                        cve_id=vuln.cve,
                        description=vuln.summary,
                    )
                    count += 1
                # İlerleme: 10 → 90 arası bağımlılık başına (canlı görünüm).
                pct = 10 + int((idx + 1) / total * 80) if total else 90
                await set_scan_progress(
                    session, scan_id, pct, phase=f"Bağımlılık {idx + 1}/{total}"
                )
            await set_scan_progress(session, scan_id, 95, phase="Bulgular kaydediliyor")
            await notify_if_critical(session, scan_id, f"{osv_ecosystem} manifest")
            await set_scan_status(session, scan_id, ScanStatus.completed)
            await log_action(
                session,
                "sca_scan",
                target=f"{osv_ecosystem} ({len(deps)} bagimlilik, {count} acik)",
            )
            return f"completed:{count}"
    finally:
        await engine.dispose()


async def _mark_failed(scan_id: int, ecosystem: str, reason: str) -> None:
    """Beklenmeyen hata → SCA taramasını 'başarısız' işaretle (sonsuza dek 'running' kalmasın).

    network/ping görevleriyle aynı kalkan: ``_run`` ``running`` yazdıktan sonra (OSV/parse)
    yakalanmayan bir hata fırlatırsa görev ``FAILURE`` olur ama DB durumu ``running``'de kalır.
    """
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    try:
        factory = async_sessionmaker(engine, expire_on_commit=False)
        async with factory() as session:
            await set_scan_status(session, scan_id, ScanStatus.failed, reason=reason)
            with contextlib.suppress(Exception):
                await create_finding(
                    session,
                    scan_id,
                    title="SCA taraması başarısız",
                    severity=Severity.info,
                    description=f"{ecosystem}: {reason}"[:500],
                )
    finally:
        await engine.dispose()


@celery_app.task(name="sca_scan")
def sca_scan_task(scan_id: int, ecosystem: str, content: str) -> str:
    try:
        return asyncio.run(_run(scan_id, ecosystem, content))
    except Exception as exc:  # OSV/parse/işleme hatası → tarama 'başarısız' (takılı kalmaz)
        with contextlib.suppress(Exception):
            asyncio.run(_mark_failed(scan_id, ecosystem, str(exc)))
        return "failed"
