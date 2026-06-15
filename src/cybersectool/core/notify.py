"""Bildirim — kritik bulgularda webhook (Slack vb.) + e-posta uyarısı gönderir.

Ayrıca tarama tamamlandığında atanan kullanıcıya (varsa) opsiyonel PDF rapor ekli
"tarama tamamlandı" e-postası gönderir (best-effort; mail hatası taramayı bozmaz).
"""

from __future__ import annotations

import contextlib
from collections.abc import Sequence
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.config import settings
from cybersectool.core.app_settings import get_settings
from cybersectool.core.findings import (
    count_by_severity,
    count_critical_for_scan,
    list_findings_by_risk,
)
from cybersectool.core.mailer import MailError, send_email
from cybersectool.core.models import AIExplanation, Finding, Scan, ScanStatus
from cybersectool.core.report_summary import render_summary_pdf
from cybersectool.core.scan_batches import batch_scans, get_batch
from cybersectool.core.users import get_user_by_id
from cybersectool.core.vulnerabilities import sync_vulnerabilities_for_scan

_TERMINAL = {ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled}


async def send_notification(message: str) -> bool:
    """Yapılandırılmış webhook'a mesaj gönderir. URL yoksa ya da hata olursa False."""
    url = settings.notify_webhook_url
    if not url:
        return False
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json={"text": message})
            resp.raise_for_status()
    except httpx.HTTPError:
        return False
    return True


async def _send_critical_email(session: AsyncSession, summary: str) -> None:
    """SMTP açık ve uyarı alıcısı tanımlıysa kritik bulgu e-postası gönderir.

    Mail hatası taramayı bozmaz (sessizce yutulur) — bildirim en iyi çabadır.
    """
    row = await get_settings(session)
    if not row.smtp_enabled or not row.alert_email_to.strip():
        return
    with contextlib.suppress(MailError):
        await send_email(
            row,
            row.alert_email_to,
            "Kangalis — Kritik zafiyet uyarısı",
            f"{summary}\n\nBu otomatik bir uyarıdır. Ayrıntılar için Kangalis panelini açın.",
        )


def _counts_from_findings(findings: Sequence[Finding]) -> dict[str, int]:
    """Bulgu listesinden önem (severity) dağılımı çıkarır ({'critical': 2, ...})."""
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.severity.value
        counts[sev] = counts.get(sev, 0) + 1
    return counts


async def _ai_summary_text(session: AsyncSession, cache_key: str) -> str | None:
    """Önbellekteki AI yönetici özetini (varsa) döndürür — salt-okunur, AI'a BEL BAĞLAMAZ.

    Opsiyonellik sözleşmesi: notify ``cybersectool.core.ai``'ı İTHAL ETMEZ; önbellek satırını
    doğrudan ``AIExplanation`` modelinden okur (AI yalnız operatör butona basınca üretip yazar).
    Özet üretilmemişse (AI kapalı / hiç tıklanmamış) None → mail/PDF özetsiz, bozulmadan gider.
    """
    result = await session.execute(
        select(AIExplanation.content).where(AIExplanation.cache_key == cache_key)
    )
    content = result.scalar_one_or_none()
    text = (content or "").strip()
    return text or None


async def notify_assigned_user(session: AsyncSession, scan_id: int) -> bool:
    """Atanan kullanıcıya tarama-tamamlandı e-postası (opsiyonel PDF rapor ekli).

    Batch tarama: yalnız TÜM üye taramalar terminal olunca BİR kez (notified_at guard);
    bu hook scan completed'a set EDİLMEDEN çağrıldığı için mevcut scan terminal sayılır.
    Standalone scan: doğrudan gönderir. Mail/SMTP yoksa sessizce çıkar (best-effort).
    """
    scan = await session.get(Scan, scan_id)
    if scan is None:
        return False

    # --- Atama + kapsam çözümü (batch vs standalone) ---
    if scan.batch_id is not None:
        batch = await get_batch(session, scan.batch_id)
        if batch is None or not batch.notify_on_complete:
            return False
        members = await batch_scans(session, batch.id)
        # Bu hook çağrıldığında mevcut scan henüz completed'a set edilmemiş olabilir;
        # onu terminal say. Diğerlerinin tümü terminal değilse son tarama değiliz.
        if not all(s.status in _TERMINAL or s.id == scan_id for s in members):
            return False
        if batch.notified_at is not None:
            return False  # zaten gönderildi (yarış/yeniden çağrı koruması)
        batch.notified_at = datetime.now(UTC)
        await session.commit()  # bir-kez muhafızı: önce yaz, sonra gönder
        assigned_user_id = batch.assigned_user_id
        attach_report = batch.attach_report
        scope_label = batch.name
        ai_summary_key = f"summary:batch:{batch.id}"
        member_ids = [s.id for s in members]
        findings = await list_findings_by_risk(session, scan_ids=member_ids)
        # count_by_severity scan_ids desteklemiyor → batch için listeden say.
        counts = _counts_from_findings(findings)
    else:
        if not scan.notify_on_complete:
            return False
        assigned_user_id = scan.assigned_user_id
        attach_report = scan.attach_report
        scope_label = scan.target
        ai_summary_key = f"summary:scan:{scan_id}"
        counts = await count_by_severity(session, scan_id=scan_id)
        findings = await list_findings_by_risk(session, scan_id=scan_id)

    if assigned_user_id is None:
        return False
    assignee = await get_user_by_id(session, assigned_user_id)
    recipient = (assignee.email or "").strip() if assignee is not None else ""
    if not recipient:
        return False

    row = await get_settings(session)
    if not row.smtp_enabled or not row.smtp_host.strip():
        return False

    # AI yönetici özeti (varsa) — salt-okunur önbellekten; yoksa mail/PDF özetsiz gider.
    ai_summary = await _ai_summary_text(session, ai_summary_key)

    subject = f"Kangalis — Tarama tamamlandı: {scope_label}"
    sev_line = ", ".join(f"{k}: {v}" for k, v in counts.items()) or "bulgu yok"
    body = f"'{scope_label}' taraması tamamlandı.\n\nBulgu özeti — {sev_line}.\n\n"
    if ai_summary:
        body += f"AI Yönetici Özeti (AI üretti — doğrulayın):\n{ai_summary}\n\n"
    body += "Ayrıntılar için Kangalis panelini açın. Bu otomatik bir bildirimdir."
    pdf = (
        render_summary_pdf(
            title=subject,
            scope=scope_label,
            counts=counts,
            findings=findings,
            ai_summary=ai_summary,
        )
        if attach_report
        else None
    )
    attachments = [("kangalis-rapor.pdf", pdf)] if pdf else None
    with contextlib.suppress(MailError):
        await send_email(row, recipient, subject, body, attachments=attachments)
    return True


async def notify_if_critical(session: AsyncSession, scan_id: int, target: str) -> int:
    """Tarama kritik bulgu içeriyorsa bildirim gönderir; kritik sayısını döndürür.

    Tüm tarama tipleri (ağ/web/sca/credentialed/zone) bunu çağırır → tutarlı bildirim.
    Webhook (env) + e-posta (app_settings) kanallarının ikisi de denenir. Ayrıca
    atanan kullanıcıya tamamlanma e-postası (best-effort) gönderir.
    """
    critical = await count_critical_for_scan(session, scan_id)
    if critical > 0:
        summary = f"Tarama #{scan_id} ({target}): {critical} KRİTİK zafiyet bulundu."
        await send_notification(f"⚠️ {summary}")
        await _send_critical_email(session, summary)
    await sync_vulnerabilities_for_scan(session, scan_id)
    # Atanan kullanıcı bildirimi — bir mail hatası taramayı asla bozmamalı.
    with contextlib.suppress(Exception):
        await notify_assigned_user(session, scan_id)
    return critical
