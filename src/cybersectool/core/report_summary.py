"""Tarama tamamlanma e-postası için özet rapor PDF'i (WeasyPrint, opsiyonel).

Atanan kullanıcıya gönderilen e-postaya iliştirilen kendine yeten (self-contained)
küçük bir özet rapor üretir: başlık, kapsam, önem (severity) dağılımı tablosu ve
en kritik bulgular tablosu. WeasyPrint yoksa (yerel kütüphaneler eksik) None döner.
"""

from __future__ import annotations

import html
from collections.abc import Sequence
from typing import Any

# Önem sırası (kritikten bilgiye) — özet tablosu bu sırayla gösterilir.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_MAX_ROWS = 50


def render_summary_pdf(
    *,
    title: str,
    scope: str,
    counts: dict[str, int],
    findings: Sequence[Any],
    ai_summary: str | None = None,
) -> bytes | None:
    """Özet rapor PDF baytlarını döndürür; WeasyPrint yoksa None.

    counts: {'critical': 3, 'high': 5, ...} önem dağılımı.
    findings: severity/title/cve_id alanlarına sahip bulgu nesneleri (ilk ~50 satır).
    ai_summary: varsa (AI üretip önbelleğe alınmışsa) raporun başına "AI Yönetici Özeti"
      bölümü eklenir; None ise rapor özetsiz, bozulmadan üretilir (AI'a bel bağlamaz).
    """
    from cybersectool.web.pdf import pdf_available, render_html_to_pdf

    if not pdf_available():
        return None

    doc = _build_html(
        title=title, scope=scope, counts=counts, findings=findings, ai_summary=ai_summary
    )
    return render_html_to_pdf(doc)


def _ai_summary_block(ai_summary: str | None) -> str:
    """AI yönetici özeti için kaçışlı HTML bloğu (boşsa boş string).

    Çift-satır = paragraf, tek-satır = ``<br>``. "AI üretti — doğrulayın" sorumluluk reddi
    her zaman gösterilir (halüsinasyon riski).
    """
    text = (ai_summary or "").strip()
    if not text:
        return ""
    paras = []
    for block in text.split("\n\n"):
        block = block.strip()
        if not block:
            continue
        inner = "<br>".join(html.escape(line) for line in block.splitlines())
        paras.append(f"<p>{inner}</p>")
    return (
        "<h2>AI Yönetici Özeti</h2>"
        "<p class='ai-note'>⚠ AI tarafından üretildi — doğrulayın.</p>"
        f"<div class='ai'>{''.join(paras)}</div>"
    )


def _build_html(
    *,
    title: str,
    scope: str,
    counts: dict[str, int],
    findings: Sequence[Any],
    ai_summary: str | None = None,
) -> str:
    """Kaçışlı (escape) küçük bir HTML belgesi üretir."""
    count_rows = "".join(
        f"<tr><td>{html.escape(sev)}</td><td>{int(counts.get(sev, 0))}</td></tr>"
        for sev in _SEVERITY_ORDER
    )
    finding_rows = "".join(
        "<tr>"
        f"<td>{html.escape(f.severity.value)}</td>"
        f"<td>{html.escape(f.title)}</td>"
        f"<td>{html.escape(f.cve_id or '-')}</td>"
        "</tr>"
        for f in list(findings)[:_MAX_ROWS]
    )
    if not finding_rows:
        finding_rows = '<tr><td colspan="3">-</td></tr>'
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<style>"
        "body{font-family:sans-serif;font-size:12px;color:#111;}"
        "h1{font-size:18px;margin:0 0 4px;}"
        "table{border-collapse:collapse;width:100%;margin:10px 0;}"
        "th,td{border:1px solid #ccc;padding:4px 8px;text-align:left;}"
        "th{background:#f2f2f2;}"
        ".ai-note{color:#a15c00;font-size:11px;margin:2px 0 6px;}"
        ".ai p{margin:4px 0;}"
        "</style></head><body>"
        f"<h1>{html.escape(title)}</h1>"
        f"<p>Kapsam: {html.escape(scope)}</p>"
        f"{_ai_summary_block(ai_summary)}"
        "<h2>Önem dağılımı</h2>"
        "<table><thead><tr><th>Önem</th><th>Adet</th></tr></thead>"
        f"<tbody>{count_rows}</tbody></table>"
        "<h2>En kritik bulgular</h2>"
        "<table><thead><tr><th>Önem</th><th>Başlık</th><th>CVE</th></tr></thead>"
        f"<tbody>{finding_rows}</tbody></table>"
        "</body></html>"
    )
