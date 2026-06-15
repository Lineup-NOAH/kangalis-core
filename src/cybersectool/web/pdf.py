"""HTML → PDF dönüştürme (WeasyPrint).

WeasyPrint, Pango/Cairo gibi yerel (native) kütüphanelere bağlıdır; bunlar
Docker imajında kuruludur ama her ortamda (örn. CI runner, Windows geliştirme
makinesi) bulunmayabilir. Bu yüzden ``weasyprint`` **modül yüklenirken değil,
yalnızca fonksiyon çağrılırken** import edilir — böylece bu modülü import etmek
hiçbir ortamda patlamaz.
"""

from __future__ import annotations


class PdfUnavailableError(RuntimeError):
    """WeasyPrint (veya yerel bağımlılıkları) bu ortamda kullanılamıyor."""


def pdf_available() -> bool:
    """WeasyPrint import edilebiliyor mu (yerel kütüphaneler dahil)?"""
    try:
        import weasyprint  # noqa: F401
    except Exception:
        return False
    return True


def render_html_to_pdf(html: str, *, base_url: str | None = None) -> bytes:
    """Verilen HTML dizesini PDF baytlarına çevirir.

    base_url: göreli kaynakların (font/resim) çözüleceği taban; genelde None.
    WeasyPrint yoksa :class:`PdfUnavailableError` yükseltir.
    """
    try:
        from weasyprint import HTML
    except Exception as exc:  # pragma: no cover - ortam bağımlı
        raise PdfUnavailableError(
            "WeasyPrint kullanılamıyor (Pango/Cairo yerel kütüphaneleri eksik olabilir)."
        ) from exc

    return bytes(HTML(string=html, base_url=base_url).write_pdf())
