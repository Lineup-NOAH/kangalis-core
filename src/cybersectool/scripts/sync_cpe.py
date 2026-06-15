"""NVD CVE + CPE indeksini elle senkronize eden CLI (offline eşleştirme için).

Kullanım:
    python -m cybersectool.scripts.sync_cpe [gün] [sayfa]
Örn. son 30 günü 4 sayfaya kadar çek (varsayılan):
    python -m cybersectool.scripts.sync_cpe
"""

from __future__ import annotations

import asyncio
import sys

from cybersectool.tasks.cpe_sync import _run


def main() -> None:
    days = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    pages = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    print(f"NVD CVE + CPE çekiliyor (son {days} gün, {pages} sayfaya kadar)...")
    result = asyncio.run(_run(days=days, max_pages=pages))
    print(f"Bitti: {result}")


if __name__ == "__main__":
    main()
