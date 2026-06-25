"""Maintainer-only: NVD'den GENİŞ tarihsel CVE/CPE çek (tohum/seed üretimi).

Müşterinin NVD'den indirmesini beklememek için: BİZ tüm CVE/CPE'yi bir kez çekeriz, dışa
aktarırız (``export_cve_seed``) ve müşteri kurarken tohum içe aktarılır (``import_cve_seed``).

Kullanım:
    python -m cybersectool.scripts.build_cve_seed [baslangic_yili] [batch]
Örn. 2000'den bugüne (varsayılan), 1000'lik commit toplulukları:
    python -m cybersectool.scripts.build_cve_seed
    python -m cybersectool.scripts.build_cve_seed 2000 2000

Her pencere TAM sayfalanır (tavan yok), commit'ler batch'lenir → hızlı. NVD anahtarı DB
ayarından (Ayarlar > Zafiyet Veritabanı) çözülür; anahtarla 50 istek/30sn.
"""

from __future__ import annotations

import asyncio
import sys

from cybersectool.tasks.cpe_sync import build_cve_seed


def main() -> None:
    start_year = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    batch = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
    print(f"NVD tam tarihsel cekim: {start_year} -> bugun (batch={batch})...", flush=True)
    result = asyncio.run(
        build_cve_seed(
            start_year=start_year,
            batch=batch,
            on_window=lambda msg: print("  " + msg, flush=True),
        )
    )
    print(f"Bitti: {result}")


if __name__ == "__main__":
    main()
