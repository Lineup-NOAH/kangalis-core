"""Maintainer: ``cves`` + ``cpe_matches`` tablolarını sıkıştırılmış tohum (seed) dosyalarına aktarır.

Müşteri NVD'den indirmesin diye: biz ``build_cve_seed`` ile tüm CVE/CPE'yi çekeriz, sonra bunu
çalıştırıp tohumu üretiriz; müşteri kurarken ``import_cve_seed`` ile saniyeler içinde yükler.

Kullanım (uygulama konteynerinde):
    python -m cybersectool.scripts.export_cve_seed [cikti_dizini]
Varsayılan çıktı dizini ``cve_seed/`` → ``cves.csv.gz`` + ``cpe_matches.csv.gz``.

asyncpg COPY (CSV) kullanır → ham, hızlı, portatif. psql/pg_dump binary'si GEREKMEZ.
"""

from __future__ import annotations

import asyncio
import gzip
import sys
from pathlib import Path

import asyncpg

from cybersectool.config import settings

# Offline eşleştirme için gereken iki tablo (tüm sütunlar; cpe_matches.id serial dahil).
_TABLES = ("cves", "cpe_matches")


def _dsn() -> str:
    """SQLAlchemy URL'sini ham asyncpg DSN'ine çevirir (``+asyncpg`` sürücü etiketini atar)."""
    return settings.database_url.replace("+asyncpg", "")


async def export_seed(outdir: Path) -> str:
    outdir.mkdir(parents=True, exist_ok=True)
    conn = await asyncpg.connect(_dsn())
    try:
        for table in _TABLES:
            count = await conn.fetchval(f"SELECT count(*) FROM {table}")  # noqa: S608 — sabit tablo adı
            path = outdir / f"{table}.csv.gz"
            with gzip.open(path, "wb") as fh:
                await conn.copy_from_table(table, output=fh, format="csv", header=True)
            size_mb = path.stat().st_size / 1048576
            print(f"  {table}: {count} satir -> {path} ({size_mb:.1f} MB)", flush=True)
    finally:
        await conn.close()
    return f"done -> {outdir}/"


def main() -> None:
    outdir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("cve_seed")
    print(f"CVE tohumu disa aktariliyor -> {outdir}/ ...", flush=True)
    print(asyncio.run(export_seed(outdir)))


if __name__ == "__main__":
    main()
