"""Kurulumda CVE/CPE tohumunu (seed) DB'ye yükler — müşteri NVD'den indirmesin diye.

``cves`` tablosu BOŞSA, ``cves.csv.gz`` + ``cpe_matches.csv.gz`` dosyalarını asyncpg COPY ile
toplu yükler (saniyeler; per-CVE indirme/commit YOK). Dolu DB'de hiçbir şey yapmaz (idempotent),
böylece kurulum/migrate akışına güvenle takılabilir. ``--force`` mevcut iki tabloyu boşaltıp
yeniden yükler (yalnız elle bakım için).

Kullanım (uygulama konteynerinde):
    python -m cybersectool.scripts.import_cve_seed [tohum_dizini] [--force]
Tohum dizini verilmezse ``CVE_SEED_DIR`` ortam değişkeni, o da yoksa ``/app/seed`` kullanılır.
"""

from __future__ import annotations

import asyncio
import gzip
import os
import sys
from pathlib import Path

import asyncpg

from cybersectool.config import settings
from cybersectool.core.models import CVE, CpeMatch

# (tablo, model) — sütun listesi modelden türetilir (export ile aynı). Ad-bazlı COPY: şema
# sütun-sırası ileride değişse bile sessiz çapraz-sütun bozulması yerine gürültülü hata.
_TABLES = (("cves", CVE), ("cpe_matches", CpeMatch))


def _dsn() -> str:
    return settings.database_url.replace("+asyncpg", "")


def _seed_dir(argv: list[str]) -> Path:
    for arg in argv[1:]:
        if not arg.startswith("--"):
            return Path(arg)
    return Path(os.environ.get("CVE_SEED_DIR", "/app/seed"))


async def import_seed(seeddir: Path, *, force: bool = False) -> str:
    missing = [t for t, _ in _TABLES if not (seeddir / f"{t}.csv.gz").exists()]
    if missing:
        return f"atlandi: tohum dosyalari yok ({', '.join(missing)}) @ {seeddir}"
    conn = await asyncpg.connect(_dsn())
    try:
        async with conn.transaction():
            # Atomik kapı: iki import yarışırsa (migrate + elle) ikincisi advisory-lock'ta bekler,
            # sonra dolu görüp temiz no-op döner (kontrol+COPY tek işlemde → çift-yükleme yok).
            await conn.execute("SELECT pg_advisory_xact_lock(7426301)")
            existing = await conn.fetchval("SELECT count(*) FROM cves")
            if existing and not force:
                return f"atlandi: CVE tablosu zaten dolu ({existing} kayit) — tohum yuklenmedi"
            for table, model in _TABLES:
                cols = list(model.__table__.columns.keys())
                if force:
                    await conn.execute(f"TRUNCATE {table}")  # noqa: S608 — sabit tablo adı
                with gzip.open(seeddir / f"{table}.csv.gz", "rb") as fh:
                    await conn.copy_to_table(
                        table, source=fh, columns=cols, format="csv", header=True
                    )
            # cpe_matches.id serial'ı ilerlet (3-arg: boşsa is_called=false → ilk id=1).
            await conn.execute(
                "SELECT setval(pg_get_serial_sequence('cpe_matches', 'id'), "
                "COALESCE((SELECT max(id) FROM cpe_matches), 1), "
                "(SELECT max(id) FROM cpe_matches) IS NOT NULL)"
            )
        cves = await conn.fetchval("SELECT count(*) FROM cves")
        cpe = await conn.fetchval("SELECT count(*) FROM cpe_matches")
        return f"yuklendi: cves={cves} cpe_matches={cpe}"
    finally:
        await conn.close()


def main() -> None:
    seeddir = _seed_dir(sys.argv)
    force = "--force" in sys.argv
    print(f"CVE tohumu yukleniyor <- {seeddir}/ (force={force}) ...", flush=True)
    print(asyncio.run(import_seed(seeddir, force=force)))


if __name__ == "__main__":
    main()
