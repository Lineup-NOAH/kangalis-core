"""EPSS (Exploit Prediction Scoring System) — FIRST.org API. Sömürülme olasılığı (0-1)."""

from __future__ import annotations

from typing import Any

import httpx

EPSS_URL = "https://api.first.org/data/v1/epss"


def parse_epss(data: dict[str, Any]) -> dict[str, float]:
    out: dict[str, float] = {}
    for item in data.get("data", []):
        cve_id = item.get("cve")
        score = item.get("epss")
        if cve_id and score is not None:
            try:
                out[str(cve_id)] = float(score)
            except (TypeError, ValueError):
                continue
    return out


# FIRST.org EPSS API tek istekte makul sayıda CVE kabul eder; 100'lük partiler güvenli.
EPSS_BATCH = 100


async def fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Verilen TÜM CVE'ler için EPSS skorlarını döndürür (100'lük partiler halinde).

    Önceden ``cve_ids[:100]`` ile sessizce kırpılıyordu → 100'den fazla CVE'de çoğunun EPSS'i
    hiç güncellenmiyordu (#144). Artık tüm liste partilenir. Bir parti hata verirse o ana
    kadarki KISMİ sonuç döner (hepsi kaybedilmez).
    """
    if not cve_ids:
        return {}
    out: dict[str, float] = {}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            for start in range(0, len(cve_ids), EPSS_BATCH):
                batch = cve_ids[start : start + EPSS_BATCH]
                resp = await client.get(EPSS_URL, params={"cve": ",".join(batch)})
                resp.raise_for_status()
                out.update(parse_epss(resp.json()))
    except (httpx.HTTPError, ValueError):
        return out  # kısmî sonuç (tamamen kaybetme)
    return out
