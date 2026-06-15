"""CISA KEV (Known Exploited Vulnerabilities) feed — vahşi doğada aktif sömürülen CVE'ler."""

from __future__ import annotations

from typing import Any

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def parse_kev(data: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for item in data.get("vulnerabilities", []):
        cve_id = item.get("cveID")
        if cve_id:
            out.add(str(cve_id))
    return out


async def fetch_kev_set() -> set[str]:
    """CISA KEV listesindeki CVE id'lerini döndürür. Hata/timeout'ta boş küme."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return set()
    return parse_kev(data)
