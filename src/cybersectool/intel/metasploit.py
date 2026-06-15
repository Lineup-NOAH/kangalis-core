"""Metasploit Framework entegrasyonu. Modül metadata JSON'ını indirip ayrıştırır.

`db/modules_metadata_base.json` ~6.6k modül içerir; `references` listesi CVE'leri taşır.
`parse_metasploit` saftır; `fetch_metasploit` ağ çağrısı yapar (hata/timeout'ta boş liste).
"""

from __future__ import annotations

from typing import Any

import httpx

from cybersectool.core.exploits import ExploitRecord
from cybersectool.core.models import ExploitSource

METASPLOIT_URL = (
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/"
    "db/modules_metadata_base.json"
)

# Metasploit sayısal rank → etiket.
RANKS = {
    0: "Manual",
    100: "Low",
    200: "Average",
    300: "Normal",
    400: "Good",
    500: "Great",
    600: "Excellent",
}


def cves_from_refs(references: Any) -> list[str]:
    """references listesinden CVE'leri ayıklar (ör. 'CVE-2007-4387')."""
    out: list[str] = []
    if not isinstance(references, list):
        return out
    for ref in references:
        token = str(ref).strip().upper()
        if token.startswith("CVE-"):
            out.append(token)
    return out


def _join(value: Any) -> str | None:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) or None
    if value:
        return str(value)
    return None


def parse_metasploit(data: dict[str, Any]) -> list[ExploitRecord]:
    records: list[ExploitRecord] = []
    for key, mod in data.items():
        if not isinstance(mod, dict):
            continue
        fullname = str(mod.get("fullname") or key)
        rank = mod.get("rank")
        rank_label = RANKS.get(rank) if isinstance(rank, int) else None
        records.append(
            ExploitRecord(
                source=ExploitSource.metasploit,
                external_id=fullname,
                title=str(mod.get("name") or fullname),
                type=(str(mod.get("type")) if mod.get("type") else None),
                platform=_join(mod.get("platform")),
                author=_join(mod.get("author")),
                date=(str(mod.get("disclosure_date")) if mod.get("disclosure_date") else None),
                rank=rank_label,
                cve_ids=cves_from_refs(mod.get("references")),
                url=f"https://www.rapid7.com/db/modules/{fullname}",
            )
        )
    return records


async def fetch_metasploit() -> list[ExploitRecord]:
    try:
        async with httpx.AsyncClient(timeout=90, follow_redirects=True) as client:
            resp = await client.get(METASPLOIT_URL)
            resp.raise_for_status()
            data = resp.json()
            return parse_metasploit(data) if isinstance(data, dict) else []
    except (httpx.HTTPError, ValueError):
        return []
