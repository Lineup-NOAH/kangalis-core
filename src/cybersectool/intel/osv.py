"""OSV.dev API entegrasyonu — açık kaynak / paket bağımlılık zafiyetleri."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import httpx

from cybersectool.core.models import Severity

OSV_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def _extract_cve(vuln_id: str, aliases: list[Any] | None) -> str | None:
    """OSV kaydından temiz CVE id'sini çıkarır (alias önce, yoksa OSV id'den).

    Çoğu ekosistem CVE'yi ``aliases``ta verir. Ancak bazıları (örn. Alpine:
    ``id="ALPINE-CVE-2024-58251"``, ``aliases=None``) CVE'yi OSV id'sine GÖMER. Bu durumda
    id'den ``CVE-YYYY-NNNN`` token'ı çekilir → finding cve_id'si CVE DB/EPSS/exploit eşleştirmesi
    ile entegre olur (yoksa "ALPINE-CVE-..." izole kalırdı, #146 BUG-4b).
    """
    for a in aliases or []:
        s = str(a)
        if s.startswith("CVE-"):
            return s
    m = _CVE_RE.search(vuln_id or "")
    return m.group(0) if m else None


_OSV_SEVERITY = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "moderate": Severity.medium,
    "low": Severity.low,
    "negligible": Severity.low,
}


@dataclass
class OsvVuln:
    id: str
    summary: str | None = None
    cve: str | None = None
    severity: Severity = Severity.medium


def parse_osv_response(data: dict[str, Any]) -> list[OsvVuln]:
    out: list[OsvVuln] = []
    for vuln in data.get("vulns", []):
        vuln_id = vuln.get("id")
        if not vuln_id:
            continue
        cve = _extract_cve(str(vuln_id), vuln.get("aliases"))
        out.append(
            OsvVuln(
                id=str(vuln_id),
                summary=vuln.get("summary"),
                cve=cve,
                # /v1/query yanıtı tam advisory taşır → gerçek önemi (database_specific.severity)
                # oku. Eskiden sabit medium'du → tüm SCA/OSV bulguları "orta" görünüyordu.
                severity=_severity_from_detail(vuln),
            )
        )
    return out


async def query_osv(name: str, version: str, ecosystem: str) -> list[OsvVuln]:
    """Bir paket/sürüm için OSV.dev'de zafiyet sorgular. Hata/timeout'ta boş liste."""
    payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(OSV_URL, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return []
    return parse_osv_response(data)


def _severity_from_detail(detail: dict[str, Any]) -> Severity:
    """OSV advisory detayından önem (database_specific.severity) — yoksa medium."""
    ds = detail.get("database_specific") or {}
    sev = str(ds.get("severity") or "").lower()
    return _OSV_SEVERITY.get(sev, Severity.medium)


def vuln_from_detail(detail: dict[str, Any]) -> OsvVuln:
    """OSV /v1/vulns/{id} detayını OsvVuln'a çevirir (CVE alias/id + önem dahil)."""
    cve = _extract_cve(str(detail.get("id") or ""), detail.get("aliases"))
    return OsvVuln(
        id=str(detail.get("id") or ""),
        summary=detail.get("summary"),
        cve=cve,
        severity=_severity_from_detail(detail),
    )


async def query_osv_packages(
    packages: list[tuple[str, str]], ecosystem: str, *, max_details: int = 200
) -> dict[tuple[str, str], list[OsvVuln]]:
    """OS paketleri için TOPLU OSV sorgusu → ``{(name, version): [OsvVuln]}``.

    ``/v1/querybatch`` ile tüm paketlerin zafiyet kimlikleri tek/birkaç istekte alınır; sonra
    yalnız ZAFİYETLİ advisory'lerin detayı (CVE/önem) çekilir (``max_details`` ile sınırlı).
    Hata/timeout'ta kısmî sonuç döner (o paket atlanır). Tamamen okuma — hedefe dokunmaz.
    """
    out: dict[tuple[str, str], list[OsvVuln]] = {}
    if not packages:
        return out
    queries = [
        {"version": ver, "package": {"name": name, "ecosystem": ecosystem}}
        for name, ver in packages
    ]
    pkg_ids: list[list[str]] = []
    detail_cache: dict[str, OsvVuln] = {}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            for start in range(0, len(queries), 500):
                resp = await client.post(
                    OSV_BATCH_URL, json={"queries": queries[start : start + 500]}
                )
                resp.raise_for_status()
                for result in resp.json().get("results", []):
                    pkg_ids.append(
                        [str(v["id"]) for v in (result.get("vulns") or []) if v.get("id")]
                    )
            while len(pkg_ids) < len(packages):
                pkg_ids.append([])
            unique: list[str] = []
            seen: set[str] = set()
            for ids in pkg_ids:
                for vid in ids:
                    if vid not in seen:
                        seen.add(vid)
                        unique.append(vid)
            for vid in unique[:max_details]:
                try:
                    dresp = await client.get(f"{OSV_VULN_URL}{vid}")
                    dresp.raise_for_status()
                    detail_cache[vid] = vuln_from_detail(dresp.json())
                except (httpx.HTTPError, ValueError):
                    detail_cache[vid] = OsvVuln(id=vid)
    except (httpx.HTTPError, ValueError):
        return out
    for (name, ver), ids in zip(packages, pkg_ids, strict=False):
        vulns = [detail_cache[v] for v in ids if v in detail_cache]
        if vulns:
            out[(name, ver)] = vulns
    return out
