"""Sistem/altyapı sağlığı — platformun Docker konteynerlerinin durumu + kaynak kullanımı.

Docker Engine API'sine ``/var/run/docker.sock`` üzerinden (yalnız GET: list + stats + df)
bağlanır; httpx'in unix-soket transport'unu kullanır → YENİ BAĞIMLILIK YOK. Soket yoksa ya da
erişilemezse ``available=False`` döner ve UI nazik bir mesaj gösterir (çökme yok).

GÜVENLİK: docker.sock'a erişim = Docker daemon'una erişim. Bu modül SADECE okuma (list/stats/
df) yapar; asla create/stop/exec değil. Soketi konteynere mount etmek OPERATÖRÜN tercihidir
(docker-compose). Sayfa yalnız admin'e açıktır.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
from dataclasses import dataclass, field
from typing import Any

import httpx

# Docker Engine API soket yolu (compose'ta app'e mount edilir). Ortamdan override edilebilir.
DOCKER_SOCK = os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")
_TIMEOUT = 8.0


@dataclass
class ContainerStat:
    """Tek bir konteynerin anlık durumu + kaynak kullanımı."""

    name: str
    image: str
    state: str  # running / exited / created / paused …
    status: str  # "Up 2 hours" / "Exited (0) 3 minutes ago" …
    cpu_pct: float | None = None
    mem_used: int | None = None  # bayt
    mem_limit: int | None = None  # bayt
    mem_pct: float | None = None


@dataclass
class DiskInfo:
    total: int
    used: int
    free: int
    pct: float


@dataclass
class SystemHealth:
    """Sistem paneli için toplu sağlık görünümü."""

    available: bool = False  # Docker soketi okunabildi mi?
    error: str | None = None
    containers: list[ContainerStat] = field(default_factory=list)
    disk: DiskInfo | None = None  # host/VM kök disk
    mem_total: int | None = None  # host/VM RAM (bayt)
    mem_used: int | None = None
    docker_disk: int | None = None  # docker imaj+volume toplam (bayt)


def _host_disk() -> DiskInfo | None:
    try:
        u = shutil.disk_usage("/")
    except OSError:
        return None
    pct = round(u.used / u.total * 100, 1) if u.total else 0.0
    return DiskInfo(total=u.total, used=u.used, free=u.free, pct=pct)


def _host_mem() -> tuple[int | None, int | None]:
    """``/proc/meminfo``'dan (varsa) toplam ve kullanılan RAM (bayt)."""
    try:
        info: dict[str, int] = {}
        with open("/proc/meminfo") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                parts = rest.strip().split()
                if parts:
                    info[key.strip()] = int(parts[0]) * 1024  # kB → bayt
    except (OSError, ValueError):
        return None, None
    total = info.get("MemTotal")
    avail = info.get("MemAvailable")
    if total is None:
        return None, None
    used = total - avail if avail is not None else None
    return total, used


def _cpu_pct(stats: dict[str, Any]) -> float | None:
    """Docker stats anlık görüntüsünden CPU yüzdesi (docker CLI formülü)."""
    try:
        cpu = stats["cpu_stats"]
        pre = stats["precpu_stats"]
        cpu_delta = float(cpu["cpu_usage"]["total_usage"] - pre["cpu_usage"]["total_usage"])
        sys_delta = float(cpu["system_cpu_usage"] - pre.get("system_cpu_usage", 0))
        ncpu = float(cpu.get("online_cpus") or len(cpu["cpu_usage"].get("percpu_usage") or []) or 1)
    except (KeyError, TypeError, ValueError):
        return None
    if cpu_delta > 0 and sys_delta > 0:
        return round(cpu_delta / sys_delta * ncpu * 100, 1)
    return 0.0


def _mem_used(mem: dict[str, Any]) -> int | None:
    """Kullanılan bellek (cache düşülmüş, docker CLI gibi)."""
    usage = mem.get("usage")
    if usage is None:
        return None
    stats = mem.get("stats") or {}
    cache = stats.get("inactive_file") or stats.get("cache") or 0
    return max(0, int(usage) - int(cache))


async def _fetch_stats(client: httpx.AsyncClient, cid: str) -> dict[str, Any] | None:
    try:
        resp = await client.get(f"/containers/{cid}/stats", params={"stream": "false"})
        data: dict[str, Any] = resp.json()
        return data
    except (httpx.HTTPError, ValueError):
        return None


def _docker_disk(df: dict[str, Any]) -> int:
    """imaj katmanları + volume'lerin yaklaşık disk kullanımı (bayt)."""
    total = int(df.get("LayersSize") or 0)
    for vol in df.get("Volumes") or []:
        total += int((vol.get("UsageData") or {}).get("Size") or 0)
    return total


def _compose_project(container: dict[str, Any]) -> str | None:
    return (container.get("Labels") or {}).get("com.docker.compose.project")


def _filter_own_project(
    raw: list[dict[str, Any]], own_id: str, override: str | None = None
) -> list[dict[str, Any]]:
    """Yalnız UYGULAMANIN kendi compose projesindeki konteynerleri tutar.

    Lab/zafiyet fixture'ları (kg-*) ve ilgisiz konteynerler ayrı bir compose projesinde
    olduğu için elenir. Proje, uygulamanın KENDİ konteynerinin (HOSTNAME = konteyner kimliği)
    ``com.docker.compose.project`` etiketinden bulunur; ``override`` (env) verilirse o kullanılır.
    Proje tespit edilemezse filtreleme yapılmaz (güvenli düşüş).
    """
    project = override
    if not project and own_id:
        for c in raw:
            if str(c.get("Id") or "").startswith(own_id):
                project = _compose_project(c)
                break
    if not project:
        return raw
    return [c for c in raw if _compose_project(c) == project]


async def system_health() -> SystemHealth:
    """Konteyner durumları + host disk/RAM'i toplar (Docker soketi GET ile)."""
    health = SystemHealth()
    health.disk = _host_disk()
    health.mem_total, health.mem_used = _host_mem()
    if not os.path.exists(DOCKER_SOCK):
        health.error = "Docker soketi bulunamadı — docker.sock konteynere mount edilmemiş."
        return health
    transport = httpx.AsyncHTTPTransport(uds=DOCKER_SOCK)
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://docker", timeout=_TIMEOUT
        ) as client:
            resp = await client.get("/containers/json", params={"all": "1"})
            resp.raise_for_status()
            raw: list[dict[str, Any]] = resp.json()
            # Yalnız uygulamanın kendi konteynerleri (lab/zafiyet fixture'ları hariç).
            raw = _filter_own_project(
                raw, os.environ.get("HOSTNAME", ""), os.environ.get("SYSTEM_PANEL_PROJECT")
            )
            with contextlib.suppress(httpx.HTTPError, ValueError):
                health.docker_disk = _docker_disk((await client.get("/system/df")).json())
            running = [c for c in raw if c.get("State") == "running"]
            stats_list = await asyncio.gather(*[_fetch_stats(client, c["Id"]) for c in running])
            stats_by_id = {c["Id"]: s for c, s in zip(running, stats_list, strict=False)}
            containers: list[ContainerStat] = []
            for c in raw:
                name = (c.get("Names") or ["?"])[0].lstrip("/")
                cs = ContainerStat(
                    name=name,
                    image=str(c.get("Image") or ""),
                    state=str(c.get("State") or ""),
                    status=str(c.get("Status") or ""),
                )
                stat = stats_by_id.get(c["Id"])
                if stat:
                    cs.cpu_pct = _cpu_pct(stat)
                    mem = stat.get("memory_stats") or {}
                    cs.mem_used = _mem_used(mem)
                    cs.mem_limit = mem.get("limit")
                    if cs.mem_used is not None and cs.mem_limit:
                        cs.mem_pct = round(cs.mem_used / cs.mem_limit * 100, 1)
                containers.append(cs)
            containers.sort(key=lambda x: (x.state != "running", x.name))
            health.containers = containers
            health.available = True
    except (httpx.HTTPError, OSError, ValueError) as exc:
        health.error = f"Docker API hatası: {exc}"
    return health
