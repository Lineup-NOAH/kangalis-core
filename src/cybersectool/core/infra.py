"""Aracın kendi altyapı (container) IP'lerini tespit — tarama/envanterden dışlama.

Müşteri kurulumunda araç bir docker-compose yığını olarak çalışır (app/worker/beat/
mcp/db/redis). Bu container'ların kendi IP'leri (ör. 172.18.0.x) tarama hedefiyle
aynı köprü ağındaysa envantere "junk" olarak düşebilir. Burası onları tek yerden
tespit eder; hem envanter gösterimi (VI-10) hem tarama hedefi seçimi (VI-7) kullanır.
"""

from __future__ import annotations

import os
import socket

# Aracın kendi docker-compose servis adları → Docker DNS içinde kendi container
# IP'lerine çözülür (Docker dışında/testlerde çözülmez → sessizce atlanır).
_OWN_SERVICE_HOSTNAMES = ("app", "worker", "beat", "mcp", "db", "redis")


def own_infra_ips() -> set[str]:
    """Aracın kendi container IP'leri + ``EXCLUDE_SCAN_IPS`` env'i (virgül/; ile ayrılmış).

    Tarama ve envanterden dışlanacak IP kümesini döner. DNS çözümü başarısızsa
    (Docker dışı ortam) o ad atlanır — fonksiyon asla patlamaz, en kötü boş döner.
    """
    ips: set[str] = set()
    for host in _OWN_SERVICE_HOSTNAMES:
        try:
            for info in socket.getaddrinfo(host, None):
                addr = str(info[4][0])
                if addr:
                    ips.add(addr)
        except (OSError, socket.gaierror):
            continue
    extra = os.environ.get("EXCLUDE_SCAN_IPS", "")
    for tok in extra.replace(";", ",").split(","):
        cleaned = tok.strip()
        if cleaned:
            ips.add(cleaned)
    return ips
