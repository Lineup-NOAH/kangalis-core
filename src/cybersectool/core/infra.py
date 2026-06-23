"""Aracın kendi altyapı (container) IP'lerini tespit — tarama/envanterden dışlama.

Müşteri kurulumunda araç bir docker-compose yığını olarak çalışır (app/worker/beat/
mcp/db/redis). Bu container'ların kendi IP'leri (ör. 172.18.0.x) tarama hedefiyle
aynı köprü ağındaysa envantere "junk" olarak düşebilir. Burası onları tek yerden
tespit eder; hem envanter gösterimi (VI-10) hem tarama hedefi seçimi (VI-7) kullanır.
"""

from __future__ import annotations

import os
import socket
import threading
from functools import lru_cache

# Aracın kendi docker-compose servis adları → Docker DNS içinde kendi container
# IP'lerine çözülür (Docker dışında/testlerde çözülmez → sessizce atlanır).
_OWN_SERVICE_HOSTNAMES = ("app", "worker", "beat", "mcp", "db", "redis")

# Tek bir ad çözümünün azami süresi (sn). Docker/k8s DNS'i bu adları anında çözer; container
# DIŞINDA (geliştirme/test) çözülmezler ve bazı platformlarda (özellikle Windows: LLMNR/NetBIOS
# geri-dönüşleri) getaddrinfo hızlı-fail yerine dakikalarca BLOKLAR. Kısa timeout, rapor üretimini
# (own_infra_ips çağıran kod yolu) yavaş/patolojik DNS'te asılı kalmaktan korur.
_RESOLVE_TIMEOUT_SEC = 1.0


def _resolve_host_ips(host: str, timeout: float = _RESOLVE_TIMEOUT_SEC) -> set[str]:
    """``host``'u getaddrinfo ile çözer; en çok ``timeout`` sn bekler (bloklamayı sınırlar).

    Çözüm bir daemon thread'de yapılır; süre aşılırsa boş küme döner (thread arkada kalır,
    getaddrinfo sonunda dönünce ya da süreçle ölür). Asla istisna fırlatmaz.
    """
    out: set[str] = set()

    def _worker() -> None:
        try:
            for info in socket.getaddrinfo(host, None):
                addr = str(info[4][0])
                if addr:
                    out.add(addr)
        except OSError:  # socket.gaierror dahil — ad çözülmedi
            pass

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    thread.join(timeout)
    return set() if thread.is_alive() else out


@lru_cache(maxsize=1)
def _resolved_infra_ips() -> frozenset[str]:
    """Kendi servis adlarının çözülen IP'leri — süreç başına BİR KEZ (DNS sabit, pahalı değil).

    Container IP'leri süreç ömründe değişmez; her ``own_infra_ips`` çağrısında yeniden çözmek
    (özellikle Windows'ta yavaş getaddrinfo ile) rapor üretimini gereksiz yavaşlatırdı.
    """
    acc: set[str] = set()
    for host in _OWN_SERVICE_HOSTNAMES:
        acc |= _resolve_host_ips(host)
    return frozenset(acc)


def own_infra_ips() -> set[str]:
    """Aracın kendi container IP'leri + ``EXCLUDE_SCAN_IPS`` env'i (virgül/; ile ayrılmış).

    Tarama ve envanterden dışlanacak IP kümesini döner. DNS çözümü başarısız ya da yavaşsa
    (Docker dışı ortam) o ad atlanır — fonksiyon asla patlamaz/uzun bloklamaz, en kötü boş döner.
    Çözülen IP'ler önbelleklenir; ``EXCLUDE_SCAN_IPS`` env'i her çağrıda taze okunur.
    """
    ips: set[str] = set(_resolved_infra_ips())
    extra = os.environ.get("EXCLUDE_SCAN_IPS", "")
    for tok in extra.replace(";", ",").split(","):
        cleaned = tok.strip()
        if cleaned:
            ips.add(cleaned)
    return ips
