"""Celery uygulaması — Redis broker/backend ile arka plan görevleri."""

from __future__ import annotations

from celery import Celery

from cybersectool.config import settings

# Çekirdek görev modülleri (tarama/CVE/rapor/zamanlama/intel-besleme) — her zaman kayıtlı.
# Not: exploit_sync/exploit_freshness ÇEKİRDEKTİR (yalnız intel besler; exploit/ paketini
# import etMEZ) — sömürü eklentisi olmadan da çalışırlar.
_task_modules = [
    "cybersectool.tasks.example",
    "cybersectool.tasks.network_scan",
    "cybersectool.tasks.ping_scan",
    "cybersectool.tasks.web_scan",
    "cybersectool.tasks.sca_scan",
    "cybersectool.tasks.scheduled",
    "cybersectool.tasks.exploit_sync",
    "cybersectool.tasks.exploit_freshness",
    "cybersectool.tasks.cpe_sync",
    "cybersectool.tasks.epss_refresh",
    "cybersectool.tasks.ldap_sync",
]

# Sömürü eklentisi (kapalı/ticari, OPSİYONEL): PoC-çalıştırma görevi yalnız ``cybersectool.exploit``
# paketi KURULUYSA kaydedilir. Paket yoksa worker yine de boot eder (açık-kaynak çekirdek tarama/
# CVE/rapor tam çalışır, yalnız sömürü çalıştırma görevi yoktur). Hafif var-mı testi (yalnız paket
# __init__'i; alt-modülleri ya da pymetasploit3'ü çekmez, döngüsel-import riski yok).
try:
    import cybersectool.exploit  # noqa: F401

    _task_modules.append("cybersectool.tasks.exploitdb_run")
except ImportError:
    pass

celery_app = Celery(
    "cybersectool",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=_task_modules,
)
celery_app.conf.task_track_started = True
celery_app.conf.beat_schedule = {
    "check-scheduled-scans": {
        "task": "check_scheduled_scans",
        "schedule": 60.0,  # her 60 saniyede bir zamanlanmış taramaları kontrol et
    },
    "exploit-db-sync": {
        "task": "exploit_sync",
        "schedule": 86400.0,  # günde bir: exploit DB'yi (NVD/Exploit-DB/Metasploit) tazele
    },
    "exploit-freshness-check": {
        "task": "exploit_freshness",
        "schedule": 3600.0,  # saatte bir: upstream'e bakıp güncel/güncel-değil işaretle
    },
    "cpe-sync": {
        "task": "cpe_sync",
        "schedule": 86400.0,  # günde bir: offline CPE/CVE indeksini tazele
    },
    "epss-refresh": {
        "task": "epss_refresh",
        "schedule": 86400.0,  # günde bir: EPSS skorlarını tazele + risk skorlarını yeniden uygula
    },
    "ldap-sync-check": {
        "task": "ldap_sync",
        "schedule": 3600.0,  # saatte bir: LDAP senkron zamanı geldiyse kullanıcıları çek (X-6)
    },
}
