"""PR-OSS-0 değişmezleri — sömürü eklentisi (kapalı/ticari, opsiyonel) ÇIKARILABİLİR olmalı.

Açık-kaynak çekirdek/sömürü-eklentisi ayrımının ilk adımı: çekirdek tarama/web/route/celery
katmanları ``cybersectool.exploit`` paketini MODÜL-ÜSTÜ KOŞULSUZ import etmemeli. Aksi halde
eklenti fiziksel kaldırılınca worker+web import-zamanında çöker (yalnız sömürü değil, TÜM tarama
durur). Bu testler import'ların GEÇ/KOŞULLU (fonksiyon-içi / try-except) kaldığını kilitler —
biri yanlışlıkla modül-üstüne geri taşırsa kırmızı yanar.

Not: sömürü eklentisi (``cybersectool.exploit``) bu açık-kaynak repoda YOK (çıkarıldı). Bu yüzden
seam testi tersine doğrular: eklenti import edilince ImportError gelir VE PoC-çalıştırma görevi
celery include listesine eklenMEZ; buna karşın çekirdek intel-besleme + tarama görevleri (eklenti
import etmez) HER ZAMAN kayıtlıdır → eklenti yokken worker+web bozulmadan boot eder.
"""

from __future__ import annotations

import pytest

import cybersectool.tasks.network_scan as network_scan
import cybersectool.tasks.web_scan as web_scan
import cybersectool.web.routes as routes
from cybersectool.tasks.celery_app import _task_modules

# Sömürü eklentisi (exploit/) sembolleri — çekirdek görev/route modüllerinde MODÜL-ÜSTÜ
# görünmemeli (geç import → fonksiyon yerel ad, modül attribute'u DEĞİL).
_EXPLOIT_RUNTIME_SYMBOLS = (
    "msf_client",
    "stage_exploitdb_attempts",
    "run_exploitation_for_scan",
)


def test_network_scan_has_no_module_level_exploit_import() -> None:
    for sym in _EXPLOIT_RUNTIME_SYMBOLS:
        assert not hasattr(network_scan, sym), (
            f"network_scan.{sym} modül-üstünde — sömürü import'u geç (fonksiyon-içi) olmalı"
        )


def test_web_scan_has_no_module_level_exploit_import() -> None:
    for sym in _EXPLOIT_RUNTIME_SYMBOLS:
        assert not hasattr(web_scan, sym), (
            f"web_scan.{sym} modül-üstünde — sömürü import'u geç (fonksiyon-içi) olmalı"
        )


def test_routes_has_no_module_level_exploit_exec_import() -> None:
    # Sömürü-ÇALIŞTIRMA sembolleri (PoC sandbox + komut doğrulama) çekirdek web katmanında
    # modül-üstü olmamalı; ilgili route handler'ları bunları fonksiyon-içi import eder.
    for sym in (
        "exploitdb_run_task",
        "stop_poc",
        "validate_override_command",
        "extract_ip_candidates",
    ):
        assert not hasattr(routes, sym), (
            f"routes.{sym} modül-üstünde — eklenti yokken web katmanı boot edemez"
        )


def test_celery_registers_exploit_task_only_when_addon_present() -> None:
    # Eklenti bu açık-kaynak repoda YOK → import ImportError vermeli (paket fiziksel kaldırıldı).
    with pytest.raises(ImportError):
        import cybersectool.exploit  # noqa: F401  (paket yok mu?)

    # Eklenti olmadığından PoC-çalıştırma görevi include listesine eklenMEMELİ.
    assert "cybersectool.tasks.exploitdb_run" not in _task_modules
    # Çekirdek intel-besleme + tarama görevleri (exploit/ import etMEZ) HER ZAMAN kayıtlı olmalı.
    assert "cybersectool.tasks.exploit_sync" in _task_modules
    assert "cybersectool.tasks.exploit_freshness" in _task_modules
    assert "cybersectool.tasks.network_scan" in _task_modules
