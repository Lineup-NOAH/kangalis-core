"""Yerel (on-prem) AI motoru — OpenAI-uyumlu, yeteneğe bağımsız.

Bu paket Kangalis'in YEREL AI asistanının ortak motorudur: müşteri ağından çıkmayan (sıfır
egress), CPU'da koşan bir LLM'e prompt yollar, metin döndürür. İstemci OpenAI ``/v1`` protokolü
konuşur → llama.cpp / LM Studio / LocalAI gibi yerel motorların hepsiyle çalışır. Katmanlar:

* ``client``  — düşük-seviye HTTP istemcisi (uygulamayı BİLMEZ: bulgu/rapor/exploit yok).
* ``service`` — yeteneğe bağımsız orkestrasyon: config çöz (``AIConfig``) + istemciyi çağır;
  AI kapalı/erişilemez ise ``None`` (asla patlamaz).

Faz 1 (raporlama: bulgu açıklama + rapor özeti) ve Faz 2 (exploit hazırlama) AYNI motoru
kullanır — coupling yok ki Faz 2 refactor'suz eklensin. AI her zaman kapı yığınının
upstream'indedir: yalnız metin üretir, hiçbir şeyi kendi tetiklemez.
"""

from __future__ import annotations

from cybersectool.core.ai.service import (
    AIConfig,
    ai_available,
    detect_ai_paths,
    generate,
    list_models,
)

# AI-OPSİYONEL SÖZLEŞMESİ (değişmez kurallar — uygulama AI'a BEL BAĞLAMADAN tam çalışır).
# tests/test_ai_optionality.py bunları CI'da zorlar; her yeni AI özelliğinden ÖNCE yeşil olmalı.
AI_OPTIONAL_CONTRACT: tuple[str, ...] = (
    "ai_enabled AppSettings'te varsayılan False; AI'ın tek aç/kapa anahtarıdır.",
    "Çekirdek motor + bildirim modülleri (core/remediation, core/findings, core/vuln, "
    "core/scans, core/exploits, core/exploit_attempts, core/notify, exploit/*, tasks/*, "
    "scanners/*) 'cybersectool.core.ai'dan İTHAL ETMEZ — AI yalnız web/settings'ten bağlanır; "
    "notify özeti AIExplanation önbelleğinden salt-okunur çeker (üretmez, yoksa atlar).",
    "generate()/list_models()/detect_ai_paths() AI kapalı/erişilemez/timeout'ta None döner; "
    "ASLA exception fırlatmaz (graceful).",
    "Her AI route üretimden ÖNCE ai_available(config) ile gate'lenir; AI yoksa HTTP 200 "
    "graceful hata/no-op fragmenti döner (asla 500).",
    "Tüm AI UI öğeleri şablonda {% if ai_enabled %} ile sarılır; AI kapalıyken DOM'da YOKtur.",
    "AI çıktısı DETERMİNİSTİK motoru (risk sırası, uyum eşlemesi, exploit özeti, parola "
    "politikası) DEĞİŞTİRMEZ — yalnız anlatır; AI hiçbir şeyi kendi ATEŞLEMEZ (insan-tetiği).",
    "Üretim yalnız iç-ağ endpoint'ine gider (sıfır-egress); client.py tek çıkış noktasıdır.",
)

__all__ = [
    "AI_OPTIONAL_CONTRACT",
    "AIConfig",
    "ai_available",
    "detect_ai_paths",
    "generate",
    "list_models",
]
