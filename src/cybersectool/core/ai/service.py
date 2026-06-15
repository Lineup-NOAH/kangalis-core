"""Yerel AI servisi — YETENEĞE BAĞIMSIZ orkestrasyon (config çöz + istemciyi çağır).

``client``'i sarar: endpoint/model/timeout'u çözer, AI etkin mi denetler, üretimi yapar.
AI kapalı/erişilemez ise ``None`` döner (asla patlamaz). Bu katman da uygulamayı BİLMEZ —
bulgu/rapor/exploit'e coupling yoktur; Faz 1 ve Faz 2 ortak kullanır.

Config çözümü: çalışma-anı kaynağı **AppSettings** (admin UI; ``ai_enabled``/model/endpoint/
timeout). AppSettings alanı boşsa ``config.py`` deployment varsayılanına (env) düşülür. Böylece
hem UI'dan yönetilebilir hem env ile override edilebilir.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from typing import Any

from cybersectool.config import settings
from cybersectool.core.ai import client

# Dil koruması — tüm sistem yönergelerine üretim anında eklenir. Yerel modeller (ör. qwen3,
# Çince kökenli) ara sıra Latin-dışı karakter sızdırıyor; bu Türkçe rapor çıktısını bozar.
# Tek yerde (üretim katmanı) zorlanır → mevcut + gelecek tüm AI yüzeyleri kapsanır.
_LANG_GUARD = (
    " Çok önemli: yanıtın TAMAMINI Türkçe ve YALNIZCA Latin alfabesiyle yaz; "
    "Çince/Kiril/Arap gibi Latin-dışı hiçbir karakter kullanma."
)


@dataclass(frozen=True, slots=True)
class AIConfig:
    """Çözülmüş AI çalışma-anı yapılandırması (yeteneğe bağımsız).

    ``available`` True ise üretim denenebilir; değilse çağıran statik içeriğe düşmelidir.
    """

    enabled: bool
    endpoint: str
    model: str
    timeout: float = 60.0

    @property
    def available(self) -> bool:
        """Üretim için gerekli her şey hazır mı (etkin + endpoint + model)."""
        return self.enabled and bool(self.endpoint) and bool(self.model)

    @classmethod
    def from_app_settings(cls, row: Any | None) -> AIConfig:
        """AppSettings satırından (admin UI) AIConfig kur; boş alanlarda env'e düş.

        ``row`` None ise ya da AI alanları henüz yoksa env varsayılanları kullanılır (graceful;
        ai_enabled varsayılan False → AI kapalı). endpoint OpenAI taban URL'idir (``.../v1``).
        """
        enabled = bool(getattr(row, "ai_enabled", False))
        endpoint = (getattr(row, "ai_endpoint_url", "") or "").strip() or settings.ai_endpoint
        model = (getattr(row, "ai_model_name", "") or "").strip() or settings.ai_model
        timeout = getattr(row, "ai_timeout_sec", None) or settings.ai_timeout
        return cls(
            enabled=enabled,
            endpoint=endpoint,
            model=model,
            timeout=float(timeout),
        )


def ai_available(config: AIConfig | None) -> bool:
    """AI kullanılabilir mi (None-güvenli kısayol — UI butonlarını göstermek için)."""
    return config is not None and config.available


async def generate(
    config: AIConfig,
    prompt: str,
    *,
    system: str = "",
    options: dict[str, Any] | None = None,
) -> str | None:
    """Verilen config ile metin üret. AI kapalı/erişilemez → ``None`` (graceful).

    Sistem yönergesi verildiyse ``_LANG_GUARD`` eklenir (Latin-dışı karakter sızıntısını önler).
    """
    if not config.available:
        return None
    return await client.generate(
        config.endpoint,
        config.model,
        prompt,
        system=(system + _LANG_GUARD) if system else system,
        timeout=config.timeout,
        options=options,
    )


async def list_models(config: AIConfig) -> list[str] | None:
    """Endpoint'teki kurulu modelleri listele (bağlantı testi). Erişilemezse ``None``."""
    return await client.list_models(config.endpoint, timeout=min(config.timeout, 10.0))


# Kurulum sihirbazının (Faz 1 çatısı) yokladığı aday yerel-AI endpoint'leri — HEPSİ müşteri ağı
# içi (sıfır egress). Öneri mantığı host-native'i önceler: container imaj/katman zincirini (yaşanan
# overlay2/WSL2 storage bozulması sınıfı) baypas eder. (host, label, endpoint).
_AI_CANDIDATES: tuple[tuple[str, str, str], ...] = (
    ("ollama-host", "Ollama (host-native)", "http://host.docker.internal:11434/v1"),
    ("lmstudio-host", "LM Studio (host-native)", "http://host.docker.internal:1234/v1"),
    ("bundled", "Gömülü container (llamacpp)", "http://llamacpp:8080/v1"),
)
# Algılama yoklaması kısa zaman aşımıyla yapılır (erişilemez aday tüm sihirbazı bekletmesin).
_DETECT_TIMEOUT = 4.0


def _host_internal_reachable() -> bool:
    """``host.docker.internal`` DNS olarak çözülüyor mu — host-native yol uygulanabilir mi.

    Docker Desktop (Win/Mac) bunu daima sağlar; Linux'ta compose ``extra_hosts: host-gateway``
    eklendiyse çözülür. Çözülmüyorsa host-native motor (Companion/LM Studio) yolu kullanılamaz →
    sihirbaz operatörü gömülü container ya da kurumsal endpoint'e yönlendirir.
    """
    try:
        socket.gethostbyname("host.docker.internal")
    except OSError:
        return False
    return True


async def _probe_candidate(key: str, label: str, endpoint: str, model: str) -> dict[str, Any]:
    """Tek bir aday endpoint'i yoklar (erişilebilir mi + sunulan modeller). Asla patlamaz."""
    models = await list_models(AIConfig(True, endpoint, model, _DETECT_TIMEOUT))
    return {
        "key": key,
        "label": label,
        "endpoint": endpoint,
        "ok": models is not None,
        "models": models or [],
    }


async def detect_ai_paths(row: Any | None = None) -> dict[str, Any]:
    """Ortamı yoklayıp erişilebilir yerel-AI motorlarını + önerilen yolu döndürür (sihirbaz çatısı).

    Aday endpoint'leri (host-native Ollama/LM Studio + gömülü container + varsa kayıtlı kurumsal)
    EŞZAMANLI yoklar. Öneri sırası: çalışan host-native (container storage'ını baypas eder) >
    kayıtlı kurumsal > gömülü container > (host erişilebilir ama motor yok → Companion kur) >
    (hiçbiri → gömülü/BYO). Tamamen okuma; hiçbir şeyi ETKİNLEŞTİRMEZ (admin yine Kaydet'e basar).
    """
    cfg = AIConfig.from_app_settings(row)
    candidates = list(_AI_CANDIDATES)
    saved = (getattr(row, "ai_endpoint_url", "") or "").strip()
    if saved and all(saved != endpoint for _, _, endpoint in candidates):
        candidates.append(("configured", "Yapılandırılmış endpoint", saved))
    results = await asyncio.gather(
        *(_probe_candidate(key, label, endpoint, cfg.model) for key, label, endpoint in candidates)
    )
    host_reachable = await asyncio.to_thread(_host_internal_reachable)
    by_key = {str(r["key"]): r for r in results}

    def _ok(key: str) -> bool:
        cand = by_key.get(key)
        return bool(cand and cand["ok"])

    if _ok("ollama-host"):
        recommended = "ollama-host"
    elif _ok("lmstudio-host"):
        recommended = "lmstudio-host"
    elif _ok("configured"):
        recommended = "configured"
    elif _ok("bundled"):
        recommended = "bundled"
    elif host_reachable:
        recommended = "install-companion"  # host var ama motor yok → Windows Companion kur
    else:
        recommended = "install"  # erişilebilir motor yok → gömülü profil ya da kurumsal endpoint
    return {"host_reachable": host_reachable, "candidates": results, "recommended": recommended}
