"""Yerel LLM düşük-seviye HTTP istemcisi — YETENEĞE BAĞIMSIZ, OpenAI-UYUMLU.

Bu katman UYGULAMAYI BİLMEZ (bulgu/rapor/exploit kavramı yok): yalnız bir endpoint'e prompt
yollayıp metin döndürür. Faz 1 (raporlama) ve Faz 2 (exploit hazırlama) aynı istemciyi paylaşır.

OpenAI-uyumlu ``/v1/chat/completions`` protokolü konuşur → yerel motorların ORTAK standardı:
**llama.cpp server**, **LM Studio**, **LocalAI**, **vLLM** vb. hepsiyle çalışır (tek bir bespoke
runtime'a — Ollama'ya — bağlı DEĞİL). Endpoint OpenAI taban URL'idir (genelde ``.../v1``).

Sıfır egress: çağrı yalnız müşteri ağındaki yerel motora gider (compose 'ai' profili ya da
host'taki native motor). Hiçbir veri buluta/dışarı çıkmaz.

Hata politikası: her şey graceful — endpoint boş/erişilemez/timeout/HTTP hatası → ``None``
döner (asla exception fırlatmaz) ki çağıran daima statik Remediation'a düşebilsin.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Akıl-yürüten modeller (qwen3 vb.) çıktıya ``<think>...</think>`` bloğu gömer — bu, kullanıcıya
# gösterilecek rapor metni DEĞİL, modelin iç düşünmesidir. Üretilen metni döndürmeden önce ayıkla.
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def _strip_think(text: str) -> str:
    """Model çıktısından ``<think>...</think>`` akıl-yürütme bloklarını ayıklar."""
    return _THINK_RE.sub("", text).strip()


async def generate(
    endpoint: str,
    model: str,
    prompt: str,
    *,
    system: str = "",
    timeout: float = 60.0,
    options: dict[str, Any] | None = None,
) -> str | None:
    """OpenAI-uyumlu ``/chat/completions`` çağrısı (stream=false) → üretilen metin ya da ``None``.

    Args:
        endpoint: OpenAI taban URL'i (ör. ``http://llamacpp:8080/v1``). Boşsa ``None`` döner.
        model: Model adı/etiketi (ör. ``qwen3:8b``). Tek-model sunan motorlarda (llama.cpp)
            etiket olabilir; çok-model sunanlarda (LM Studio) yüklü model id'siyle eşleşmeli.
            Boşsa ``None`` döner.
        prompt: Kullanıcı prompt'u (grounded içerik buraya gömülür).
        system: Opsiyonel sistem yönergesi (rol/biçim/dil talimatı) → ``system`` rol mesajı.
        timeout: Üst zaman aşımı (saniye). CPU çıkarımı yavaştır → cömert tutulur.
        options: Payload'a EKLENEN üst-seviye OpenAI parametreleri (ör. ``{"temperature": 0.2}``).

    Erişilemez/timeout/HTTP hatası/beklenmeyen yanıt → ``None`` (loglanır, fırlatılmaz).
    """
    if not endpoint or not model:
        return None
    url = endpoint.rstrip("/") + "/chat/completions"
    messages: list[dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    payload: dict[str, Any] = {"model": model, "messages": messages, "stream": False}
    if options:
        payload.update(options)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("AI üretimi başarısız (%s): %s", url, exc)
        return None
    text = _extract_message(data)
    if text is None:
        return None
    cleaned = _strip_think(text)
    return cleaned or None


def _extract_message(data: Any) -> str | None:
    """OpenAI yanıtından ``choices[0].message.content`` çıkarır (beklenmeyen şekil → None)."""
    if not isinstance(data, dict):
        return None
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    return content if isinstance(content, str) else None


async def list_models(endpoint: str, *, timeout: float = 10.0) -> list[str] | None:
    """OpenAI-uyumlu ``/models`` → sunulan model id'leri (bağlantı testi için).

    Erişilemezse ``None`` (bağlantı yok); erişilirse model id listesi (boş olabilir).
    """
    if not endpoint:
        return None
    url = endpoint.rstrip("/") + "/models"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("AI model listesi alınamadı (%s): %s", url, exc)
        return None
    raw = data.get("data", []) if isinstance(data, dict) else []
    ids = [m.get("id", "") for m in raw if isinstance(m, dict)]
    return [i for i in ids if i]
