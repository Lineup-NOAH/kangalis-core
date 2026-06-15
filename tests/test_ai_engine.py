"""Yerel AI motoru (yeteneğe bağımsız) testleri — client + service, mock OpenAI motoruyla.

Gerçek motor gerekmez: httpx.MockTransport ile OpenAI ``/v1/chat/completions`` & ``/v1/models``
taklit edilir. Kritik invariant: AI kapalı/erişilemez/hatalı → her zaman ``None`` (asla patlamaz)
→ çağıran statik Remediation'a graceful düşer.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from cybersectool.core.ai import cache as ai_cache
from cybersectool.core.ai import client as ai_client
from cybersectool.core.ai import service as ai_service
from cybersectool.core.ai.service import AIConfig

BASE = "http://llamacpp:8080/v1"


def _chat(content: str) -> dict[str, Any]:
    """OpenAI /chat/completions yanıt gövdesi."""
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


def _models(ids: list[str]) -> dict[str, Any]:
    """OpenAI /models yanıt gövdesi."""
    return {"data": [{"id": i} for i in ids]}


def _mock_httpx(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    """client modülündeki httpx.AsyncClient'i MockTransport'lu istemciyle değiştirir."""
    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs.pop("transport", None)
        return real_client(*args, transport=transport, **kwargs)

    monkeypatch.setattr(ai_client.httpx, "AsyncClient", factory)


# --- client.generate ---


async def test_generate_success(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = request.content
        return httpx.Response(200, json=_chat("  Açıklama metni.  "))

    _mock_httpx(monkeypatch, handler)
    out = await ai_client.generate(BASE, "qwen3:8b", "neden?", system="Sen analistsin")
    assert out == "Açıklama metni."  # baştaki/sondaki boşluk kırpıldı
    assert seen["url"].endswith("/chat/completions")  # OpenAI chat endpoint'i
    assert b'"stream":false' in seen["body"]  # stream kapalı (httpx kompakt JSON)
    assert b'"role":"system"' in seen["body"]  # sistem yönergesi mesaj olarak gömüldü


async def test_generate_strips_think_block(monkeypatch: pytest.MonkeyPatch) -> None:
    """qwen3 gibi akıl-yürüten modellerin <think>...</think> bloğu çıktıdan ayıklanır."""

    def handler(_req: httpx.Request) -> httpx.Response:
        body = "<think>kullanıcı CVE soruyor, CVSS yüksek</think>\nGerçek çözüm adımı."
        return httpx.Response(200, json=_chat(body))

    _mock_httpx(monkeypatch, handler)
    out = await ai_client.generate(BASE, "qwen3:8b", "p")
    assert out == "Gerçek çözüm adımı."
    assert "<think>" not in (out or "")


async def test_generate_empty_endpoint_or_model_returns_none() -> None:
    # Hiç HTTP yapılmamalı — mock bile gerekmez.
    assert await ai_client.generate("", "qwen3:8b", "p") is None
    assert await ai_client.generate(BASE, "", "p") is None


async def test_generate_http_error_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    _mock_httpx(monkeypatch, handler)
    assert await ai_client.generate(BASE, "qwen3:8b", "p") is None


async def test_generate_connect_error_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("engine down")

    _mock_httpx(monkeypatch, handler)
    assert await ai_client.generate(BASE, "qwen3:8b", "p") is None


async def test_generate_empty_content_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_chat("   "))  # yalnız boşluk

    _mock_httpx(monkeypatch, handler)
    assert await ai_client.generate(BASE, "qwen3:8b", "p") is None


async def test_generate_malformed_response_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": []})  # boş choices → None

    _mock_httpx(monkeypatch, handler)
    assert await ai_client.generate(BASE, "qwen3:8b", "p") is None


# --- client.list_models ---


async def test_list_models_success(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).endswith("/models")  # OpenAI /v1/models
        return httpx.Response(200, json=_models(["qwen3:8b", "phi3.5"]))

    _mock_httpx(monkeypatch, handler)
    assert await ai_client.list_models(BASE) == ["qwen3:8b", "phi3.5"]


async def test_list_models_unreachable_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    _mock_httpx(monkeypatch, handler)
    assert await ai_client.list_models(BASE) is None


async def test_list_models_empty_endpoint() -> None:
    assert await ai_client.list_models("") is None


# --- service.AIConfig ---


def test_aiconfig_available() -> None:
    assert AIConfig(True, BASE, "qwen3:8b").available is True
    assert AIConfig(False, BASE, "qwen3:8b").available is False  # kapalı
    assert AIConfig(True, "", "qwen3:8b").available is False  # endpoint yok
    assert AIConfig(True, BASE, "").available is False  # model yok


def test_aiconfig_from_app_settings_none_uses_env_defaults() -> None:
    # row=None → env varsayılanları, ai_enabled False (admin açmadan AI kapalı).
    cfg = AIConfig.from_app_settings(None)
    assert cfg.enabled is False
    assert cfg.endpoint  # env varsayılanı dolu
    assert cfg.model
    assert cfg.available is False


def test_aiconfig_from_app_settings_row() -> None:
    class Row:
        ai_enabled = True
        ai_endpoint_url = "http://custom:1234/v1"
        ai_model_name = "llama3.2:3b"
        ai_timeout_sec = 90

    cfg = AIConfig.from_app_settings(Row())
    assert cfg.enabled is True
    assert cfg.endpoint == "http://custom:1234/v1"
    assert cfg.model == "llama3.2:3b"
    assert cfg.timeout == 90.0
    assert cfg.available is True


def test_aiconfig_from_app_settings_blank_fields_fall_back_to_env() -> None:
    class Row:
        ai_enabled = True
        ai_endpoint_url = ""  # boş → env'e düş
        ai_model_name = "  "  # boşluk → env'e düş
        ai_timeout_sec = 0  # 0 → env'e düş

    cfg = AIConfig.from_app_settings(Row())
    assert cfg.endpoint  # env varsayılanı
    assert cfg.model
    assert cfg.timeout > 0


def test_ai_available_none_safe() -> None:
    assert ai_service.ai_available(None) is False
    assert ai_service.ai_available(AIConfig(False, "x", "y")) is False
    assert ai_service.ai_available(AIConfig(True, "x", "y")) is True


# --- service.generate ---


async def test_service_generate_unavailable_returns_none_without_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = {"hit": False}

    def handler(_req: httpx.Request) -> httpx.Response:
        called["hit"] = True
        return httpx.Response(200, json=_chat("x"))

    _mock_httpx(monkeypatch, handler)
    # Kapalı config → hiç HTTP yapılmamalı (CPU boşa yorulmasın).
    out = await ai_service.generate(AIConfig(False, BASE, "m"), "p")
    assert out is None
    assert called["hit"] is False


async def test_service_generate_available_calls_client(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_chat("Yanıt."))

    _mock_httpx(monkeypatch, handler)
    out = await ai_service.generate(AIConfig(True, BASE, "qwen3:8b"), "p")
    assert out == "Yanıt."


async def test_service_generate_appends_language_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sistem yönergesi verilince üretim katmanı Latin-only dil korumasını ekler (CJK sızıntısı)."""
    import json

    captured: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        captured["system"] = next(
            (m["content"] for m in body["messages"] if m["role"] == "system"), ""
        )
        return httpx.Response(200, json=_chat("Yanıt."))

    _mock_httpx(monkeypatch, handler)
    await ai_service.generate(AIConfig(True, BASE, "qwen3:8b"), "p", system="Sen analistsin")
    assert "Sen analistsin" in captured["system"]  # özgün yönerge korunur
    assert "Latin" in captured["system"]  # dil koruması eklendi


# --- cache.digest (jenerik önbellek-anahtarı özeti) ---


def test_cache_digest_is_sha256_32_and_stable() -> None:
    # Önbellek özeti sha256[:32] = 128-bit; kararlı (aynı girdi→aynı), girdi-duyarlı.
    d = ai_cache.digest("merhaba")
    assert len(d) == 32
    assert all(c in "0123456789abcdef" for c in d)
    assert ai_cache.digest("merhaba") == d
    assert ai_cache.digest("merhabb") != d
