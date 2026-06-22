"""Yerel AI kurulum sihirbazı (Faz 1 çatısı) — ortam algılama + /plugins/ai/detect testleri.

``detect_ai_paths`` aday endpoint'leri (host-native Ollama/LM Studio + gömülü container + kayıtlı)
eşzamanlı yoklayıp önerilen yolu seçer; öneri host-native'i önceler (container storage'ını baypas
eder). Ağ çağrıları ``list_models`` + ``_host_internal_reachable`` monkeypatch ile taklit edilir.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.ai import service
from cybersectool.core.models import Role
from cybersectool.core.users import create_user


def _patch_reachable(monkeypatch: pytest.MonkeyPatch, *reachable: str, host: bool) -> None:
    """``list_models``'i yalnız endpoint'i ``reachable`` parçalarından birini içeren adaylarda
    başarılı kılar; ``_host_internal_reachable``'i ``host`` yapar."""

    async def fake_list_models(cfg: service.AIConfig) -> list[str] | None:
        return ["qwen3:8b"] if any(s in cfg.endpoint for s in reachable) else None

    monkeypatch.setattr(service, "list_models", fake_list_models)
    monkeypatch.setattr(service, "_host_internal_reachable", lambda: host)


async def test_detect_recommends_host_native_when_ollama_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_reachable(monkeypatch, "host.docker.internal:11434", host=True)  # Ollama host-native
    res = await service.detect_ai_paths(None)
    assert res["recommended"] == "ollama-host"  # host-native > bundled (container baypas)
    ollama = next(c for c in res["candidates"] if c["key"] == "ollama-host")
    assert ollama["ok"] is True and ollama["models"] == ["qwen3:8b"]
    bundled = next(c for c in res["candidates"] if c["key"] == "bundled")
    assert bundled["ok"] is False


async def test_detect_recommends_bundled_when_only_container_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_reachable(monkeypatch, "ollama:11434", host=True)  # yalnız gömülü container
    res = await service.detect_ai_paths(None)
    assert res["recommended"] == "bundled"


async def test_detect_install_companion_when_host_reachable_no_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_reachable(monkeypatch, host=True)  # hiçbir motor yok ama host erişilebilir
    res = await service.detect_ai_paths(None)
    assert res["recommended"] == "install-companion"  # → Windows Companion kur


async def test_detect_install_when_nothing_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_reachable(monkeypatch, host=False)  # host bile erişilemez (k8s/izole)
    res = await service.detect_ai_paths(None)
    assert res["recommended"] == "install"
    assert all(c["ok"] is False for c in res["candidates"])


# --- Route: /plugins/ai/detect (admin-gated, HTMX parçası) ---


async def _login(
    client: AsyncClient,
    factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role = Role.admin,
) -> None:
    async with factory() as session:
        await create_user(session, username, "pass1234", role=role)
    await client.post("/auth/login", json={"username": username, "password": "pass1234"})


async def test_settings_ai_detect_admin_returns_fragment(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cybersectool.web import routes

    async def fake_detect(row: object) -> dict[str, Any]:
        return {
            "host_reachable": True,
            "recommended": "ollama-host",
            "candidates": [
                {
                    "key": "ollama-host",
                    "label": "Ollama (host-native)",
                    "endpoint": "http://host.docker.internal:11434/v1",
                    "ok": True,
                    "models": ["qwen3:8b"],
                },
                {
                    "key": "bundled",
                    "label": "Gömülü container (Ollama)",
                    "endpoint": "http://ollama:11434/v1",
                    "ok": False,
                    "models": [],
                },
            ],
        }

    monkeypatch.setattr(routes, "detect_ai_paths", fake_detect)
    await _login(client, session_factory, "admdetect", Role.admin)
    resp = await client.post("/plugins/ai/detect")
    assert resp.status_code == 200
    assert "host.docker.internal:11434" in resp.text
    assert "Ollama" in resp.text


async def test_settings_ai_detect_non_admin_redirect(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "andetect", Role.analyst)
    resp = await client.post("/plugins/ai/detect", follow_redirects=False)
    assert resp.status_code == 303


async def test_settings_ai_detect_anonymous_redirect(client: AsyncClient) -> None:
    resp = await client.post("/plugins/ai/detect", follow_redirects=False)
    assert resp.status_code == 303
