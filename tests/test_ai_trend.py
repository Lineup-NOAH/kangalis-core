"""AI tarama-trendi anlatısı testleri (Dalga 3) — salt-okunur, grounded, komut üretmez.

(1) ``build_trend_prompt``: gerçek trend sayılarını + başlıkları gömer; MTTR None ise süre uydurmaz.
(2) Route ``/ai/trend``: AI açık + zafiyet var → üret+önbellek (sayı-hash anahtarı); gerçek trend
    sayıları prompt'a gömülür (grounding); AI kapalı / hiç zafiyet yok → graceful parça.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.ai import client as ai_client
from cybersectool.core.ai import prompts as ai_prompts
from cybersectool.core.ai import service as ai_service
from cybersectool.core.app_settings import save_ai_settings
from cybersectool.core.assets import upsert_asset
from cybersectool.core.models import (
    AIExplanation,
    FindingStatus,
    Role,
    ScanType,
    Severity,
    Vulnerability,
)
from cybersectool.core.users import create_user

# --- saf prompt: grounding + MTTR-None koruması ---


def test_build_trend_prompt_grounds_numbers() -> None:
    system, prompt = ai_prompts.build_trend_prompt(
        open_total=42,
        resolved_total=100,
        new_7d=5,
        resolved_7d=12,
        regressions=2,
        aging_30d=9,
        mttr_days=8.5,
        aging={"fresh": 10, "recent": 23, "old": 9},
        points=[
            {"label": "06-01", "open": 60, "new": 3, "resolved": 1},
            {"label": "06-08", "open": 42, "new": 5, "resolved": 12},
        ],
    )
    # Başlıklar + grounding + uydurma yasağı.
    assert "DURUM" in system
    assert "8 HAFTALIK YÖN" in system
    assert "ODAK" in system
    assert "UYDURMA" in system
    # Gerçek sayılar gömülü.
    assert "42" in prompt
    assert "8.5" in prompt
    assert "06-08" in prompt


def test_build_trend_prompt_mttr_none_not_invented() -> None:
    # Çözülen zafiyet yokken MTTR None → 'henüz yok' (süre UYDURULMAZ).
    _system, prompt = ai_prompts.build_trend_prompt(
        open_total=3,
        resolved_total=0,
        new_7d=3,
        resolved_7d=0,
        regressions=0,
        aging_30d=0,
        mttr_days=None,
        aging={"fresh": 3, "recent": 0, "old": 0},
        points=[],
    )
    assert "henüz yok" in prompt


# --- route altyapısı ---


def _mock_engine(monkeypatch: pytest.MonkeyPatch, response_text: str) -> None:
    real = httpx.AsyncClient

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"choices": [{"message": {"role": "assistant", "content": response_text}}]}
        )

    def factory(*a: Any, **k: Any) -> httpx.AsyncClient:
        k.pop("transport", None)
        return real(*a, transport=httpx.MockTransport(handler), **k)

    monkeypatch.setattr(ai_client.httpx, "AsyncClient", factory)


async def _seed_trend(
    client: AsyncClient,
    fac: async_sessionmaker[AsyncSession],
    username: str,
    *,
    ai_enabled: bool = True,
    empty: bool = False,
) -> None:
    """İki açık (biri yaşlanan) + bir çözülmüş zafiyet kurar + login eder (route login-gated)."""
    async with fac() as session:
        await create_user(session, username, "pass1234", role=Role.viewer)
        if ai_enabled:
            await save_ai_settings(
                session,
                ai_enabled=True,
                ai_endpoint_url="http://ollama:11434",
                ai_model_name="qwen3:8b",
                ai_timeout_sec=60,
            )
        if not empty:
            asset = await upsert_asset(session, "10.0.0.5")
            now = datetime.now(UTC)

            def _v(
                fp: str, first: datetime, resolved: datetime | None, sev: Severity
            ) -> Vulnerability:
                return Vulnerability(
                    asset_id=asset.id,
                    fingerprint=fp,
                    scan_type=ScanType.network,
                    title=fp,
                    severity=sev,
                    first_seen=first,
                    last_seen=now,
                    resolved_at=resolved,
                    status=FindingStatus.resolved if resolved else FindingStatus.open,
                )

            session.add(_v("a", now - timedelta(days=3), None, Severity.high))  # açık, taze
            session.add(_v("b", now - timedelta(days=40), None, Severity.critical))  # açık, eski
            session.add(
                _v("c", now - timedelta(days=40), now - timedelta(days=35), Severity.medium)
            )  # çözülmüş, mttr=5g
        await session.commit()
    await client.post("/auth/login", json={"username": username, "password": "pass1234"})


async def test_ai_trend_generates_and_caches(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_engine(monkeypatch, "DURUM: 2 açık zafiyet var, biri yaşlanmış.")
    await _seed_trend(client, session_factory, "trend1")
    r = await client.post("/ai/trend")
    assert r.status_code == 200
    assert "yaşlanmış" in r.text
    # Sayı-hash anahtarı önbelleğe yazıldı (anahtar değeri sayılara bağlı → 'trend:%' ile doğrula).
    async with session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(AIExplanation).where(AIExplanation.cache_key.like("trend:%"))
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 1


async def test_ai_trend_grounds_real_numbers(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Route'un gerçek trend sayılarını (açık=2, MTTR=5.0) prompt'a gömdüğünü doğrula (grounding).
    captured: dict[str, str] = {}

    async def _capture(config: Any, prompt: str, *, system: str = "", options: Any = None) -> str:
        captured["prompt"] = prompt
        captured["system"] = system
        return "DURUM: test."

    monkeypatch.setattr(ai_service, "generate", _capture)
    await _seed_trend(client, session_factory, "trendgnd")
    r = await client.post("/ai/trend")
    assert r.status_code == 200
    p = captured["prompt"]
    assert "Açık (toplam): 2" in p
    assert "5.0" in p  # MTTR = 5 gün (c: 40g→35g)
    assert "8 HAFTALIK YÖN" in captured["system"]


async def test_ai_trend_graceful_when_ai_off(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _seed_trend(client, session_factory, "trendoff", ai_enabled=False)
    r = await client.post("/ai/trend")
    assert r.status_code == 200
    assert "asistanı kapalı" in r.text  # ai_disabled


async def test_ai_trend_graceful_when_no_data(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Hiç zafiyet yok → AI ÜRETMEZ (halüsinasyon yok), graceful "veri yok".
    await _seed_trend(client, session_factory, "trendempty", empty=True)
    r = await client.post("/ai/trend")
    assert r.status_code == 200
    assert "yeterli" in r.text.lower()  # ai_trend_no_data
    async with session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(AIExplanation).where(AIExplanation.cache_key.like("trend:%"))
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 0
