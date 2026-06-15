"""AI uyum anlatısı testleri (Dalga 3) — salt-okunur, grounded, skor/madde üretmez.

(1) ``build_compliance_prompt``: CIS + KVKK/ISO/PCI skorları + başarısız kontrolleri gömer;
    mevzuat yokken 'eşleme yok' geçer; salt-ANLATI (skor uydurma yasağı).
(2) Route ``/ai/compliance``: AI açık + uyum verisi var → üret+önbellek; gerçek skor/kontrol verisi
    prompt'a gömülür (grounding); AI kapalı / uyum verisi yok → graceful parça.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.ai import cache as ai_cache
from cybersectool.core.ai import client as ai_client
from cybersectool.core.ai import prompts as ai_prompts
from cybersectool.core.ai import service as ai_service
from cybersectool.core.app_settings import save_ai_settings
from cybersectool.core.models import ComplianceCheck, Role, ScanType, Severity
from cybersectool.core.scans import create_scan
from cybersectool.core.users import create_user

# --- saf prompt: grounding + mevzuat-yok + uydurma yasağı ---


def test_build_compliance_prompt_grounds_data() -> None:
    system, prompt = ai_prompts.build_compliance_prompt(
        scope_label="Tarama #5 — 10.0.0.5",
        cis_scores=[{"framework": "CIS Linux", "score": 72, "passed": 36, "total": 50}],
        reg_scores=[{"regulation": "KVKK", "score": 70, "passed": 35, "failed": 15}],
        failed_controls=[
            {
                "framework": "CIS Linux",
                "control_id": "5.2.8",
                "title": "SSH root",
                "severity": "high",
            }
        ],
    )
    assert "GENEL UYUM" in system
    assert "MEVZUAT" in system
    assert "ÖNCELİK" in system
    assert "UYDURMA" in system
    # Gerçek skor/kontrol/mevzuat gömülü.
    assert "CIS Linux" in prompt
    assert "5.2.8" in prompt
    assert "KVKK" in prompt
    assert "72" in prompt
    assert "Tarama #5" in prompt


def test_build_compliance_prompt_no_regulations_or_fails() -> None:
    _system, prompt = ai_prompts.build_compliance_prompt(
        scope_label="x",
        cis_scores=[{"framework": "CIS Linux", "score": 80, "passed": 8, "total": 10}],
        reg_scores=[],
        failed_controls=[],
    )
    assert "Mevzuat eşlemesi yok" in prompt
    assert "(başarısız kontrol yok)" in prompt


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


async def _seed_compliance(
    client: AsyncClient,
    fac: async_sessionmaker[AsyncSession],
    username: str,
    *,
    ai_enabled: bool = True,
    empty: bool = False,
) -> int:
    """CIS Linux/Windows kontrolleri (pass+fail, mevzuata eşlenen) içeren tarama kurar + login."""
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
        scan = await create_scan(session, ScanType.credentialed, "10.0.0.5")
        sid = scan.id
        if not empty:
            session.add_all(
                [
                    ComplianceCheck(
                        scan_id=sid,
                        framework="CIS Linux",
                        control_id="5.2.8",
                        title="SSH root girişi",
                        status="fail",
                        severity=Severity.high,
                    ),
                    ComplianceCheck(
                        scan_id=sid,
                        framework="CIS Linux",
                        control_id="1.1.2",
                        title="sticky bit",
                        status="pass",
                    ),
                    ComplianceCheck(
                        scan_id=sid,
                        framework="CIS Windows",
                        control_id="18.3.1",
                        title="SMBv1 kapalı",
                        status="fail",
                        severity=Severity.critical,
                    ),
                ]
            )
        await session.commit()
    await client.post("/auth/login", json={"username": username, "password": "pass1234"})
    return sid


async def test_ai_compliance_generates_and_caches(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_engine(monkeypatch, "GENEL UYUM: CIS Linux orta seviyede.")
    sid = await _seed_compliance(client, session_factory, "comp1")
    r = await client.post("/ai/compliance", data={"scope": "scan", "scope_id": sid})
    assert r.status_code == 200
    assert "orta seviyede" in r.text
    async with session_factory() as session:
        assert await ai_cache.get_cached(session, f"compliance:scan:{sid}") is not None


async def test_ai_compliance_grounds_real_data(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Route'un gerçek CIS skoru + mevzuat eşlemesi + başarısız kontrolü gömdüğünü doğrula.
    captured: dict[str, str] = {}

    async def _capture(config: Any, prompt: str, *, system: str = "", options: Any = None) -> str:
        captured["prompt"] = prompt
        captured["system"] = system
        return "GENEL UYUM: test."

    monkeypatch.setattr(ai_service, "generate", _capture)
    sid = await _seed_compliance(client, session_factory, "compgnd")
    r = await client.post("/ai/compliance", data={"scope": "scan", "scope_id": sid})
    assert r.status_code == 200
    p = captured["prompt"]
    assert "CIS Linux" in p
    assert "5.2.8" in p  # başarısız kontrol gömülü
    assert "KVKK" in p  # mevzuat eşlemesi gömülü
    assert "MEVZUAT" in captured["system"]


async def test_ai_compliance_graceful_when_ai_off(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sid = await _seed_compliance(client, session_factory, "compoff", ai_enabled=False)
    r = await client.post("/ai/compliance", data={"scope": "scan", "scope_id": sid})
    assert r.status_code == 200
    assert "asistanı kapalı" in r.text  # ai_disabled


async def test_ai_compliance_graceful_when_no_data(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Uyum kontrolü olmayan tarama → AI ÜRETMEZ (halüsinasyon yok), graceful "veri yok".
    sid = await _seed_compliance(client, session_factory, "compempty", empty=True)
    r = await client.post("/ai/compliance", data={"scope": "scan", "scope_id": sid})
    assert r.status_code == 200
    assert "kontrol verisi yok" in r.text  # ai_compliance_no_data
    async with session_factory() as session:
        assert await ai_cache.get_cached(session, f"compliance:scan:{sid}") is None
