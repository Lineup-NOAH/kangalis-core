"""Yerel AI grounded prompt + önbellek testleri (#183).

prompts.py SAF (I/O yok) → in-memory Finding/CVE/Service ile test edilir.
cache.py DB round-trip + anahtar tekilliği (paylaşımlı CVE anahtarı).
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
from cybersectool.core.app_settings import save_ai_settings
from cybersectool.core.assets import upsert_asset
from cybersectool.core.findings import create_finding
from cybersectool.core.models import CVE, Finding, Role, ScanType, Service, Severity
from cybersectool.core.remediation import Remediation
from cybersectool.core.scans import create_scan
from cybersectool.core.users import create_user

# --- prompts (grounding) ---


def test_build_finding_prompt_grounds_cve_data() -> None:
    finding = Finding(title="Apache httpd path traversal", severity=Severity.high, cve_id="CVE-X")
    cve = CVE(
        cve_id="CVE-X",
        description="Path traversal in Apache 2.4.49.",
        cvss_score=7.5,
        severity=Severity.high,
        kev_flag=True,
        epss_score=0.97,
        references=["https://nvd.example/CVE-X"],
    )
    service = Service(port=80, protocol="tcp", product="Apache httpd", version="2.4.49")
    system, prompt = ai_prompts.build_finding_prompt(finding, cve, service, None)
    # Sistem yönergesi: Türkçe + grounding + yapı.
    assert "Türkçe" in system
    assert "UYDURMA" in system
    # Yerel CVE verisi prompt'a gömülmeli (anti-halüsinasyon temeli).
    assert "CVE-X" in prompt
    assert "7.5" in prompt
    assert "Path traversal in Apache 2.4.49." in prompt
    assert "KEV" in prompt  # aktif sömürü işareti
    assert "%97" in prompt  # EPSS yüzde
    assert "Apache httpd 2.4.49 (80/tcp)" in prompt  # servis etiketi


def test_build_finding_prompt_no_cve_does_not_crash() -> None:
    # Zayıf kimlik / açık servis (CVE yok) → yine de prompt üretir, çökmez.
    finding = Finding(title="Zayıf SSH parolası", severity=Severity.medium, cve_id=None)
    rem = Remediation(cause="SSH zayıf parola", summary="Güçlü parola politikası uygula.")
    system, prompt = ai_prompts.build_finding_prompt(finding, None, None, rem)
    assert "Zayıf SSH parolası" in prompt
    assert "Güçlü parola politikası uygula." in prompt  # statik çözüm gömülü
    assert system  # sistem yönergesi dolu


def test_build_cve_prompt() -> None:
    cve = CVE(cve_id="CVE-Y", description="RCE in Foo.", cvss_score=9.8, severity=Severity.critical)
    _system, prompt = ai_prompts.build_cve_prompt(cve, title="Foo RCE")
    assert "CVE-Y" in prompt
    assert "RCE in Foo." in prompt
    assert "9.8" in prompt
    assert "Foo RCE" in prompt


def test_finding_system_has_fewshot_example() -> None:
    # Few-shot örneği FINDING_SYSTEM'e gömülü: modele BİÇİMİ + grounding davranışını öğretir.
    sys = ai_prompts.FINDING_SYSTEM
    assert "ÖRNEK — GİRDİ:" in sys
    assert "ÖRNEK — YANIT:" in sys
    # Üç başlık örnek yanıtta da görünür (biçim öğretimi).
    assert "AÇIKLAMA:" in sys and "NEDEN ÖNEMLİ:" in sys and "ÇÖZÜM:" in sys
    # Grounding davranışı öğretiliyor: eksik alanı uydurma, "sağlanan veride yok" de.
    assert "sağlanan veride" in sys
    # Kurallar hâlâ duruyor (örnek onları ezmedi).
    assert "UYDURMA" in sys


def test_build_summary_prompt() -> None:
    system, prompt = ai_prompts.build_summary_prompt(
        target="10.0.0.0/24",
        host_count=12,
        severity_counts={"critical": 2, "high": 5, "info": 9},
        top_findings=[
            {
                "title": "Apache RCE",
                "cve_id": "CVE-Z",
                "severity": "critical",
                "cvss": 9.8,
                "kev": True,
            },
        ],
    )
    assert "yönetici" in system.lower()
    assert "10.0.0.0/24" in prompt
    assert "12" in prompt
    assert "Kritik: 2" in prompt
    assert "Apache RCE" in prompt
    assert "CVE-Z" in prompt
    assert "KEV-acil" in prompt


def test_build_summary_prompt_audience_switches_system_only() -> None:
    # Müşteri kitlesi → teslim tonu sistem yönergesi; iç yönetici → standart. Gömülü veri AYNI.
    kw: dict[str, Any] = {
        "target": "10.0.0.0/24",
        "host_count": 3,
        "severity_counts": {"critical": 1},
        "top_findings": [],
    }
    sys_int, prompt_int = ai_prompts.build_summary_prompt(audience="internal", **kw)
    sys_cust, prompt_cust = ai_prompts.build_summary_prompt(audience="customer", **kw)
    assert prompt_int == prompt_cust  # kullanıcı prompt'u (grounding) değişmez
    assert sys_int != sys_cust  # yalnız ton/sistem yönergesi değişir
    assert "MÜŞTERİYE" in sys_cust  # teslim tonu
    assert "jargon" in sys_cust.lower()


def test_build_priorities_prompt_preserves_order_and_grounds() -> None:
    system, prompt = ai_prompts.build_priorities_prompt(
        target="10.0.0.0/24",
        ranked_findings=[
            {
                "title": "Apache RCE",
                "cve_id": "CVE-A",
                "severity": "critical",
                "cvss": 9.8,
                "kev": True,
                "epss": 97,
                "asset": "10.0.0.5",
            },
            {"title": "Zayıf SSH parolası", "cve_id": "", "severity": "high"},
        ],
    )
    # Sistem yönergesi: sırayı KORU + uydurma yasağı (deterministik motor değişmez).
    assert "DEĞİŞTİRME" in system
    assert "UYDURMA" in system
    # DETERMİNİSTİK sıra: 1. madde Apache, 2. madde SSH (route'un verdiği sıra korunur).
    first = prompt.index("1. Apache RCE")
    second = prompt.index("2. Zayıf SSH parolası")
    assert 0 <= first < second
    # Grounding: yerel sinyaller gömülü.
    assert "CVE-A" in prompt
    assert "CVSS 9.8" in prompt
    assert "EPSS %97" in prompt
    assert "KEV-acil" in prompt
    assert "10.0.0.5" in prompt


def test_build_remediation_script_prompt_grounds_and_no_autorun() -> None:
    cve = CVE(cve_id="CVE-X", description="RCE in Apache 2.4.49.", cvss_score=9.8)
    service = Service(port=80, protocol="tcp", product="Apache httpd", version="2.4.49")
    system, prompt = ai_prompts.build_remediation_script_prompt(
        title="Apache outdated",
        severity="high",
        cve_id="CVE-X",
        cve=cve,
        service=service,
        remediation=None,
    )
    # Sistem: TASLAK (oto-çalışmaz) + uydurma yasağı.
    assert "TASLAK" in system
    assert "UYDURMA" in system
    # Grounding: servis + CVE gömülü.
    assert "Apache httpd 2.4.49" in prompt
    assert "CVE-X" in prompt
    assert "RCE in Apache 2.4.49." in prompt


def test_build_asset_story_prompt_grounds_host_findings() -> None:
    system, prompt = ai_prompts.build_asset_story_prompt(
        label="web01",
        ip="10.0.0.9",
        findings=[
            {
                "title": "Apache RCE",
                "cve_id": "CVE-A",
                "severity": "critical",
                "cvss": 9.8,
                "kev": True,
            },
            {"title": "Açık Redis", "cve_id": "", "severity": "high"},
        ],
    )
    assert "RİSK" in system  # risk hikâyesi
    assert "UYDURMA" in system
    assert "web01" in prompt
    assert "10.0.0.9" in prompt
    assert "Apache RCE" in prompt
    assert "CVE-A" in prompt
    assert "KEV" in prompt
    assert "Açık Redis" in prompt


def test_report_systems_have_fewshot_examples() -> None:
    # #272: few-shot örneği rapor-seviyesi 3 yüzeye de gömülü (biçim + grounding öğretimi).
    for sys in (
        ai_prompts.SUMMARY_SYSTEM,
        ai_prompts.SUMMARY_SYSTEM_EXEC,
        ai_prompts.REMEDIATION_SCRIPT_SYSTEM,
    ):
        assert "ÖRNEK — GİRDİ:" in sys
        assert "ÖRNEK — YANIT:" in sys
        assert "UYDURMA" in sys or "<doldurun>" in sys  # kurallar örnekten sonra hâlâ duruyor


def test_summary_systems_teach_distinct_tone() -> None:
    # İç özet ile müşteri özeti AYRI örnek tonu öğretir; müşteri örneği CVE kodu sızdırmamayı,
    # 'Öncelikli aksiyonlar' / 'Önerilen sonraki adımlar' başlıklarıyla biçimi gösterir.
    internal = ai_prompts.SUMMARY_SYSTEM
    customer = ai_prompts.SUMMARY_SYSTEM_EXEC
    assert internal != customer
    assert "Öncelikli aksiyonlar:" in internal  # iç ton örneği
    assert "Önerilen sonraki adımlar:" in customer  # teslim tonu örneği
    # Müşteri YANIT'ında iş diline çeviri öğretiliyor → örnek yanıt bloğunda CVE kodu yok.
    cust_answer = customer.split("ÖRNEK — YANIT:", 1)[1]
    assert "CVE-2021-41773" not in cust_answer


def test_remediation_script_example_teaches_multi_os_and_placeholder() -> None:
    # #272: script örneği çok-OS blok biçimini (apt + dnf) ve <doldurun> grounding'ini öğretir.
    sys = ai_prompts.REMEDIATION_SCRIPT_SYSTEM
    answer = sys.split("ÖRNEK — YANIT:", 1)[1]
    assert "apt-get" in answer and "dnf" in answer  # birden çok dağıtım bloğu
    assert "<doldurun>" in answer  # bilinmeyen sürüm için yer-tutucu
    assert "sağlanan veride yok" in answer  # grounding davranışı


def test_remaining_systems_have_fewshot_examples() -> None:
    # #274: few-shot örneği kalan 2 yüzeye de gömülü (öncelik / asset-story).
    for sys in (
        ai_prompts.PRIORITIES_SYSTEM,
        ai_prompts.ASSET_STORY_SYSTEM,
    ):
        assert "ÖRNEK — GİRDİ:" in sys
        assert "ÖRNEK — YANIT:" in sys
    # Kurallar örnekten sonra hâlâ duruyor (yüzeye özgü çekirdek talimat).
    assert "DEĞİŞTİRME" in ai_prompts.PRIORITIES_SYSTEM  # sıra korunur
    assert "UYDURMA" in ai_prompts.ASSET_STORY_SYSTEM  # servis/CVE uydurma


# --- cache ---


def test_finding_cache_key() -> None:
    # CVE varsa cve:<id> (büyük harf normalize) → rapor/Zafiyetler paylaşır.
    assert ai_cache.finding_cache_key(cve_id="cve-2021-1", title="x") == "cve:CVE-2021-1"
    # CVE yoksa başlık hash'i (kararlı) → finding:<hash>.
    k1 = ai_cache.finding_cache_key(cve_id=None, title="Zayıf SSH parolası")
    k2 = ai_cache.finding_cache_key(cve_id="", title="Zayıf SSH parolası")
    assert k1 == k2 and k1.startswith("finding:")
    # Farklı başlık → farklı anahtar.
    assert ai_cache.finding_cache_key(cve_id=None, title="Başka") != k1


async def test_cache_store_get_roundtrip(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        assert await ai_cache.get_cached(session, "cve:CVE-1") is None
        row = await ai_cache.store(session, "cve:CVE-1", "açıklama metni", model="qwen3:8b")
        assert row.content == "açıklama metni"
        assert row.model == "qwen3:8b"
        got = await ai_cache.get_cached(session, "cve:CVE-1")
        assert got is not None and got.content == "açıklama metni"
        # Aynı anahtara tekrar yaz → içerik tazelenir, tek satır kalır (tekil cache_key).
        row2 = await ai_cache.store(session, "cve:CVE-1", "yeni metin", model="llama3.2:3b")
        assert row2.id == row.id
        assert row2.content == "yeni metin"
        assert row2.model == "llama3.2:3b"


async def test_cache_get_many(session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as session:
        await ai_cache.store(session, "cve:CVE-1", "a", model="m")
        await ai_cache.store(session, "cve:CVE-2", "b", model="m")
        got = await ai_cache.get_many(session, ["cve:CVE-1", "cve:CVE-2", "cve:CVE-MISSING"])
        assert set(got.keys()) == {"cve:CVE-1", "cve:CVE-2"}
        assert got["cve:CVE-1"].content == "a"
        assert await ai_cache.get_many(session, []) == {}


# --- route: /ai/explain (login + mock OpenAI motoru) ---


def _mock_engine(monkeypatch: pytest.MonkeyPatch, response_text: str) -> None:
    """Route'un ai_service→client→httpx yolunu sabit bir OpenAI yanıtıyla taklit eder."""
    real = httpx.AsyncClient

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"choices": [{"message": {"role": "assistant", "content": response_text}}]}
        )

    def factory(*a: Any, **k: Any) -> httpx.AsyncClient:
        k.pop("transport", None)
        return real(*a, transport=httpx.MockTransport(handler), **k)

    monkeypatch.setattr(ai_client.httpx, "AsyncClient", factory)


async def test_ai_explain_route_disabled_then_enabled_then_cached(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_engine(monkeypatch, "AÇIKLAMA: yol-geçişi test açıklaması.")
    async with session_factory() as session:
        await create_user(session, "aiu", "pass1234", role=Role.viewer)
        asset = await upsert_asset(session, "10.0.0.50")
        scan = await create_scan(session, ScanType.network, "10.0.0.50")
        f = await create_finding(
            session, scan.id, "CVE-2021-41773 — Apache", asset_id=asset.id, cve_id="CVE-2021-41773"
        )
        fid = f.id
    await client.post("/auth/login", json={"username": "aiu", "password": "pass1234"})

    # AI KAPALI (varsayılan) → üretim YOK (graceful no-op).
    r_off = await client.post("/ai/explain", data={"finding_id": fid})
    assert r_off.status_code == 200
    assert "yol-geçişi test açıklaması" not in r_off.text

    # AI AÇ → cache miss → generate → store.
    async with session_factory() as session:
        await save_ai_settings(
            session,
            ai_enabled=True,
            ai_endpoint_url="http://ollama:11434",
            ai_model_name="qwen3:8b",
            ai_timeout_sec=60,
        )
    r_on = await client.post("/ai/explain", data={"finding_id": fid})
    assert r_on.status_code == 200
    assert "yol-geçişi test açıklaması" in r_on.text

    # Önbellek: aynı CVE 2. çağrı "önbellekten" rozetiyle gelir (üretim tekrarlanmaz).
    r_cached = await client.post("/ai/explain", data={"finding_id": fid})
    assert "yol-geçişi test açıklaması" in r_cached.text
    assert "önbellek" in r_cached.text.lower()
    # DB'de tek satır kaldı (paylaşımlı cve: anahtarı).
    async with session_factory() as session:
        assert await ai_cache.get_cached(session, "cve:CVE-2021-41773") is not None


async def test_ai_summary_route(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_engine(monkeypatch, "Bu taramada 1 kritik açık var; öncelik Apache yamasıdır.")
    async with session_factory() as session:
        await create_user(session, "ais", "pass1234", role=Role.viewer)
        asset = await upsert_asset(session, "10.0.0.60")
        scan = await create_scan(session, ScanType.network, "10.0.0.60")
        await create_finding(
            session, scan.id, "CVE-2021-41773 — Apache", asset_id=asset.id, cve_id="CVE-2021-41773"
        )
        scan_id = scan.id
        await save_ai_settings(
            session,
            ai_enabled=True,
            ai_endpoint_url="http://ollama:11434",
            ai_model_name="qwen3:8b",
            ai_timeout_sec=60,
        )
    await client.post("/auth/login", json={"username": "ais", "password": "pass1234"})
    r = await client.post("/ai/summary", data={"scope": "scan", "scope_id": scan_id})
    assert r.status_code == 200
    assert "öncelik Apache yamasıdır" in r.text
    async with session_factory() as session:
        assert await ai_cache.get_cached(session, f"summary:scan:{scan_id}") is not None


async def test_ai_summary_customer_audience_separate_cache(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """audience=customer → ayrı önbellek (:exec) + ai_summary_exec; iç özetten bağımsız."""
    _mock_engine(monkeypatch, "Sayın müşterimiz, güvenlik durumunuz iyileştirilebilir.")
    async with session_factory() as session:
        await create_user(session, "aic", "pass1234", role=Role.viewer)
        asset = await upsert_asset(session, "10.0.0.80")
        scan = await create_scan(session, ScanType.network, "10.0.0.80")
        await create_finding(
            session, scan.id, "CVE-2021-41773 — Apache", asset_id=asset.id, cve_id="CVE-2021-41773"
        )
        scan_id = scan.id
        await save_ai_settings(
            session,
            ai_enabled=True,
            ai_endpoint_url="http://ollama:11434",
            ai_model_name="qwen3:8b",
            ai_timeout_sec=60,
        )
    await client.post("/auth/login", json={"username": "aic", "password": "pass1234"})
    r = await client.post(
        "/ai/summary", data={"scope": "scan", "scope_id": scan_id, "audience": "customer"}
    )
    assert r.status_code == 200
    assert "Sayın müşterimiz" in r.text
    async with session_factory() as session:
        # Müşteri özeti :exec anahtarında; iç özet anahtarı DOKUNULMAMIŞ (ayrı yüzey).
        assert await ai_cache.get_cached(session, f"summary:scan:{scan_id}:exec") is not None
        assert await ai_cache.get_cached(session, f"summary:scan:{scan_id}") is None


async def test_ai_priorities_route(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_engine(monkeypatch, "1. Önce Apache RCE yamasını uygulayın; aktif sömürü var.")
    async with session_factory() as session:
        await create_user(session, "aip", "pass1234", role=Role.viewer)
        asset = await upsert_asset(session, "10.0.0.70")
        scan = await create_scan(session, ScanType.network, "10.0.0.70")
        await create_finding(
            session, scan.id, "CVE-2021-41773 — Apache", asset_id=asset.id, cve_id="CVE-2021-41773"
        )
        scan_id = scan.id
        await save_ai_settings(
            session,
            ai_enabled=True,
            ai_endpoint_url="http://ollama:11434",
            ai_model_name="qwen3:8b",
            ai_timeout_sec=60,
        )
    await client.post("/auth/login", json={"username": "aip", "password": "pass1234"})
    r = await client.post("/ai/priorities", data={"scope": "scan", "scope_id": scan_id})
    assert r.status_code == 200
    assert "Apache RCE yamasını uygulayın" in r.text
    async with session_factory() as session:
        assert await ai_cache.get_cached(session, f"priorities:scan:{scan_id}") is not None


async def test_ai_remediation_script_route(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_engine(monkeypatch, "Amaç: Apache yamala.\n```\napt install apache2\n```")
    async with session_factory() as session:
        await create_user(session, "airs", "pass1234", role=Role.viewer)
        asset = await upsert_asset(session, "10.0.0.90")
        scan = await create_scan(session, ScanType.network, "10.0.0.90")
        f = await create_finding(
            session, scan.id, "CVE-2021-41773 — Apache", asset_id=asset.id, cve_id="CVE-2021-41773"
        )
        fid = f.id
        await save_ai_settings(
            session,
            ai_enabled=True,
            ai_endpoint_url="http://ollama:11434",
            ai_model_name="qwen3:8b",
            ai_timeout_sec=60,
        )
    await client.post("/auth/login", json={"username": "airs", "password": "pass1234"})
    r = await client.post("/ai/remediation-script", data={"finding_id": fid})
    assert r.status_code == 200
    assert "apt install apache2" in r.text
    async with session_factory() as session:
        # Script ayrı namespace'te (per-bulgu açıklamadan farklı) → script:cve:<id>.
        assert await ai_cache.get_cached(session, "script:cve:CVE-2021-41773") is not None


async def test_ai_asset_story_route(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_engine(monkeypatch, "Bu cihaz internete açık kritik bir Apache barındırıyor.")
    async with session_factory() as session:
        await create_user(session, "aias", "pass1234", role=Role.viewer)
        asset = await upsert_asset(session, "10.0.0.91")
        scan = await create_scan(session, ScanType.network, "10.0.0.91")
        await create_finding(
            session, scan.id, "CVE-2021-41773 — Apache", asset_id=asset.id, cve_id="CVE-2021-41773"
        )
        aid = asset.id
        scan_id = scan.id
        await save_ai_settings(
            session,
            ai_enabled=True,
            ai_endpoint_url="http://ollama:11434",
            ai_model_name="qwen3:8b",
            ai_timeout_sec=60,
        )
    await client.post("/auth/login", json={"username": "aias", "password": "pass1234"})
    r = await client.post(
        "/ai/asset-story", data={"asset_id": aid, "scope": "scan", "scope_id": scan_id}
    )
    assert r.status_code == 200
    assert "Apache barındırıyor" in r.text
    async with session_factory() as session:
        assert await ai_cache.get_cached(session, f"story:scan:{scan_id}:asset:{aid}") is not None
