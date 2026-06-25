"""Uygulama ayarları (app_settings) servis testleri."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.app_settings import (
    ai_brand_enabled,
    clean_dns_servers,
    get_nvd_api_key,
    get_settings,
    get_smtp_password,
    normalize_ai_timeout,
    parse_asset_scope_cidrs,
    probe_ai_endpoint,
    save_ai_settings,
    save_asset_scope_settings,
    save_hardening_settings,
    save_network_settings,
    save_nvd_settings,
    save_ratelimit_settings,
    save_scan_settings,
    save_smtp_settings,
    save_syslog_settings,
    set_ai_brand_cache,
)


def test_parse_asset_scope_cidrs() -> None:
    """F1: satır/virgül ayır; tek IP → /32; geçersiz at; dedup + sıra koru."""
    raw = "10.0.0.0/8, 192.168.1.5\n\n# yorum-değil-ama-geçersiz\n203.0.113.0/24\n10.0.0.0/8"
    out = parse_asset_scope_cidrs(raw)
    assert out == ["10.0.0.0/8", "192.168.1.5/32", "203.0.113.0/24"]
    # Tümü geçersiz → boş liste (kapsam zorlanmaz).
    assert parse_asset_scope_cidrs("not-an-ip\nfoo bar") == []
    assert parse_asset_scope_cidrs("") == []


async def test_save_asset_scope_settings(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """F1: kaydedilen kapsam doğrulanmış CIDR listesi olarak saklanır; varsayılan private içerir."""
    async with session_factory() as session:
        # Varsayılan: özel ağ aralıkları + loopback.
        s = await get_settings(session)
        assert "10.0.0.0/8" in s.asset_scope_cidrs
        # Özel kapsam kaydet.
        s2 = await save_asset_scope_settings(session, raw_cidrs="172.16.0.0/12\n203.0.113.10")
        assert s2.asset_scope_cidrs == ["172.16.0.0/12", "203.0.113.10/32"]


def test_clean_dns_servers() -> None:
    """VI-6: yalnız geçerli IP kalır; enjeksiyon/geçersiz atılır; en fazla 3."""
    assert clean_dns_servers("10.0.0.1, 10.0.0.2") == "10.0.0.1,10.0.0.2"
    assert clean_dns_servers("8.8.8.8; rm -rf, bad") == "8.8.8.8"
    assert clean_dns_servers("1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4") == "1.1.1.1,2.2.2.2,3.3.3.3"
    assert clean_dns_servers("") == ""


async def test_save_network_settings(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """VI-6 + SCAN-SPEED: DNS temizlenir + reverse bayrağı + tarama hızı saklanır."""
    async with session_factory() as session:
        s = await save_network_settings(
            session,
            dns_servers="10.0.0.1; evil, 10.0.0.2",
            reverse_dns_enabled=False,
            scan_speed="insane",
        )
        assert s.dns_servers == "10.0.0.1,10.0.0.2"
        assert s.reverse_dns_enabled is False
        assert s.scan_speed == "insane"
        # Kaydedilen değer korunur (yeni satır varsayılanı da artık KAPALI).
        fresh = await get_settings(session)
        assert fresh.reverse_dns_enabled is False  # az önce kaydedildi


async def test_save_network_settings_scan_speed_defaults(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """SCAN-SPEED: varsayılan hız 'fast'; geçersiz değer güvenli 'fast'a normalize edilir."""
    async with session_factory() as session:
        # Yeni satır varsayılanı fast.
        assert (await get_settings(session)).scan_speed == "fast"
        # Geçersiz değer komuta sızmaz → fast'a düşer.
        s = await save_network_settings(
            session, dns_servers="", reverse_dns_enabled=True, scan_speed="bogus"
        )
        assert s.scan_speed == "fast"


async def test_save_scan_settings(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """SCAN-SETTINGS-UX: tarama hızı + fan-out (DNS'ten ayrı). worker sayısı 1-32'ye kısılır."""
    async with session_factory() as session:
        # Varsayılan: fan-out açık, 8 worker.
        d = await get_settings(session)
        assert d.scan_fanout is True
        assert d.fanout_workers == 8
        # Kaydet: hız + fan-out kapalı + worker üst sınırı aşımı → 32'ye kısılır.
        s = await save_scan_settings(
            session, scan_speed="slow", scan_fanout=False, fanout_workers=999
        )
        assert s.scan_speed == "slow"
        assert s.scan_fanout is False
        assert s.fanout_workers == 32
        # Geçersiz hız → fast; None worker → varsayılan (8).
        s2 = await save_scan_settings(
            session, scan_speed="bogus", scan_fanout=True, fanout_workers=None
        )
        assert s2.scan_speed == "fast"
        assert s2.fanout_workers == 8


async def test_get_settings_creates_defaults(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        s = await get_settings(session)
        assert s.id == 1
        assert s.ratelimit_enabled is False
        assert s.ratelimit_max_attempts == 5
        assert s.smtp_port == 587
        assert s.smtp_use_tls is True
        assert s.syslog_protocol == "udp"
        assert s.syslog_format == "rfc5424"
        assert s.password_min_length == 8
        # İkinci çağrı yeni satır oluşturmaz (tekil, id=1).
        s2 = await get_settings(session)
        assert s2.id == 1


async def test_save_ratelimit_clamps(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        s = await save_ratelimit_settings(
            session, enabled=True, max_attempts=0, window_sec=5, lockout_sec=999_999_999
        )
        assert s.ratelimit_enabled is True
        assert s.ratelimit_max_attempts == 1  # 0 → alt sınır 1
        assert s.ratelimit_window_sec == 10  # 5 → alt sınır 10
        assert s.ratelimit_lockout_sec == 86_400  # üst sınır


async def test_save_smtp_encrypts_and_keeps_password(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        s = await save_smtp_settings(
            session,
            enabled=True,
            host="smtp.x",
            port=587,
            username="u",
            sender="from@x",
            use_tls=True,
            alert_to="soc@x",
            password="secret",
        )
        assert s.smtp_password_encrypted is not None
        assert s.smtp_password_encrypted != "secret"  # düz metin saklanmaz
        assert get_smtp_password(s) == "secret"
        # Parola boş gönderilirse eski parola korunur; diğer alanlar güncellenir.
        s2 = await save_smtp_settings(
            session,
            enabled=True,
            host="smtp.y",
            port=25,
            username="u2",
            sender="from@y",
            use_tls=False,
            alert_to="",
            password=None,
        )
        assert get_smtp_password(s2) == "secret"
        assert s2.smtp_host == "smtp.y"
        assert s2.smtp_port == 25


async def test_save_nvd_settings_clamps_and_keeps_key(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """CVE-COVERAGE FE: gün sınırlanır; API anahtarı şifreli saklanır + boşta korunur."""
    async with session_factory() as session:
        # Varsayılan günlük pencere 7 gün (oto-senkron son 1 hafta), anahtar yok.
        s0 = await get_settings(session)
        assert s0.nvd_sync_days == 7
        assert get_nvd_api_key(s0) == ""
        # Üst sınırı aşan gün → 730'a sıkışır; anahtar şifreli saklanır.
        s = await save_nvd_settings(session, sync_days=99_999, api_key="abc-key")
        assert s.nvd_sync_days == 730
        assert s.nvd_api_key_encrypted is not None
        assert s.nvd_api_key_encrypted != "abc-key"  # düz metin saklanmaz
        assert get_nvd_api_key(s) == "abc-key"
        # Alt sınırın altı (0) → 1'e sıkışır; boş anahtar → eski anahtar KORUNUR.
        s2 = await save_nvd_settings(session, sync_days=0, api_key=None)
        assert s2.nvd_sync_days == 1  # alt sınır (operatör 3 gün gibi kısa pencere girebilir)
        assert get_nvd_api_key(s2) == "abc-key"
        # Operatör kısa pencere (3 gün) girebilmeli (eski 30-gün alt sınırı kaldırıldı).
        s3 = await save_nvd_settings(session, sync_days=3, api_key=None)
        assert s3.nvd_sync_days == 3


async def test_record_cve_sync(session_factory: async_sessionmaker[AsyncSession]) -> None:
    """CVE-FRESHNESS: cpe_sync/backfill sonrası cve_last_sync güncellenir (exploit'ten ayrı)."""
    from datetime import UTC, datetime

    from cybersectool.core.app_settings import record_cve_sync

    async with session_factory() as session:
        assert (await get_settings(session)).cve_last_sync is None
        when = datetime(2026, 6, 9, 12, 0, tzinfo=UTC)
        await record_cve_sync(session, when)
        row = await get_settings(session)
        assert row.cve_last_sync is not None
        # sqlite tzinfo'yu düşürür → UTC kabul ederek karşılaştır.
        stored = row.cve_last_sync
        if stored.tzinfo is None:
            stored = stored.replace(tzinfo=UTC)
        assert stored == when
        # Exploit tazeliği etkilenmez (ayrı alanlar).
        assert row.exploit_last_sync is None


async def test_save_syslog_whitelists(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        s = await save_syslog_settings(
            session, enabled=True, host="siem", port=514, protocol="bogus", fmt="bogus"
        )
        assert s.syslog_protocol == "udp"  # geçersiz → varsayılan
        assert s.syslog_format == "rfc5424"
        s2 = await save_syslog_settings(
            session, enabled=True, host="siem", port=601, protocol="tcp", fmt="cef"
        )
        assert s2.syslog_protocol == "tcp"
        assert s2.syslog_format == "cef"


async def test_save_hardening_clamps_and_preserves_mfa(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        # Org MFA anahtarını önce aç; hardening kaydı bunu ezmemeli (mfa_required=None).
        s = await get_settings(session)
        s.mfa_required = True
        await session.commit()
        s2 = await save_hardening_settings(
            session,
            session_timeout_min=30,
            password_min_length=2,
            password_require_complexity=True,
            ldaps_verify_cert=True,
            ldaps_ca_cert="   ",
        )
        assert s2.session_timeout_min == 30
        assert s2.password_min_length == 4  # 2 → alt sınır 4
        assert s2.password_require_complexity is True
        assert s2.ldaps_verify_cert is True
        assert s2.ldaps_ca_cert is None  # boş PEM → None
        assert s2.mfa_required is True  # korunmalı


# --- Yerel AI ayarları (#182) ---


def test_normalize_ai_timeout() -> None:
    assert normalize_ai_timeout(90) == 90
    assert normalize_ai_timeout(None) == 300  # boş → varsayılan (#273: ağır CPU yüzeyleri)
    assert normalize_ai_timeout(0) == 300
    assert normalize_ai_timeout(2) == 300  # 5 altı → varsayılan
    assert normalize_ai_timeout(9999) == 600  # üst sınır


async def test_ai_timeout_default_is_300(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Taze ayar satırının AI zaman aşımı varsayılanı 300 sn (#273): ağır CPU yüzeyleri 60 sn'de
    timeout'a düşmesin. Kolon/form/compose varsayılanlarının sessizce kaymasını kilitler."""
    async with session_factory() as session:
        assert (await get_settings(session)).ai_timeout_sec == 300


async def test_save_ai_settings(session_factory: async_sessionmaker[AsyncSession]) -> None:
    """AI ayarları kaydı: aç/kapa + endpoint/model strip + timeout kısma. Varsayılan KAPALI."""
    async with session_factory() as session:
        d = await get_settings(session)
        assert d.ai_enabled is False  # varsayılan: AI kapalı (admin açana dek)
        s = await save_ai_settings(
            session,
            ai_enabled=True,
            ai_endpoint_url="  http://ollama:11434  ",
            ai_model_name="  qwen3:8b  ",
            ai_timeout_sec=900,
        )
        assert s.ai_enabled is True
        assert s.ai_endpoint_url == "http://ollama:11434"  # strip'lendi
        assert s.ai_model_name == "qwen3:8b"
        assert s.ai_timeout_sec == 600  # 900 → 600'e kısıldı
        # Boş endpoint/model saklanır (çözüm anında env'e düşer).
        s2 = await save_ai_settings(
            session, ai_enabled=False, ai_endpoint_url="", ai_model_name="", ai_timeout_sec=30
        )
        assert s2.ai_enabled is False
        assert s2.ai_endpoint_url == ""
        assert s2.ai_model_name == ""
        assert s2.ai_timeout_sec == 30


async def test_probe_ai_endpoint_mocked(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """probe_ai_endpoint: OpenAI /models'tan model listesini çeker; model kurulu mu raporlar."""
    import httpx

    from cybersectool.core.ai import client as ai_client

    real_client = httpx.AsyncClient  # gerçek istemciyi BİR KEZ yakala (mock'u mock'lama)

    def install(handler: object) -> None:
        transport = httpx.MockTransport(handler)  # type: ignore[arg-type]

        def factory(*a: object, **k: object) -> httpx.AsyncClient:
            k.pop("transport", None)
            return real_client(*a, transport=transport, **k)  # type: ignore[arg-type]

        monkeypatch.setattr(ai_client.httpx, "AsyncClient", factory)

    async with session_factory() as session:
        row = await save_ai_settings(
            session,
            ai_enabled=True,
            ai_endpoint_url="http://ollama:11434/v1",
            ai_model_name="qwen3:8b",
            ai_timeout_sec=60,
        )

        # Model kurulu → ok + has_model (OpenAI /models formatı: data[].id).
        def ok_handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": [{"id": "qwen3:8b"}, {"id": "phi3.5"}]})

        install(ok_handler)
        res = await probe_ai_endpoint(row)
        assert res["ok"] is True
        assert res["has_model"] is True
        assert res["model"] == "qwen3:8b"

        # Endpoint erişilebilir ama model yok → ok=True, has_model=False.
        def no_model(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": [{"id": "llama3.2:3b"}]})

        install(no_model)
        res2 = await probe_ai_endpoint(row)
        assert res2["ok"] is True
        assert res2["has_model"] is False

        # Erişilemez → ok=False.
        def down(_req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("down")

        install(down)
        res3 = await probe_ai_endpoint(row)
        assert res3["ok"] is False


def test_ai_brand_cache_pure() -> None:
    """AI marka cache'i set/get (sync context processor bunu okur)."""
    set_ai_brand_cache(True)
    assert ai_brand_enabled() is True
    set_ai_brand_cache(False)
    assert ai_brand_enabled() is False


async def test_ai_brand_mode_follows_ai_enabled(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """AI eklentisi açık → marka 'Kangalis AI' (ai_brand_enabled True); save + get tazeler."""
    set_ai_brand_cache(False)
    async with session_factory() as session:
        await save_ai_settings(
            session,
            ai_enabled=True,
            ai_endpoint_url="http://x:11434",
            ai_model_name="qwen3:8b",
            ai_timeout_sec=60,
        )
    assert ai_brand_enabled() is True  # save anında tazeledi
    # Cache'i boz → get_settings DB'den tekrar tazelemeli.
    set_ai_brand_cache(False)
    async with session_factory() as session:
        await get_settings(session)
    assert ai_brand_enabled() is True
    # AI kapatılınca markaya geri döner.
    async with session_factory() as session:
        await save_ai_settings(
            session,
            ai_enabled=False,
            ai_endpoint_url="",
            ai_model_name="",
            ai_timeout_sec=60,
        )
    assert ai_brand_enabled() is False
