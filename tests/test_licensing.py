"""Çevrimdışı, imza-temelli ticari lisans doğrulaması (core/licensing.py) + Lisans web formu.

verify_license: geçerli/süresi-dolmuş/geçersiz(kurcalama|yanlış-anahtar)/yok/devre-dışı
durumlarını test eder; feature_licensed true/false; admin lisans kaydeder + durum görünür,
admin olmayan yönlendirilir. Test anahtar çifti TESTTE üretilir; app_config.license_public_key
monkeypatch'lenir (gerçek anahtar gerekmez).
"""

from __future__ import annotations

import base64
import json
from datetime import date, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.config import settings as app_config
from cybersectool.core.app_settings import save_license_key
from cybersectool.core.licensing import active_license, feature_licensed, verify_license
from cybersectool.core.models import Role
from cybersectool.core.users import create_user


def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _make_license(
    private_key: ed25519.Ed25519PrivateKey,
    *,
    customer: str = "Acme A.S.",
    expires: str | None = None,
    features: tuple[str, ...] = ("exploit",),
) -> str:
    """gen_license mantığını yansıtan küçük yardımcı: imzalı lisans kodu üretir."""
    payload = {
        "customer": customer,
        "issued": date.today().isoformat(),
        "expires": expires,
        "features": list(features),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    signature = private_key.sign(payload_bytes)
    return f"{_b64url_nopad(payload_bytes)}.{_b64url_nopad(signature)}"


@pytest.fixture
def signing_key(monkeypatch: pytest.MonkeyPatch) -> ed25519.Ed25519PrivateKey:
    """Test anahtar çifti üretir + açık anahtarı app_config'e monkeypatch'ler."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_b64 = base64.b64encode(private_key.public_key().public_bytes_raw()).decode("ascii")
    monkeypatch.setattr(app_config, "license_public_key", public_b64)
    return private_key


def test_valid_license(signing_key: ed25519.Ed25519PrivateKey) -> None:
    """Geçerli imza + geçerli özellik → status 'valid', özellikler taşınır."""
    code = _make_license(signing_key, customer="Acme", features=("exploit", "report"))
    info = verify_license(code)
    assert info.status == "valid"
    assert info.is_valid
    assert info.customer == "Acme"
    assert "exploit" in info.features
    assert "report" in info.features


def test_perpetual_license_has_no_expiry(signing_key: ed25519.Ed25519PrivateKey) -> None:
    """expires=null → süresiz; valid kalır."""
    code = _make_license(signing_key, expires=None)
    info = verify_license(code)
    assert info.status == "valid"
    assert info.expires is None


def test_expired_license(signing_key: ed25519.Ed25519PrivateKey) -> None:
    """Dün biten lisans → status 'expired' (yine de müşteri/özellik görüntü için döner)."""
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    code = _make_license(signing_key, customer="Eski", expires=yesterday)
    info = verify_license(code)
    assert info.status == "expired"
    assert not info.is_valid
    assert info.customer == "Eski"
    assert info.expires == yesterday
    assert info.features == ("exploit",)


def test_future_expiry_is_valid(signing_key: ed25519.Ed25519PrivateKey) -> None:
    """Gelecekte biten lisans → valid."""
    future = (date.today() + timedelta(days=30)).isoformat()
    info = verify_license(_make_license(signing_key, expires=future))
    assert info.status == "valid"


def test_tampered_payload_invalid(signing_key: ed25519.Ed25519PrivateKey) -> None:
    """Payload kurcalanırsa imza tutmaz → 'invalid'."""
    code = _make_license(signing_key, customer="Acme")
    payload_b64, sig_b64 = code.split(".", 1)
    # Payload'ı boz: farklı müşteriyle yeniden kodla, imzayı ESKİ bırak.
    bad_payload = {
        "customer": "Saldırgan",
        "issued": date.today().isoformat(),
        "expires": None,
        "features": ["exploit"],
    }
    bad_b64 = _b64url_nopad(
        json.dumps(bad_payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    info = verify_license(f"{bad_b64}.{sig_b64}")
    assert info.status == "invalid"


def test_wrong_key_signature_invalid(signing_key: ed25519.Ed25519PrivateKey) -> None:
    """Başka bir anahtarla imzalanmış kod → 'invalid' (açık anahtar eşleşmez)."""
    other_key = ed25519.Ed25519PrivateKey.generate()
    code = _make_license(other_key, customer="Acme")
    info = verify_license(code)
    assert info.status == "invalid"


def test_garbage_string_invalid(signing_key: ed25519.Ed25519PrivateKey) -> None:
    """Biçimsiz metin (nokta yok / base64 değil) → 'invalid'."""
    assert verify_license("bu-gecerli-bir-lisans-degil").status == "invalid"
    assert verify_license("a.b.c").status == "invalid"


def test_non_dict_payload_invalid(signing_key: ed25519.Ed25519PrivateKey) -> None:
    """İmzalı ama NESNE-OLMAYAN payload (liste) → 'invalid' (AttributeError FIRLATMAZ)."""
    payload_bytes = json.dumps([1, 2, 3], separators=(",", ":")).encode("utf-8")
    sig = signing_key.sign(payload_bytes)
    code = f"{_b64url_nopad(payload_bytes)}.{_b64url_nopad(sig)}"
    assert verify_license(code).status == "invalid"  # fırlatmadan kilit-tarafa düşer


def test_malformed_public_key_invalid(
    signing_key: ed25519.Ed25519PrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bozuk açık anahtar (kısa / base64-değil) → 'invalid', istisna fırlatmaz."""
    code = _make_license(signing_key)
    monkeypatch.setattr(app_config, "license_public_key", base64.b64encode(b"12345678").decode())
    assert verify_license(code).status == "invalid"  # 8 bayt ≠ 32 → from_public_bytes hata
    monkeypatch.setattr(app_config, "license_public_key", "bu-base64-degil!!")
    assert verify_license(code).status == "invalid"


def test_expiry_boundary_today_valid(signing_key: ed25519.Ed25519PrivateKey) -> None:
    """Bugün biten lisans hâlâ 'valid' (kesin '<' → bugün henüz dolmamış sayılır)."""
    today = date.today().isoformat()
    assert verify_license(_make_license(signing_key, expires=today)).status == "valid"


def test_empty_string_none(signing_key: ed25519.Ed25519PrivateKey) -> None:
    """Boş/boşluk → status 'none'."""
    assert verify_license("").status == "none"
    assert verify_license("   ").status == "none"


def test_public_key_unset_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Açık anahtar yapılandırılmamış → 'disabled' (lisanslama kapalı)."""
    monkeypatch.setattr(app_config, "license_public_key", "")
    # Boş olmayan bir kod gönderilse bile (anahtar yokken) önce 'disabled' döner.
    assert verify_license("herhangi.birsey").status == "disabled"


async def test_feature_licensed_true_false(
    signing_key: ed25519.Ed25519PrivateKey,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """DB'deki lisans 'exploit' içeriyorsa True; başka özellik için False."""
    code = _make_license(signing_key, features=("exploit",))
    async with session_factory() as s:
        await save_license_key(s, license_key=code)
    async with session_factory() as s:
        assert await feature_licensed(s, "exploit") is True
        assert await feature_licensed(s, "report") is False


async def test_feature_licensed_false_without_license(
    signing_key: ed25519.Ed25519PrivateKey,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Lisans yokken (boş) feature_licensed False."""
    async with session_factory() as s:
        assert await feature_licensed(s, "exploit") is False


def test_generator_roundtrip(signing_key: ed25519.Ed25519PrivateKey) -> None:
    """scripts/gen_license ürettiği kodu verify_license kabul eder (uçtan uca)."""
    # ``scripts`` paket olarak kurulu değil (depo kökü sys.path'te olmayabilir) → dosyadan yükle.
    import importlib.util
    from pathlib import Path

    script_path = Path(__file__).resolve().parent.parent / "scripts" / "gen_license.py"
    spec = importlib.util.spec_from_file_location("gen_license", script_path)
    assert spec is not None and spec.loader is not None
    gen_license = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen_license)

    private_b64 = base64.b64encode(signing_key.private_bytes_raw()).decode("ascii")
    code = gen_license.build_license(private_b64, "Acme", days=10, features=("exploit",))
    info = verify_license(code)
    assert info.status == "valid"
    assert info.customer == "Acme"
    assert "exploit" in info.features


# --- Web formu (Lisans kartı) ---


async def _login(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role,
) -> None:
    async with session_factory() as s:
        await create_user(s, username, "pass1234", role=role)
    await client.post(
        "/login", data={"username": username, "password": "pass1234"}, follow_redirects=False
    )


async def test_license_form_admin_saves(
    signing_key: ed25519.Ed25519PrivateKey,
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Admin lisans kodunu kaydeder → DB'ye yazılır + feature_licensed açılır."""
    await _login(client, session_factory, "lic_adm", Role.admin)
    code = _make_license(signing_key, customer="Acme", features=("exploit",))
    resp = await client.post("/license", data={"license_key": code}, follow_redirects=False)
    assert resp.status_code in (302, 303)
    # Kayıttan sonra ayrı Lisans sekmesine yönlenir (Ayarlar'a değil).
    assert resp.headers["location"].startswith("/license")
    async with session_factory() as s:
        assert await feature_licensed(s, "exploit") is True


async def test_license_page_admin_renders(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Admin için /license sayfası 200 döner + lisans formunu (action=/license) içerir."""
    await _login(client, session_factory, "lic_get_adm", Role.admin)
    resp = await client.get("/license")
    assert resp.status_code == 200
    assert 'action="/license"' in resp.text


async def test_license_page_shows_license_status(
    signing_key: ed25519.Ed25519PrivateKey,
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Geçerli lisans kaydedilince Lisans sayfasında müşteri adı görünür."""
    await _login(client, session_factory, "lic_adm2", Role.admin)
    code = _make_license(signing_key, customer="GorunenMusteri")
    await client.post("/license", data={"license_key": code}, follow_redirects=False)
    resp = await client.get("/license")
    assert resp.status_code == 200
    assert 'action="/license"' in resp.text
    assert "GorunenMusteri" in resp.text


async def test_settings_page_no_license_card(
    signing_key: ed25519.Ed25519PrivateKey,
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Lisans kartı Ayarlar'dan taşındı → Ayarlar sayfası artık lisans formunu içermez."""
    await _login(client, session_factory, "lic_adm3", Role.admin)
    resp = await client.get("/settings")
    assert resp.status_code == 200
    assert "/settings/license" not in resp.text
    assert "license_key" not in resp.text


async def test_license_form_non_admin_redirected(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Admin olmayan lisans yazamaz (yönlendirilir, lisans yazılmaz)."""
    await _login(client, session_factory, "lic_an", Role.analyst)
    resp = await client.post("/license", data={"license_key": "x.y"}, follow_redirects=False)
    assert resp.status_code in (302, 303)
    # GET sayfası da admin değilse köke yönlenir.
    get_resp = await client.get("/license", follow_redirects=False)
    assert get_resp.status_code in (302, 303)
    assert get_resp.headers["location"] == "/"
    async with session_factory() as s:
        from cybersectool.core.app_settings import get_settings

        row = await get_settings(s)
        assert row.license_key == ""


# --- Açık anahtar (public key) DB'den / UI'dan (env yerine) ---


def test_verify_license_uses_db_pubkey_without_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Açık anahtar parametre olarak verilince env GEREKMEZ → 'valid'."""
    monkeypatch.setattr(app_config, "license_public_key", "")  # env boş
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode("ascii")
    code = _make_license(priv, customer="DbKeyCo")
    info = verify_license(code, public_key=pub_b64)
    assert info.status == "valid"
    assert info.customer == "DbKeyCo"


def test_verify_license_db_pubkey_wins_over_env(
    signing_key: ed25519.Ed25519PrivateKey,
) -> None:
    """DB açık anahtarı env'i EZER: env doğru olsa da yanlış DB anahtarı → 'invalid'."""
    # signing_key fixture env'i DOĞRU anahtara ayarlar; ama yanlış bir DB anahtarı verelim.
    other_pub = base64.b64encode(
        ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    ).decode("ascii")
    code = _make_license(signing_key, customer="Acme")
    assert verify_license(code, public_key=other_pub).status == "invalid"
    # Aynı kod, DB anahtarı boş → env fallback (doğru) → 'valid'.
    assert verify_license(code, public_key="").status == "valid"


async def test_license_page_pubkey_saved_and_used(
    monkeypatch: pytest.MonkeyPatch,
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Açık anahtar + kod UI'dan (env'siz) kaydedilince active_license 'valid' olur."""
    monkeypatch.setattr(app_config, "license_public_key", "")  # env yok → yalnız DB anahtarı
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode("ascii")
    code = _make_license(priv, customer="UiKeyCo", features=("exploit",))
    await _login(client, session_factory, "lic_pk_adm", Role.admin)
    resp = await client.post(
        "/license",
        data={"license_public_key": pub_b64, "license_key": code},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)
    async with session_factory() as s:
        info = await active_license(s)
        assert info.status == "valid"
        assert info.customer == "UiKeyCo"
        assert await feature_licensed(s, "exploit") is True
