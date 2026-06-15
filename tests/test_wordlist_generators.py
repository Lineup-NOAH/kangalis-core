"""Kelime listesi üreticileri: kullanıcı adı (ad-soyad → AD kalıpları) saf + web rota testleri."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Role, WordlistKind
from cybersectool.core.users import create_user
from cybersectool.core.wordlist_defaults import generate_usernames as builtin_generate_usernames
from cybersectool.core.wordlist_generators import (
    USERNAME_PATTERN_KEYS,
    PasswordSpec,
    apply_custom_pattern,
    generate_passwords,
    generate_usernames,
    normalize_tr,
    parse_name_pairs,
    password_passes_policy,
)
from cybersectool.core.wordlists import list_wordlists


async def _login_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession], username: str
) -> None:
    async with session_factory() as session:
        await create_user(session, username, "pass1234", role=Role.admin)
    await client.post("/auth/login", json={"username": username, "password": "pass1234"})


# --- Saf fonksiyonlar ---


def test_normalize_tr() -> None:
    assert normalize_tr("Yılmaz") == "yilmaz"
    assert normalize_tr("İŞĞÜÖÇ") == "isguoc"
    assert normalize_tr("  Ahmet  ") == "ahmet"
    assert normalize_tr("Şükrü") == "sukru"


def test_parse_name_pairs() -> None:
    pairs = parse_name_pairs("Ahmet Yılmaz\nMehmet Kaya")
    assert pairs == [("Ahmet", "Yılmaz"), ("Mehmet", "Kaya")]
    # Virgül de ayraç; tek kelime → soyadsız; çok kelime → ilk+son.
    assert parse_name_pairs("Ali, Veli Can Demir") == [("Ali", ""), ("Veli", "Demir")]
    assert parse_name_pairs("   \n\n") == []


def test_generate_usernames_all_patterns() -> None:
    out = generate_usernames([("Ahmet", "Yılmaz")])
    # 7 kalıp, TR normalize açık (varsayılan): ayilmaz/ahmet.yilmaz/a.yilmaz/...
    assert out == [
        "ayilmaz",
        "ahmet.yilmaz",
        "a.yilmaz",
        "ahmetyilmaz",
        "ahmet_yilmaz",
        "ahmet",
        "ahmety",
    ]


def test_generate_usernames_pattern_subset_keeps_canonical_order() -> None:
    # Yalnız iki kalıp seç; kanonik sıraya indirgenir (giriş sırası önemsiz).
    out = generate_usernames([("Ayse", "Kara")], patterns=["first", "flast"])
    assert out == ["akara", "ayse"]  # flast kanonik sırada first'ten önce


def test_generate_usernames_normalize_toggle() -> None:
    # normalize=False → Türkçe karakter + büyük/küçük harf korunur (yalnız strip).
    out = generate_usernames([("Şük", "Öz")], patterns=["flast"], normalize=False)
    assert out == ["ŞÖz"]  # "Ş" + "Öz"
    out2 = generate_usernames([("Şük", "Öz")], patterns=["flast"], normalize=True)
    assert out2 == ["soz"]  # ASCII + küçük harf


def test_generate_usernames_single_word_uses_no_last_patterns() -> None:
    # Soyadsız giriş → yalnız soyad gerektirmeyen kalıplar üretilir.
    out = generate_usernames([("admin", "")])
    assert out == ["admin"]  # firstlast/first/firstl hepsi 'admin'e indirger → dedup


def test_generate_usernames_dedup_across_names() -> None:
    out = generate_usernames([("ahmet", "kaya"), ("ahmet", "kaya")])
    assert len(out) == len(set(out))  # tekrar yok


def test_builtin_generator_matches_module() -> None:
    # Yerleşik üretici artık ortak modülü kullanır; çıktı boş değil ve tekildir.
    builtin = builtin_generate_usernames()
    assert len(builtin) > 100
    assert len(builtin) == len(set(builtin))
    # Bilinen örnekler beklenen kalıplarda var.
    assert "ayilmaz" in builtin
    assert "ahmet.yilmaz" in builtin


def test_username_pattern_keys_stable() -> None:
    assert USERNAME_PATTERN_KEYS[0] == "flast"
    assert "first.last" in USERNAME_PATTERN_KEYS
    assert len(USERNAME_PATTERN_KEYS) == 7


def test_apply_custom_pattern() -> None:
    assert apply_custom_pattern("{first}.{last}", "ahmet", "yilmaz") == "ahmet.yilmaz"
    assert apply_custom_pattern("{f}{last}", "ahmet", "yilmaz") == "ayilmaz"
    assert apply_custom_pattern("{first}-{l}", "ahmet", "yilmaz") == "ahmet-y"
    # Soyad gerektiren token var ama soyad yok → None (atla).
    assert apply_custom_pattern("{f}{last}", "admin", "") is None
    assert apply_custom_pattern("{l}.{first}", "admin", "") is None
    # Soyad gerektirmeyen şablon tek adda çalışır.
    assert apply_custom_pattern("svc-{first}", "admin", "") == "svc-admin"


def test_generate_usernames_with_custom_patterns() -> None:
    out = generate_usernames(
        [("Ahmet", "Yılmaz")],
        patterns=["first"],  # yalnız 'first' preset
        custom_patterns=["{first}.{last}", "{f}{last}"],
    )
    # Önce preset 'first' (ahmet), sonra custom'lar (TR normalize uygulanmış).
    assert out == ["ahmet", "ahmet.yilmaz", "ayilmaz"]


def test_generate_usernames_custom_dedup_with_preset() -> None:
    # Custom şablon preset ile aynı çıktıyı verirse tekrar edilmez.
    out = generate_usernames([("ali", "kaya")], patterns=["flast"], custom_patterns=["{f}{last}"])
    assert out == ["akaya"]  # preset flast == custom {f}{last} → tek


# --- Parola üretici (saf) ---


def test_password_passes_policy() -> None:
    spec = PasswordSpec(min_len=8, require_upper=True, require_lower=True, require_digit=True)
    assert password_passes_policy("Sirket123", spec)
    assert not password_passes_policy("sirket123", spec)  # büyük harf yok
    assert not password_passes_policy("Sirket", spec)  # rakam yok + 8 hane değil
    assert not password_passes_policy("Sir1", spec)  # 8 hane değil
    spec_special = PasswordSpec(require_special=True)
    assert password_passes_policy("Sirket123!", spec_special)
    assert not password_passes_policy("Sirket123", spec_special)  # özel karakter yok


def test_generate_passwords_all_compliant() -> None:
    spec = PasswordSpec(
        min_len=8,
        require_upper=True,
        require_lower=True,
        require_digit=True,
        capitalize=True,
        suffixes=("", "!"),
        digits=("123", "2024"),
        years=(),
    )
    out = generate_passwords(["sirket"], spec)
    # ÜretiLEN her parola politikaya uymalı.
    assert out, "en az bir aday üretilmeli"
    assert all(password_passes_policy(p, spec) for p in out)
    # Beklenen örnekler: Sirket + sayı (+ ops. !). 'sirket123' (büyük harf yok) ELENİR.
    assert "Sirket123" in out
    assert "Sirket123!" in out
    assert "sirket123" not in out


def test_generate_passwords_dedup_and_cap() -> None:
    spec = PasswordSpec(min_len=1, require_upper=False, require_lower=False, require_digit=False)
    out = generate_passwords(["a", "a"], spec)
    assert len(out) == len(set(out))  # tekrar yok
    capped = PasswordSpec(
        min_len=1,
        require_upper=False,
        require_lower=False,
        require_digit=False,
        max_results=3,
    )
    assert len(generate_passwords(["sirket", "istanbul", "marka"], capped)) <= 3


def test_generate_passwords_examples_included_directly() -> None:
    # Örnek parola politikaya uyuyorsa doğrudan (önce) eklenir.
    spec = PasswordSpec(min_len=8, require_upper=True, require_lower=True, require_digit=True)
    out = generate_passwords([], spec, examples=["Aa123456", "kisa"])
    assert "Aa123456" in out  # uyar → eklenir
    assert "kisa" not in out  # politikaya uymaz → elenir


def test_generate_passwords_leet() -> None:
    spec = PasswordSpec(
        min_len=1,
        require_upper=False,
        require_lower=False,
        require_digit=False,
        capitalize=False,
        leet=True,
        suffixes=("",),
        digits=(),
    )
    out = generate_passwords(["sirket"], spec)
    assert "sirket" in out
    assert "$1rk3t" in out  # s→$, i→1, e→3


# --- Web rotaları ---


async def test_generate_usernames_web_creates_wordlist(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login_admin(client, session_factory, "adm_gen_user")
    resp = await client.post(
        "/wordlists/generate/usernames",
        data={
            "name": "hedef-kullanicilar",
            "names_text": "Ahmet Yılmaz\nMehmet Kaya",
            "patterns": ["flast", "first.last"],
            "normalize": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/wordlists/" in resp.headers["location"]
    async with session_factory() as session:
        lists = await list_wordlists(session, WordlistKind.username)
    created = next((w for w in lists if w.name == "hedef-kullanicilar"), None)
    assert created is not None
    # 2 isim × 2 kalıp = 4 kullanıcı adı, TR normalize uygulanmış.
    assert created.entries == ["ayilmaz", "ahmet.yilmaz", "mkaya", "mehmet.kaya"]


async def test_generate_usernames_web_empty_is_rejected(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login_admin(client, session_factory, "adm_gen_empty")
    resp = await client.post(
        "/wordlists/generate/usernames",
        data={"name": "bos", "names_text": "   ", "patterns": ["flast"]},
        follow_redirects=False,
    )
    assert resp.status_code == 400  # üretilecek ad yok → hata


async def test_generate_usernames_preview_returns_fragment(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login_admin(client, session_factory, "adm_gen_prev")
    resp = await client.post(
        "/wordlists/generate/usernames/preview",
        data={"names_text": "Ahmet Yılmaz", "patterns": ["flast", "first"], "normalize": "on"},
    )
    assert resp.status_code == 200
    body = resp.text
    assert "ayilmaz" in body
    assert "ahmet" in body


async def test_generate_usernames_requires_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        await create_user(session, "viewer_gen", "pass1234", role=Role.viewer)
    await client.post("/auth/login", json={"username": "viewer_gen", "password": "pass1234"})
    resp = await client.post(
        "/wordlists/generate/usernames",
        data={"name": "x", "names_text": "Ahmet Yılmaz"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"  # admin değil → ana sayfaya


async def test_generate_passwords_web_creates_wordlist(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login_admin(client, session_factory, "adm_gen_pass")
    resp = await client.post(
        "/wordlists/generate/passwords",
        data={
            "name": "hedef-parolalar",
            "bases_text": "sirket",
            "min_len": "8",
            "require_upper": "on",
            "require_lower": "on",
            "require_digit": "on",
            "capitalize": "on",
            "suffixes": ["!"],
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/wordlists/" in resp.headers["location"]
    async with session_factory() as session:
        lists = await list_wordlists(session, WordlistKind.password)
    created = next((w for w in lists if w.name == "hedef-parolalar"), None)
    assert created is not None
    assert created.entries  # boş değil
    # Üretilen her parola politikaya uygun (büyük+küçük+rakam, >=8).
    spec = PasswordSpec(min_len=8, require_upper=True, require_lower=True, require_digit=True)
    assert all(password_passes_policy(p, spec) for p in created.entries)
    assert "Sirket123" in created.entries


async def test_generate_passwords_web_empty_is_rejected(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login_admin(client, session_factory, "adm_gen_pass_empty")
    # Politika çok katı + taban yok → hiç aday → hata.
    resp = await client.post(
        "/wordlists/generate/passwords",
        data={"name": "bos", "bases_text": "", "require_special": "on", "min_len": "14"},
        follow_redirects=False,
    )
    assert resp.status_code == 400


async def test_generate_passwords_preview_returns_fragment(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login_admin(client, session_factory, "adm_gen_pass_prev")
    resp = await client.post(
        "/wordlists/generate/passwords/preview",
        data={
            "bases_text": "sirket",
            "min_len": "8",
            "require_upper": "on",
            "require_lower": "on",
            "require_digit": "on",
            "capitalize": "on",
        },
    )
    assert resp.status_code == 200
    assert "Sirket" in resp.text
