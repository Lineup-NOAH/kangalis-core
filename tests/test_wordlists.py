"""Kelime listesi (Wordlist) testleri: parse + CRUD + web rotaları."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core import ldap as ldap_mod
from cybersectool.core.ldap import LdapUser
from cybersectool.core.ldap_config import save_ldap_config
from cybersectool.core.models import Role, WordlistKind
from cybersectool.core.users import create_user
from cybersectool.core.wordlists import (
    create_wordlist,
    delete_wordlist,
    list_wordlists,
    parse_entries,
    seed_builtin_wordlists,
    update_wordlist,
)


async def _login(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role,
) -> None:
    async with session_factory() as session:
        await create_user(session, username, "pass1234", role=role)
    await client.post("/auth/login", json={"username": username, "password": "pass1234"})


def test_parse_entries() -> None:
    raw = "admin\n  login \n\n# yorum\nadmin\nbackup,api\n"
    # Strip + boş/yorum at + virgül & satır ayır + sıra koruyarak tekilleştir.
    assert parse_entries(raw) == ["admin", "login", "backup", "api"]
    # Tümü boş/yorum → boş liste.
    assert parse_entries("   \n# yalnız yorum\n") == []
    # Aşırı uzun satır atlanır.
    long = "x" * 300
    assert parse_entries(f"ok\n{long}\n") == ["ok"]


async def test_create_and_list_wordlist(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        wd = await create_wordlist(
            session, "dizinler", WordlistKind.web_dir, ["admin", "login"], description="test"
        )
        assert wd.id is not None
        assert wd.entries == ["admin", "login"]
        await create_wordlist(session, "kullanicilar", WordlistKind.username, ["root", "admin"])
        # Tür filtresi yalnız o türü döndürür.
        web = await list_wordlists(session, WordlistKind.web_dir)
        assert [w.name for w in web] == ["dizinler"]
        # Filtresiz hepsi.
        assert len(await list_wordlists(session)) == 2


async def test_create_wordlist_validation(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        await create_wordlist(session, "dup", WordlistKind.web_dir, ["a"])
        with pytest.raises(ValueError):  # aynı isim
            await create_wordlist(session, "dup", WordlistKind.web_dir, ["b"])
        with pytest.raises(ValueError):  # boş satır listesi
            await create_wordlist(session, "bos", WordlistKind.web_dir, [])


async def test_update_wordlist(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        wd = await create_wordlist(session, "wl", WordlistKind.web_dir, ["a"])
        upd = await update_wordlist(
            session, wd.id, "wl2", WordlistKind.smb_share, ["x", "y"], description="d"
        )
        assert upd is not None
        assert upd.name == "wl2"
        assert upd.kind == WordlistKind.smb_share
        assert upd.entries == ["x", "y"]
        # Boş satır listesi → ValueError.
        with pytest.raises(ValueError):
            await update_wordlist(session, wd.id, "wl2", WordlistKind.web_dir, [])
        # Olmayan liste → None.
        assert await update_wordlist(session, 9999, "x", WordlistKind.web_dir, ["a"]) is None


async def test_builtin_wordlist_protected(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        wd = await create_wordlist(
            session, "yerlesik", WordlistKind.web_dir, ["a"], is_builtin=True
        )
        # Yerleşik liste düzenlenemez/silinemez.
        with pytest.raises(ValueError):
            await update_wordlist(session, wd.id, "x", WordlistKind.web_dir, ["b"])
        with pytest.raises(ValueError):
            await delete_wordlist(session, wd.id)


async def test_delete_wordlist(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        wd = await create_wordlist(session, "gecici", WordlistKind.web_dir, ["a"])
        assert await delete_wordlist(session, wd.id) is True
        assert await delete_wordlist(session, wd.id) is False
        assert await list_wordlists(session) == []


async def test_wordlist_create_route_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "wladmin", Role.admin)
    resp = await client.post(
        "/wordlists/create",
        data={
            "name": "rota-listesi",
            "kind": "web_dir",
            "description": "form",
            "entries_text": "admin\nlogin\nadmin\n# yorum",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/wordlists"  # ayrı sayfaya yönlendirir
    # Kelime listesi DB'de + Kelime Listeleri sayfasında görünür (tekilleştirilmiş 2 satır).
    async with session_factory() as session:
        lists = await list_wordlists(session)
        assert len(lists) == 1
        assert lists[0].entries == ["admin", "login"]
    page = await client.get("/wordlists")
    assert "rota-listesi" in page.text


async def test_wordlist_create_route_file_upload(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "wlfile", Role.admin)
    resp = await client.post(
        "/wordlists/create",
        data={"name": "dosya-listesi", "kind": "password"},
        files={"entries_file": ("rockyou-mini.txt", b"123456\npassword\nadmin\n", "text/plain")},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        lists = await list_wordlists(session, WordlistKind.password)
        assert len(lists) == 1
        assert lists[0].entries == ["123456", "password", "admin"]


async def test_wordlist_create_route_requires_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "wlanalyst", Role.analyst)
    resp = await client.post(
        "/wordlists/create",
        data={"name": "yetkisiz", "kind": "web_dir", "entries_text": "a"},
        follow_redirects=False,
    )
    # Admin değil → ana sayfaya yönlendirilir, liste oluşmaz.
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    async with session_factory() as session:
        assert await list_wordlists(session) == []


async def test_wordlist_delete_route(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "wldel", Role.admin)
    async with session_factory() as session:
        wd = await create_wordlist(session, "silinecek", WordlistKind.web_dir, ["a"])
        wid = wd.id
    resp = await client.post(f"/wordlists/{wid}/delete", follow_redirects=False)
    assert resp.status_code == 303
    async with session_factory() as session:
        assert await list_wordlists(session) == []


async def test_seed_builtin_wordlists_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Yerleşik listeler seed edilir (EN/TR + spray) ve ikinci çağrı kopya üretmez."""
    async with session_factory() as session:
        created = await seed_builtin_wordlists(session)
        assert created == 10  # web EN/TR + user EN/TR + üretilen + pass EN/TR + spray + smb + snmp
        lists = await list_wordlists(session)
        assert all(w.is_builtin for w in lists)
        names = {w.name for w in lists}
        assert "Zayıf parolalar (EN)" in names and "Zayıf parolalar (TR)" in names
        assert "Web dizinleri (EN)" in names and "Web dizinleri (TR)" in names
        assert "Politika-uyumlu parolalar (spray)" in names
        assert "SNMP toplulukları" in names
        assert "Üretilen kullanıcı adları (AD)" in names
        # Karmaşıklık-politikasını-atlatan yaygın kalıp (Aa123456) yerleşik parolada bulunmalı.
        pw_lists = await list_wordlists(session, WordlistKind.password)
        assert any("Aa123456" in w.entries for w in pw_lists)
        # İdempotent: ikinci çağrı 0 ekler, sayı sabit.
        assert await seed_builtin_wordlists(session) == 0
        assert len(await list_wordlists(session)) == 10


def test_generate_usernames() -> None:
    """AD kullanıcı adı kalıpları üretilir: flast/first.last/f.last vb., deterministik."""
    from cybersectool.core.wordlist_defaults import generate_usernames

    users = generate_usernames()
    assert len(users) >= 100
    assert len(users) == len(set(users))  # tekrar yok
    # ahmet + yilmaz → tüm kalıplar.
    for expected in ("ayilmaz", "ahmet.yilmaz", "a.yilmaz", "ahmetyilmaz", "ahmet_yilmaz", "ahmet"):
        assert expected in users, expected


def test_generate_policy_passwords() -> None:
    """Üretilen parolalar politikayı karşılar: ≥1 büyük + ≥1 küçük + ≥1 rakam, ≥8 hane."""
    from cybersectool.core.wordlist_defaults import generate_policy_passwords

    pws = generate_policy_passwords()
    assert len(pws) >= 100  # gözle görülür sayıda spray adayı
    assert len(pws) == len(set(pws))  # tekrar yok
    assert "Summer2024!" in pws and "Galatasaray1" in pws and "Aa123456!" in pws
    for pw in pws:
        assert len(pw) >= 8
        assert any(c.isupper() for c in pw), pw
        assert any(c.islower() for c in pw), pw
        assert any(c.isdigit() for c in pw), pw


async def test_seed_reconcile_removes_stale_and_keeps_user(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Seed: kanonik olmayan eski YERLEŞİK silinir; kullanıcı listesi KORUNUR."""
    async with session_factory() as session:
        # Eski adlı yerleşik (artık kanonik değil) + aynı isimde kullanıcı listesi.
        await create_wordlist(
            session, "Eski yerleşik (yerleşik)", WordlistKind.web_dir, ["a"], is_builtin=True
        )
        await create_wordlist(session, "benim-listem", WordlistKind.password, ["x"])
        await seed_builtin_wordlists(session)
        names = {w.name for w in await list_wordlists(session)}
        assert "Eski yerleşik (yerleşik)" not in names  # stale yerleşik temizlendi
        assert "benim-listem" in names  # kullanıcı listesi korundu
        assert "Zayıf parolalar (EN)" in names  # kanonik eklendi


async def test_wordlists_page_admin_only(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """/wordlists yalnız admin; analyst kök sayfaya yönlendirilir."""
    await _login(client, session_factory, "wlpage_an", Role.analyst)
    resp = await client.get("/wordlists", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    await _login(client, session_factory, "wlpage_adm", Role.admin)
    ok = await client.get("/wordlists")
    assert ok.status_code == 200


async def test_wordlist_view_page(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Salt-okunur görüntüleme: yerleşik liste dahil satırlar görünür."""
    await _login(client, session_factory, "wlview", Role.admin)
    async with session_factory() as session:
        wd = await create_wordlist(
            session, "gorunum", WordlistKind.web_dir, ["admin", "gizli-yol"], is_builtin=True
        )
        wid = wd.id
    resp = await client.get(f"/wordlists/{wid}/view")
    assert resp.status_code == 200
    assert "gizli-yol" in resp.text  # içerik salt-okunur görünüyor


# --- LDAP Kullanıcı Kasası rotası ---


async def _setup_ldap_config(session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as session:
        await save_ldap_config(
            session,
            server_uri="ldap://x:389",
            use_ssl=False,
            bind_dn="cn=admin,dc=x",
            base_dn="dc=x",
            user_filter="(objectClass=person)",
            attr_username="uid",
            attr_email="mail",
            attr_display_name="cn",
            default_role="analyst",
            bind_password="secret",
        )


def _fake_ldap_users(*names: str) -> object:
    def _search(
        config: object,
        bind_password: str,
        query: str,
        verify_cert: bool,
        ca_cert: str | None,
    ) -> list[LdapUser]:
        return [LdapUser(username=n, email=None, display_name=None, dn="") for n in names]

    return _search


async def test_ldap_vault_route_creates_username_wordlist(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LDAP'tan çekilen kullanıcı adları username wordlist'ine kaydedilir (dedup, sıra)."""
    await _login(client, session_factory, "ldapvault", Role.admin)
    await _setup_ldap_config(session_factory)
    # 'alice' tekrarı dedup edilmeli; sıra korunmalı.
    monkeypatch.setattr(ldap_mod, "_search_users", _fake_ldap_users("alice", "bob", "alice"))
    resp = await client.post(
        "/wordlists/ldap-users",
        data={"name": "ldap-kullanicilari", "query": ""},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        lists = await list_wordlists(session, WordlistKind.username)
    match = [w for w in lists if w.name == "ldap-kullanicilari"]
    assert match and match[0].entries == ["alice", "bob"]


async def test_ldap_vault_route_requires_config(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """LDAP yapılandırılmamışsa hata sayfası (400) döner, liste oluşmaz."""
    await _login(client, session_factory, "ldapvault_noc", Role.admin)
    resp = await client.post("/wordlists/ldap-users", data={"name": "x", "query": ""})
    assert resp.status_code == 400
    async with session_factory() as session:
        lists = await list_wordlists(session, WordlistKind.username)
    assert not [w for w in lists if w.name == "x"]


async def test_ldap_vault_route_requires_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin olmayan kullanıcı kasaya erişemez (→ /)."""
    await _login(client, session_factory, "ldapvault_an", Role.analyst)
    resp = await client.post("/wordlists/ldap-users", data={"name": "x"}, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"


async def test_ldap_vault_preview(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Önizleme sayıyı + örnekleri döner, kaydetmez."""
    await _login(client, session_factory, "ldapvault_pv", Role.admin)
    await _setup_ldap_config(session_factory)
    monkeypatch.setattr(ldap_mod, "_search_users", _fake_ldap_users("carol", "dave"))
    resp = await client.post("/wordlists/ldap-users/preview", data={"query": ""})
    assert resp.status_code == 200
    assert "carol" in resp.text and "dave" in resp.text
    async with session_factory() as session:
        lists = await list_wordlists(session, WordlistKind.username)
    assert not lists  # önizleme kayıt yapmaz
