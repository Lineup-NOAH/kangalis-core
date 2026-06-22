"""#A: Yardım/Dokümanlar (/help) statik sayfası — tüm giriş yapan kullanıcılar.

İçerik web/help_content.py'de TEK KAYNAK; grounding_text AYNI içeriği (ileride) AI Q&A
ekranı (#2c) için düz metne çevirir. Sayfa admin-gated DEĞİL (admin: false).
"""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Role
from cybersectool.core.users import create_user
from cybersectool.web.help_content import HELP_SECTIONS, grounding_text


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


async def test_help_page_all_users_render(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin OLMAYAN kullanıcı /help'i görebilir; başlık + bölüm + komut snippet render olur."""
    await _login(client, session_factory, "an_help", Role.analyst)
    resp = await client.get("/help")
    assert resp.status_code == 200
    body = resp.text
    assert "Yardım" in body  # help_title (TR varsayılan)
    assert "Başlangıç" in body  # ilk bölüm başlığı
    assert "set_scope" in body  # kapsam komutu snippet'i
    assert "nvd.nist.gov" in body  # NVD anahtarı snippet'i
    assert 'href="/help"' in body  # sol menü girişi (Ayarlar'ın altında)


async def test_help_page_requires_login(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Giriş yapılmadan /help login'e yönlendirir."""
    resp = await client.get("/help", follow_redirects=False)
    assert resp.status_code in (302, 303)
    assert "login" in resp.headers.get("location", "").lower()


def test_grounding_text_covers_all_sections() -> None:
    """grounding_text (AI Q&A #2c kaynağı) tüm bölüm başlıklarını + komut snippet'lerini içerir."""
    text = grounding_text("tr")
    assert text
    for sec in HELP_SECTIONS:
        assert sec.title_tr in text
    assert "set_scope" in text  # snippet'ler de bağlama dahil
    assert "ollama pull" in text
