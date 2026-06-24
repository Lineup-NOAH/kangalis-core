"""Test altyapısı: bellek-içi SQLite + bağımlılık override + async istemci."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from cybersectool.api.app import app
from cybersectool.config import settings
from cybersectool.core.db import Base, get_session


@pytest.fixture(autouse=True)
def _allow_aggressive_by_default() -> Iterator[None]:
    """Test ortamında agresif tarama global kilidi (ALLOW_AGGRESSIVE_SCANS) AÇIK varsayılır.

    Böylece agresif route'lar test edilebilir; kilit KAPALI iken 403 davranışı ilgili testte
    ``settings.allow_aggressive_scans = False`` ile ayrıca doğrulanır.
    """
    original = settings.allow_aggressive_scans
    settings.allow_aggressive_scans = True
    yield
    settings.allow_aggressive_scans = original


@pytest.fixture(autouse=True)
def _bypass_disclaimer_gate(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sorumluluk reddi kapısı kesişen (cross-cutting) bir kısıttır; onu sınamayan testlerde
    kapatılır → mevcut/gelecek tarama testleri kabul akışını tekrar etmek zorunda kalmaz.

    Kapının kendisi (giriş yönlendirmesi + /scans* engeli) ``@pytest.mark.disclaimer_gate``
    işaretli özel testte gerçek haliyle doğrulanır; o test bu bypass'ı atlar.
    """
    if request.node.get_closest_marker("disclaimer_gate"):
        return
    monkeypatch.setattr("cybersectool.core.disclaimer.disclaimer_enforced", lambda: False)


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def client(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    async def _override() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = _override
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
