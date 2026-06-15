"""Veritabani baglantisi: async engine, session factory ve declarative Base."""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from cybersectool.config import settings


class Base(DeclarativeBase):
    """Tum ORM modelleri icin temel sinif (modeller PR-05'te eklenecek)."""


engine: AsyncEngine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_pre_ping=True,
)

SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI bagimlilik enjeksiyonu icin async DB oturumu uretir."""
    async with SessionLocal() as session:
        yield session
