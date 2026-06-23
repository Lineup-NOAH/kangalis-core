"""Bileşen sürüm tespiti (core/versions) — hata-yutar; nmap parse + gather_versions.

Her probe başarısız olursa None döner (sayfa çökmez). SQLite'ta ``SELECT version()`` yok →
postgres_version None döner (fail-soft kanıtı). Redis test ortamında yok → None.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import cybersectool.core.versions as ver
from cybersectool.core.app_settings import get_settings


def test_app_version_is_single_source() -> None:
    from cybersectool import __version__

    assert ver.app_version() == __version__
    assert ver.app_version()  # boş değil


def test_python_version_nonempty() -> None:
    assert ver.python_version()


def test_nmap_version_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ver.shutil, "which", lambda _name: None)
    assert ver.nmap_version() is None


def test_nmap_version_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ver.shutil, "which", lambda _name: "/usr/bin/nmap")

    class _R:
        stdout = "Nmap version 7.94 ( https://nmap.org )\nPlatform: x86_64\n"

    monkeypatch.setattr(ver.subprocess, "run", lambda *a, **k: _R())
    assert ver.nmap_version() == "7.94"


def test_nmap_version_failsoft(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ver.shutil, "which", lambda _name: "/usr/bin/nmap")

    def _boom(*_a: object, **_k: object) -> None:
        raise OSError("nmap patladı")

    monkeypatch.setattr(ver.subprocess, "run", _boom)
    assert ver.nmap_version() is None


async def test_gather_versions_failsoft(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ver, "nmap_version", lambda: "7.94")

    async def _no_redis() -> None:
        return None

    monkeypatch.setattr(ver, "redis_version", _no_redis)
    async with session_factory() as s:
        row = await get_settings(s)
        data = await ver.gather_versions(s, row)
    assert data["app"] == ver.app_version()
    assert data["python"]
    assert data["nmap"] == "7.94"
    assert data["postgres"] is None  # SQLite: SELECT version() yok → fail-soft None
    assert data["redis"] is None
    assert data["ai"] is None  # ai_enabled varsayılan False → AI satırı gizlenir


async def test_gather_versions_ai_label_when_enabled(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ver, "nmap_version", lambda: None)

    async def _no_redis() -> None:
        return None

    monkeypatch.setattr(ver, "redis_version", _no_redis)
    async with session_factory() as s:
        row = await get_settings(s)
        row.ai_enabled = True
        row.ai_model_name = "qwen3:8b"
        await s.commit()
        data = await ver.gather_versions(s, row)
    assert data["ai"] == "qwen3:8b"
