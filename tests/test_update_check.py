"""Sürüm denetimi (core/update_check) — semver kıyas + uzak denetim (mock'lu egress).

run_update_check ASLA istisna fırlatmaz; ağ hatası/404 dürüst durum alanına yansır.
``disabled`` iken (force değil) HİÇ egress yapılmaz. httpx mock'lanır → gerçek ağ yok.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import cybersectool.core.update_check as uc
from cybersectool.core.app_settings import get_settings


class _Resp:
    def __init__(self, status_code: int, data: dict | None = None) -> None:
        self.status_code = status_code
        self._data = data if data is not None else {}

    def json(self) -> dict:
        return self._data


class _Client:
    def __init__(self, resp: _Resp | None = None, exc: Exception | None = None) -> None:
        self._resp = resp
        self._exc = exc

    async def __aenter__(self) -> _Client:
        return self

    async def __aexit__(self, *_: object) -> bool:
        return False

    async def get(self, url: str, headers: dict | None = None) -> _Resp:
        if self._exc:
            raise self._exc
        assert self._resp is not None
        return self._resp


def _patch_httpx(
    monkeypatch: pytest.MonkeyPatch, *, resp: _Resp | None = None, exc: Exception | None = None
) -> None:
    monkeypatch.setattr(uc.httpx, "AsyncClient", lambda *a, **k: _Client(resp=resp, exc=exc))


def test_parse_version() -> None:
    assert uc.parse_version("v1.2.3") == (1, 2, 3)
    assert uc.parse_version("1.2") == (1, 2, 0)
    assert uc.parse_version("1.2.3-rc1") == (1, 2, 3)
    assert uc.parse_version("") == (0, 0, 0)
    assert uc.parse_version("garbage") == (0, 0, 0)


def test_is_newer() -> None:
    assert uc.is_newer("1.1.0", "1.0.0")
    assert uc.is_newer("2.0.0", "1.9.9")
    assert not uc.is_newer("1.0.0", "1.0.0")
    assert not uc.is_newer("0.9.0", "1.0.0")
    assert not uc.is_newer("", "1.0.0")  # boş latest → güncelleme yok


async def test_run_update_check_newer(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_httpx(monkeypatch, resp=_Resp(200, {"tag_name": "v9.9.9"}))
    async with session_factory() as s:
        result = await uc.run_update_check(s, force=True)
    assert result.status == "ok"
    assert result.latest == "9.9.9"
    assert result.available is True
    # DB'ye yazıldı mı (sayfa yüklenişinde stored_status okur)
    async with session_factory() as s:
        st = uc.stored_status(await get_settings(s))
    assert st.latest == "9.9.9"
    assert st.available is True


async def test_run_update_check_same_version_not_available(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_httpx(monkeypatch, resp=_Resp(200, {"tag_name": f"v{uc.__version__}"}))
    async with session_factory() as s:
        result = await uc.run_update_check(s, force=True)
    assert result.status == "ok"
    assert result.available is False


async def test_run_update_check_404_no_release(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_httpx(monkeypatch, resp=_Resp(404))
    async with session_factory() as s:
        result = await uc.run_update_check(s, force=True)
    assert result.status == "no_release"


async def test_run_update_check_network_error_unreachable(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_httpx(monkeypatch, exc=httpx.ConnectError("boom"))
    async with session_factory() as s:
        result = await uc.run_update_check(s, force=True)
    assert result.status == "unreachable"


async def test_disabled_skips_egress(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    # enabled=False + force=False → ağ çağrısı YAPILMAMALI (egress yok)
    def _boom(*_a: object, **_k: object) -> None:
        raise AssertionError("disabled iken egress olmamalı")

    monkeypatch.setattr(uc.httpx, "AsyncClient", _boom)
    async with session_factory() as s:
        row = await get_settings(s)
        row.update_check_enabled = False
        await s.commit()
    async with session_factory() as s:
        result = await uc.run_update_check(s, force=False)
    assert result.status == "disabled"


async def test_force_overrides_disabled(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_httpx(monkeypatch, resp=_Resp(200, {"tag_name": "v2.0.0"}))
    async with session_factory() as s:
        row = await get_settings(s)
        row.update_check_enabled = False
        await s.commit()
    async with session_factory() as s:
        result = await uc.run_update_check(s, force=True)
    assert result.status == "ok"
    assert result.latest == "2.0.0"


async def test_stored_status_reads_db(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as s:
        row = await get_settings(s)
        row.latest_version = "5.0.0"
        row.update_last_status = "ok"
        row.update_last_checked = datetime.now(UTC)
        await s.commit()
        st = uc.stored_status(row)
    assert st.latest == "5.0.0"
    assert st.available is True  # 5.0.0 > 1.0.0 (current)
    assert st.current == uc.__version__
