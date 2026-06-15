"""MCP per-user RBAC testleri: saf politika + pure ASGI middleware enforcement."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from cybersectool.core.models import Role
from cybersectool.mcp import server
from cybersectool.mcp.rbac import (
    extract_tool_calls,
    first_denied_tool,
    is_tool_allowed,
    required_role_for_tool,
)

# --- saf politika ---


def test_required_role_defaults_to_viewer() -> None:
    assert required_role_for_tool("list_assets") == Role.viewer
    assert required_role_for_tool("start_scan") == Role.analyst


def test_is_tool_allowed_hierarchy() -> None:
    # viewer salt-okunur araçları çağırabilir ama start_scan'i çağıramaz
    assert is_tool_allowed(Role.viewer, "list_assets") is True
    assert is_tool_allowed(Role.viewer, "start_scan") is False
    # analyst ve admin start_scan'i çağırabilir
    assert is_tool_allowed(Role.analyst, "start_scan") is True
    assert is_tool_allowed(Role.admin, "start_scan") is True
    assert is_tool_allowed(None, "list_assets") is False


def test_extract_tool_calls() -> None:
    body = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"start_scan"}}'
    assert extract_tool_calls(body) == ["start_scan"]
    # tools/list gibi diğer metodlar yok sayılır
    assert extract_tool_calls(b'{"method":"tools/list"}') == []
    # geçersiz JSON → boş
    assert extract_tool_calls(b"not json") == []
    assert extract_tool_calls(b"") == []


def test_extract_tool_calls_batch() -> None:
    body = (
        b'[{"method":"tools/call","params":{"name":"list_assets"}},'
        b'{"method":"tools/call","params":{"name":"start_scan"}}]'
    )
    assert extract_tool_calls(body) == ["list_assets", "start_scan"]


def test_first_denied_tool() -> None:
    body = b'{"method":"tools/call","params":{"name":"start_scan"}}'
    assert first_denied_tool(Role.viewer, body) == "start_scan"
    assert first_denied_tool(Role.analyst, body) is None


# --- middleware enforcement (pure ASGI, monkeypatch'li auth) ---


class _FakeSession:
    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *args: object) -> bool:
        return False


def _fake_session_local() -> _FakeSession:
    return _FakeSession()


_TOKENS = {
    "viewer-tok": Role.viewer,
    "analyst-tok": Role.analyst,
    "admin-tok": Role.admin,
}


async def _fake_user_from_token(session: object, raw: str) -> object | None:
    role = _TOKENS.get(raw)
    if role is None:
        return None
    return SimpleNamespace(id=1, username=raw, role=role)


# Basic auth (kullanıcı:parola) için sahte yerel/LDAP kullanıcıları
_PASSWORDS = {
    ("alice", "pw"): Role.viewer,
    ("ann", "pw"): Role.analyst,
}


async def _fake_authenticate_user(session: object, username: str, password: str) -> object | None:
    role = _PASSWORDS.get((username, password))
    if role is None:
        return None
    return SimpleNamespace(id=2, username=username, role=role)


async def _noop_log(*args: object, **kwargs: object) -> None:
    return None


async def _handler(request: Request) -> JSONResponse:
    # Gövdenin doğru tekrar oynatıldığını kanıtlamak için echo'la
    payload = await request.body()
    return JSONResponse({"ok": True, "len": len(payload)})


@pytest.fixture
def rbac_client(monkeypatch: pytest.MonkeyPatch) -> httpx.AsyncClient:
    monkeypatch.setattr(server, "SessionLocal", _fake_session_local)
    monkeypatch.setattr(server, "user_from_token", _fake_user_from_token)
    monkeypatch.setattr(server, "authenticate_user", _fake_authenticate_user)
    monkeypatch.setattr(server, "log_action", _noop_log)
    app = Starlette(routes=[Route("/mcp", _handler, methods=["GET", "POST"])])
    app.add_middleware(server.TokenAuthASGIMiddleware)
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def _call(name: str) -> bytes:
    return (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"' + name.encode() + b'"}}'
    )


async def test_invalid_token_rejected(rbac_client: httpx.AsyncClient) -> None:
    async with rbac_client as client:
        resp = await client.post("/mcp", headers={"Authorization": "Bearer nope"})
        assert resp.status_code == 401


async def test_viewer_allowed_read_tool(rbac_client: httpx.AsyncClient) -> None:
    async with rbac_client as client:
        resp = await client.post(
            "/mcp",
            headers={"Authorization": "Bearer viewer-tok"},
            content=_call("list_assets"),
        )
        assert resp.status_code == 200
        # gövde alt uygulamaya doğru iletildi (replay çalışıyor)
        assert resp.json()["len"] > 0


async def test_viewer_denied_start_scan(rbac_client: httpx.AsyncClient) -> None:
    async with rbac_client as client:
        resp = await client.post(
            "/mcp",
            headers={"Authorization": "Bearer viewer-tok"},
            content=_call("start_scan"),
        )
        assert resp.status_code == 403


async def test_analyst_allowed_start_scan(rbac_client: httpx.AsyncClient) -> None:
    async with rbac_client as client:
        resp = await client.post(
            "/mcp",
            headers={"Authorization": "Bearer analyst-tok"},
            content=_call("start_scan"),
        )
        assert resp.status_code == 200


async def test_non_tool_call_passes(rbac_client: httpx.AsyncClient) -> None:
    async with rbac_client as client:
        resp = await client.post(
            "/mcp",
            headers={"Authorization": "Bearer viewer-tok"},
            content=b'{"method":"tools/list"}',
        )
        assert resp.status_code == 200


# --- Basic auth (kullanıcı:parola — yerel/LDAP) ---


async def test_basic_auth_valid_user(rbac_client: httpx.AsyncClient) -> None:
    async with rbac_client as client:
        resp = await client.post("/mcp", auth=("alice", "pw"), content=_call("list_assets"))
        assert resp.status_code == 200
        assert resp.json()["len"] > 0  # gövde replay'i çalışıyor


async def test_basic_auth_invalid_password(rbac_client: httpx.AsyncClient) -> None:
    async with rbac_client as client:
        resp = await client.post("/mcp", auth=("alice", "wrong"), content=_call("list_assets"))
        assert resp.status_code == 401


async def test_basic_auth_rbac_applies(rbac_client: httpx.AsyncClient) -> None:
    async with rbac_client as client:
        # viewer Basic kullanıcısı start_scan'i çağıramaz
        resp = await client.post("/mcp", auth=("alice", "pw"), content=_call("start_scan"))
        assert resp.status_code == 403
        # analyst Basic kullanıcısı çağırabilir
        resp2 = await client.post("/mcp", auth=("ann", "pw"), content=_call("start_scan"))
        assert resp2.status_code == 200


async def test_basic_auth_malformed_header(rbac_client: httpx.AsyncClient) -> None:
    async with rbac_client as client:
        resp = await client.post(
            "/mcp",
            headers={"Authorization": "Basic not-base64!!"},
            content=_call("list_assets"),
        )
        assert resp.status_code == 401
