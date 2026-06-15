"""Uzak (HTTP) MCP token doğrulama middleware'i testi."""

from __future__ import annotations

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from cybersectool.mcp.server import TokenAuthASGIMiddleware


async def _handler(request: Request) -> JSONResponse:
    return JSONResponse({"ok": True})


async def test_mcp_http_requires_token() -> None:
    app = Starlette(routes=[Route("/mcp", _handler, methods=["GET", "POST"])])
    app.add_middleware(TokenAuthASGIMiddleware)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Token yok → 401
        assert (await client.get("/mcp")).status_code == 401
        # Bearer değil → 401
        resp = await client.get("/mcp", headers={"Authorization": "Basic abc"})
        assert resp.status_code == 401
