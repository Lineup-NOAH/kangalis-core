"""Komut satırından bir kullanıcı için API token oluşturma (MCP/API kurulumu için).

Kullanım (stack ayaktayken):
    docker compose exec app python -m cybersectool.scripts.create_token \\
        --username admin --name "mcp-claude"
"""

from __future__ import annotations

import argparse
import asyncio

from cybersectool.core.db import SessionLocal
from cybersectool.core.tokens import create_api_token
from cybersectool.core.users import get_user_by_username


async def _run(username: str, name: str) -> None:
    async with SessionLocal() as session:
        user = await get_user_by_username(session, username)
        if user is None:
            print(f"Kullanıcı bulunamadı: {username}")
            return
        _token, raw = await create_api_token(session, user.id, name)
        print(f"Token olusturuldu (kullanici={username}, ad={name}). BIR KEZ gosterilir:")
        print(raw)


def main() -> None:
    parser = argparse.ArgumentParser(description="Kangalis API token oluştur")
    parser.add_argument("--username", required=True)
    parser.add_argument("--name", required=True, help="Token'ı tanımlayan ad (örn. mcp-claude)")
    args = parser.parse_args()
    asyncio.run(_run(args.username, args.name))


if __name__ == "__main__":
    main()
