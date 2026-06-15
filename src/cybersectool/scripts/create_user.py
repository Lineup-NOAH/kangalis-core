"""Komut satırından kullanıcı oluşturma.

Kullanım (stack ayaktayken):
    docker compose exec app python -m cybersectool.scripts.create_user \\
        --username admin --password "GucluParola!" --role admin
"""

from __future__ import annotations

import argparse
import asyncio

from cybersectool.core.db import SessionLocal
from cybersectool.core.models import Role
from cybersectool.core.users import create_user, get_user_by_username


async def _run(username: str, password: str, role: Role, email: str | None) -> None:
    async with SessionLocal() as session:
        if await get_user_by_username(session, username) is not None:
            print(f"Kullanıcı zaten var: {username}")
            return
        user = await create_user(session, username, password, role=role, email=email)
        print(f"Oluşturuldu: {user.username} (rol={user.role}, id={user.id})")


def main() -> None:
    parser = argparse.ArgumentParser(description="Kangalis kullanıcı oluştur")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--role", choices=[r.value for r in Role], default=Role.viewer.value)
    parser.add_argument("--email", default=None)
    args = parser.parse_args()
    asyncio.run(_run(args.username, args.password, Role(args.role), args.email))


if __name__ == "__main__":
    main()
