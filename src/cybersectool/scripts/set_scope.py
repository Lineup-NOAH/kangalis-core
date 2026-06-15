"""Yetkili kapsam (scope) politikası tanımlama.

Yeni politika aktif edilir; önceki politikalar pasifleştirilir.

Kullanım (stack ayaktayken):
    docker compose exec app python -m cybersectool.scripts.set_scope \\
        --name "ic-ag" --allow 10.0.0.0/8 --allow 192.168.0.0/16 --deny 10.0.0.1/32
"""

from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import update

from cybersectool.core.db import SessionLocal
from cybersectool.core.models import ScopePolicy


async def _run(name: str, allow: list[str], deny: list[str]) -> None:
    async with SessionLocal() as session:
        await session.execute(update(ScopePolicy).values(is_active=False))
        policy = ScopePolicy(name=name, allowed_cidrs=allow, denied_cidrs=deny, is_active=True)
        session.add(policy)
        await session.commit()
        print(f"Scope tanimlandi: {name} | izinli={allow} | yasak={deny}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Kangalis yetkili kapsam tanimla")
    parser.add_argument("--name", required=True)
    parser.add_argument(
        "--allow", action="append", default=[], help="izinli CIDR (tekrarlanabilir)"
    )
    parser.add_argument("--deny", action="append", default=[], help="yasak CIDR (tekrarlanabilir)")
    args = parser.parse_args()
    asyncio.run(_run(args.name, args.allow, args.deny))


if __name__ == "__main__":
    main()
