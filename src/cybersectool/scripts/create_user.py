"""Komut satırından kullanıcı oluşturma.

Parola kaynağı (öncelik sırası):
    1) --password-stdin  -> parolayı STDIN'den okur (argv'de GÖRÜNMEZ; önerilen).
    2) --password <değer> -> geriye-uyum (argv'de GÖRÜNÜR; çok-kullanıcılı host'ta önerilmez).
    3) KANGALIS_ADMIN_PASSWORD ortam değişkeni -> ayarlıysa kullanılır (argv'de görünmez).

Kullanım (stack ayaktayken, parola argv'de görünmeden):
    # ortam değişkeni ile (kurulum sihirbazının kullandığı yol; -e VARNAME = isim-only geçiş):
    KANGALIS_ADMIN_PASSWORD='GucluParola!' docker compose exec -T -e KANGALIS_ADMIN_PASSWORD \\
        app python -m cybersectool.scripts.create_user --username admin --role admin
    # ya da stdin ile (--password-stdin):
    printf '%s' 'GucluParola!' | docker compose exec -T app \\
        python -m cybersectool.scripts.create_user --username admin --role admin --password-stdin
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from cybersectool.core.db import SessionLocal
from cybersectool.core.models import Role
from cybersectool.core.users import create_user, get_user_by_username

_PASSWORD_ENV = "KANGALIS_ADMIN_PASSWORD"


async def _run(username: str, password: str, role: Role, email: str | None) -> None:
    async with SessionLocal() as session:
        if await get_user_by_username(session, username) is not None:
            print(f"Kullanıcı zaten var: {username}")
            return
        user = await create_user(session, username, password, role=role, email=email)
        print(f"Oluşturuldu: {user.username} (rol={user.role}, id={user.id})")


def _resolve_password(args: argparse.Namespace) -> str:
    """Parolayı stdin / --password / ortam değişkeninden (bu öncelikle) çözer.

    Argv'de parola taşımayı önlemek için kurulum sihirbazları ortam değişkenini kullanır.
    """
    if args.password_stdin:
        # İlk satır = parola; sondaki CR/LF kırpılır (kabuk/PowerShell newline ekler).
        return sys.stdin.readline().rstrip("\r\n")
    password: str | None = args.password  # Namespace attr'ı Any döner; str|None'a sabitle
    if password is not None:
        return password
    env_pw = os.environ.get(_PASSWORD_ENV)
    if env_pw:
        return env_pw
    raise SystemExit(
        "Parola verilmedi. Şunlardan birini kullanın: --password-stdin, "
        f"--password <değer> ya da {_PASSWORD_ENV} ortam değişkeni."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Kangalis kullanıcı oluştur")
    parser.add_argument("--username", required=True)
    parser.add_argument(
        "--password",
        default=None,
        help="Parola (argv'de GÖRÜNÜR; çok-kullanıcılı host'ta önerilmez — "
        "--password-stdin ya da KANGALIS_ADMIN_PASSWORD tercih edin).",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Parolayı STDIN'den oku (argv'de görünmez).",
    )
    parser.add_argument("--role", choices=[r.value for r in Role], default=Role.viewer.value)
    parser.add_argument("--email", default=None)
    args = parser.parse_args()
    password = _resolve_password(args)
    asyncio.run(_run(args.username, password, Role(args.role), args.email))


if __name__ == "__main__":
    main()
