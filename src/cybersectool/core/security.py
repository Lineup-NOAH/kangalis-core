"""Parola hash'leme ve doğrulama (argon2)."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Düz parolayı argon2 ile hash'ler."""
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Düz parolayı hash ile karşılaştırır."""
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False
