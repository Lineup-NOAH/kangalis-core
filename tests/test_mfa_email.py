"""E-posta OTP (mfa_email) çekirdek testleri — sahte Redis ile."""

from __future__ import annotations

import pytest

from cybersectool.core import mfa_email


class FakeRedis:
    """mfa_email'in kullandığı asenkron Redis alt kümesi (get/set/delete)."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.store[key] = value

    async def get(self, key: str) -> str | None:
        return self.store.get(key)

    async def delete(self, *keys: str) -> None:
        for key in keys:
            self.store.pop(key, None)


def test_generate_otp_format() -> None:
    for _ in range(20):
        code = mfa_email.generate_email_otp()
        assert len(code) == 6 and code.isdigit()


async def test_store_verify_single_use(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRedis()
    monkeypatch.setattr(mfa_email, "_redis", lambda: fake)
    await mfa_email.store_email_otp(7, "123456")
    # Yanlış kod → False, doğru kod (boşluk temizlenir) → True.
    assert await mfa_email.verify_email_otp(7, "000000") is False
    assert await mfa_email.verify_email_otp(7, " 123456 ") is True
    # Tek kullanımlık: aynı kod ikinci kez geçersiz.
    assert await mfa_email.verify_email_otp(7, "123456") is False
    assert await mfa_email.verify_email_otp(7, "") is False


async def test_verify_without_stored_code(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRedis()
    monkeypatch.setattr(mfa_email, "_redis", lambda: fake)
    assert await mfa_email.verify_email_otp(99, "123456") is False


async def test_fail_closed_on_redis_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class Boom:
        async def get(self, key: str) -> str | None:
            raise ConnectionError("redis down")

    monkeypatch.setattr(mfa_email, "_redis", lambda: Boom())
    # Redis hatasında doğrulama False (fail-closed — MFA bypass edilmez).
    assert await mfa_email.verify_email_otp(1, "123456") is False
