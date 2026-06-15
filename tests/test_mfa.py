"""MFA çekirdek (TOTP üretim/doğrulama + QR) testleri."""

from __future__ import annotations

import pyotp

from cybersectool.core import mfa


def test_generate_and_verify_totp() -> None:
    secret = mfa.generate_totp_secret()
    assert len(secret) >= 16
    code = pyotp.TOTP(secret).now()
    assert mfa.verify_totp(secret, code) is True
    # Boşluklu kod da temizlenip doğrulanır.
    assert mfa.verify_totp(secret, f" {code} ") is True
    # Geçersiz / eksik kod ve boş sır reddedilir.
    assert mfa.verify_totp(secret, "12") is False
    assert mfa.verify_totp(secret, "") is False
    assert mfa.verify_totp("", code) is False


def test_provisioning_uri_and_qr() -> None:
    secret = mfa.generate_totp_secret()
    uri = mfa.totp_provisioning_uri(secret, "alice")
    assert uri.startswith("otpauth://totp/")
    assert "Kangalis" in uri
    svg = mfa.totp_qr_svg(uri)
    assert "<svg" in svg  # inline SVG QR
