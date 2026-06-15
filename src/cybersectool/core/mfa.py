"""MFA (çok adımlı doğrulama) yardımcıları — TOTP.

TOTP sırrı ``pyotp`` ile üretilir ve doğrulanır; kayıt için QR kodu (otpauth URI)
``qrcode`` ile inline **SVG** olarak çizilir (PIL gerektirmez). Sır DB'de Fernet ile
şifreli saklanır (bkz. core/users.py). E-posta OTP yöntemi ayrı bir adımda eklenir.
"""

from __future__ import annotations

import io

import pyotp
import qrcode
import qrcode.image.svg

ISSUER = "Kangalis"
MFA_METHODS = ("none", "totp", "email")


def generate_totp_secret() -> str:
    """Yeni rastgele bir TOTP sırrı (base32) üretir."""
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, username: str) -> str:
    """Authenticator uygulamasına eklemek için otpauth:// URI'si döndürür."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def verify_totp(secret: str, code: str) -> bool:
    """6 haneli TOTP kodunu doğrular (±1 zaman penceresi — saat kaymasına tolerans)."""
    cleaned = (code or "").strip().replace(" ", "")
    if not cleaned or not secret:
        return False
    return bool(pyotp.TOTP(secret).verify(cleaned, valid_window=1))


def totp_qr_svg(uri: str) -> str:
    """otpauth URI'sini inline SVG QR koduna çevirir (şablona |safe ile gömülür)."""
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")
