"""Kimlik kasası için simetrik şifreleme (Fernet).

Kimlik bilgisi parolaları veritabanında **şifreli** saklanır (geri döndürülebilir; tarama
anında çözülmesi gerektiği için hash değil şifreleme kullanılır).

Anahtar `CREDENTIAL_ENCRYPTION_KEY` ortam değişkeninden gelir (Fernet anahtarı). Verilmezse
`SECRET_KEY`'den deterministik olarak türetilir — bu **yalnızca geliştirme** içindir;
üretimde ayrı, gizli bir anahtar verilmeli (yoksa SECRET_KEY sızarsa parolalar açılır).

Anahtar üretimi:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

from __future__ import annotations

import base64
import hashlib
from functools import lru_cache

from cryptography.fernet import Fernet

from cybersectool.config import settings


def _derive_key_from_secret(secret_key: str) -> bytes:
    """SECRET_KEY'den geçerli bir Fernet anahtarı (32 bayt, url-safe base64) türetir."""
    digest = hashlib.sha256(secret_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    key = settings.credential_encryption_key.strip()
    if key:
        return Fernet(key.encode("utf-8"))
    return Fernet(_derive_key_from_secret(settings.secret_key))


def encrypt_secret(plaintext: str) -> str:
    """Düz metin parolayı şifreler; saklanabilir token (str) döndürür."""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(token: str) -> str:
    """Şifreli token'ı çözüp düz metin parolayı döndürür."""
    return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")
