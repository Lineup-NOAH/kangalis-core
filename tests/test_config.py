"""Yapılandırma güvenlik testleri: üretimde zayıf SECRET_KEY reddi."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from cybersectool.config import Settings


def test_production_rejects_weak_secret() -> None:
    # Üretimde varsayılan/zayıf SECRET_KEY ile başlatma engellenir (fail-fast).
    with pytest.raises(ValidationError):
        Settings(app_env="production", secret_key="change-me")
    with pytest.raises(ValidationError):
        Settings(app_env="production", secret_key="dev-secret")
    with pytest.raises(ValidationError):
        Settings(app_env="production", secret_key="")


def test_production_requires_credential_key() -> None:
    """#141: Üretimde CREDENTIAL_ENCRYPTION_KEY zorunlu (SECRET_KEY'den türetilmemeli)."""
    with pytest.raises(ValidationError):
        Settings(
            app_env="production",
            secret_key="9f3a-Zx82-strong-random-material-kkk-7Q",
            credential_encryption_key="",
        )


def test_production_allows_strong_secret() -> None:
    s = Settings(
        app_env="production",
        secret_key="9f3a-Zx82-strong-random-material-kkk-7Q",
        credential_encryption_key="separate-vault-key-material-distinct",
    )
    assert s.app_env == "production"


def test_development_allows_default_secret() -> None:
    # Geliştirmede (varsayılan ortam) zayıf anahtar serbest — kolaylık için.
    s = Settings(app_env="development", secret_key="change-me")
    assert s.secret_key == "change-me"
