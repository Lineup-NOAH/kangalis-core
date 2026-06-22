"""Parola politikası (password_policy) birim testleri."""

from __future__ import annotations

from cybersectool.core.password_policy import validate_password


def test_min_length() -> None:
    assert validate_password("abc", min_length=8, require_complexity=False) is not None
    assert validate_password("abcdefgh", min_length=8, require_complexity=False) is None


def test_complexity_requires_letter_and_digit() -> None:
    # Yalnız harf / yalnız rakam reddedilir.
    assert validate_password("abcdefgh", min_length=8, require_complexity=True) is not None
    assert validate_password("12345678", min_length=8, require_complexity=True) is not None
    # Harf + rakam → geçer.
    assert validate_password("abc12345", min_length=8, require_complexity=True) is None


def test_complexity_off_allows_letters_only() -> None:
    assert validate_password("abcdefgh", min_length=8, require_complexity=False) is None


def test_whitespace_only_rejected() -> None:
    # Yalnızca boşluktan oluşan parola, uzunluk yetse bile reddedilir.
    assert validate_password("        ", min_length=4, require_complexity=False) is not None
    assert validate_password("   ", min_length=2, require_complexity=False) is not None
    assert validate_password("\t\t\t\t", min_length=2, require_complexity=False) is not None


def test_leading_trailing_whitespace_rejected() -> None:
    # Baştaki/sondaki boşlukla doldurarak uzunluk/karmaşıklık geçilemez.
    assert validate_password("  abc12345", min_length=8, require_complexity=True) is not None
    assert validate_password("abc12345  ", min_length=8, require_complexity=True) is not None
    # İçteki boşluk (parola cümlesi) kabul edilir.
    assert validate_password("abc def 123", min_length=8, require_complexity=True) is None
