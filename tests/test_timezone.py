"""Global saat dilimi (IX-1) — SAF birim testleri (DB/SSH gerekmez)."""

from __future__ import annotations

from datetime import UTC, datetime

from cybersectool.core.app_settings import (
    DEFAULT_TIMEZONE,
    format_local,
    get_app_timezone,
    set_app_timezone_cache,
    to_local,
    valid_timezone,
)


def test_valid_timezone() -> None:
    assert valid_timezone("Europe/Istanbul") == "Europe/Istanbul"
    assert valid_timezone("UTC") == "UTC"
    assert valid_timezone("  Asia/Tokyo  ") == "Asia/Tokyo"  # boşluklar kırpılır
    # Geçersiz / boş → güvenli varsayılan
    assert valid_timezone("not/a/zone") == DEFAULT_TIMEZONE
    assert valid_timezone("") == DEFAULT_TIMEZONE


def test_to_local_converts_utc_to_istanbul() -> None:
    set_app_timezone_cache("Europe/Istanbul")
    try:
        # Türkiye yıl boyu UTC+3 (DST yok) — 12:00 UTC = 15:00 yerel.
        local = to_local(datetime(2026, 6, 7, 12, 0, tzinfo=UTC))
        assert local.hour == 15
        offset = local.utcoffset()
        assert offset is not None and offset.total_seconds() == 3 * 3600
    finally:
        set_app_timezone_cache(DEFAULT_TIMEZONE)


def test_to_local_naive_treated_as_utc() -> None:
    set_app_timezone_cache("Europe/Istanbul")
    try:
        # tzinfo yoksa UTC kabul edilir → +3.
        assert to_local(datetime(2026, 6, 7, 12, 0)).hour == 15
    finally:
        set_app_timezone_cache(DEFAULT_TIMEZONE)


def test_format_local_none_and_formats() -> None:
    set_app_timezone_cache("Europe/Istanbul")
    try:
        assert format_local(None) == "—"  # None → tire
        dt = datetime(2026, 6, 7, 12, 0, tzinfo=UTC)
        assert format_local(dt) == "2026-06-07 15:00"
        assert format_local(dt, "%Y-%m-%d") == "2026-06-07"
    finally:
        set_app_timezone_cache(DEFAULT_TIMEZONE)


def test_format_local_other_zone() -> None:
    set_app_timezone_cache("America/New_York")
    try:
        # 12:00 UTC = 08:00 EDT (yaz, UTC-4).
        assert format_local(datetime(2026, 6, 7, 12, 0, tzinfo=UTC)) == "2026-06-07 08:00"
    finally:
        set_app_timezone_cache(DEFAULT_TIMEZONE)


def test_cache_get_set() -> None:
    set_app_timezone_cache(DEFAULT_TIMEZONE)
    assert get_app_timezone() == DEFAULT_TIMEZONE
    set_app_timezone_cache("Asia/Tokyo")
    assert get_app_timezone() == "Asia/Tokyo"
    set_app_timezone_cache(DEFAULT_TIMEZONE)
