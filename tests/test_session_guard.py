"""Oturum idle zaman aşımı (session_guard) birim testleri."""

from __future__ import annotations

import time

from cybersectool.core.session_guard import (
    SESSION_SEEN_KEY,
    SESSION_TTL_KEY,
    session_idle_expired,
    start_session_timeout,
    touch_session,
)


def test_start_sets_ttl_and_seen() -> None:
    sess: dict[str, object] = {}
    start_session_timeout(sess, 30)
    assert sess[SESSION_TTL_KEY] == 1800
    assert SESSION_SEEN_KEY in sess


def test_start_zero_clears() -> None:
    sess: dict[str, object] = {SESSION_TTL_KEY: 100, SESSION_SEEN_KEY: 5}
    start_session_timeout(sess, 0)
    assert SESSION_TTL_KEY not in sess and SESSION_SEEN_KEY not in sess


def test_not_expired_without_ttl() -> None:
    assert session_idle_expired({}) is False
    assert session_idle_expired({SESSION_SEEN_KEY: 0}) is False  # TTL yok


def test_expired_when_idle_too_long() -> None:
    now = int(time.time())
    sess = {SESSION_TTL_KEY: 60, SESSION_SEEN_KEY: now - 120}
    assert session_idle_expired(sess) is True


def test_not_expired_when_recent() -> None:
    now = int(time.time())
    sess = {SESSION_TTL_KEY: 60, SESSION_SEEN_KEY: now - 5}
    assert session_idle_expired(sess) is False


def test_touch_updates_seen_only_with_ttl() -> None:
    sess: dict[str, object] = {SESSION_TTL_KEY: 60, SESSION_SEEN_KEY: 0}
    touch_session(sess)
    assert sess[SESSION_SEEN_KEY] != 0  # damga tazelendi
    no_ttl: dict[str, object] = {}
    touch_session(no_ttl)
    assert SESSION_SEEN_KEY not in no_ttl  # TTL yoksa dokunmaz
