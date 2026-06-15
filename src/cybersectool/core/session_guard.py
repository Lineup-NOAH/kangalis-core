"""Oturum idle (atalet) zaman aşımı — session cookie içinde tutulan TTL ile.

Giriş anında ``app_settings.session_timeout_min`` değeri oturuma yazılır; böylece her
istekte veritabanına bakmaya gerek kalmaz (ayar değişikliği yeni girişlerde geçerli olur).
Her kimlik-doğrulanmış istekte son etkinlik kontrol edilir; süre aşılırsa oturum geçersiz
sayılır. **Kayan (sliding) pencere**: her istekte etkinlik damgası tazelenir.
"""

from __future__ import annotations

import time
from collections.abc import MutableMapping
from typing import Any

SESSION_TTL_KEY = "idle_ttl"
SESSION_SEEN_KEY = "seen"

Session = MutableMapping[str, Any]


def start_session_timeout(session: Session, timeout_min: int) -> None:
    """Giriş anında idle TTL'ini oturuma yazar (0 ya da negatif → zaman aşımı yok)."""
    if timeout_min and timeout_min > 0:
        session[SESSION_TTL_KEY] = int(timeout_min) * 60
        session[SESSION_SEEN_KEY] = int(time.time())
    else:
        session.pop(SESSION_TTL_KEY, None)
        session.pop(SESSION_SEEN_KEY, None)


def session_idle_expired(session: Session) -> bool:
    """Idle süresi aşıldıysa True döner. TTL ayarlı değilse asla True."""
    ttl = session.get(SESSION_TTL_KEY)
    if not ttl:
        return False
    now = int(time.time())
    seen = int(session.get(SESSION_SEEN_KEY, now))
    return (now - seen) > int(ttl)


def touch_session(session: Session) -> None:
    """Etkinlik damgasını günceller (kayan pencere). TTL yoksa hiçbir şey yapmaz."""
    if session.get(SESSION_TTL_KEY):
        session[SESSION_SEEN_KEY] = int(time.time())
