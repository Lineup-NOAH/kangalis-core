"""X-7: AUDIT_EVENTS kayıt defteri + anlamlı mesaj + SIEM parser regex testleri.

Bu testler saftır (DB/IO yok): kayıt defteri tutarlılığı, mesaj oluşturma ve
üretilen syslog satırının kendi regex'iyle birebir parse edilebilmesi doğrulanır.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import cybersectool
from cybersectool.core.audit_events import (
    AUDIT_EVENTS,
    UNKNOWN_EVENT_ID,
    category_for,
    event_id_for,
    meta_for,
    render_message,
)
from cybersectool.core.models import AuditLog
from cybersectool.core.syslog_forward import (
    SUPPORTED_FORMATS,
    format_syslog,
    parser_regex_for_format,
)

_VALID_CATEGORIES = {"auth", "scan", "exploit", "user", "compliance", "system"}


def test_event_ids_unique() -> None:
    """Her eylemin event_id'si benzersiz olmalı (SIEM filtrelemesi için)."""
    ids = [m.event_id for m in AUDIT_EVENTS.values()]
    assert len(ids) == len(set(ids))


def test_event_ids_dont_collide_with_unknown() -> None:
    """Hiçbir kayıtlı eylem UNKNOWN_EVENT_ID (9000) ile çakışmamalı."""
    assert all(m.event_id != UNKNOWN_EVENT_ID for m in AUDIT_EVENTS.values())


def test_categories_valid() -> None:
    """Tüm kategoriler bilinen kümeden olmalı."""
    assert all(m.category in _VALID_CATEGORIES for m in AUDIT_EVENTS.values())


# log_action(session, "eylem", ...) çağrısındaki string-literal eylem adını yakalar.
# Dinamik (değişkenli, ör. log_action(session, action, ...)) çağrılar tırnaksız
# olduğu için eşleşmez — onlar zaten kayıtlı sabitlere (scan_start vb.) çözülür.
_LOG_ACTION_RE = re.compile(r'log_action\(\s*session\s*,\s*"([a-z_]+)"', re.DOTALL)


def test_all_used_actions_are_registered() -> None:
    """REGRESYON KALKANI: kaynak ağacındaki her log_action("...") eylemi AUDIT_EVENTS'te
    kayıtlı olmalı. Aksi halde denetim günlüğünde UNKNOWN_EVENT_ID (9000) "Kayıtsız eylem"
    satırı oluşur — SIEM filtrelemesi ve okunaklı mesaj kaybolur.
    """
    src_root = Path(cybersectool.__file__).resolve().parent
    used: set[str] = set()
    for path in src_root.rglob("*.py"):
        used.update(_LOG_ACTION_RE.findall(path.read_text(encoding="utf-8")))
    # Sağlık kontrolü: tarayıcı en azından bilinen birkaç eylemi bulmalı (regex bozulmadı).
    assert {"scan_stop", "user_create", "ldap_test"} <= used, used
    missing = sorted(a for a in used if a not in AUDIT_EVENTS)
    assert not missing, f"AUDIT_EVENTS'te kayıtsız (9000'e düşen) eylem(ler): {missing}"


def test_known_event_ids_preserved() -> None:
    """Önceden var olan event_id'ler korunmalı (stabilite şartı)."""
    assert event_id_for("scan_start") == 1001
    assert event_id_for("login_failed") == 4090
    assert event_id_for("login_locked") == 4091
    assert event_id_for("token_create") == 5001
    assert event_id_for("ldap_user_import") == 7002
    assert event_id_for("demo_task") == 8999


def test_event_id_for_unknown() -> None:
    assert event_id_for("totally_unknown_action") == UNKNOWN_EVENT_ID
    assert category_for("totally_unknown_action") == "system"


def test_render_message_tr_and_en() -> None:
    """action → anlamlı (okunaklı) mesaj; hem TR hem EN."""
    tr = render_message("login_failed", target="admin", user="-", lang="tr")
    assert tr == "Başarısız giriş denemesi: admin"
    en = render_message("login_failed", target="admin", user="-", lang="en")
    assert en == "Failed login attempt: admin"


def test_render_message_empty_target() -> None:
    """Boş target '-' ile gösterilir; mesaj asla patlamaz."""
    msg = render_message("scan_start", target=None, user=None, lang="tr")
    assert "-" in msg


def test_render_message_unknown_action_uses_fallback() -> None:
    msg = render_message("weird_action", target="x", user=None, lang="tr")
    assert "weird_action" in msg  # {action} yer tutucusu doldurulur


def test_meta_for_returns_dataclass() -> None:
    meta = meta_for("exploit_success")
    assert meta.event_id == 9003
    assert meta.category == "exploit"
    assert "{target}" in meta.message_tr


def _sample_entry() -> AuditLog:
    return AuditLog(
        id=42,
        action="login_failed",
        user_id=7,
        target="admin@10.0.0.5",
        event_id=event_id_for("login_failed"),
        created_at=datetime(2026, 6, 7, 13, 5, 9, tzinfo=UTC),
    )


def test_parser_regex_roundtrip_all_formats() -> None:
    """KRİTİK: format_syslog ile üretilen satır, parser_regex ile aynı kaynaktan
    türetildiği için adlandırılmış grupları doğru yakalamalı (format ↔ regex drift yok).
    """
    entry = _sample_entry()
    for fmt in SUPPORTED_FORMATS:
        line = format_syslog(fmt, entry)
        pattern = parser_regex_for_format(fmt)
        match = re.match(pattern, line)
        assert match is not None, f"{fmt}: regex satırı eşleyemedi:\n{line}\n{pattern}"
        gd = match.groupdict()
        assert gd["event_id"] == "4090"
        assert gd["action"] == "login_failed"
        assert gd["user"] == "7"
        assert gd["category"] == "auth"
        assert gd["target"] == "admin@10.0.0.5"
        # Anlamlı mesaj satıra gömülü ve yakalanmış olmalı.
        assert "Başarısız giriş denemesi" in gd["message"]


def test_parser_regex_rfc5424_has_timestamp_and_host() -> None:
    entry = _sample_entry()
    line = format_syslog("rfc5424", entry)
    match = re.match(parser_regex_for_format("rfc5424"), line)
    assert match is not None
    assert match.group("timestamp") == "2026-06-07T13:05:09Z"
    assert match.group("host")
    assert match.group("app") == "Kangalis"


def test_parser_regex_cef_header_fields() -> None:
    entry = _sample_entry()
    line = format_syslog("cef", entry)
    match = re.match(parser_regex_for_format("cef"), line)
    assert match is not None
    assert match.group("vendor") == "Lineup-NOAH"
    assert match.group("product") == "Kangalis"
    assert match.group("event_id") == "4090"


def test_parser_regex_handles_target_with_spaces() -> None:
    """Hedef boşluk içerse de (tırnaklı alan) doğru yakalanmalı."""
    entry = AuditLog(
        id=1,
        action="network_scan",
        user_id=None,
        target="10.0.0.0/24 [aggressive] (5 servis)",
        event_id=event_id_for("network_scan"),
        created_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
    )
    for fmt in ("rfc5424", "rfc3164"):
        line = format_syslog(fmt, entry)
        match = re.match(parser_regex_for_format(fmt), line)
        assert match is not None, fmt
        assert match.group("target") == "10.0.0.0/24 [aggressive] (5 servis)"
        assert match.group("user") == "-"
