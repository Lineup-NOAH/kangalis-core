"""Audit (denetim) olaylarını syslog/SIEM toplayıcıya iletir.

``app_settings``'teki ``syslog_*`` ayarlarına göre çalışır. Üç biçim desteklenir:
RFC5424, RFC3164 (BSD) ve CEF (ArcSight). UDP ya da TCP ile gönderilir.

Her satır, eylemin **anlamlı** mesajını (TR) ve yapısal alanlarını (event_id,
category, action, user, target) taşır. Aynı satır biçiminden, SIEM tarafında
parser olarak kullanılacak **adlandırılmış-grup REGEX**'i tek kaynaktan üretilir
(:func:`parser_regex_for_format`) — biçim ile regex asla birbirinden ayrışmaz.

**Best-effort**: gönderim hatası ne audit yazımını ne de isteği bozar (suppress).
Senkron socket çağrısı ``asyncio.to_thread`` ile event loop'u bloklamadan çalışır.
"""

from __future__ import annotations

import asyncio
import json
import socket
from datetime import UTC, datetime

from cybersectool import __version__
from cybersectool.core.audit_events import category_for, render_message
from cybersectool.core.models import AppSettings, AuditLog

_FACILITY = 1  # user-level mesajlar
_SEVERITY = 6  # informational
_PRI = _FACILITY * 8 + _SEVERITY  # = 14
_APP = "Kangalis"
_VENDOR = "Lineup-NOAH"
SUPPORTED_FORMATS = ("rfc5424", "rfc3164", "cef", "json")
_MONTHS = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)  # fmt: skip


def _hostname() -> str:
    try:
        return socket.gethostname() or "kangalis"
    except OSError:
        return "kangalis"


def _event_time(entry: AuditLog) -> datetime:
    return entry.created_at or datetime.now(UTC)


def _clean(value: str) -> str:
    """Serbest metni tek satıra indirger ve alan ayraçlarını (\" | =) güvenli kılar."""
    return value.replace("\n", " ").replace("\r", " ").replace('"', "'").replace("|", "/")[:200]


def _user(entry: AuditLog) -> str:
    return str(entry.user_id) if entry.user_id is not None else "-"


def _detail(entry: AuditLog) -> str:
    """RFC5424/RFC3164 gövdesi: yapısal alanlar + anlamlı mesaj (tek kaynak).

    Biçim: ``event_id=N category=C action=A user=U target="..." msg="..."``
    — :func:`parser_regex_for_format` aynı sırayı kullanır.
    """
    target = _clean(entry.target or "")
    message = _clean(render_message(entry.action, entry.target, _user(entry), lang="tr"))
    return (
        f"event_id={entry.event_id} category={category_for(entry.action)} "
        f'action={entry.action} user={_user(entry)} target="{target}" msg="{message}"'
    )


def format_syslog(fmt: str, entry: AuditLog) -> str:
    """Audit kaydını seçilen biçimde tek satırlık syslog mesajına çevirir."""
    host = _hostname()
    ts = _event_time(entry)
    if fmt == "json":
        # JSON: yapısal tek-satır nesne — SIEM tarafı doğrudan JSON ayrıştırır (regex gerekmez).
        # Alanlar _detail() ile aynı yapısal küme; ensure_ascii=False → Türkçe okunur kalır.
        obj = {
            "event_id": entry.event_id,
            "category": category_for(entry.action),
            "action": entry.action,
            "user": _user(entry),
            "target": _clean(entry.target or ""),
            "msg": _clean(render_message(entry.action, entry.target, _user(entry), lang="tr")),
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "host": host,
        }
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    if fmt == "cef":
        # CEF: sabit başlık + uzantı (key=value). msg = anlamlı mesaj.
        message = _clean(render_message(entry.action, entry.target, _user(entry), lang="tr"))
        ext = (
            f"cat={category_for(entry.action)} "
            f"suser={_user(entry)} "
            f"cs1={_clean(entry.target or '')} cs1Label=target "
            f"msg={message}"
        )
        return (
            f"CEF:0|{_VENDOR}|{_APP}|{__version__}|{entry.event_id}|"
            f"{entry.action}|{_SEVERITY}|{ext}"
        )
    if fmt == "rfc3164":
        stamp = f"{_MONTHS[ts.month - 1]} {ts.day:2d} {ts:%H:%M:%S}"
        return f"<{_PRI}>{stamp} {host} {_APP}: {_detail(entry)}"
    # Varsayılan: RFC5424
    stamp = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"<{_PRI}>1 {stamp} {host} {_APP} - audit{entry.event_id} - {_detail(entry)}"


# --- SIEM parser regex (tek kaynak: yukarıdaki biçimlendirici ile aynı yapı) ---

# Yapısal gövde (RFC5424/RFC3164) için adlandırılmış-grup deseni. Alan sırası
# _detail() ile birebir aynıdır; biçim değişirse bu desen de değişir (tek kaynak).
_BODY_RE = (
    r"event_id=(?P<event_id>\d+) "
    r"category=(?P<category>\w+) "
    r"action=(?P<action>\S+) "
    r"user=(?P<user>\S+) "
    r'target="(?P<target>[^"]*)" '
    r'msg="(?P<message>[^"]*)"'
)


def parser_regex_for_format(fmt: str) -> str:
    """Verilen biçimde üretilen satırı alanlara ayıran adlandırılmış-grup REGEX'i döndürür.

    Üretilen desen şu grupları yakalar: ``timestamp``, ``host``, ``app``, ``event_id``,
    ``category``, ``action``, ``user``, ``target``, ``message`` (CEF'te ek olarak
    ``vendor``, ``product``, ``version``, ``severity``). Operatör bunu SIEM parser
    yapılandırmasına kopyalar. Desen, :func:`format_syslog` ile *aynı kaynaktan* türer.
    """
    pri = _PRI
    if fmt == "json":
        # JSON yapısaldır → SIEM tarafı JSON olarak ayrıştırır; adlandırılmış-grup regex GEREKMEZ.
        # Yalnız zarf doğrulayan basit desen (alanlar: event_id, category, action, user, target,
        # msg, timestamp, host).
        return r"^\{.*\}$"
    if fmt == "cef":
        # CEF:0|vendor|product|version|event_id|action|severity|ext...
        return (
            r"^CEF:0\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|"
            r"(?P<event_id>\d+)\|(?P<action>[^|]*)\|(?P<severity>\d+)\|"
            r"cat=(?P<category>\w+) suser=(?P<user>\S+) "
            r"cs1=(?P<target>.*?) cs1Label=target msg=(?P<message>.*)$"
        )
    if fmt == "rfc3164":
        # <PRI>Mon DD HH:MM:SS host app: body
        return (
            rf"^<{pri}>"
            r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "
            r"(?P<host>\S+) (?P<app>\S+?): " + _BODY_RE + r"$"
        )
    # RFC5424: <PRI>1 timestamp host app - audit<event_id> - body
    return (
        rf"^<{pri}>1 "
        r"(?P<timestamp>\S+) (?P<host>\S+) (?P<app>\S+) - audit\d+ - " + _BODY_RE + r"$"
    )


def _send_sync(host: str, port: int, protocol: str, payload: str) -> None:
    """Senkron syslog gönderimi (thread içinde çalışır)."""
    data = payload.encode("utf-8", errors="replace")
    if protocol == "tcp":
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.sendall(data + b"\n")
    else:  # udp
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(data, (host, port))


async def forward_audit(row: AppSettings, entry: AuditLog) -> bool:
    """Audit kaydını yapılandırılmış syslog hedefine iletir. Kapalı/hatalı → False."""
    if not row.syslog_enabled or not row.syslog_host.strip():
        return False
    payload = format_syslog(row.syslog_format, entry)
    try:
        await asyncio.to_thread(
            _send_sync, row.syslog_host.strip(), row.syslog_port, row.syslog_protocol, payload
        )
    except OSError:
        return False
    return True
