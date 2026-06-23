"""MCP araçları için rol tabanlı erişim politikası (saf, test edilebilir).

Uzak (HTTP) MCP'de her API token'ı bir kullanıcıya ve role bağlıdır. Bu modül
hangi aracın hangi minimum rolü gerektirdiğini ve bir JSON-RPC gövdesinden
çağrılan araç adlarını ayrıştırmayı sağlar. Ağ/DB bağımlılığı yoktur.
"""

from __future__ import annotations

import json

from cybersectool.core.models import Role

# Rol hiyerarşisi: viewer < analyst < admin
_ROLE_RANK: dict[Role, int] = {Role.viewer: 1, Role.analyst: 2, Role.admin: 3}

# Salt-okunur araçlar varsayılan olarak viewer'a açıktır. Aşağıdakiler daha
# yüksek rol ister (durum değiştiren / gerçek ağ etkinliği tetikleyen araçlar).
TOOL_MIN_ROLE: dict[str, Role] = {
    "start_scan": Role.analyst,
}
DEFAULT_MIN_ROLE = Role.viewer


def role_rank(role: Role | None) -> int:
    if role is None:
        return 0
    return _ROLE_RANK.get(role, 0)


def required_role_for_tool(tool_name: str) -> Role:
    return TOOL_MIN_ROLE.get(tool_name, DEFAULT_MIN_ROLE)


def is_tool_allowed(role: Role | None, tool_name: str) -> bool:
    """Verilen rol, aracı çağırmaya yetkili mi?"""
    return role_rank(role) >= role_rank(required_role_for_tool(tool_name))


def extract_tool_calls(body: bytes) -> list[str]:
    """JSON-RPC gövdesinden ``tools/call`` çağrılarının araç adlarını çıkarır.

    Tek istek ya da batch (liste) destekler. tools/call olmayan mesajlar (init,
    bildirim, tools/list vb.) yok sayılır → boş liste.
    """
    if not body:
        return []
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return []
    messages = data if isinstance(data, list) else [data]
    names: list[str] = []
    for msg in messages:
        if not isinstance(msg, dict) or msg.get("method") != "tools/call":
            continue
        params = msg.get("params") or {}
        name = params.get("name") if isinstance(params, dict) else None
        if isinstance(name, str) and name:
            names.append(name)
    return names


def first_denied_tool(role: Role | None, body: bytes) -> str | None:
    """Gövdedeki ilk yetkisiz araç adını döndürür; hepsi yetkiliyse None."""
    for name in extract_tool_calls(body):
        if not is_tool_allowed(role, name):
            return name
    return None


def is_parseable_jsonrpc(body: bytes) -> bool:
    """Gövde fail-closed RBAC için kabul edilebilir mi?

    Boş gövde (GET/SSE el sıkışması) ya da geçerli JSON → ``True``. Boş-OLMAYAN ama geçersiz JSON
    → ``False`` (middleware 400 ile reddeder). Aksi halde bozuk gövde ``extract_tool_calls``'da
    sessizce ``[]``'e düşüp "araç çağrısı yok" sayılır ve RBAC'tan geçerdi (latent atlatma).
    """
    if not body:
        return True
    try:
        json.loads(body)
    except (ValueError, TypeError):
        return False
    return True
