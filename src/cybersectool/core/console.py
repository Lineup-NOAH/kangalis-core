"""Admin güvenli komut konsolu — ALLOWLIST'li komut kayıt defteri (KABUK DEĞİL).

GÜVENLİK ÇEKİRDEĞİ — bu modülün tamamı bir RCE/kabuk DEĞİLDİR:

* Yalnızca burada KAYITLI (``COMMANDS``) komutlar çalışır. Kayıtlı olmayan her girdi
  "bilinmeyen komut" döner — hiçbir şey çalıştırılmaz.
* Girdi ``str.split()`` ile token'lara ayrılır; bir kabuğa/``subprocess``'e **hiçbir
  kullanıcı girdisi ham geçmez**. Komutlar yalnızca tipli Python fonksiyonlarını
  (mevcut servisler/görevler) çağırır.
* Argümanlar doğrulanır (tarama id = int, rol = Role enum, hedef = ScopePolicy ile
  ``validate_target``). Hedef kapsam dışıysa tarama AÇILMAZ (dispatch atlar).
* Çağrı yeri (web/routes.py) **admin-gated** + her komut ``console_exec`` ile
  **audit'lenir**. Bu modül istisna sızdırmaz — beklenmeyen hata genel mesajla döner.

Komut grameri: ``<isim> <alt-komut> [argümanlar]`` (örn. ``scan start 10.0.0.5``).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.audit_events import render_message
from cybersectool.core.exploit_seam import exploit_plugin_available
from cybersectool.core.licensing import active_license, feature_licensed
from cybersectool.core.models import AuditLog, Role, ScanMode, ScanStatus, ScanType, User
from cybersectool.core.scans import get_scan, list_scans, set_scan_status
from cybersectool.core.system_health import system_health
from cybersectool.core.users import (
    get_user_by_username,
    list_users,
    set_user_active,
    set_user_role,
)
from cybersectool.dispatch import dispatch_target_list_scan
from cybersectool.tasks.celery_app import celery_app


class ConsoleError(Exception):
    """Beklenen doğrulama hatası (kötü argüman vb.) — çağırana kısa mesaj olarak döner."""


@dataclass(frozen=True)
class ConsoleResult:
    """Bir komutun sonucu: ``ok`` (başarı) + ``output`` (terminalde gösterilecek metin)."""

    ok: bool
    output: str


Handler = Callable[[AsyncSession, User, list[str], str], Awaitable[str]]


@dataclass(frozen=True)
class Command:
    """Tek bir konsol komutu (allowlist girdisi): isim + kullanım + handler."""

    noun: str
    usage: str
    summary: str
    handler: Handler


def _require(condition: bool, message: str) -> None:
    """``condition`` yanlışsa ``ConsoleError(message)`` fırlatır (arg doğrulama kısayolu)."""
    if not condition:
        raise ConsoleError(message)


# --- Komut handler'ları (her biri yalnız mevcut tipli servisleri çağırır) ----------


async def _cmd_scan(session: AsyncSession, user: User, args: list[str], lang: str) -> str:
    verb = args[0].lower() if args else ""
    if verb == "list":
        scans = await list_scans(session)
        if not scans:
            return "Tarama yok."
        rows = [
            f"#{s.id:<5} {s.scan_type:<11} {s.status:<10} %{s.progress:<3} {s.target}"
            for s in scans[:15]
        ]
        return "ID    TÜR         DURUM      İLERLEME HEDEF\n" + "\n".join(rows)
    if verb == "status":
        _require(len(args) >= 2, "Kullanım: scan status <id>")
        scan_id = _parse_int(args[1], "tarama id")
        scan = await get_scan(session, scan_id)
        _require(scan is not None, f"Tarama bulunamadı: #{scan_id}")
        assert scan is not None
        phase = f" — {scan.phase}" if scan.phase else ""
        return (
            f"#{scan.id} {scan.scan_type} [{scan.mode}] durum={scan.status} "
            f"%{scan.progress}{phase}\nhedef: {scan.target}"
        )
    if verb == "start":
        _require(len(args) >= 2, "Kullanım: scan start <hedef>  (güvenli ağ taraması)")
        target = args[1]
        # Mod KASITLI olarak 'safe' — agresif/exploit konsoldan açılmaz (UI ack akışı gerekir).
        result = await dispatch_target_list_scan(
            session, [target], ScanMode.safe, user.id, label="konsol", scan_type=ScanType.network
        )
        if result.skipped:
            return f"Hedef kapsam dışı (ScopePolicy), tarama açılmadı: {', '.join(result.skipped)}"
        ids = ", ".join(f"#{s.id}" for s in result.scans)
        return f"Tarama başlatıldı (güvenli ağ): {ids}  ·  hedef: {target}"
    if verb == "stop":
        _require(len(args) >= 2, "Kullanım: scan stop <id>")
        scan_id = _parse_int(args[1], "tarama id")
        scan = await get_scan(session, scan_id)
        _require(scan is not None, f"Tarama bulunamadı: #{scan_id}")
        assert scan is not None
        if scan.task_id:
            celery_app.control.revoke(scan.task_id, terminate=True, signal="SIGTERM")
        await set_scan_status(session, scan_id, ScanStatus.cancelled)
        return f"Tarama durduruldu: #{scan_id}"
    raise ConsoleError("Kullanım: scan list | status <id> | start <hedef> | stop <id>")


_SYNC_TASKS = {"nvd": "cpe_sync", "epss": "epss_refresh", "exploitdb": "exploit_sync"}


async def _cmd_sync(session: AsyncSession, user: User, args: list[str], lang: str) -> str:
    verb = args[0].lower() if args else ""
    _require(verb in _SYNC_TASKS, "Kullanım: sync nvd | epss | exploitdb")
    # Görev adıyla gönder (import sırası/kuyruk yönlendirmesinden bağımsız, güvenli).
    celery_app.send_task(_SYNC_TASKS[verb])
    return f"Senkron tetiklendi: {verb} (görev kuyruğa alındı; tamamlanınca tazelik güncellenir)."


async def _cmd_user(session: AsyncSession, user: User, args: list[str], lang: str) -> str:
    verb = args[0].lower() if args else ""
    if verb == "list":
        users = await list_users(session)
        rows = [
            f"{u.username:<20} {u.role:<9} {'aktif' if u.is_active else 'pasif'}" for u in users
        ]
        return "KULLANICI            ROL       DURUM\n" + "\n".join(rows)
    if verb == "role":
        _require(len(args) >= 3, "Kullanım: user role <ad> <admin|analyst|viewer>")
        target = await _lookup_user(session, args[1])
        try:
            role = Role(args[2].lower())
        except ValueError as exc:
            raise ConsoleError("Geçersiz rol (admin | analyst | viewer).") from exc
        # Kendini admin'den düşürme (kilitlenme/yetki-kaybı koruması).
        _require(
            not (target.id == user.id and role != Role.admin),
            "Kendi admin rolünü düşüremezsin (kilitlenme koruması).",
        )
        await set_user_role(session, target.id, role)
        return f"Rol güncellendi: {target.username} → {role}"
    if verb in ("disable", "enable"):
        _require(len(args) >= 2, f"Kullanım: user {verb} <ad>")
        target = await _lookup_user(session, args[1])
        if verb == "disable":
            _require(
                target.id != user.id, "Kendi hesabını pasifleştiremezsin (kilitlenme koruması)."
            )
        await set_user_active(session, target.id, verb == "enable")
        durum = "etkinleştirildi" if verb == "enable" else "pasifleştirildi"
        return f"Kullanıcı {durum}: {target.username}"
    raise ConsoleError("Kullanım: user list | role <ad> <rol> | disable <ad> | enable <ad>")


async def _cmd_system(session: AsyncSession, user: User, args: list[str], lang: str) -> str:
    health = await system_health()
    if not health.available:
        base = "Konteyner verisi yok (Docker soketi erişilemez)."
        # Disk/RAM yine de gösterilebilir (host /proc + shutil).
        return f"{base}\n{_fmt_disk_mem(health)}"
    running = sum(1 for c in health.containers if getattr(c, "state", "") == "running")
    lines = [f"Konteyner: {running}/{len(health.containers)} çalışıyor", _fmt_disk_mem(health)]
    return "\n".join(lines)


async def _cmd_license(session: AsyncSession, user: User, args: list[str], lang: str) -> str:
    info = await active_license(session)
    parts = [f"durum={info.status}"]
    if info.customer:
        parts.append(f"müşteri={info.customer}")
    if info.expires:
        parts.append(f"bitiş={info.expires}")
    if info.features:
        parts.append(f"özellikler={','.join(info.features)}")
    return "Lisans: " + "  ".join(parts)


async def _cmd_plugin(session: AsyncSession, user: User, args: list[str], lang: str) -> str:
    installed = exploit_plugin_available()
    licensed = await feature_licensed(session, "exploit")
    return (
        f"Sömürü eklentisi (cybersectool.exploit): {'kurulu' if installed else 'pasif'}\n"
        f"Sömürü lisansı: {'lisanslı' if licensed else 'lisans gerekli'}\n"
        f"Sömürü açık mı: {'EVET' if (installed and licensed) else 'hayır (eklenti+lisans şart)'}"
    )


async def _cmd_worker(session: AsyncSession, user: User, args: list[str], lang: str) -> str:
    verb = args[0].lower() if args else ""
    if verb == "ping":
        # control.ping SENKRON + ağ bekler → event loop'u bloklamamak için thread'e al.
        replies = await asyncio.to_thread(celery_app.control.ping, timeout=1.5)
        if not replies:
            return "Yanıt veren worker yok (çalışmıyor olabilir)."
        names = ", ".join(sorted(k for r in replies for k in r))
        return f"Çalışan worker ({len(replies)}): {names}"
    if verb == "restart":
        # pool_restart: worker süreci ölmeden havuzu yeniden başlatır (worker_pool_restarts=True).
        await asyncio.to_thread(
            celery_app.control.broadcast, "pool_restart", arguments={"reload": False}
        )
        return "Worker havuzu yeniden başlatma sinyali gönderildi (pool_restart)."
    raise ConsoleError("Kullanım: worker ping | restart")


async def _cmd_logs(session: AsyncSession, user: User, args: list[str], lang: str) -> str:
    limit = 20
    if args:
        limit = max(1, min(_parse_int(args[0], "satır sayısı"), 100))
    result = await session.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit))
    rows = list(result.scalars().all())
    if not rows:
        return "Denetim kaydı yok."
    out = []
    for r in reversed(rows):
        ts = r.created_at.strftime("%Y-%m-%d %H:%M:%S") if r.created_at else "-"
        out.append(f"{ts}  {render_message(r.action, r.target, None, lang)}")
    return "\n".join(out)


# --- Yardımcılar -------------------------------------------------------------------


def _parse_int(raw: str, label: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise ConsoleError(f"Geçersiz {label}: {raw}") from exc


async def _lookup_user(session: AsyncSession, username: str) -> User:
    target = await get_user_by_username(session, username)
    if target is None:
        raise ConsoleError(f"Kullanıcı bulunamadı: {username}")
    return target


def _fmt_disk_mem(health: object) -> str:
    disk = getattr(health, "disk", None)
    mem_total = getattr(health, "mem_total", None)
    mem_used = getattr(health, "mem_used", None)
    parts = []
    if disk is not None:
        used = getattr(disk, "used", None)
        total = getattr(disk, "total", None)
        if used is not None and total:
            parts.append(f"Disk: {_gb(used)}/{_gb(total)} GB")
    if mem_total:
        parts.append(f"RAM: {_gb(mem_used or 0)}/{_gb(mem_total)} GB")
    return "  ".join(parts) if parts else "Disk/RAM bilgisi yok."


def _gb(num_bytes: int) -> str:
    return f"{num_bytes / (1024**3):.1f}"


# --- Kayıt defteri (ALLOWLIST) — yalnız buradakiler çalışır ------------------------

COMMANDS: dict[str, Command] = {
    "scan": Command(
        "scan", "scan list | status <id> | start <hedef> | stop <id>", "Tarama işlemleri", _cmd_scan
    ),
    "sync": Command("sync", "sync nvd | epss | exploitdb", "Zafiyet verisi senkronu", _cmd_sync),
    "user": Command(
        "user",
        "user list | role <ad> <rol> | disable <ad> | enable <ad>",
        "Kullanıcı yönetimi",
        _cmd_user,
    ),
    "system": Command("system", "system status", "Sistem (CPU/RAM/disk/konteyner)", _cmd_system),
    "license": Command("license", "license status", "Lisans durumu", _cmd_license),
    "plugin": Command("plugin", "plugin status", "Eklenti durumu (sömürü)", _cmd_plugin),
    "worker": Command("worker", "worker ping | restart", "Celery worker", _cmd_worker),
    "logs": Command("logs", "logs [N]", "Son N denetim olayı (varsayılan 20)", _cmd_logs),
}

_HELP_ALIASES = {"help", "?", "yardım", "yardim"}


def _help_text() -> str:
    """Allowlist'teki tüm komutların kullanım listesini üretir."""
    lines = ["Kullanılabilir komutlar (yalnız bunlar — keyfi kabuk YOK):"]
    for cmd in COMMANDS.values():
        lines.append(f"  {cmd.usage:<48} — {cmd.summary}")
    lines.append(f"  {'help':<48} — bu liste")
    return "\n".join(lines)


async def run_console(
    session: AsyncSession, user: User, line: str, lang: str = "tr"
) -> ConsoleResult:
    """Tek bir konsol satırını çalıştırır (allowlist) — ASLA istisna sızdırmaz.

    Akış: boş satır → hata; ``help`` → liste; ilk token ``COMMANDS``'ta değilse
    "bilinmeyen komut" (çalıştırma YOK); aksi halde ilgili handler çağrılır.
    ``ConsoleError`` → kısa mesaj; beklenmeyen hata → genel mesaj (traceback sızmaz).
    """
    text = (line or "").strip()
    if not text:
        return ConsoleResult(False, "Boş komut. 'help' yazın.")
    tokens = text.split()
    noun = tokens[0].lower()
    if noun in _HELP_ALIASES:
        return ConsoleResult(True, _help_text())
    cmd = COMMANDS.get(noun)
    if cmd is None:
        return ConsoleResult(False, f"Bilinmeyen komut: {noun}. 'help' yazın.")
    try:
        output = await cmd.handler(session, user, tokens[1:], lang)
        return ConsoleResult(True, output)
    except ConsoleError as exc:
        return ConsoleResult(False, str(exc))
    except Exception:  # noqa: BLE001 — konsol ASLA patlamamalı; traceback'i kullanıcıya sızdırma
        return ConsoleResult(False, "Komut çalıştırılamadı (beklenmeyen hata). Loglara bakın.")
