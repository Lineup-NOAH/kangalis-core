"""Web dashboard router'ı (Jinja2 + HTMX + Tailwind).

Sayfa (HTML) uçları; programatik JSON API'den (`/auth/*`, `/scans` POST JSON) ayrıdır.
Oturum cookie'si ile çalışır.
"""

from __future__ import annotations

import asyncio
import contextlib
import csv
import io
import ipaddress
import json
import socket
from collections import defaultdict
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from html import escape
from pathlib import Path
from typing import Annotated, cast
from urllib.parse import quote, urlparse

from fastapi import APIRouter, File, Form, Request, Response, UploadFile, status
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.api.deps import SessionDep
from cybersectool.config import APP_NAME, VERSION, settings
from cybersectool.core import cve_backfill, disclaimer
from cybersectool.core.ai import AIConfig, ai_available, detect_ai_paths
from cybersectool.core.ai import cache as ai_cache
from cybersectool.core.ai import prompts as ai_prompts
from cybersectool.core.ai import service as ai_service
from cybersectool.core.ai_limiter import ai_rate_limited
from cybersectool.core.app_settings import (
    COMMON_TIMEZONES,
    NVD_SYNC_DAYS_MAX,
    NVD_SYNC_DAYS_MIN,
    SYSLOG_FORMATS,
    SYSLOG_PROTOCOLS,
    ai_brand_enabled,
    format_local,
    get_settings,
    parse_asset_scope_cidrs,
    probe_ai_endpoint,
    save_ai_settings,
    save_asset_scope_settings,
    save_hardening_settings,
    save_ldap_sync_settings,
    save_license_key,
    save_license_public_key,
    save_network_settings,
    save_nvd_settings,
    save_ratelimit_settings,
    save_scan_settings,
    save_smtp_settings,
    save_syslog_settings,
    save_timezone_settings,
    save_update_settings,
)
from cybersectool.core.assets import (
    count_inventory_assets,
    create_url_asset,
    get_asset,
    hosts_in_scope,
    list_assets,
    list_inventory_assets,
    list_services,
    services_for_target,
    set_asset_name,
    upsert_asset,
    web_scan_host_entries,
)
from cybersectool.core.audit import (
    category_for,
    export_audit_logs,
    log_action,
    query_audit_logs,
    range_since,
    render_message,
)
from cybersectool.core.audit_events import AUDIT_EVENTS
from cybersectool.core.compliance import (
    compliance_for_scan,
    compliance_overview,
    compliance_summary,
    regulation_summary,
    top_failed_controls,
)
from cybersectool.core.cpe import count_cpe_matches
from cybersectool.core.credentials import (
    create_credential,
    create_credential_zone,
    credentials_in_zone,
    delete_credential,
    delete_credential_zone,
    effective_port,
    get_credential,
    get_credential_zone,
    list_credential_zones,
    list_credentials,
    update_credential,
    update_credential_zone,
)
from cybersectool.core.cve_browse import (
    CVE_PER_PAGE_CHOICES,
    count_cves_filtered,
    cpe_counts_for_cves,
    list_cves_page,
)
from cybersectool.core.cve_browse import category_counts as cve_category_counts
from cybersectool.core.cve_compliance import FRAMEWORKS, frameworks_for_cve
from cybersectool.core.exploit_attempts import (
    annotate_exploitdb_runnable,
    build_exploit_overview,
    exploitdb_staged_list,
    list_exploit_attempts,
)
from cybersectool.core.exploit_classify import CATEGORIES
from cybersectool.core.exploit_freshness import compute_up_to_date
from cybersectool.core.exploit_seam import exploit_plugin_available
from cybersectool.core.exploits import (
    build_exploit_arsenal,
    categories_for_cves,
    cve_exploit_signals,
    exploit_summary_for_cves,
    facet_counts,
    list_exploits,
)
from cybersectool.core.findings import (
    count_by_severity,
    count_findings_by_scan,
    list_findings_by_risk,
)
from cybersectool.core.ldap import (
    LdapSearchError,
    ldap_group_members,
    ldap_list_groups,
    ldap_list_ous,
    ldap_search_users,
    ldap_test_connection,
)
from cybersectool.core.ldap_config import get_bind_password, get_ldap_config, save_ldap_config
from cybersectool.core.licensing import active_license, exploit_unlocked, feature_licensed
from cybersectool.core.login_guard import (
    clear_login_failures,
    login_lockout_remaining,
    record_login_failure,
)
from cybersectool.core.mailer import MailError, send_email, smtp_sender
from cybersectool.core.mfa import totp_provisioning_uri, totp_qr_svg, verify_totp
from cybersectool.core.mfa_email import (
    OTP_TTL_SEC,
    generate_email_otp,
    store_email_otp,
    verify_email_otp,
)
from cybersectool.core.models import (
    CVE,
    AIExplanation,
    AppSettings,
    Asset,
    AuditLog,
    ComplianceCheck,
    Credential,
    CredentialType,
    Exploit,
    ExploitAttempt,
    ExploitSource,
    Finding,
    FindingStatus,
    LdapConfig,
    Role,
    Scan,
    ScanBatch,
    ScanMode,
    ScanStatus,
    ScanType,
    Service,
    Severity,
    User,
    WordlistKind,
    Zone,
)
from cybersectool.core.password_policy import validate_password
from cybersectool.core.remediation import remediation_for
from cybersectool.core.risk import is_urgent
from cybersectool.core.scan_batches import (
    batch_scans,
    batch_status,
    count_findings_by_batch,
    create_batch,
    delete_batch,
    get_batch,
    list_batches,
    next_quick_scan_name,
)
from cybersectool.core.scan_policy import (
    WIZARD_MODES,
    AggressiveScanNotAllowed,
    does_exploitation,
    ensure_mode_allowed,
    estimate_scan_seconds,
    is_aggressive,
    parse_mode,
    resolve_wizard_mode,
    sanitize_ports,
)
from cybersectool.core.scans import (
    count_scans,
    create_scan,
    delete_scan,
    get_scan,
    list_scans,
    set_scan_status,
)
from cybersectool.core.schedules import (
    create_schedule,
    delete_schedule,
    get_schedule,
    list_schedules,
    set_schedule_active,
)
from cybersectool.core.scope import get_active_policy, set_active_scope
from cybersectool.core.security import verify_password
from cybersectool.core.session_guard import (
    session_idle_expired,
    start_session_timeout,
    touch_session,
)
from cybersectool.core.syslog_forward import parser_regex_for_format
from cybersectool.core.system_health import system_health
from cybersectool.core.tokens import (
    create_api_token,
    list_user_tokens,
    revoke_user_token,
)
from cybersectool.core.update_check import run_update_check, stored_status
from cybersectool.core.users import (
    authenticate_user,
    begin_email_enrollment,
    begin_totp_enrollment,
    create_user,
    delete_user,
    disable_mfa,
    enable_mfa,
    get_mfa_secret,
    get_user_by_id,
    get_user_by_username,
    import_ldap_user,
    import_ldap_users,
    list_users,
    set_user_active,
    set_user_email,
    set_user_password,
    set_user_role,
)
from cybersectool.core.versions import app_version, gather_versions
from cybersectool.core.vuln import count_cves, cves_by_ids
from cybersectool.core.vuln_category import VULN_CATEGORIES, is_os_package_title
from cybersectool.core.vulnerabilities import (
    category_counts,
    count_vulnerabilities,
    list_vulnerabilities,
    list_vulnerabilities_page,
    set_vuln_status,
    severity_counts_by_asset,
    severity_counts_open,
    vuln_lifecycle_stats,
    vuln_trend,
)
from cybersectool.core.wordlist_defaults import builtin_display_name
from cybersectool.core.wordlist_generators import (
    USERNAME_PATTERN_KEYS,
    PasswordSpec,
    generate_passwords,
    generate_usernames,
    parse_name_pairs,
)
from cybersectool.core.wordlists import (
    create_wordlist,
    delete_wordlist,
    get_wordlist,
    list_wordlists,
    parse_entries,
    update_wordlist,
)
from cybersectool.core.zones import (
    create_zone,
    delete_zone,
    get_zone,
    is_url_entry,
    list_zones,
    parse_cidr_input,
    update_zone,
)
from cybersectool.dispatch import (
    assets_in_zones,
    audit_credentialed_to_scan,
    dispatch_cisco_ios_audit_hosts,
    dispatch_credential_zone_scan,
    dispatch_credential_zones_scan,
    dispatch_db_audit_hosts,
    dispatch_esxi_audit_hosts,
    dispatch_ldap_audit_hosts,
    dispatch_ping_scan,
    dispatch_smb_audit_hosts,
    dispatch_snmp_audit_hosts,
    dispatch_target_list_scan,
    dispatch_telnet_audit_hosts,
    dispatch_zone_credentialed,
    dispatch_zone_scan,
    dispatch_zones_scan,
    first_cred_of_type,
)
from cybersectool.tasks.celery_app import celery_app
from cybersectool.tasks.cpe_sync import cpe_sync_task, nvd_backfill_task
from cybersectool.tasks.exploit_sync import sync_exploits_task
from cybersectool.tasks.sca_scan import sca_scan_task
from cybersectool.tasks.web_scan import web_scan_task
from cybersectool.web.help_content import HELP_SECTIONS
from cybersectool.web.help_content import grounding_text as help_grounding_text
from cybersectool.web.i18n import LANG_COOKIE, normalize_lang, translator
from cybersectool.web.pdf import PdfUnavailableError, render_html_to_pdf

router = APIRouter(tags=["web"])


def _i18n_context(request: Request) -> dict[str, object]:
    """Her şablona aktif dil + t() + AI marka modunu enjekte eder.

    ``ai_brand``: AI eklentisi etkinse True → arayüz markası "Kangalis AI" olur (her sayfada).
    ``brand_name``: marka adı (başlık/title için). Marka durumu süreç-içi cache'ten (DB değil)
    okunur, böylece bu sync context processor her render'da DB sorgusu yapmaz (app_settings cache).
    """
    lang = normalize_lang(request.cookies.get(LANG_COOKIE))
    ai_brand = ai_brand_enabled()
    return {
        "lang": lang,
        "t": translator(lang),
        "ai_brand": ai_brand,
        "brand_name": f"{APP_NAME} AI" if ai_brand else APP_NAME,
        "app_version": app_version(),
    }


templates = Jinja2Templates(
    directory=str(Path(__file__).parent / "templates"),
    context_processors=[_i18n_context],
)
# IX-1: tüm tarih/saat gösterimleri için yerel-saat filtresi. UTC saklanır,
# şablonda {{ dt | localdt }} (veya {{ dt | localdt('%Y-%m-%d') }}) ile çevrilir.
templates.env.filters["localdt"] = format_local


def _frameworks_for_exploit(exploit: Exploit) -> list[str]:
    """Exploit satırı için ilgili uyum çerçeveleri (IX-10; exploit DB rozetleri)."""
    return frameworks_for_cve(
        title=exploit.title or "",
        severity=exploit.severity.value if exploit.severity else None,
        categories=exploit.categories or [],
    )


def _frameworks_for_finding(finding: Finding, cve: CVE | None = None) -> list[str]:
    """Rapor bulgusu için ilgili uyum çerçeveleri (IX-10; rapor rozetleri)."""
    return frameworks_for_cve(
        title=finding.title or "",
        severity=finding.severity.value if finding.severity else None,
        cvss_score=cve.cvss_score if cve else None,
        kev=cve.kev_flag if cve else False,
    )


def _frameworks_for_cve_row(cve: CVE) -> list[str]:
    """CVE satırı için ilgili uyum çerçeveleri (Zafiyet DB rozetleri) — açıklamadan türetir."""
    return frameworks_for_cve(
        title=cve.description or "",
        severity=cve.severity.value if cve.severity else None,
        cvss_score=cve.cvss_score,
        kev=cve.kev_flag,
    )


# IX-10: şablonlarda CVE→uyum rozetleri için global yardımcılar.
templates.env.globals["frameworks_for_exploit"] = _frameworks_for_exploit
templates.env.globals["frameworks_for_finding"] = _frameworks_for_finding
templates.env.globals["frameworks_for_cve_row"] = _frameworks_for_cve_row


def _audit_message(log: AuditLog, username: str | None, lang: str) -> str:
    """X-7: denetim satırı için anlamlı (okunaklı) mesaj (aktif dile göre)."""
    return render_message(log.action, log.target, username, lang=lang)


# X-7: denetim sayfasında ham 'action' yerine anlamlı mesaj göstermek için.
templates.env.globals["audit_message"] = _audit_message
templates.env.globals["audit_category"] = category_for
# OSPKG: raporda OS-paket (OSV.dev) bulgularını rozetlemek için.
templates.env.globals["is_os_package_title"] = is_os_package_title
# #214: yerleşik kelime listesi adlarını render-zamanı TR/EN gösterimi (DB kanonik adı değişmez).
templates.env.globals["builtin_wl_name"] = builtin_display_name


async def _current_user(request: Request, session: AsyncSession) -> User | None:
    user_id = request.session.get("user_id")
    if user_id is None:
        return None
    # Idle zaman aşımı: süre dolduysa oturumu düşür (yeniden giriş gerekir).
    if session_idle_expired(request.session):
        request.session.clear()
        return None
    user = await get_user_by_id(session, int(user_id))
    if user is not None:
        touch_session(request.session)
    return user


def _redirect_login() -> RedirectResponse:
    return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)


def _redirect_disclaimer() -> RedirectResponse:
    return RedirectResponse("/disclaimer", status_code=status.HTTP_303_SEE_OTHER)


def _resolve_assignment(
    user: User,
    assigned_user_id: int | None,
    notify_on_complete: str,
    attach_report: str,
) -> tuple[int | None, bool, bool]:
    """Tarama atama alanlarını çözer (yalnız admin atayabilir).

    Admin değilse tüm alanlar yok sayılır (varsayılan: atama yok, bildirim kapalı).
    Döner: (assigned_user_id, notify_on_complete, attach_report).
    """
    if user.role != Role.admin:
        return None, False, False
    return assigned_user_id, bool(notify_on_complete), bool(attach_report)


async def _ldaps_tls(session: AsyncSession) -> tuple[bool, str | None]:
    """LDAPS sertifika doğrulama ayarlarını okur: (verify_cert, ca_cert_pem)."""
    row = await get_settings(session)
    return row.ldaps_verify_cert, (row.ldaps_ca_cert or None)


async def _scans_page(
    request: Request,
    session: AsyncSession,
    user: User,
    *,
    error: str | None = None,
    message: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> Response:
    """Taramalar sayfasını (tarama listesi + zone'lar + sihirbaz verileri) döndürür."""
    is_admin = user.role == Role.admin
    creds = await list_credentials(session) if is_admin else []
    czones = await list_credential_zones(session)
    # Sihirbaz/hızlı kimlik pop-up'larında hover ipucu: kimlik id → domain\kullanıcı.
    cred_user_by_id = {
        c.id: (f"{c.domain}\\{c.username}" if c.domain else c.username) for c in creds
    }
    credzone_users = {
        cz.id: ", ".join(cred_user_by_id.get(i, "") for i in cz.credential_ids) for cz in czones
    }
    return templates.TemplateResponse(
        request,
        "scans.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "scans": await list_scans(session),
            "batch_names": await _batch_name_map(session),
            "zones": await list_zones(session),
            "assets": await list_assets(session),
            "credential_zones": czones,
            "credentials": creds,
            "cred_user_by_id": cred_user_by_id,
            "credzone_users": credzone_users,
            # Dizin taraması için seçilebilir web-dizin kelime listeleri (yoksa yerleşik).
            "web_wordlists": await list_wordlists(session, WordlistKind.web_dir),
            # SMB gizli-paylaşım keşfi için seçilebilir paylaşım-adı kelime listeleri.
            "smb_wordlists": await list_wordlists(session, WordlistKind.smb_share),
            "scan_categories": CATEGORIES,
            # Atama (yalnız admin): tarama bitince e-posta gönderilecek kullanıcı seçimi.
            "all_users": await list_users(session) if is_admin else [],
            "error": error,
            "message": message,
            "allow_aggressive": settings.allow_aggressive_scans,
            # Sömürme modu yalnız eklenti+lisans varsa forma düşer (scans.html exploit_unlocked).
            "exploit_unlocked": await exploit_unlocked(session),
        },
        status_code=status_code,
    )


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> Response:
    return templates.TemplateResponse(
        request,
        "login.html",
        {"app_name": APP_NAME, "ldap_enabled": settings.ldap_enabled},
    )


def _login_error(request: Request, message: str, status_code: int) -> Response:
    """login.html'i hata mesajıyla döndürür (LDAP ipucu korunur)."""
    return templates.TemplateResponse(
        request,
        "login.html",
        {"app_name": APP_NAME, "ldap_enabled": settings.ldap_enabled, "error": message},
        status_code=status_code,
    )


def _lockout_message(remaining_sec: int) -> str:
    """Kalan kilit süresinden kullanıcıya gösterilecek mesaj (dakika)."""
    minutes = max(1, remaining_sec // 60)
    return (
        "Çok fazla başarısız deneme. Hesap geçici olarak kilitlendi; "
        f"yaklaşık {minutes} dk sonra tekrar deneyin."
    )


@router.post("/login")
async def login_submit(
    request: Request,
    session: SessionDep,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
) -> Response:
    settings_row = await get_settings(session)
    # 1) Hesap kilitliyse doğru parola bile reddedilir.
    remaining = await login_lockout_remaining(settings_row, username)
    if remaining:
        await log_action(session, "login_locked", target=username[:120])
        return _login_error(request, _lockout_message(remaining), status.HTTP_429_TOO_MANY_REQUESTS)
    user = await authenticate_user(session, username, password)
    if user is None:
        # Başarısız giriş: sayacı artır, denetim günlüğüne yaz, eşikte kilitle.
        locked = await record_login_failure(settings_row, username)
        await log_action(session, "login_failed", target=username[:120])
        if locked:
            await log_action(session, "login_locked", target=username[:120])
            return _login_error(
                request, _lockout_message(locked), status.HTTP_429_TOO_MANY_REQUESTS
            )
        return _login_error(
            request, "Kullanıcı adı veya parola hatalı", status.HTTP_401_UNAUTHORIZED
        )
    # Parola doğru. MFA etkinse ikinci adıma geç (oturumu HENÜZ açma).
    if user.mfa_enabled:
        request.session["mfa_user_id"] = user.id
        if user.mfa_method == "email":
            await _send_mfa_email_otp(session, user)
        return RedirectResponse("/login/mfa", status_code=status.HTTP_303_SEE_OTHER)
    # MFA yok: girişi tamamla (sayaç + kilidi temizle).
    await clear_login_failures(username)
    request.session["user_id"] = user.id
    # Sorumluluk reddi kabul bayrağı (gate middleware bunu okur — DB sorgusu yok).
    request.session["disclaimer_ok"] = user.disclaimer_accepted_at is not None
    start_session_timeout(request.session, settings_row.session_timeout_min)
    if disclaimer.disclaimer_enforced() and user.disclaimer_accepted_at is None:
        return _redirect_disclaimer()
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


async def _send_mfa_email_otp(session: AsyncSession, user: User) -> bool:
    """6 haneli OTP üretir, Redis'e (hash'li) yazar ve kullanıcının e-postasına gönderir.

    SMTP kapalıysa ya da kullanıcının e-postası yoksa False döner (gönderim yapılmaz).
    """
    row = await get_settings(session)
    recipient = (user.email or "").strip()
    if not row.smtp_enabled or not recipient:
        return False
    code = generate_email_otp()
    await store_email_otp(user.id, code)
    try:
        await send_email(
            row,
            recipient,
            "Kangalis — Doğrulama kodu",
            f"Doğrulama kodunuz: {code}\n\nKod {OTP_TTL_SEC // 60} dakika geçerlidir. "
            "Bu isteği siz yapmadıysanız parolanızı değiştirin.",
        )
    except MailError:
        return False
    return True


@router.get("/login/mfa", response_class=HTMLResponse)
async def login_mfa_page(request: Request, session: SessionDep) -> Response:
    """Parola sonrası ikinci doğrulama (MFA kod) sayfası. Bekleyen giriş yoksa /login."""
    pending_id = request.session.get("mfa_user_id")
    if pending_id is None:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    user = await get_user_by_id(session, int(pending_id))
    if user is None or not user.mfa_enabled:
        request.session.pop("mfa_user_id", None)
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request,
        "login_mfa.html",
        {"app_name": APP_NAME, "method": user.mfa_method},
    )


@router.post("/login/mfa")
async def login_mfa_submit(
    request: Request,
    session: SessionDep,
    code: Annotated[str, Form()],
) -> Response:
    pending_id = request.session.get("mfa_user_id")
    if pending_id is None:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    user = await get_user_by_id(session, int(pending_id))
    if user is None or not user.mfa_enabled:
        request.session.pop("mfa_user_id", None)
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    settings_row = await get_settings(session)
    # MFA kodu kaba-kuvvetine karşı: aynı kilit mekanizması.
    if await login_lockout_remaining(settings_row, user.username):
        await log_action(session, "login_locked", target=user.username[:120])
        request.session.pop("mfa_user_id", None)
        return _login_error(
            request,
            _lockout_message(settings_row.ratelimit_lockout_sec),
            status.HTTP_429_TOO_MANY_REQUESTS,
        )
    if user.mfa_method == "email":
        verified = await verify_email_otp(user.id, code)
    else:
        verified = user.mfa_method == "totp" and verify_totp(get_mfa_secret(user), code)
    if not verified:
        locked = await record_login_failure(settings_row, user.username)
        await log_action(session, "login_failed", target=user.username[:120])
        if locked:
            await log_action(session, "login_locked", target=user.username[:120])
            request.session.pop("mfa_user_id", None)
            return _login_error(
                request, _lockout_message(locked), status.HTTP_429_TOO_MANY_REQUESTS
            )
        return templates.TemplateResponse(
            request,
            "login_mfa.html",
            {
                "app_name": APP_NAME,
                "method": user.mfa_method,
                "error": "Kod hatalı. Tekrar deneyin.",
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    # Doğrulandı: girişi tamamla.
    await clear_login_failures(user.username)
    request.session.pop("mfa_user_id", None)
    request.session["user_id"] = user.id
    request.session["disclaimer_ok"] = user.disclaimer_accepted_at is not None
    start_session_timeout(request.session, settings_row.session_timeout_min)
    if disclaimer.disclaimer_enforced() and user.disclaimer_accepted_at is None:
        return _redirect_disclaimer()
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/login/mfa/resend")
async def login_mfa_resend(request: Request, session: SessionDep) -> Response:
    """E-posta OTP'yi yeniden gönderir (bekleyen e-posta MFA girişi için)."""
    pending_id = request.session.get("mfa_user_id")
    if pending_id is None:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    user = await get_user_by_id(session, int(pending_id))
    if user is not None and user.mfa_enabled and user.mfa_method == "email":
        await _send_mfa_email_otp(session, user)
    return RedirectResponse("/login/mfa", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/logout")
async def logout(request: Request) -> Response:
    # POST (GET değil): oturum sonlandırma durum-değiştiren bir eylem; GET olması logout-CSRF'e
    # (zararsız ama can sıkıcı zorla-çıkış) açık bırakırdı. Nav'daki bağlantı artık POST formu.
    request.session.clear()
    return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/disclaimer", response_class=HTMLResponse)
async def disclaimer_page(request: Request, session: SessionDep) -> Response:
    """Sorumluluk reddi (DISCLAIMER.md) onay ekranı. Kabul edildiyse → panele yönlendirir."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.disclaimer_accepted_at is not None:
        request.session["disclaimer_ok"] = True  # bayrağı tazele (eski oturum/yeni sürüm)
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    ctx = _i18n_context(request)
    ctx["app_name"] = APP_NAME
    return templates.TemplateResponse(request, "disclaimer.html", ctx)


@router.post("/disclaimer/accept")
async def disclaimer_accept(
    request: Request,
    session: SessionDep,
    acknowledge: Annotated[str, Form()] = "",
) -> Response:
    """Sorumluluk reddini kabul kaydeder: zaman damgası (DB) + denetim kaydı + oturum bayrağı."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if acknowledge != "on":
        return _redirect_disclaimer()  # onay kutusu işaretlenmedi (tarayıcı zaten 'required')
    if user.disclaimer_accepted_at is None:
        user.disclaimer_accepted_at = datetime.now(UTC)
        await session.commit()
        await log_action(session, "disclaimer_accepted", user_id=user.id, target=user.username)
    request.session["disclaimer_ok"] = True
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/lang/{code}")
async def set_language(request: Request, code: str) -> Response:
    """Arayüz dilini (tr/en) çerezde saklar ve gelinen sayfaya döner."""
    # Açık yönlendirme koruması: yalnızca AYNI KÖKEN / göreli referer'a dön; aksi halde "/".
    referer = request.headers.get("referer") or "/"
    parsed = urlparse(referer)
    target = referer if (not parsed.netloc or parsed.netloc == request.url.netloc) else "/"
    response = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        LANG_COOKIE, normalize_lang(code), max_age=60 * 60 * 24 * 365, samesite="lax"
    )
    return response


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session: SessionDep) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    top_vulns = await list_vulnerabilities(session, resolved=False, limit=5)
    assets = await list_assets(session)
    ip_by_id = {a.id: a.ip for a in assets}
    device_by_id = {a.id: a.display_name for a in assets}
    cve_map = await cves_by_ids(session, [v.cve_id for v in top_vulns if v.cve_id])
    exploit_facets = await facet_counts(session)
    lifecycle = await vuln_lifecycle_stats(session)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "app_name": APP_NAME,
            "version": VERSION,
            "user": user,
            "asset_count": await count_inventory_assets(session),
            "vuln_open": await count_vulnerabilities(session, resolved=False),
            "vuln_resolved": await count_vulnerabilities(session, resolved=True),
            "scan_count": await count_scans(session),
            "zone_count": len(await list_zones(session)),
            "severity_counts": await severity_counts_open(session),
            "lifecycle": lifecycle,
            "exploit_total": exploit_facets["total"],
            "exploit_by_severity": exploit_facets["by_severity"],
            "exploit_by_category": exploit_facets["by_category"],
            "cpe_total": await count_cpe_matches(session),
            "top_vulns": top_vulns,
            "ip_by_id": ip_by_id,
            "device_by_id": device_by_id,
            "cve_map": cve_map,
        },
    )


@router.get("/trends", response_class=HTMLResponse)
async def trends_page(request: Request, session: SessionDep) -> Response:
    """Zafiyet trend paneli — haftalık açık/yeni/çözülen + aging + MTTR (VI-3)."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    trend = await vuln_trend(session, weeks=8)
    lifecycle = await vuln_lifecycle_stats(session)
    # AI trend anlatısı butonu yalnız AI açıkken görünür (Dalga 3); graceful aksi halde.
    config = AIConfig.from_app_settings(await get_settings(session))
    return templates.TemplateResponse(
        request,
        "trends.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "trend": trend,
            "lifecycle": lifecycle,
            "ai_enabled": ai_available(config),
        },
    )


@router.get("/scans", response_class=HTMLResponse)
async def scans_page(request: Request, session: SessionDep) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    return await _scans_page(request, session, user, message=request.query_params.get("msg"))


async def _batch_name_map(session: AsyncSession) -> dict[int, str]:
    """{batch_id: ad} — tarama satırlarında 'tarama adı' kolonu için."""
    return {b.id: b.name for b in await list_batches(session)}


@router.get("/scans/table", response_class=HTMLResponse)
async def scans_table(request: Request, session: SessionDep) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    scans = await list_scans(session)
    return templates.TemplateResponse(
        request,
        "scans_table.html",
        {"scans": scans, "batch_names": await _batch_name_map(session), "user": user},
    )


def _eta_seconds(scan: Scan) -> int | None:
    """Tahmini kalan saniye (None = bilinmiyor).

    nmap fazında (ağ/vuln, ilerleme<%55) ETA, geçen-süreden lineer ekstrapolasyon YERİNE
    hedef-boyutu + mod tahmininden türetilir → STABİL ve azalan (eski 73dk→5dk yo-yo'su,
    nmap'in tüm süreyi tek %10 dilimine sıkıştırmasından kaynaklanıyordu). İşleme kuyruğunda
    (%55+, kısa) ya da diğer tarama türlerinde klasik lineer tahmin kullanılır.
    """
    if scan.started_at is None or not (0 < scan.progress < 100):
        return None
    started = scan.started_at if scan.started_at.tzinfo else scan.started_at.replace(tzinfo=UTC)
    elapsed = (datetime.now(UTC) - started).total_seconds()
    if elapsed <= 0:
        return None
    if scan.scan_type in (ScanType.network, ScanType.vuln) and scan.progress < 55:
        est = estimate_scan_seconds(
            scan.target, scan.mode, scan.ports, include_udp=scan.include_udp
        )
        return max(int(est - elapsed), 10)
    return int(elapsed * (100 - scan.progress) / scan.progress)


def _group_by_host(
    items: Sequence[Finding | Service],
    asset_by_id: dict[int, Asset],
    fallback_label: str,
) -> list[dict[str, object]]:
    """Bulgu/servisleri asset_id'ye göre cihaz (host) gruplarına ayırır.

    Dönen her grup: {label, ip, asset_id, items}. asset_id=None (henüz varlık
    yaratılmamış / kapsam dışı) öğeler fallback_label altında ve listenin sonunda
    toplanır; gerçek host'lar IP'ye göre sıralanır. Böylece canlı görünümde ve raporda
    hangi servis/CVE hangi cihaza ait olduğu net olur.
    """
    groups: dict[int | None, list[Finding | Service]] = defaultdict(list)
    for it in items:
        groups[it.asset_id].append(it)
    out: list[dict[str, object]] = []
    for aid, lst in groups.items():
        asset = asset_by_id.get(aid) if aid is not None else None
        out.append(
            {
                "label": asset.display_name if asset else fallback_label,
                "ip": asset.ip if asset else None,
                "asset_id": aid,
                "items": lst,
            }
        )
    out.sort(key=lambda g: (g["ip"] is None, str(g["ip"] or ""), str(g["label"])))
    return out


async def _scan_live_context(session: AsyncSession, scan: Scan) -> dict[str, object]:
    """Canlı takip için: ilerleme + faz + ETA + bulunan servisler/portlar + CVE bulguları."""
    findings = await list_findings_by_risk(session, scan_id=scan.id)
    services = await services_for_target(session, scan.target)
    cve_ids = [f.cve_id for f in findings if f.cve_id]
    cve_map = await cves_by_ids(session, cve_ids)
    exploit_map = await exploit_summary_for_cves(session, cve_ids)
    asset_by_id = {a.id: a for a in await list_assets(session)}
    # Bulunan hostlar (yanıt veren IP'ler) — rapora girmeden burada görünür. Web taramasında
    # iç envanteri DEĞİL, yalnız taranan URL'in host'unu (çözülen IP + şema/port) göster.
    if scan.scan_type == ScanType.web:
        live_hosts = web_scan_host_entries([scan])
    else:
        live_hosts = await hosts_in_scope(session, [scan.target])
    live_attempts = await list_exploit_attempts(session, [scan.id])
    # OSS çekirdek: sömürü ÇALIŞTIRMA eklentide; staged PoC paneli salt-bilgi (Çalıştır yok).
    exec_enabled = False
    exploitdb_staged = await annotate_exploitdb_runnable(
        session, exploitdb_staged_list(live_attempts), exec_enabled=exec_enabled
    )
    return {
        "scan": scan,
        "findings": findings,
        "services": services,
        "live_hosts": live_hosts,
        "cve_map": cve_map,
        "exploit_map": exploit_map,
        # Kullanılabilir exploit cephaneliği (#172): kaç CVE'de MSF modülü / Exploit-DB PoC MEVCUT
        # — yalnız BİLGİ, sömürmez. "arsenal_runs_exploit" False ise bant "DENENMEDİ" der (güvenli/
        # agresif CVE sömürmez); True (yalnız Sömürme modu) ise deneme durumu ayrı panelde.
        "exploit_arsenal": build_exploit_arsenal(cve_ids, exploit_map),
        "arsenal_runs_exploit": scan.scan_type == ScanType.vuln and does_exploitation(scan.mode),
        "eta_seconds": _eta_seconds(scan),
        # Cihaza (host) göre gruplanmış görünüm — "hangi servis/CVE hangi cihazın".
        "services_by_host": _group_by_host(services, asset_by_id, scan.target),
        "findings_by_host": _group_by_host(findings, asset_by_id, scan.target),
        # Exploit DENEME özeti — "exploit var" ≠ "denendi/sömürüldü".
        "exploit_overview": build_exploit_overview(
            live_attempts,
            # SR-1: sömürü yalnız Sömürme modunda beklenir (agresif CVE artık sömürmez).
            expected=scan.scan_type == ScanType.vuln and does_exploitation(scan.mode),
        ),
        # Exploit-DB staged PoC denemeleri (EXDB-C/D) — operatör sandbox'ta Çalıştır/Durdur.
        "exploitdb_staged": exploitdb_staged,
        "exploitdb_exec_enabled": exec_enabled,
    }


@router.get("/scans/{scan_id}/live", response_class=HTMLResponse)
async def scan_live_page(request: Request, session: SessionDep, scan_id: int) -> Response:
    """Bir taramanın canlı takip sayfası (HTMX ile periyodik yenilenir)."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    scan = await get_scan(session, scan_id)
    if scan is None:
        return RedirectResponse("/scans", status_code=status.HTTP_303_SEE_OTHER)
    context = await _scan_live_context(session, scan)
    context.update({"app_name": APP_NAME, "user": user})
    return templates.TemplateResponse(request, "scan_live.html", context)


@router.get("/scans/{scan_id}/live/panel", response_class=HTMLResponse)
async def scan_live_panel(request: Request, session: SessionDep, scan_id: int) -> Response:
    """Canlı takip parçası (HTMX hx-get her 2 sn). İlerleme + servisler + CVE'ler."""
    user = await _current_user(request, session)
    if user is None:
        return PlainTextResponse("", status_code=status.HTTP_401_UNAUTHORIZED)
    scan = await get_scan(session, scan_id)
    if scan is None:
        return PlainTextResponse("", status_code=status.HTTP_404_NOT_FOUND)
    context = await _scan_live_context(session, scan)
    return templates.TemplateResponse(request, "scan_live_panel.html", context)


@router.post("/scans/{scan_id}/stop")
async def stop_scan_web(request: Request, session: SessionDep, scan_id: int) -> Response:
    """Çalışan bir taramayı durdurur: Celery görevini revoke eder + 'iptal' işaretler."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role not in (Role.admin, Role.analyst):
        return RedirectResponse("/scans", status_code=status.HTTP_303_SEE_OTHER)
    scan = await get_scan(session, scan_id)
    if scan is not None and scan.status in (ScanStatus.pending, ScanStatus.running):
        if scan.task_id:
            # broker erişilemezse yine de 'iptal' işaretle (en iyi çaba).
            with contextlib.suppress(Exception):
                celery_app.control.revoke(scan.task_id, terminate=True, signal="SIGTERM")
        await set_scan_status(session, scan_id, ScanStatus.cancelled)
        await log_action(session, "scan_stop", user_id=user.id, target=scan.target)
    return RedirectResponse(f"/scans/{scan_id}/live", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/scans/{scan_id}/delete")
async def delete_scan_web(request: Request, session: SessionDep, scan_id: int) -> Response:
    """Bir taramayı (ve bulgularını) kalıcı olarak siler. Yalnız admin."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/scans", status_code=status.HTTP_303_SEE_OTHER)
    scan = await get_scan(session, scan_id)
    if scan is not None:
        # Çalışan taramayı önce iptal et (Celery görevi varsa revoke), sonra sil.
        if scan.status in (ScanStatus.pending, ScanStatus.running) and scan.task_id:
            with contextlib.suppress(Exception):
                celery_app.control.revoke(scan.task_id, terminate=True, signal="SIGTERM")
        target = scan.target
        await delete_scan(session, scan_id)
        await log_action(session, "scan_delete", user_id=user.id, target=target)
        msg = f"Tarama #{scan_id} silindi."
    else:
        msg = "Tarama bulunamadı."
    return RedirectResponse(f"/scans?msg={quote(msg)}", status_code=status.HTTP_303_SEE_OTHER)


# Tekrar taranabilir (teknik) tarama türleri — kimlik/dosya gerektiren denetimler hariç.
_RESCANNABLE_TYPES = {ScanType.network, ScanType.ping, ScanType.vuln, ScanType.web}


@router.post("/scans/{scan_id}/rescan")
async def rescan_web(request: Request, session: SessionDep, scan_id: int) -> Response:
    """Var olan bir taramayı aynı tür/mod/hedef/portla yeniden başlatır (yeni tarama satırı).

    Yalnız teknik türler (ağ/ping/CVE/web) tekrar taranabilir — kimlikli denetimler kimlik,
    SCA dosya gerektirdiğinden butonları gösterilmez. Agresif tekrar tarama, başlatma ile
    aynı kapıdan geçer (admin + global kill-switch).
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role not in (Role.admin, Role.analyst):
        return RedirectResponse("/scans", status_code=status.HTTP_303_SEE_OTHER)
    scan = await get_scan(session, scan_id)
    if scan is None or scan.scan_type not in _RESCANNABLE_TYPES:
        return RedirectResponse(
            f"/scans?msg={quote('Bu tarama tekrar taranamaz.')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    # Agresif tekrar tarama: başlatmadaki kill-switch + admin kapısıyla tutarlı (#1).
    if is_aggressive(scan.mode):
        if user.role != Role.admin:
            return RedirectResponse(
                f"/scans?msg={quote('Agresif tarama yalnız admin ile tekrarlanabilir.')}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        try:
            ensure_mode_allowed(scan.mode, allow_aggressive=settings.allow_aggressive_scans)
        except AggressiveScanNotAllowed as exc:
            return RedirectResponse(
                f"/scans?msg={quote(str(exc))}", status_code=status.HTTP_303_SEE_OTHER
            )

    names = await _batch_name_map(session)
    base_name = (names.get(scan.batch_id) if scan.batch_id is not None else None) or scan.target
    batch = await create_batch(session, f"{base_name} (tekrar)", scan.mode, None, user.id)
    # Hedef alanı birden çok CIDR/IP'yi boşlukla birleştirebilir (sihirbaz tek taramada
    # birleştirir) → tekrar tararken listeye geri böl ki her blok scope'tan ayrı geçsin.
    target_list = scan.target.split() or [scan.target]

    if scan.scan_type == ScanType.ping:
        await dispatch_ping_scan(session, target_list, user.id, label="tekrar", batch_id=batch.id)
    elif scan.scan_type == ScanType.web:
        # Web hedefi tek URL'dir; her URL kendi taraması olarak yeniden kuyruğa alınır.
        # Orijinal taramanın dış-hedef izni korunur (yoksa tekrar tarama kapsam dışı düşerdi).
        for tgt in target_list:
            new_scan = await create_scan(
                session,
                ScanType.web,
                tgt,
                created_by=user.id,
                batch_id=batch.id,
                mode=scan.mode,
                allow_external=scan.allow_external,
                dir_scan=scan.dir_scan,
                wordlist_id=scan.wordlist_id,
            )
            action = "aggressive_scan_start" if is_aggressive(scan.mode) else "scan_start"
            await log_action(session, action, user_id=user.id, target=tgt)
            web_scan_task.delay(new_scan.id, tgt, str(scan.mode))
    else:  # network / vuln
        await dispatch_target_list_scan(
            session,
            target_list,
            scan.mode,
            user.id,
            label="tekrar",
            batch_id=batch.id,
            scan_type=scan.scan_type,
            ports=scan.ports,
        )
    await log_action(session, "scan_rescan", user_id=user.id, target=scan.target)
    return RedirectResponse(
        f"/scans?msg={quote(f'#{scan_id} taraması tekrar başlatıldı.')}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# Hızlı tarama mod anahtarları (sihirbaz 5 modu + web). Sihirbaz ve hızlı tarama AYNI
# backend'i (resolve_wizard_mode) paylaşır (FAZ VIII-4 tasarım ilkesi).
# Web modları WIZARD_MODES'a EKLENMEZ (resolve_wizard_mode/ağ dispatch'i ScanType.web'i yanlış
# yönlendirir) — özel web dalında (start handler) işlenir. SR-3b: Web CVE + Web Sömürü tierları.
_WEB_MODE_KEYS = {"web", "web_aggressive"}
_QUICK_MODE_KEYS = set(WIZARD_MODES) | _WEB_MODE_KEYS


def _effective_quick_mode(mode: str, scan_type: str) -> str:
    """Hızlı tarama form alanlarını tek bir mod anahtarına indirger (FAZ VIII-4).

    Yeni form tek ``mode`` alanı gönderir (network/ping/cve_safe/cve_aggressive/
    credentialed/web). Eski çağrılar (ayrı ``scan_type`` + ``mode``=safe/aggressive)
    geriye-uyumlu eşlenir: web→web, ping→ping, vuln→cve_safe|cve_aggressive,
    network→network|cve_aggressive (yoğunluğa göre).
    """
    key = (mode or "").strip()
    if key in _QUICK_MODE_KEYS:
        return key
    aggressive = key.lower() == "aggressive"
    st = (scan_type or "").strip().lower()
    if st == "web":
        # SR-3b: eski "agresif web" (scan_type=web + mode=aggressive) → yeni "Web CVE" modu
        # (web_aggressive). Sade "web" pasiftir. Geriye-uyumlu: legacy DAST çağrıları korunur.
        return "web_aggressive" if aggressive else "web"
    if st == "ping":
        return "ping"
    if st == "vuln":
        return "cve_aggressive" if aggressive else "cve_safe"
    return "cve_aggressive" if aggressive else "network"


def _split_url_targets(targets: list[str]) -> tuple[list[str], list[str]]:
    """Hedef listesini (host/IP/CIDR, URL) olarak ayırır — URL = ``://`` içeren girdi (SR-3c).

    Ağ/CVE/sömürü modlarında hedef alanına URL girilince, URL'ler ayrılıp web denetimine
    yönlendirilir (nmap'e GİTMEZ); host/IP/CIDR'ler ağ taramasına gider. İkisi aynı taramada
    (batch) ve aynı yoğunlukta koşar — patron isteği "URL+IP birlikte → ikisini de tara".
    """
    urls = [t for t in targets if "://" in t]
    hosts = [t for t in targets if "://" not in t]
    return hosts, urls


def _url_host(url: str) -> str | None:
    """URL'den host (hostname/IP) çıkarır; çözümlenemezse None."""
    try:
        return urlparse(url).hostname or None
    except ValueError:
        return None


async def _resolve_url_hosts(urls: list[str]) -> list[str]:
    """URL'lerin host'larını IP'ye çözer (normal ağ taramasına EKLEMEK için).

    Patron isteği: normal (ağ/CVE) taramada bir URL hedefi verildiğinde URL'nin host'u da
    IP'ye çözülüp port/CVE taranır (web denetimine EK olarak). Host zaten IP ise doğrudan
    kullanılır; hostname ise DNS ile çözülür. Çözülen IP yine scope guard'dan geçer
    (``dispatch_target_list_scan`` her hedefi ``validate_target`` ile doğrular). Çözülemeyen
    URL atlanır (web taraması kendi çözümünü yapar). Sıra korunur, tekilleştirilir.
    """
    out: list[str] = []
    seen: set[str] = set()
    for url in urls:
        host = _url_host(url)
        if not host:
            continue
        try:
            ipaddress.ip_address(host)
            ip = host
        except ValueError:
            try:
                ip = await asyncio.to_thread(socket.gethostbyname, host)
            except OSError:
                continue
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


@router.post("/scans/start")
async def start_scan_web(
    request: Request,
    session: SessionDep,
    targets: Annotated[str, Form()] = "",
    zone_ids: Annotated[list[int] | None, Form()] = None,
    asset_ids: Annotated[list[int] | None, Form()] = None,
    scan_type: Annotated[str, Form()] = "network",
    mode: Annotated[str, Form()] = "safe",
    ports: Annotated[str, Form()] = "top",
    ports_custom: Annotated[str, Form()] = "",
    name: Annotated[str, Form()] = "",
    aggressive_ack: Annotated[str, Form()] = "",
    credential_zone_ids: Annotated[list[int] | None, Form()] = None,
    credential_ids: Annotated[list[int] | None, Form()] = None,
    categories: Annotated[list[str] | None, Form()] = None,
    sched_mode: Annotated[str, Form()] = "run_now",
    sched_period: Annotated[str, Form()] = "daily",
    sched_interval_minutes: Annotated[int, Form()] = 1440,
    sched_start_at: Annotated[str, Form()] = "",
    assigned_user_id: Annotated[int | None, Form()] = None,
    notify_on_complete: Annotated[str, Form()] = "",
    attach_report: Annotated[str, Form()] = "",
    web_external: Annotated[str, Form()] = "",
    web_dirscan: Annotated[str, Form()] = "",
    web_wordlist_id: Annotated[int | None, Form()] = None,
    udp_scan: Annotated[str, Form()] = "",
) -> Response:
    """Hızlı tarama: bir ya da çok hedef (virgül/yeni-satır) — ağ / zafiyet / web.

    Opsiyonel kimlik (kimlik bölgesi + tekil) seçilirse OS-öncelikli (SSH/WinRM) kimlikli
    denetim yapılır. Agresif mod, global env kilidi yerine admin + açık "kabul ediyorum"
    onayıyla (aggressive_ack) çalışır. Port seçimi: genel (top-1000) / tüm (-p-) / elle
    liste. İsim verilmezse "Hızlı tarama N" otomatik numaralanır → isimli ScanBatch
    (raporda tek satır).
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()

    if user.role not in (Role.admin, Role.analyst):
        return await _scans_page(
            request,
            session,
            user,
            error="Tarama başlatma yetkiniz yok.",
            status_code=status.HTTP_403_FORBIDDEN,
        )

    # Hedefler: yazılan (textarea) ∪ envanterden seçilen (IP zone CIDR'leri + tekil varlık IP'leri).
    # Sihirbaz (alias) yalnız zone/asset gönderir; hızlı tarama yazılan hedef gönderir; ikisi de
    # olabilir. Sırayı koruyarak tekilleştirilir. (SCAN-MERGE: tek 'Tarama' paneli ortak backend.)
    inv_targets: list[str] = []
    for zid in zone_ids or []:
        zone = await get_zone(session, zid)
        if zone is not None:
            inv_targets.extend(zone.cidrs)
    for aid in asset_ids or []:
        asset = await get_asset(session, aid)
        if asset is not None:
            # URL varlığı → URL hedef olarak akar (web denetimi + host'u çözülerek ağ taraması);
            # IP varlığı → IP. (URL varlığında ip=NULL.)
            tgt = asset.url or asset.ip
            if tgt:
                inv_targets.append(tgt)
    target_list = list(dict.fromkeys(parse_cidr_input(targets) + inv_targets))
    if not target_list:
        return await _scans_page(
            request,
            session,
            user,
            error="En az bir hedef girin (yazın ya da envanterden seçin).",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Ürün/CVE kategori filtresi (boş = tümü). Yalnızca bilinen kategoriler kabul edilir.
    cats = [c for c in (categories or []) if c in CATEGORIES]

    # İsim verilmezse otomatik "Hızlı tarama N".
    scan_name = name.strip() or await next_quick_scan_name(session)

    # Atama (yalnız admin): tarama bitince atanan kullanıcıya e-posta (ops. PDF rapor).
    assign_uid, notify_done, attach_pdf = _resolve_assignment(
        user, assigned_user_id, notify_on_complete, attach_report
    )

    # --- Mod çözümle (FAZ VIII-4): hızlı tarama da sihirbazla AYNI 5 modu + web kullanır.
    # Tek 'mode' alanı; eski scan_type+yoğunluk çağrıları geriye-uyumlu eşlenir. ---
    effective = _effective_quick_mode(mode, scan_type)

    # --- Web taraması: hedefler URL. Pasif derinlik her zaman; AKTİF DAST yalnız agresif
    # (ack) + admin (VI-2). Yeni 'web' modunda 'kabul ediyorum' DAST'ı açar. ---
    if effective in _WEB_MODE_KEYS:
        # SR-3b: web de güvenli/CVE(agresif)/sömürü merdivenine sahip.
        # - web           → YALNIZ güvenli (pasif: headers/TLS/cookie/info + ops. dirscan/dış).
        #   DAST bu moddan KALDIRILDI (artık "Web CVE" modunda) → onay/uyarı İSTEMEZ.
        # - web_aggressive → "Web CVE": aktif DAST + web-yığını CVE tespiti + exploit göster.
        web_mode = ScanMode.aggressive if effective == "web_aggressive" else ScanMode.safe
        if is_aggressive(web_mode):
            if user.role != Role.admin:
                return await _scans_page(
                    request,
                    session,
                    user,
                    error="Agresif/sömürü web taraması yalnızca admin rolü ile başlatılabilir.",
                    status_code=status.HTTP_403_FORBIDDEN,
                )
            if not aggressive_ack:
                return await _scans_page(
                    request,
                    session,
                    user,
                    error="Müdahaleci web taraması için 'kabul ediyorum' onayını işaretleyin.",
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            # Global kill-switch (zone/API ile tutarlı): agresif kapalıysa onay olsa bile reddet.
            try:
                ensure_mode_allowed(web_mode, allow_aggressive=settings.allow_aggressive_scans)
            except AggressiveScanNotAllowed as exc:
                return await _scans_page(
                    request, session, user, error=str(exc), status_code=status.HTTP_403_FORBIDDEN
                )
        # Dış (public internet) web hedefi: iç-ağ scope guard'ı yerine yalnız-public guard
        # uygulanır → admin + açık onay (kutucuk) şart. İşaretliyse her hedef için scan'e
        # allow_external=True yazılır; web görevi loopback/iç/link-local/metadata'yı yine reddeder.
        want_external = bool(web_external)
        if want_external and user.role != Role.admin:
            return await _scans_page(
                request,
                session,
                user,
                error="Dış web hedefi taraması yalnızca admin rolü ile başlatılabilir.",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        batch = await create_batch(
            session,
            scan_name,
            web_mode,
            None,
            user.id,
            assigned_user_id=assign_uid,
            notify_on_complete=notify_done,
            attach_report=attach_pdf,
        )
        # Dizin taraması açıksa seçilen özel kelime listesi (yoksa yerleşik liste kullanılır).
        want_dirscan = bool(web_dirscan)
        dir_wordlist_id = web_wordlist_id if want_dirscan else None
        for tgt in target_list:
            scan = await create_scan(
                session,
                ScanType.web,
                tgt,
                created_by=user.id,
                batch_id=batch.id,
                mode=web_mode,
                allow_external=want_external,
                dir_scan=want_dirscan,
                wordlist_id=dir_wordlist_id,
            )
            action = "aggressive_scan_start" if is_aggressive(web_mode) else "scan_start"
            await log_action(session, action, user_id=user.id, target=tgt)
            web_scan_task.delay(scan.id, tgt, str(web_mode))
        msg = f"'{batch.name}': {len(target_list)} web taraması başlatıldı."
        return RedirectResponse(f"/scans?msg={quote(msg)}", status_code=status.HTTP_303_SEE_OTHER)

    # --- 5 IP modu: sihirbazla ORTAK backend (resolve_wizard_mode) ---
    spec = resolve_wizard_mode(effective)

    # --- Opsiyonel kimlikleri topla (kimlik bölgeleri + tekil kimlikler) ---
    creds: list[Credential] = []
    seen: set[int] = set()
    for czid in credential_zone_ids or []:
        cz = await get_credential_zone(session, czid)
        if cz is not None:
            for cred in await credentials_in_zone(session, cz):
                if cred.id not in seen:
                    seen.add(cred.id)
                    creds.append(cred)
    for cid in credential_ids or []:
        single = await get_credential(session, cid)
        if single is not None and single.id not in seen:
            seen.add(single.id)
            creds.append(single)

    # --- Mod kapıları (admin / agresif onayı) — NESSUS modeli: kimlik ayrı mod değil ---
    if spec.admin_only and user.role != Role.admin:
        return await _scans_page(
            request,
            session,
            user,
            error="Bu mod (agresif/sömürme) yalnızca admin rolü ile başlatılabilir.",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    if spec.needs_ack and not aggressive_ack:
        return await _scans_page(
            request,
            session,
            user,
            error="Bu müdahaleci mod için 'kabul ediyorum' onayını işaretleyin.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    # Global kill-switch (zone/API ile tutarlı): agresif mod kapalıysa onay olsa bile reddet.
    try:
        ensure_mode_allowed(spec.nmap_mode, allow_aggressive=settings.allow_aggressive_scans)
    except AggressiveScanNotAllowed as exc:
        return await _scans_page(
            request, session, user, error=str(exc), status_code=status.HTTP_403_FORBIDDEN
        )
    # Kimlik (opsiyonel add-on) yalnız admin tarafından kullanılabilir.
    if creds and user.role != Role.admin:
        return await _scans_page(
            request,
            session,
            user,
            error="Kimlikli (authenticated) tarama yalnızca admin rolü ile yapılabilir.",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    # Port seçimi yalnız Ağ taramasında; diğer modlar nmap varsayılanı/keşif kullanır.
    port_spec = (
        sanitize_ports(ports_custom if ports == "custom" else ports) if spec.needs_ports else None
    )
    # UDP servis taraması (#143) yalnız port taraması yapan modlarda (ağ / zafiyet) anlamlı —
    # ping/web modlarında yok sayılır.
    want_udp = bool(udp_scan) and (spec.needs_ports or spec.scan_type == ScanType.vuln)
    # Priv-esc DENEMESİ yalnız ONAY GEREKTİREN (agresif) modda + ack doğrulanmışken açılır
    # (#5): ham aggressive_ack'e değil, spec.needs_ack ile birlikte değerlendirilir → non-agresif
    # kimlikli taramada ack alanı gönderilse bile gerçek priv-esc denemesi tetiklenmez.
    attempt_privesc = bool(spec.needs_ack and aggressive_ack)

    # --- Zamanlama seçildiyse: hemen başlatma, ScheduledScan şablonu oluştur (yalnız envanter
    # hedefi — şablonda yazılan-hedef kolonu yok). Şablon scan_type + nmap modu + (varsa) kimlik
    # + kategorileri taşır. (SCAN-MERGE: sihirbazın zamanlama yeteneği birleşik panele taşındı.) ---
    if sched_mode == "schedule":
        if not (zone_ids or asset_ids):
            return await _scans_page(
                request,
                session,
                user,
                error="Zamanlı tarama için envanterden hedef seçin "
                "(yazılan hedefler zamanlanamaz).",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        sched_name = name.strip() or "Zamanlı tarama"
        await create_schedule(
            session,
            spec.scan_type,
            period=sched_period,
            interval_minutes=max(1, sched_interval_minutes),
            start_at=_parse_datetime_local(sched_start_at),
            name=sched_name,
            zone_ids=zone_ids or [],
            asset_ids=asset_ids or [],
            credential_zone_ids=credential_zone_ids or [],
            credential_ids=credential_ids or [],
            mode=spec.nmap_mode,
            categories=cats,
            created_by=user.id,
        )
        await log_action(
            session, "schedule_create", user_id=user.id, target=f"{sched_name} [{sched_period}]"
        )
        msg = f"'{sched_name}' zamanlandı ({sched_period}). Zamanlama sayfasında görünür."
        return RedirectResponse(f"/scans?msg={quote(msg)}", status_code=status.HTTP_303_SEE_OTHER)

    # --- Ping taraması (host keşfi): yalnız ayakta hostları bulur (kimlik yok sayılır) ---
    if spec.scan_type == ScanType.ping:
        batch = await create_batch(
            session,
            scan_name,
            ScanMode.safe,
            None,
            user.id,
            assigned_user_id=assign_uid,
            notify_on_complete=notify_done,
            attach_report=attach_pdf,
        )
        ping_res = await dispatch_ping_scan(
            session, target_list, user.id, label="hızlı", batch_id=batch.id
        )
        if not ping_res.scanned:
            await delete_batch(session, batch.id)
            return await _scans_page(
                request,
                session,
                user,
                error="Hiçbir hedef başlatılamadı; tümü yetkili kapsam dışı: "
                + ", ".join(ping_res.skipped),
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        msg = f"'{batch.name}': {len(ping_res.scanned)} hedef için ping taraması başlatıldı."
        if ping_res.skipped:
            msg += f" {len(ping_res.skipped)} kapsam dışı atlandı."
        return RedirectResponse(f"/scans?msg={quote(msg)}", status_code=status.HTTP_303_SEE_OTHER)

    # --- Ağ / Güvenli CVE / Agresif CVE / Sömürme + (ops.) KİMLİK add-on + URL→web (SR-3c) ---
    # SR-3c: hedef alanına URL ('://') girilirse host/IP'ler ağ taramasına, URL'ler AYNI batch'te
    # web denetimine (ağ moduyla aynı yoğunluk: güvenli→pasif+CVE, agresif→Web CVE, sömürme→Web
    # Sömürü) gider. Web hedefi iç-kapsam (allow_external=False); dış URL için ayrı Web modu var.
    host_targets, url_targets = _split_url_targets(target_list)
    want_web_urls = bool(url_targets) and spec.scan_type in (ScanType.vuln, ScanType.network)
    # Patron isteği: normal (ağ/CVE) taramada URL hedefinin HOST'u da çözülüp port/CVE taranır
    # (web denetimine EK olarak). URL host'u IP'ye çözülür → host_targets'a eklenir → scope+nmap.
    # (Web modunda bu yapılmaz; orada zaten her hedef doğrudan web olarak taranır.)
    if want_web_urls:
        for resolved_ip in await _resolve_url_hosts(url_targets):
            if resolved_ip not in host_targets:
                host_targets.append(resolved_ip)

    batch = await create_batch(
        session,
        scan_name,
        spec.nmap_mode,
        cats,
        user.id,
        assigned_user_id=assign_uid,
        notify_on_complete=notify_done,
        attach_report=attach_pdf,
    )
    result = None
    # NESSUS modeli: kimlik seçildiyse AYNI taramaya içeriden kimlikli denetim (CIS + priv-esc)
    # eklenir — ayrı tarama satırı AÇILMAZ (kullanıcı tek tarama görür).
    cz_res = None
    if host_targets:
        result = await dispatch_target_list_scan(
            session,
            host_targets,
            spec.nmap_mode,
            user.id,
            label="hızlı",
            categories=cats,
            batch_id=batch.id,
            scan_type=spec.scan_type,
            ports=port_spec,
            include_udp=want_udp,
        )
        if creds and result.scans:
            cz_res = await audit_credentialed_to_scan(
                session,
                result.scans[0].id,
                host_targets,
                creds,
                attempt_privesc=attempt_privesc,
                user_id=user.id,
            )
    # SR-3c: URL hedeflerine web denetimi (aynı batch, aynı yoğunluk; iç-kapsam zorunlu).
    web_urls_started: list[str] = []
    if want_web_urls:
        for url in url_targets:
            wscan = await create_scan(
                session,
                ScanType.web,
                url,
                created_by=user.id,
                batch_id=batch.id,
                mode=spec.nmap_mode,
                allow_external=False,
            )
            action = "aggressive_scan_start" if is_aggressive(spec.nmap_mode) else "scan_start"
            await log_action(session, action, user_id=user.id, target=url)
            web_scan_task.delay(wscan.id, url, str(spec.nmap_mode))
            web_urls_started.append(url)

    net_scanned = list(result.scanned) if result is not None else []
    if not net_scanned and not web_urls_started and cz_res is None:
        await delete_batch(session, batch.id)
        skipped = list(result.skipped) if result is not None else []
        return await _scans_page(
            request,
            session,
            user,
            error="Hiçbir hedef başlatılamadı; tümü yetkili kapsam dışı: " + ", ".join(skipped),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    kind = "zafiyet" if spec.scan_type == ScanType.vuln else "ağ"
    msg = f"'{batch.name}': {len(net_scanned)} hedef için {kind} taraması başlatıldı."
    if web_urls_started:
        msg += f" {len(web_urls_started)} URL için web denetimi eklendi."
    if cz_res is not None:
        msg += f" Kimlikli denetim: {len(cz_res.matched)} host'ta kimlik tuttu."
    if result is not None and result.skipped:
        msg += f" {len(result.skipped)} kapsam dışı atlandı."
    return RedirectResponse(f"/scans?msg={quote(msg)}", status_code=status.HTTP_303_SEE_OTHER)


_SCA_MAX_BYTES = 1_000_000  # 1 MB manifest sınırı (kötüye kullanım koruması)


def _detect_sca_ecosystem(filename: str) -> str | None:
    """Yüklenen dosya adından ekosistemi sezer (package*.json→npm, requirements/*.txt→PyPI)."""
    name = filename.lower()
    if name.endswith(".json") and "package" in name:
        return "npm"
    if "requirements" in name or name.endswith(".txt"):
        return "PyPI"
    return None


@router.post("/scans/sca")
async def start_sca_web(
    request: Request,
    session: SessionDep,
    content: Annotated[str, Form()] = "",
    ecosystem: Annotated[str, Form()] = "PyPI",
    manifest_file: Annotated[UploadFile | None, File()] = None,
) -> Response:
    """Bağımlılık manifesti (requirements.txt / package.json) → OSV zafiyet taraması.

    İçerik ya yapıştırılır (``content``) ya da dosya yüklenir (``manifest_file``). Dosya
    verilirse içeriği okunur ve ekosistem dosya adından otomatik sezilir (1 MB sınır).
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role not in (Role.admin, Role.analyst):
        return await _scans_page(
            request,
            session,
            user,
            error="Tarama başlatma yetkiniz yok.",
            status_code=status.HTTP_403_FORBIDDEN,
        )

    text = content
    eco = ecosystem
    if manifest_file is not None and manifest_file.filename:
        raw = await manifest_file.read(_SCA_MAX_BYTES + 1)
        if len(raw) > _SCA_MAX_BYTES:
            return await _scans_page(
                request,
                session,
                user,
                error="Manifest dosyası çok büyük (en fazla 1 MB).",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return await _scans_page(
                request,
                session,
                user,
                error="Dosya UTF-8 metin değil — requirements.txt / package.json yükleyin.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        detected = _detect_sca_ecosystem(manifest_file.filename)
        if detected:
            eco = detected

    if not text.strip():
        return await _scans_page(
            request,
            session,
            user,
            error="Bağımlılık içeriği boş — yapıştırın ya da dosya yükleyin.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    scan = await create_scan(session, ScanType.sca, f"{eco} manifest", created_by=user.id)
    await log_action(session, "sca_start", user_id=user.id, target=eco)
    sca_scan_task.delay(scan.id, eco, text)
    return RedirectResponse("/scans", status_code=status.HTTP_303_SEE_OTHER)


# DB denetim motoru → (gerekli kimlik tipi, gösterim etiketi).
_DB_ENGINES: dict[str, tuple[CredentialType, str]] = {
    "postgres": (CredentialType.postgres, "PostgreSQL"),
    "mysql": (CredentialType.mysql, "MySQL"),
    "mssql": (CredentialType.mssql, "MSSQL"),
    "oracle": (CredentialType.oracle, "Oracle"),
}


async def _audit_hosts(
    session: AsyncSession,
    host: str,
    zone_ids: list[int] | None,
    asset_ids: list[int] | None,
) -> list[str]:
    """Denetim hedef listesi: tekil host + IP zone'lardaki ayakta varlıklar + seçilen varlıklar.

    Tekil ``host`` (elle yazılan) ilk sırada gelir; ardından seçilen IP zone'lara düşen
    AYAKTA envanter varlıkları (X-3 kararı: /24 → 254 host'a AÇILMAZ, yalnız kayıtlı/ayakta
    varlıklar) ve açıkça seçilen tekil IP varlıkları eklenir. Sıra korunarak tekilleştirilir.
    Kapsam-koruması her host için per-host dispatch içinde yapılır.
    """
    hosts: list[str] = []
    cleaned = host.strip()
    if cleaned:
        hosts.append(cleaned)
    hosts.extend(await assets_in_zones(session, zone_ids or []))
    for aid in asset_ids or []:
        asset = await get_asset(session, aid)
        if asset is not None:
            tgt = asset.url or asset.ip  # URL varlığı → URL hedef; IP varlığı → IP
            if tgt:
                hosts.append(tgt)
    return list(dict.fromkeys(hosts))  # sırayı koruyarak tekilleştir


async def _audit_credentials(
    session: AsyncSession, credential_zone_ids: list[int] | None
) -> list[Credential]:
    """Seçilen kimlik bölgelerindeki kimlikleri toplar (sıra korunur, id tekrarı elenir) (X-3)."""
    creds: list[Credential] = []
    seen: set[int] = set()
    for czid in credential_zone_ids or []:
        cz = await get_credential_zone(session, czid)
        if cz is None:
            continue
        for cred in await credentials_in_zone(session, cz):
            if cred.id not in seen:
                seen.add(cred.id)
                creds.append(cred)
    return creds


@router.post("/scans/db")
async def start_db_audit_web(
    request: Request,
    session: SessionDep,
    host: Annotated[str, Form()] = "",
    credential_id: Annotated[int | None, Form()] = None,
    engine: Annotated[str, Form()] = "postgres",
    port: Annotated[int, Form()] = 5432,
    database: Annotated[str, Form()] = "",
    zone_ids: Annotated[list[int] | None, Form()] = None,
    asset_ids: Annotated[list[int] | None, Form()] = None,
    credential_zone_ids: Annotated[list[int] | None, Form()] = None,
) -> Response:
    """DB salt-okunur kimlikli config/uyum denetimi (VII-2a / IX-4). Yalnız admin.

    Tekil host + kimlik klasik akışı korunur; ek olarak IP zone (envanterdeki ayakta
    varlıklar) + kimlik bölgesi seçilebilir → her host'a tipe uygun DB kimliğiyle denetim (X-3).
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return await _scans_page(
            request,
            session,
            user,
            error="Kimlikli DB denetimi yalnızca admin rolü ile yapılabilir.",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    if engine not in _DB_ENGINES:
        engine = "postgres"
    required_type, label = _DB_ENGINES[engine]
    # Tipe uygun kimlik: tekil seçim öncelikli, yoksa kimlik bölgelerinden ilk eşleşen.
    cred = await get_credential(session, credential_id) if credential_id is not None else None
    if cred is not None and cred.cred_type != required_type:
        cred = None
    if cred is None:
        zone_creds = await _audit_credentials(session, credential_zone_ids)
        cred = first_cred_of_type(zone_creds, required_type)
    if cred is None:
        return await _scans_page(
            request,
            session,
            user,
            error=f"Geçerli bir {label} kimliği seçin (kimlik tipi '{required_type.value}').",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    hosts = await _audit_hosts(session, host, zone_ids, asset_ids)
    if not hosts:
        return await _scans_page(
            request,
            session,
            user,
            error="En az bir hedef girin (tekil host ya da IP zone/varlık).",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    await dispatch_db_audit_hosts(
        session, hosts, port, cred, database.strip(), user.id, engine=engine
    )
    msg = quote(f"{label} denetimi tamamlandı: {len(hosts)} host")
    return RedirectResponse(f"/scans?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


async def _resolve_audit_credential(
    session: AsyncSession,
    credential_id: int | None,
    credential_zone_ids: list[int] | None,
    cred_type: CredentialType,
) -> tuple[Credential | None, bool]:
    """SNMP/SMB/LDAP/Telnet için tipe uygun kimliği çözer (opsiyonel) (X-3).

    Döner ``(credential, ok)``. Tekil seçim öncelikli; yoksa kimlik bölgelerinden ilk eşleşen
    tip alınır (kimlik OPSİYONELDİR → bulunamazsa anonim denetim). Tekil seçim YANLIŞ tipteyse
    ``ok=False`` döner (kullanıcı hata almalı). Hiç seçim yoksa ``(None, True)`` (anonim).
    """
    if credential_id is not None:
        cred = await get_credential(session, credential_id)
        if cred is None or cred.cred_type != cred_type:
            return None, False
        return cred, True
    zone_creds = await _audit_credentials(session, credential_zone_ids)
    return first_cred_of_type(zone_creds, cred_type), True


@router.post("/scans/snmp")
async def start_snmp_audit_web(
    request: Request,
    session: SessionDep,
    host: Annotated[str, Form()] = "",
    port: Annotated[int, Form()] = 161,
    zone_ids: Annotated[list[int] | None, Form()] = None,
    asset_ids: Annotated[list[int] | None, Form()] = None,
) -> Response:
    """SNMP salt-okunur envanter + zayıf-topluluk denetimi (VII-2b). Yalnız admin.

    Kimlik/community gerektirmez: dahili community wordlist'i (public/private…) v1 VE
    v2c ile denenir (versiyon seçilmez). Tekil host + opsiyonel IP zone/varlık
    (envanterdeki ayakta) hedeflenir; her host scope guard'dan geçer (X-3).
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return await _scans_page(
            request,
            session,
            user,
            error="SNMP denetimi yalnızca admin rolü ile yapılabilir.",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    hosts = await _audit_hosts(session, host, zone_ids, asset_ids)
    if not hosts:
        return await _scans_page(
            request,
            session,
            user,
            error="En az bir hedef girin (tekil host ya da IP zone/varlık).",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    await dispatch_snmp_audit_hosts(
        session,
        hosts,
        port,
        credential=None,
        user_id=user.id,
        extra_communities=None,
    )
    msg = quote(f"SNMP denetimi tamamlandı: {len(hosts)} host")
    return RedirectResponse(f"/scans?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/scans/smb")
async def start_smb_audit_web(
    request: Request,
    session: SessionDep,
    host: Annotated[str, Form()] = "",
    port: Annotated[int, Form()] = 445,
    credential_id: Annotated[int | None, Form()] = None,
    zone_ids: Annotated[list[int] | None, Form()] = None,
    asset_ids: Annotated[list[int] | None, Form()] = None,
    credential_zone_ids: Annotated[list[int] | None, Form()] = None,
    smb_wordlist_id: Annotated[int | None, Form()] = None,
) -> Response:
    """SMB salt-okunur paylaşım/güvenlik denetimi (IX-7a). Yalnız admin.

    Kimlik OPSİYONELDİR: seçilmezse anonim denetim yapılır (null/guest/imza/SMBv1 yine
    bulunur); seçilirse 'smb' tipi olmalıdır. Tekil host + opsiyonel IP zone/varlık
    (envanterdeki ayakta) hedeflenir; her host scope guard'dan geçer (X-3).
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return await _scans_page(
            request,
            session,
            user,
            error="Kimlikli SMB denetimi yalnızca admin rolü ile yapılabilir.",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    credential, ok = await _resolve_audit_credential(
        session, credential_id, credential_zone_ids, CredentialType.smb
    )
    if not ok:
        return await _scans_page(
            request,
            session,
            user,
            error="Geçerli bir SMB kimliği seçin (kimlik tipi 'smb').",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    hosts = await _audit_hosts(session, host, zone_ids, asset_ids)
    if not hosts:
        return await _scans_page(
            request,
            session,
            user,
            error="En az bir hedef girin (tekil host ya da IP zone/varlık).",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    # Paylaşım adı kelime listesi (smb_share türü) seçildiyse gizli-paylaşım keşfi de yapılır.
    share_names: list[str] | None = None
    if smb_wordlist_id is not None:
        wl = await get_wordlist(session, smb_wordlist_id)
        if wl is not None and wl.entries:
            share_names = list(wl.entries)
    await dispatch_smb_audit_hosts(
        session, hosts, port, credential=credential, user_id=user.id, share_names=share_names
    )
    msg = quote(f"SMB denetimi tamamlandı: {len(hosts)} host")
    return RedirectResponse(f"/scans?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/scans/ldap")
async def start_ldap_audit_web(
    request: Request,
    session: SessionDep,
    host: Annotated[str, Form()] = "",
    port: Annotated[int, Form()] = 389,
    credential_id: Annotated[int | None, Form()] = None,
    zone_ids: Annotated[list[int] | None, Form()] = None,
    asset_ids: Annotated[list[int] | None, Form()] = None,
    credential_zone_ids: Annotated[list[int] | None, Form()] = None,
) -> Response:
    """LDAP/AD salt-okunur güvenlik denetimi (IX-7b). Yalnız admin.

    Kimlik OPSİYONELDİR: seçilmezse anonim denetim yapılır (anonim bind/okuma + şifreleme
    yine bulunur); seçilirse 'ldap' tipi olmalıdır. Tekil host + opsiyonel IP zone/varlık
    (envanterdeki ayakta) hedeflenir; her host scope guard'dan geçer (X-3).
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return await _scans_page(
            request,
            session,
            user,
            error="Kimlikli LDAP denetimi yalnızca admin rolü ile yapılabilir.",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    credential, ok = await _resolve_audit_credential(
        session, credential_id, credential_zone_ids, CredentialType.ldap
    )
    if not ok:
        return await _scans_page(
            request,
            session,
            user,
            error="Geçerli bir LDAP kimliği seçin (kimlik tipi 'ldap').",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    hosts = await _audit_hosts(session, host, zone_ids, asset_ids)
    if not hosts:
        return await _scans_page(
            request,
            session,
            user,
            error="En az bir hedef girin (tekil host ya da IP zone/varlık).",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    await dispatch_ldap_audit_hosts(session, hosts, port, credential=credential, user_id=user.id)
    msg = quote(f"LDAP denetimi tamamlandı: {len(hosts)} host")
    return RedirectResponse(f"/scans?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/scans/telnet")
async def start_telnet_audit_web(
    request: Request,
    session: SessionDep,
    host: Annotated[str, Form()] = "",
    port: Annotated[int, Form()] = 23,
    credential_id: Annotated[int | None, Form()] = None,
    zone_ids: Annotated[list[int] | None, Form()] = None,
    asset_ids: Annotated[list[int] | None, Form()] = None,
    credential_zone_ids: Annotated[list[int] | None, Form()] = None,
) -> Response:
    """Telnet/Cisco CLI salt-okunur güvenlik denetimi (IX-7c). Yalnız admin.

    Kimlik OPSİYONELDİR: seçilmezse Telnet açıklığı + banner denetlenir; seçilirse 'telnet'
    tipi olmalıdır (CLI'a girip 'show running-config' okunur). Tekil host + opsiyonel IP
    zone/varlık (envanterdeki ayakta) hedeflenir; her host scope guard'dan geçer (X-3).
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return await _scans_page(
            request,
            session,
            user,
            error="Kimlikli Telnet denetimi yalnızca admin rolü ile yapılabilir.",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    credential, ok = await _resolve_audit_credential(
        session, credential_id, credential_zone_ids, CredentialType.telnet
    )
    if not ok:
        return await _scans_page(
            request,
            session,
            user,
            error="Geçerli bir Telnet kimliği seçin (kimlik tipi 'telnet').",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    hosts = await _audit_hosts(session, host, zone_ids, asset_ids)
    if not hosts:
        return await _scans_page(
            request,
            session,
            user,
            error="En az bir hedef girin (tekil host ya da IP zone/varlık).",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    await dispatch_telnet_audit_hosts(session, hosts, port, credential=credential, user_id=user.id)
    msg = quote(f"Telnet denetimi tamamlandı: {len(hosts)} host")
    return RedirectResponse(f"/scans?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/scans/cisco")
async def start_cisco_ios_audit_web(
    request: Request,
    session: SessionDep,
    host: Annotated[str, Form()] = "",
    port: Annotated[int, Form()] = 22,
    credential_id: Annotated[int | None, Form()] = None,
    zone_ids: Annotated[list[int] | None, Form()] = None,
    asset_ids: Annotated[list[int] | None, Form()] = None,
    credential_zone_ids: Annotated[list[int] | None, Form()] = None,
) -> Response:
    """Cisco IOS SSH salt-okunur sertleştirme denetimi (VII-2d). Yalnız admin.

    Telnet denetiminin aksine kimlik ZORUNLUDUR ('ssh' tipi) — SSH ile giriş yapıp
    'show running-config' okunur (Telnet kapalı / SSH-only cihazları kapsar). Tekil host +
    opsiyonel IP zone/varlık hedeflenir; her host scope guard'dan geçer (X-3).
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return await _scans_page(
            request,
            session,
            user,
            error="Cisco IOS SSH denetimi yalnızca admin rolü ile yapılabilir.",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    credential, ok = await _resolve_audit_credential(
        session, credential_id, credential_zone_ids, CredentialType.ssh
    )
    if not ok or credential is None:
        return await _scans_page(
            request,
            session,
            user,
            error="Cisco IOS SSH denetimi için bir SSH kimliği seçin (kimlik tipi 'ssh').",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    hosts = await _audit_hosts(session, host, zone_ids, asset_ids)
    if not hosts:
        return await _scans_page(
            request,
            session,
            user,
            error="En az bir hedef girin (tekil host ya da IP zone/varlık).",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    await dispatch_cisco_ios_audit_hosts(
        session, hosts, port, credential=credential, user_id=user.id
    )
    msg = quote(f"Cisco IOS SSH denetimi tamamlandı: {len(hosts)} host")
    return RedirectResponse(f"/scans?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/scans/esxi")
async def start_esxi_audit_web(
    request: Request,
    session: SessionDep,
    host: Annotated[str, Form()] = "",
    port: Annotated[int, Form()] = 443,
    zone_ids: Annotated[list[int] | None, Form()] = None,
    asset_ids: Annotated[list[int] | None, Form()] = None,
) -> Response:
    """VMware ESXi/vCenter kimliksiz HTTPS duruş denetimi (VII-2c). Yalnız admin.

    Kimlik GEREKMEZ: 443 ucu kimliksiz yoklanır (ürün/sürüm tanımı, sürüm ifşası, MOB
    açıklığı, TLS duruşu). Tekil host + opsiyonel IP zone/varlık hedeflenir; her host
    scope guard'dan geçer. Hedefe YAZMAZ.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return await _scans_page(
            request,
            session,
            user,
            error="ESXi/vCenter denetimi yalnızca admin rolü ile yapılabilir.",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    hosts = await _audit_hosts(session, host, zone_ids, asset_ids)
    if not hosts:
        return await _scans_page(
            request,
            session,
            user,
            error="En az bir hedef girin (tekil host ya da IP zone/varlık).",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    await dispatch_esxi_audit_hosts(session, hosts, port, user_id=user.id)
    msg = quote(f"ESXi/vCenter denetimi tamamlandı: {len(hosts)} host")
    return RedirectResponse(f"/scans?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


async def _zones_page(
    request: Request,
    session: AsyncSession,
    user: User,
    *,
    error: str | None = None,
    message: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> Response:
    """IP Zone'ları sayfası (tekil IP varlıkları → Varlıklar'a taşındı; kimlikler /credentials)."""
    return templates.TemplateResponse(
        request,
        "zones.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "zones": await list_zones(session),
            "error": error,
            "message": message,
            "allow_aggressive": settings.allow_aggressive_scans,
        },
        status_code=status_code,
    )


@router.get("/zones", response_class=HTMLResponse)
async def zones_page(request: Request, session: SessionDep) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    return await _zones_page(request, session, user, message=request.query_params.get("msg"))


@router.post("/zones/create")
async def create_zone_web(
    request: Request,
    session: SessionDep,
    name: Annotated[str, Form()],
    cidrs: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return await _zones_page(
            request,
            session,
            user,
            error="Zone oluşturma yalnızca admin rolü ile yapılabilir.",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    try:
        await create_zone(session, name, parse_cidr_input(cidrs), description or None)
    except ValueError as exc:
        return await _zones_page(
            request,
            session,
            user,
            error=str(exc),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    await log_action(session, "zone_create", user_id=user.id, target=name)
    return RedirectResponse("/zones", status_code=status.HTTP_303_SEE_OTHER)


def _zone_edit_return_path(token: str | None) -> str:
    """Zone düzenleme sonrası dönülecek GÜVENLİ iç yol (open-redirect koruması).

    Yalnızca bilinen kaynaklar kabul edilir: sihirbazdan (Taramalar) gelindiyse /scans,
    aksi halde IP Zone kataloğu (/zones). Serbest URL kabul EDİLMEZ.
    """
    return "/scans" if token == "scans" else "/zones"


@router.get("/zones/{zone_id}/edit", response_class=HTMLResponse)
async def zone_edit_page(request: Request, session: SessionDep, zone_id: int) -> Response:
    """Birleşik zone düzenleme ekranı — hem /zones kataloğu hem sihirbaz buraya gelir."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/zones", status_code=status.HTTP_303_SEE_OTHER)
    zone = await get_zone(session, zone_id)
    if zone is None:
        return RedirectResponse("/zones", status_code=status.HTTP_303_SEE_OTHER)
    # Nereden gelindi? Kaydedince oraya dön (sihirbazdan→Taramalar, katalogdan→Zone'lar).
    return_to = "scans" if request.query_params.get("from") == "scans" else "zones"
    return templates.TemplateResponse(
        request,
        "zone_edit.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "zone": zone,
            "error": request.query_params.get("err"),
            "return_to": return_to,
            "back_url": _zone_edit_return_path(return_to),
        },
    )


@router.post("/zones/{zone_id}/edit")
async def zone_edit_submit(
    request: Request,
    session: SessionDep,
    zone_id: int,
    name: Annotated[str, Form()],
    cidrs: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    return_to: Annotated[str, Form()] = "zones",
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/zones", status_code=status.HTTP_303_SEE_OTHER)
    try:
        zone = await update_zone(
            session, zone_id, name, parse_cidr_input(cidrs), description or None
        )
    except ValueError as exc:
        return RedirectResponse(
            f"/zones/{zone_id}/edit?err={quote(str(exc))}&from={quote(return_to)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    if zone is None:
        return RedirectResponse("/zones", status_code=status.HTTP_303_SEE_OTHER)
    await log_action(session, "zone_update", user_id=user.id, target=name)
    msg = quote(f"Zone güncellendi: {name}")
    dest = _zone_edit_return_path(return_to)
    return RedirectResponse(f"{dest}?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/scans/zone")
async def scan_zone_web(
    request: Request,
    session: SessionDep,
    zone_id: Annotated[int, Form()],
    kind: Annotated[str, Form()] = "safe",
    port: Annotated[int, Form()] = 22,
    username: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
    credential_zone_id: Annotated[int, Form()] = 0,
) -> Response:
    """Bir zone'u tarar: kind = safe | aggressive | credentialed | credzone."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role not in (Role.admin, Role.analyst):
        return await _scans_page(
            request,
            session,
            user,
            error="Tarama başlatma yetkiniz yok.",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    zone = await get_zone(session, zone_id)
    if zone is None:
        return await _scans_page(
            request, session, user, error="Zone bulunamadı.", status_code=status.HTTP_404_NOT_FOUND
        )

    # --- Credentialed (kimlikli) zone taraması ---
    if kind == "credentialed":
        if user.role != Role.admin:
            return await _scans_page(
                request,
                session,
                user,
                error="Kimlikli (credentialed) tarama yalnızca admin rolü ile yapılabilir.",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        if not username or not password:
            return await _scans_page(
                request,
                session,
                user,
                error="Kimlikli tarama için kullanıcı adı ve parola gerekli.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        cred = await dispatch_zone_credentialed(session, zone, port, username, password, user.id)
        methods = ", ".join(f"{h} ({m})" for h, m in cred.methods.items())
        msg = f"Zone '{zone.name}' (kimlikli): {len(cred.scanned)} host tarandı"
        if methods:
            msg += f" [{methods}]"
        if cred.failed:
            msg += f", {len(cred.failed)} başarısız ({', '.join(cred.failed)})"
        if cred.skipped:
            msg += f", {len(cred.skipped)} kapsam dışı"
        return RedirectResponse(f"/scans?msg={quote(msg)}", status_code=status.HTTP_303_SEE_OTHER)

    # --- IP zone × kimlik bölgesi (kasadan kimliklerle, OS öncelikli) ---
    # Kimlik bölgesi seçilmişse (opsiyonel) ağ moduna bakmaksızın kimlikli denetim yapılır.
    if credential_zone_id:
        if user.role != Role.admin:
            return await _scans_page(
                request,
                session,
                user,
                error="Kimlik bölgesiyle tarama yalnızca admin rolü ile yapılabilir.",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        cred_zone = await get_credential_zone(session, credential_zone_id)
        if cred_zone is None:
            return await _scans_page(
                request,
                session,
                user,
                error="Kimlik bölgesi seçilmedi / bulunamadı.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        creds = await credentials_in_zone(session, cred_zone)
        czr = await dispatch_credential_zone_scan(session, zone, creds, user.id)
        msg = f"'{zone.name}' × '{cred_zone.name}': {len(czr.matched)} host'ta kimlik tuttu"
        if czr.windows_reachable:
            msg += f", {len(czr.windows_reachable)} Windows portu açık (WinRM/RDP)"
        if czr.failed:
            msg += f", {len(czr.failed)} başarısız"
        if czr.skipped:
            msg += f", {len(czr.skipped)} kapsam dışı"
        return RedirectResponse(f"/scans?msg={quote(msg)}", status_code=status.HTTP_303_SEE_OTHER)

    # --- Ağ taraması (güvenli / agresif) ---
    scan_mode = parse_mode(kind)
    if is_aggressive(scan_mode):
        if user.role != Role.admin:
            return await _scans_page(
                request,
                session,
                user,
                error="Agresif (müdahaleci) tarama yalnızca admin rolü ile başlatılabilir.",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        try:
            ensure_mode_allowed(scan_mode, allow_aggressive=settings.allow_aggressive_scans)
        except AggressiveScanNotAllowed as exc:
            return await _scans_page(
                request, session, user, error=str(exc), status_code=status.HTTP_403_FORBIDDEN
            )
    result = await dispatch_zone_scan(session, zone, scan_mode, user.id)
    msg = f"Zone '{zone.name}': {len(result.scanned)} blok için tarama başlatıldı [{scan_mode}]."
    if result.skipped:
        msg += f" {len(result.skipped)} blok atlandı (kapsam dışı): {', '.join(result.skipped)}"
    return RedirectResponse(f"/scans?msg={quote(msg)}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/scans/zones")
async def scan_zones_web(
    request: Request,
    session: SessionDep,
    zone_ids: Annotated[list[int] | None, Form()] = None,
    credential_zone_ids: Annotated[list[int] | None, Form()] = None,
    kind: Annotated[str, Form()] = "safe",
) -> Response:
    """Toplu zone taraması: birden çok IP zone × opsiyonel birden çok kimlik bölgesi.

    Kimlik bölgesi seçilmişse (admin) kasadaki kimliklerle OS-öncelikli kimlikli denetim;
    yoksa seçilen yoğunlukta (güvenli/agresif) ağ taraması yapılır.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role not in (Role.admin, Role.analyst):
        return await _scans_page(
            request,
            session,
            user,
            error="Tarama başlatma yetkiniz yok.",
            status_code=status.HTTP_403_FORBIDDEN,
        )

    zids = zone_ids or []
    czids = credential_zone_ids or []
    ip_zones: list[Zone] = []
    for zid in zids:
        zone = await get_zone(session, zid)
        if zone is not None:
            ip_zones.append(zone)
    if not ip_zones:
        return await _scans_page(
            request,
            session,
            user,
            error="En az bir IP zone seçin.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # --- Kimlik bölgeleriyle (kasadan) kimlikli tarama — yalnızca admin ---
    if czids:
        if user.role != Role.admin:
            return await _scans_page(
                request,
                session,
                user,
                error="Kimlik bölgesiyle tarama yalnızca admin rolü ile yapılabilir.",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        creds: list[Credential] = []
        seen: set[int] = set()
        for czid in czids:
            cz = await get_credential_zone(session, czid)
            if cz is None:
                continue
            for cred in await credentials_in_zone(session, cz):
                if cred.id not in seen:
                    seen.add(cred.id)
                    creds.append(cred)
        if not creds:
            return await _scans_page(
                request,
                session,
                user,
                error="Seçili kimlik bölgelerinde kimlik yok.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        cz_res = await dispatch_credential_zones_scan(session, ip_zones, creds, user.id)
        msg = (
            f"{len(ip_zones)} IP zone × {len(czids)} kimlik bölgesi: "
            f"{len(cz_res.matched)} host'ta kimlik tuttu"
        )
        if cz_res.windows_reachable:
            msg += f", {len(cz_res.windows_reachable)} Windows erişilebilir"
        if cz_res.failed:
            msg += f", {len(cz_res.failed)} başarısız"
        if cz_res.skipped:
            msg += f", {len(cz_res.skipped)} kapsam dışı"
        return RedirectResponse(f"/scans?msg={quote(msg)}", status_code=status.HTTP_303_SEE_OTHER)

    # --- Ağ taraması (güvenli / agresif) ---
    scan_mode = parse_mode(kind)
    if is_aggressive(scan_mode):
        if user.role != Role.admin:
            return await _scans_page(
                request,
                session,
                user,
                error="Agresif (müdahaleci) tarama yalnızca admin rolü ile başlatılabilir.",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        try:
            ensure_mode_allowed(scan_mode, allow_aggressive=settings.allow_aggressive_scans)
        except AggressiveScanNotAllowed as exc:
            return await _scans_page(
                request, session, user, error=str(exc), status_code=status.HTTP_403_FORBIDDEN
            )
    net_res = await dispatch_zones_scan(session, ip_zones, scan_mode, user.id)
    if not net_res.scanned:
        return await _scans_page(
            request,
            session,
            user,
            error="Hiçbir blok başlatılamadı; seçilen zone'lar tümüyle kapsam dışı.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    msg = f"{len(ip_zones)} zone: {len(net_res.scanned)} blok için tarama başlatıldı [{scan_mode}]."
    if net_res.skipped:
        msg += f" {len(net_res.skipped)} blok atlandı (kapsam dışı)."
    return RedirectResponse(f"/scans?msg={quote(msg)}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/scans/wizard")
async def scan_wizard_web(
    request: Request,
    session: SessionDep,
    zone_ids: Annotated[list[int] | None, Form()] = None,
    asset_ids: Annotated[list[int] | None, Form()] = None,
    credential_zone_ids: Annotated[list[int] | None, Form()] = None,
    credential_ids: Annotated[list[int] | None, Form()] = None,
    mode: Annotated[str, Form()] = "network",
    ports: Annotated[str, Form()] = "top",
    ports_custom: Annotated[str, Form()] = "",
    aggressive_ack: Annotated[str, Form()] = "",
    categories: Annotated[list[str] | None, Form()] = None,
    name: Annotated[str, Form()] = "",
    sched_mode: Annotated[str, Form()] = "run_now",
    sched_period: Annotated[str, Form()] = "daily",
    sched_interval_minutes: Annotated[int, Form()] = 1440,
    sched_start_at: Annotated[str, Form()] = "",
    assigned_user_id: Annotated[int | None, Form()] = None,
    notify_on_complete: Annotated[str, Form()] = "",
    attach_report: Annotated[str, Form()] = "",
) -> Response:
    """Çok adımlı tarama sihirbazı: zone+tekil IP hedefleri × tek "mod seç" (FAZ VIII).

    Hedefler IP zone'larının CIDR'leri + envanterden seçilen tekil IP varlıklarıdır.
    Tek mod seçici 5 modu yönetir (``resolve_wizard_mode``): Ağ taraması (+port seçici),
    Ping, Güvenli CVE, Agresif CVE, Kimlikli. Her mod ``WizardModeSpec`` ile backend'e
    eşlenir (scan_type + nmap modu + kapılar). Agresif CVE → admin + açık "kabul ediyorum";
    Kimlikli → admin + en az bir kimlik. categories: seçili ürün/CVE kategorileri (boş =
    tümü) — rapor bu kategorilere göre filtrelenir. Hızlı tarama ile AYNI backend.
    """
    # SCAN-MERGE: sihirbaz artik birlesik /scans/start backend'ine delege eder (tek kaynak,
    # ayni mantik). Hedef = zone/asset; web modu yok; yazilan hedef bos. Auth/rol + tum gating
    # start_scan_web icinde uygulanir.
    return await start_scan_web(
        request,
        session,
        targets="",
        zone_ids=zone_ids,
        asset_ids=asset_ids,
        scan_type="network",
        mode=mode,
        ports=ports,
        ports_custom=ports_custom,
        name=name,
        aggressive_ack=aggressive_ack,
        credential_zone_ids=credential_zone_ids,
        credential_ids=credential_ids,
        categories=categories,
        sched_mode=sched_mode,
        sched_period=sched_period,
        sched_interval_minutes=sched_interval_minutes,
        sched_start_at=sched_start_at,
        assigned_user_id=assigned_user_id,
        notify_on_complete=notify_on_complete,
        attach_report=attach_report,
    )


@router.post("/zones/{zone_id}/delete")
async def delete_zone_web(request: Request, session: SessionDep, zone_id: int) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return await _zones_page(
            request,
            session,
            user,
            error="Zone silme yalnızca admin rolü ile yapılabilir.",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    await delete_zone(session, zone_id)
    await log_action(session, "zone_delete", user_id=user.id, target=str(zone_id))
    return RedirectResponse("/zones", status_code=status.HTTP_303_SEE_OTHER)


# --- Kimlik kasası (credentials + credential zones) — yalnızca admin ---


async def _credentials_page(
    request: Request,
    session: AsyncSession,
    user: User,
    *,
    error: str | None = None,
    message: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> Response:
    creds = await list_credentials(session)
    return templates.TemplateResponse(
        request,
        "credentials.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "credentials": creds,
            "credential_zones": await list_credential_zones(session),
            "cred_name_by_id": {c.id: c.name for c in creds},
            "effective_port": effective_port,
            "cred_types": [t.value for t in CredentialType],
            "error": error,
            "message": message,
        },
        status_code=status_code,
    )


async def _wordlists_page(
    request: Request,
    session: AsyncSession,
    user: User,
    *,
    error: str | None = None,
    message: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> Response:
    """Kelime Listeleri sayfası (ayrı menü — Kimlikler ile Zafiyetler arasında)."""
    ldap_cfg = await get_ldap_config(session)
    ldap_configured = ldap_cfg is not None and bool(ldap_cfg.server_uri) and bool(ldap_cfg.base_dn)
    return templates.TemplateResponse(
        request,
        "wordlists.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "wordlists": await list_wordlists(session),
            "wordlist_kinds": [k.value for k in WordlistKind],
            "ldap_configured": ldap_configured,
            "error": error,
            "message": message,
        },
        status_code=status_code,
    )


@router.get("/wordlists", response_class=HTMLResponse)
async def wordlists_page(request: Request, session: SessionDep) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return await _wordlists_page(request, session, user, message=request.query_params.get("msg"))


@router.get("/wordlists/{wordlist_id}/view", response_class=HTMLResponse)
async def wordlist_view_page(request: Request, session: SessionDep, wordlist_id: int) -> Response:
    """Kelime listesi salt-okunur görüntüleme (yerleşik dahil tüm listeler). Yalnız admin."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    wordlist = await get_wordlist(session, wordlist_id)
    if wordlist is None:
        return RedirectResponse("/wordlists", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request,
        "wordlist_view.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "wordlist": wordlist,
            "entries_joined": "\n".join(wordlist.entries),
        },
    )


@router.get("/credentials", response_class=HTMLResponse)
async def credentials_page(request: Request, session: SessionDep) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return await _credentials_page(request, session, user, message=request.query_params.get("msg"))


@router.post("/credentials/create")
async def create_credential_web(
    request: Request,
    session: SessionDep,
    name: Annotated[str, Form()],
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    cred_type: Annotated[str, Form()] = "ssh",
    domain: Annotated[str, Form()] = "",
    port: Annotated[str, Form()] = "",
    port_custom: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    try:
        ctype = CredentialType(cred_type)
    except ValueError:
        return await _credentials_page(
            request,
            session,
            user,
            error="Geçersiz kimlik tipi.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    # Port: listeden seçilen değer ("" = tip varsayılanı, "custom" = elle girilen).
    chosen_port = port_custom if port == "custom" else port
    port_val: int | None = None
    if chosen_port.strip():
        try:
            port_val = int(chosen_port)
        except ValueError:
            return await _credentials_page(
                request,
                session,
                user,
                error="Port bir sayı olmalı.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        if not 1 <= port_val <= 65535:
            return await _credentials_page(
                request,
                session,
                user,
                error="Port 1-65535 aralığında olmalı.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
    try:
        await create_credential(
            session,
            name,
            ctype,
            username,
            password,
            domain=domain or None,
            port=port_val,
            description=description or None,
        )
    except ValueError as exc:
        return await _credentials_page(
            request, session, user, error=str(exc), status_code=status.HTTP_400_BAD_REQUEST
        )
    await log_action(session, "credential_create", user_id=user.id, target=name)
    return RedirectResponse("/credentials", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/credentials/{credential_id}/delete")
async def delete_credential_web(
    request: Request, session: SessionDep, credential_id: int
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await delete_credential(session, credential_id)
    await log_action(session, "credential_delete", user_id=user.id, target=str(credential_id))
    return RedirectResponse("/credentials", status_code=status.HTTP_303_SEE_OTHER)


def _cred_edit_return_path(token: str | None) -> str:
    """Kimlik/kimlik-bölgesi düzenleme sonrası dönülecek GÜVENLİ iç yol (open-redirect koruması).

    Sihirbazdan (Taramalar) gelindiyse /scans, aksi halde Kimlik kasası (/credentials).
    """
    return "/scans" if token == "scans" else "/credentials"


@router.get("/credentials/{credential_id}/edit", response_class=HTMLResponse)
async def credential_edit_page(
    request: Request, session: SessionDep, credential_id: int
) -> Response:
    """Kimlik düzenleme ekranı (admin). Parola gösterilmez; boş bırakılırsa değişmez."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    cred = await get_credential(session, credential_id)
    if cred is None:
        return RedirectResponse("/credentials", status_code=status.HTTP_303_SEE_OTHER)
    return_to = "scans" if request.query_params.get("from") == "scans" else "credentials"
    return templates.TemplateResponse(
        request,
        "credential_edit.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "cred": cred,
            "cred_types": [t.value for t in CredentialType],
            "error": request.query_params.get("err"),
            "return_to": return_to,
            "back_url": _cred_edit_return_path(return_to),
        },
    )


@router.post("/credentials/{credential_id}/edit")
async def credential_edit_submit(
    request: Request,
    session: SessionDep,
    credential_id: int,
    name: Annotated[str, Form()],
    username: Annotated[str, Form()],
    cred_type: Annotated[str, Form()] = "ssh",
    password: Annotated[str, Form()] = "",
    domain: Annotated[str, Form()] = "",
    port: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
    return_to: Annotated[str, Form()] = "credentials",
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    edit_url = f"/credentials/{credential_id}/edit?from={quote(return_to)}"
    try:
        ctype = CredentialType(cred_type)
    except ValueError:
        return RedirectResponse(
            f"{edit_url}&err={quote('Geçersiz kimlik tipi.')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    port_val: int | None = None
    if port.strip():
        try:
            port_val = int(port)
        except ValueError:
            return RedirectResponse(
                f"{edit_url}&err={quote('Port bir sayı olmalı.')}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        if not 1 <= port_val <= 65535:
            return RedirectResponse(
                f"{edit_url}&err={quote('Port 1-65535 aralığında olmalı.')}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
    try:
        cred = await update_credential(
            session,
            credential_id,
            name,
            ctype,
            username,
            secret=password or None,
            domain=domain or None,
            port=port_val,
            description=description or None,
        )
    except ValueError as exc:
        return RedirectResponse(
            f"{edit_url}&err={quote(str(exc))}", status_code=status.HTTP_303_SEE_OTHER
        )
    if cred is None:
        return RedirectResponse("/credentials", status_code=status.HTTP_303_SEE_OTHER)
    await log_action(session, "credential_update", user_id=user.id, target=name)
    msg = quote(f"Kimlik güncellendi: {name}")
    dest = _cred_edit_return_path(return_to)
    return RedirectResponse(f"{dest}?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/credential-zones/create")
async def create_credential_zone_web(
    request: Request,
    session: SessionDep,
    name: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    credential_ids: Annotated[list[int] | None, Form()] = None,
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    try:
        await create_credential_zone(session, name, credential_ids or [], description or None)
    except ValueError as exc:
        return await _credentials_page(
            request, session, user, error=str(exc), status_code=status.HTTP_400_BAD_REQUEST
        )
    await log_action(session, "credential_zone_create", user_id=user.id, target=name)
    return RedirectResponse("/credentials", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/credential-zones/{zone_id}/delete")
async def delete_credential_zone_web(
    request: Request, session: SessionDep, zone_id: int
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await delete_credential_zone(session, zone_id)
    await log_action(session, "credential_zone_delete", user_id=user.id, target=str(zone_id))
    return RedirectResponse("/credentials", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/credential-zones/{zone_id}/edit", response_class=HTMLResponse)
async def credential_zone_edit_page(
    request: Request, session: SessionDep, zone_id: int
) -> Response:
    """Kimlik bölgesi düzenleme ekranı (admin): ad + içindeki kimlikleri sil/ekle."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    zone = await get_credential_zone(session, zone_id)
    if zone is None:
        return RedirectResponse("/credentials", status_code=status.HTTP_303_SEE_OTHER)
    return_to = "scans" if request.query_params.get("from") == "scans" else "credentials"
    return templates.TemplateResponse(
        request,
        "credential_zone_edit.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "zone": zone,
            "credentials": await list_credentials(session),
            "error": request.query_params.get("err"),
            "return_to": return_to,
            "back_url": _cred_edit_return_path(return_to),
        },
    )


@router.post("/credential-zones/{zone_id}/edit")
async def credential_zone_edit_submit(
    request: Request,
    session: SessionDep,
    zone_id: int,
    name: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    credential_ids: Annotated[list[int] | None, Form()] = None,
    return_to: Annotated[str, Form()] = "credentials",
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    try:
        zone = await update_credential_zone(
            session, zone_id, name, credential_ids or [], description or None
        )
    except ValueError as exc:
        return RedirectResponse(
            f"/credential-zones/{zone_id}/edit?from={quote(return_to)}&err={quote(str(exc))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    if zone is None:
        return RedirectResponse("/credentials", status_code=status.HTTP_303_SEE_OTHER)
    await log_action(session, "credential_zone_update", user_id=user.id, target=name)
    msg = quote(f"Kimlik bölgesi güncellendi: {name}")
    dest = _cred_edit_return_path(return_to)
    return RedirectResponse(f"{dest}?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


# --- Kelime listeleri (Wordlist — dizin/SMB/brute force tek kaynak) ---

_WORDLIST_MAX_BYTES = 8 * 1024 * 1024  # yüklenen .txt için üst sınır (8 MB)


async def _wordlist_raw_text(
    entries_text: str, entries_file: UploadFile | None
) -> tuple[str | None, str | None]:
    """Yapıştırılan metin + (varsa) yüklenen .txt'i birleştirip ham metni döndürür.

    Dönüş: ``(raw, error)`` — hata varsa ``raw`` None'dur.
    """
    parts: list[str] = []
    if entries_text.strip():
        parts.append(entries_text)
    if entries_file is not None and entries_file.filename:
        raw_bytes = await entries_file.read(_WORDLIST_MAX_BYTES + 1)
        if len(raw_bytes) > _WORDLIST_MAX_BYTES:
            return None, "Yüklenen dosya çok büyük (en fazla 8 MB)."
        try:
            parts.append(raw_bytes.decode("utf-8"))
        except UnicodeDecodeError:
            return None, "Dosya UTF-8 metin değil — düz metin (.txt) yükleyin."
    return "\n".join(parts), None


@router.post("/wordlists/create")
async def create_wordlist_web(
    request: Request,
    session: SessionDep,
    name: Annotated[str, Form()],
    kind: Annotated[str, Form()] = "web_dir",
    description: Annotated[str, Form()] = "",
    entries_text: Annotated[str, Form()] = "",
    entries_file: Annotated[UploadFile | None, File()] = None,
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    try:
        wkind = WordlistKind(kind)
    except ValueError:
        return await _wordlists_page(
            request,
            session,
            user,
            error="Geçersiz kelime listesi türü.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    raw, err = await _wordlist_raw_text(entries_text, entries_file)
    if err is not None or raw is None:
        return await _wordlists_page(
            request,
            session,
            user,
            error=err or "Kelime listesi okunamadı.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    entries = parse_entries(raw)
    try:
        await create_wordlist(
            session, name, wkind, entries, description=description or None, created_by=user.id
        )
    except ValueError as exc:
        return await _wordlists_page(
            request, session, user, error=str(exc), status_code=status.HTTP_400_BAD_REQUEST
        )
    await log_action(session, "wordlist_create", user_id=user.id, target=name)
    return RedirectResponse("/wordlists", status_code=status.HTTP_303_SEE_OTHER)


# --- Kullanıcı adı üretici (ad-soyad → AD/LDAP kalıpları → username wordlist) ---

_GEN_PREVIEW_MAX = 40  # önizlemede gösterilecek örnek sayısı


def _selected_username_patterns(patterns: list[str]) -> list[str]:
    """Formdan gelen kalıpları doğrula; hiçbiri seçilmemişse tüm kalıpları kullan."""
    chosen = [p for p in patterns if p in USERNAME_PATTERN_KEYS]
    return chosen or list(USERNAME_PATTERN_KEYS)


@router.post("/wordlists/generate/usernames/preview", response_class=HTMLResponse)
async def generate_usernames_preview(
    request: Request,
    session: SessionDep,
    names_text: Annotated[str, Form()] = "",
    patterns: Annotated[list[str], Form()] = [],  # noqa: B006 (FastAPI Form varsayılanı)
    normalize: Annotated[bool, Form()] = False,
    custom_patterns_text: Annotated[str, Form()] = "",
) -> Response:
    """HTMX canlı önizleme — üretilecek kullanıcı adı sayısı + ilk N örnek (KAYDETMEZ)."""
    user = await _current_user(request, session)
    if user is None or user.role != Role.admin:
        return HTMLResponse("", status_code=status.HTTP_403_FORBIDDEN)
    pairs = parse_name_pairs(names_text)
    usernames = generate_usernames(
        pairs,
        _selected_username_patterns(patterns),
        normalize=normalize,
        custom_patterns=parse_entries(custom_patterns_text),
    )
    return templates.TemplateResponse(
        request,
        "_wordlist_gen_preview.html",
        {"count": len(usernames), "sample": usernames[:_GEN_PREVIEW_MAX]},
    )


@router.post("/wordlists/generate/usernames")
async def generate_usernames_web(
    request: Request,
    session: SessionDep,
    name: Annotated[str, Form()],
    names_text: Annotated[str, Form()] = "",
    patterns: Annotated[list[str], Form()] = [],  # noqa: B006 (FastAPI Form varsayılanı)
    normalize: Annotated[bool, Form()] = False,
    custom_patterns_text: Annotated[str, Form()] = "",
) -> Response:
    """Ad-soyad listesinden kullanıcı adı üretip yeni bir ``username`` wordlist'i kaydeder."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    pairs = parse_name_pairs(names_text)
    usernames = generate_usernames(
        pairs,
        _selected_username_patterns(patterns),
        normalize=normalize,
        custom_patterns=parse_entries(custom_patterns_text),
    )
    if not usernames:
        return await _wordlists_page(
            request,
            session,
            user,
            error="Üretilecek kullanıcı adı yok — en az bir ad girip kalıp seçin.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    try:
        wordlist = await create_wordlist(
            session,
            name,
            WordlistKind.username,
            usernames,
            description="Ad-soyad listesinden üretildi (kullanıcı adı üretici)",
            created_by=user.id,
        )
    except ValueError as exc:
        return await _wordlists_page(
            request, session, user, error=str(exc), status_code=status.HTTP_400_BAD_REQUEST
        )
    await log_action(
        session,
        "wordlist_generate_usernames",
        user_id=user.id,
        target=f"{name} ({len(usernames)} kullanıcı adı)",
    )
    return RedirectResponse(f"/wordlists/{wordlist.id}/view", status_code=status.HTTP_303_SEE_OTHER)


# --- LDAP Kullanıcı Kasası (LDAP'tan kullanıcı adı çek → username wordlist) ---


async def _ldap_usernames(session: AsyncSession, query: str) -> list[str]:
    """LDAP yapılandırmasından kullanıcı adlarını çeker (sıra korunur, dedup).

    Yapılandırma yoksa/eksikse ``LdapSearchError`` yükseltir. Tarama YAPMAZ —
    yalnız dizinden kullanıcı adı listesi okur.
    """
    config = await get_ldap_config(session)
    if config is None or not config.server_uri or not config.base_dn:
        raise LdapSearchError("Önce LDAP bağlantısını (sunucu + base DN) Ayarlar'dan yapılandırın.")
    verify_cert, ca_cert = await _ldaps_tls(session)
    users = await ldap_search_users(
        config, get_bind_password(config), query, verify_cert=verify_cert, ca_cert=ca_cert
    )
    seen: set[str] = set()
    out: list[str] = []
    for ldap_user in users:
        uname = (ldap_user.username or "").strip()
        if uname and uname not in seen:
            seen.add(uname)
            out.append(uname)
    return out


@router.post("/wordlists/ldap-users/preview", response_class=HTMLResponse)
async def ldap_users_preview(
    request: Request,
    session: SessionDep,
    query: Annotated[str, Form()] = "",
) -> Response:
    """HTMX canlı önizleme — LDAP'tan çekilecek kullanıcı adı sayısı + ilk N örnek (KAYDETMEZ)."""
    user = await _current_user(request, session)
    if user is None or user.role != Role.admin:
        return HTMLResponse("", status_code=status.HTTP_403_FORBIDDEN)
    try:
        usernames = await _ldap_usernames(session, query)
    except LdapSearchError as exc:
        return HTMLResponse(
            f'<div class="k-sm" style="color:var(--err,#e06c75);">{escape(str(exc))}</div>'
        )
    return templates.TemplateResponse(
        request,
        "_wordlist_gen_preview.html",
        {"count": len(usernames), "sample": usernames[:_GEN_PREVIEW_MAX]},
    )


@router.post("/wordlists/ldap-users")
async def ldap_users_web(
    request: Request,
    session: SessionDep,
    name: Annotated[str, Form()],
    query: Annotated[str, Form()] = "",
) -> Response:
    """LDAP dizininden kullanıcı adlarını çekip yeni bir ``username`` wordlist'i kaydeder."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    try:
        usernames = await _ldap_usernames(session, query)
    except LdapSearchError as exc:
        return await _wordlists_page(
            request, session, user, error=str(exc), status_code=status.HTTP_400_BAD_REQUEST
        )
    if not usernames:
        return await _wordlists_page(
            request,
            session,
            user,
            error="LDAP'tan kullanıcı adı çekilemedi — filtreyi/bağlantıyı kontrol edin.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    try:
        wordlist = await create_wordlist(
            session,
            name,
            WordlistKind.username,
            usernames,
            description="LDAP dizininden çekildi (kullanıcı kasası)",
            created_by=user.id,
        )
    except ValueError as exc:
        return await _wordlists_page(
            request, session, user, error=str(exc), status_code=status.HTTP_400_BAD_REQUEST
        )
    await log_action(
        session,
        "wordlist_ldap_users",
        user_id=user.id,
        target=f"{name} ({len(usernames)} kullanıcı adı)",
    )
    return RedirectResponse(f"/wordlists/{wordlist.id}/view", status_code=status.HTTP_303_SEE_OTHER)


# --- Parola üretici (taban kelime + örnek + politika → uyumlu aday → password wordlist) ---

_ALLOWED_PW_SUFFIXES = {"!", ".", "?", "@", "_", "*", "-", "#"}


def _password_spec_from_form(
    min_len: int,
    require_upper: bool,
    require_lower: bool,
    require_digit: bool,
    require_special: bool,
    capitalize: bool,
    leet: bool,
    suffixes: list[str],
    years: list[int],
) -> PasswordSpec:
    """Formdan gelen politika yanıtlarını doğrulanmış bir ``PasswordSpec``e dönüştürür."""
    safe_suffixes: list[str] = [""]  # sonek-yok her zaman dahil
    for suffix in suffixes:
        if suffix in _ALLOWED_PW_SUFFIXES and suffix not in safe_suffixes:
            safe_suffixes.append(suffix)
    safe_years = tuple(sorted({y for y in years if 1990 <= y <= 2100}))
    return PasswordSpec(
        min_len=max(1, min(min_len, 64)),
        require_upper=require_upper,
        require_lower=require_lower,
        require_digit=require_digit,
        require_special=require_special,
        capitalize=capitalize,
        leet=leet,
        suffixes=tuple(safe_suffixes),
        years=safe_years,
    )


@router.post("/wordlists/generate/passwords/preview", response_class=HTMLResponse)
async def generate_passwords_preview(
    request: Request,
    session: SessionDep,
    bases_text: Annotated[str, Form()] = "",
    examples_text: Annotated[str, Form()] = "",
    min_len: Annotated[int, Form()] = 8,
    require_upper: Annotated[bool, Form()] = False,
    require_lower: Annotated[bool, Form()] = False,
    require_digit: Annotated[bool, Form()] = False,
    require_special: Annotated[bool, Form()] = False,
    capitalize: Annotated[bool, Form()] = False,
    leet: Annotated[bool, Form()] = False,
    suffixes: Annotated[list[str], Form()] = [],  # noqa: B006 (FastAPI Form varsayılanı)
    years: Annotated[list[int], Form()] = [],  # noqa: B006 (FastAPI Form varsayılanı)
) -> Response:
    """HTMX canlı önizleme — üretilecek parola sayısı + ilk N örnek (KAYDETMEZ)."""
    user = await _current_user(request, session)
    if user is None or user.role != Role.admin:
        return HTMLResponse("", status_code=status.HTTP_403_FORBIDDEN)
    spec = _password_spec_from_form(
        min_len,
        require_upper,
        require_lower,
        require_digit,
        require_special,
        capitalize,
        leet,
        suffixes,
        years,
    )
    passwords = generate_passwords(
        parse_entries(bases_text), spec, examples=parse_entries(examples_text)
    )
    return templates.TemplateResponse(
        request,
        "_wordlist_gen_preview.html",
        {"count": len(passwords), "sample": passwords[:_GEN_PREVIEW_MAX]},
    )


@router.post("/wordlists/generate/passwords")
async def generate_passwords_web(
    request: Request,
    session: SessionDep,
    name: Annotated[str, Form()],
    bases_text: Annotated[str, Form()] = "",
    examples_text: Annotated[str, Form()] = "",
    min_len: Annotated[int, Form()] = 8,
    require_upper: Annotated[bool, Form()] = False,
    require_lower: Annotated[bool, Form()] = False,
    require_digit: Annotated[bool, Form()] = False,
    require_special: Annotated[bool, Form()] = False,
    capitalize: Annotated[bool, Form()] = False,
    leet: Annotated[bool, Form()] = False,
    suffixes: Annotated[list[str], Form()] = [],  # noqa: B006 (FastAPI Form varsayılanı)
    years: Annotated[list[int], Form()] = [],  # noqa: B006 (FastAPI Form varsayılanı)
) -> Response:
    """Taban kelime + örnek + politikadan parola üretip yeni ``password`` wordlist'i kaydeder."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    spec = _password_spec_from_form(
        min_len,
        require_upper,
        require_lower,
        require_digit,
        require_special,
        capitalize,
        leet,
        suffixes,
        years,
    )
    passwords = generate_passwords(
        parse_entries(bases_text), spec, examples=parse_entries(examples_text)
    )
    if not passwords:
        return await _wordlists_page(
            request,
            session,
            user,
            error="Politikaya uyan parola üretilemedi — taban kelime girip politikayı gevşetin.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    try:
        wordlist = await create_wordlist(
            session,
            name,
            WordlistKind.password,
            passwords,
            description="Taban kelime + politikadan üretildi (parola üretici)",
            created_by=user.id,
        )
    except ValueError as exc:
        return await _wordlists_page(
            request, session, user, error=str(exc), status_code=status.HTTP_400_BAD_REQUEST
        )
    await log_action(
        session,
        "wordlist_generate_passwords",
        user_id=user.id,
        target=f"{name} ({len(passwords)} parola)",
    )
    return RedirectResponse(f"/wordlists/{wordlist.id}/view", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/wordlists/{wordlist_id}/delete")
async def delete_wordlist_web(request: Request, session: SessionDep, wordlist_id: int) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    try:
        await delete_wordlist(session, wordlist_id)
    except ValueError as exc:
        return await _wordlists_page(
            request, session, user, error=str(exc), status_code=status.HTTP_400_BAD_REQUEST
        )
    await log_action(session, "wordlist_delete", user_id=user.id, target=str(wordlist_id))
    return RedirectResponse("/wordlists", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/wordlists/{wordlist_id}/edit", response_class=HTMLResponse)
async def wordlist_edit_page(request: Request, session: SessionDep, wordlist_id: int) -> Response:
    """Kelime listesi düzenleme ekranı (admin). Yerleşik listeler düzenlenemez."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    wordlist = await get_wordlist(session, wordlist_id)
    if wordlist is None or wordlist.is_builtin:
        return RedirectResponse("/wordlists", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request,
        "wordlist_edit.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "wordlist": wordlist,
            "wordlist_kinds": [k.value for k in WordlistKind],
            "entries_joined": "\n".join(wordlist.entries),
            "error": request.query_params.get("err"),
        },
    )


@router.post("/wordlists/{wordlist_id}/edit")
async def wordlist_edit_submit(
    request: Request,
    session: SessionDep,
    wordlist_id: int,
    name: Annotated[str, Form()],
    kind: Annotated[str, Form()] = "web_dir",
    description: Annotated[str, Form()] = "",
    entries_text: Annotated[str, Form()] = "",
    entries_file: Annotated[UploadFile | None, File()] = None,
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    edit_url = f"/wordlists/{wordlist_id}/edit"
    try:
        wkind = WordlistKind(kind)
    except ValueError:
        return RedirectResponse(
            f"{edit_url}?err={quote('Geçersiz kelime listesi türü.')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    raw, err = await _wordlist_raw_text(entries_text, entries_file)
    if err is not None or raw is None:
        return RedirectResponse(
            f"{edit_url}?err={quote(err or 'Kelime listesi okunamadı.')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    entries = parse_entries(raw)
    try:
        wordlist = await update_wordlist(
            session, wordlist_id, name, wkind, entries, description=description or None
        )
    except ValueError as exc:
        return RedirectResponse(
            f"{edit_url}?err={quote(str(exc))}", status_code=status.HTTP_303_SEE_OTHER
        )
    if wordlist is None:
        return RedirectResponse("/wordlists", status_code=status.HTTP_303_SEE_OTHER)
    await log_action(session, "wordlist_update", user_id=user.id, target=name)
    msg = quote(f"Kelime listesi güncellendi: {name}")
    return RedirectResponse(f"/wordlists?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


# --- Exploit veritabanı (Exploit-DB + Metasploit) ---


@router.get("/exploits", response_class=HTMLResponse)
async def exploits_page(request: Request, session: SessionDep) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    q = (request.query_params.get("q") or "").strip() or None
    src_raw = (request.query_params.get("source") or "").strip()
    cat_raw = (request.query_params.get("category") or "").strip()
    sev_raw = (request.query_params.get("severity") or "").strip()
    fw_raw = (request.query_params.get("framework") or "").strip()
    try:
        source = ExploitSource(src_raw) if src_raw else None
    except ValueError:
        source = None
    try:
        severity = Severity(sev_raw) if sev_raw else None
    except ValueError:
        severity = None
    category = cat_raw if cat_raw in CATEGORIES else None
    framework = fw_raw if fw_raw in FRAMEWORKS else None
    exploits = await list_exploits(
        session,
        query=q,
        source=source,
        category=category,
        severity=severity,
        framework=framework,
        limit=100,
    )
    # Faceted sayımlar — aktif filtrelere göre (her boyut kendi dışındaki filtreleri uygular).
    facets = await facet_counts(
        session, query=q, source=source, category=category, severity=severity, framework=framework
    )
    # Tazelik durumu (VI-9): saatlik beat'in işaretini + canlı yaş-bazlı kontrolü birleştir.
    s = await get_settings(session)
    age_ok = compute_up_to_date(s.exploit_last_sync, None, datetime.now(UTC))
    freshness = {
        "never": s.exploit_last_sync is None,
        "up_to_date": bool(s.exploit_up_to_date and age_ok),
        "last_sync": s.exploit_last_sync,
        "last_check": s.exploit_last_check,
    }
    return templates.TemplateResponse(
        request,
        "exploits.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "exploits": exploits,
            "total": facets["total"],
            "by_source": facets["by_source"],
            "by_severity": facets["by_severity"],
            "by_category": facets["by_category"],
            "categories": CATEGORIES,
            "frameworks": FRAMEWORKS,
            "q": q or "",
            "source": src_raw,
            "category": cat_raw,
            "severity": sev_raw,
            "framework": fw_raw,
            "message": request.query_params.get("msg"),
            "freshness": freshness,
        },
    )


def _cve_freshness(row: AppSettings) -> dict[str, object]:
    """CVE/CPE bilgi bankası tazeliği (cve_last_sync yaşına göre) — Zafiyet DB + Ayarlar paneli.

    Exploit deposu tazeliğinden AYRIDIR. Yaş eşiğin (STALE_AFTER_HOURS) altındaysa güncel.
    """
    last = row.cve_last_sync
    return {
        "never": last is None,
        "up_to_date": bool(last is not None and compute_up_to_date(last, None, datetime.now(UTC))),
        "last_sync": last,
    }


@router.get("/cve-db", response_class=HTMLResponse)
async def cve_db_page(request: Request, session: SessionDep) -> Response:
    """Zafiyet Veritabanı (CVE) gezgini — yerel CVE/CPE indeksini ara/filtrele/sayfala.

    Exploit/Payload deposundan (/exploits) AYRIDIR: burası "hangi zafiyetler var" bilgi
    bankası (NVD backfill ile dolan ~yüz binlerce CVE), orası sızma cephaneliği.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    q = (request.query_params.get("q") or "").strip() or None
    sev_raw = (request.query_params.get("severity") or "").strip()
    fw_raw = (request.query_params.get("framework") or "").strip()
    cat_raw = (request.query_params.get("category") or "").strip()
    kev_only = request.query_params.get("kev") == "1"
    try:
        severity = Severity(sev_raw) if sev_raw else None
    except ValueError:
        severity = None
    framework = fw_raw if fw_raw in FRAMEWORKS else None
    category = cat_raw if cat_raw in CATEGORIES else None
    try:
        per = int(request.query_params.get("per") or 50)
    except ValueError:
        per = 50
    if per not in CVE_PER_PAGE_CHOICES:
        per = 50
    try:
        page = max(1, int(request.query_params.get("page") or 1))
    except ValueError:
        page = 1
    total = await count_cves_filtered(
        session, q=q, severity=severity, kev_only=kev_only, framework=framework, category=category
    )
    pages = max(1, (total + per - 1) // per)
    page = min(page, pages)
    cves = await list_cves_page(
        session,
        q=q,
        severity=severity,
        kev_only=kev_only,
        framework=framework,
        category=category,
        page=page,
        per=per,
    )
    cve_ids = [c.cve_id for c in cves]
    cpe_counts = await cpe_counts_for_cves(session, cve_ids)
    # Sömürülebilirlik sinyali (Exploit→MSF köprüsü): msf=otomatik, poc=referans/manuel.
    exploit_signals = await cve_exploit_signals(session, cve_ids)
    return templates.TemplateResponse(
        request,
        "cve_db.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "cves": cves,
            "total": total,
            "cve_total": await count_cves(session),
            "cpe_total": await count_cpe_matches(session),
            "cpe_counts": cpe_counts,
            "exploit_signals": exploit_signals,
            "sevs": [s.value for s in Severity],
            "frameworks": FRAMEWORKS,
            "categories": CATEGORIES,
            "by_category": await cve_category_counts(session),
            "per_choices": CVE_PER_PAGE_CHOICES,
            "q": q or "",
            "severity": sev_raw,
            "framework": fw_raw if framework else "",
            "category": cat_raw if category else "",
            "kev_only": kev_only,
            "per": per,
            "page": page,
            "pages": pages,
            "freshness": _cve_freshness(await get_settings(session)),
            "message": request.query_params.get("msg"),
        },
    )


@router.post("/cve-db/sync")
async def cve_db_sync_web(request: Request, session: SessionDep) -> Response:
    """Zafiyet (CVE/CPE) veritabanını güncelle — cpe_sync'i arka planda tetikler (admin).

    Bitince ``cve_last_sync`` güncellenir → hem Zafiyet DB sayfası hem Ayarlar paneli tazelenir.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/cve-db", status_code=status.HTTP_303_SEE_OTHER)
    cpe_sync_task.delay()
    await log_action(session, "cve_sync_start", user_id=user.id, target="nvd-cve-cpe")
    msg = quote("CVE/CPE veritabanı güncellemesi arka planda başlatıldı (birkaç dakika sürebilir).")
    return RedirectResponse(f"/cve-db?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/exploits/sync")
async def exploits_sync_web(request: Request, session: SessionDep) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/exploits", status_code=status.HTTP_303_SEE_OTHER)
    sync_exploits_task.delay()
    await log_action(session, "exploit_sync_start", user_id=user.id, target="exploitdb+metasploit")
    msg = "Exploit veritabanı güncellemesi arka planda başlatıldı (birkaç dakika sürebilir)."
    return RedirectResponse(f"/exploits?msg={quote(msg)}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/assets", response_class=HTMLResponse)
async def assets_page(request: Request, session: SessionDep) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    show_all = request.query_params.get("all") == "1"
    total = len(await list_assets(session))
    assets = await list_inventory_assets(session, show_all=show_all)
    hidden_count = 0 if show_all else total - len(assets)
    services = await list_services(session)
    by_asset: defaultdict[int, list[Service]] = defaultdict(list)
    for svc in services:
        by_asset[svc.asset_id].append(svc)
    return templates.TemplateResponse(
        request,
        "assets.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "assets": assets,
            "services_by_asset": by_asset,
            "message": request.query_params.get("msg"),
            "error": request.query_params.get("err"),
            "can_edit": user.role in (Role.admin, Role.analyst),
            "hidden_count": hidden_count,
            "show_all": show_all,
        },
    )


@router.post("/assets/add")
async def asset_add_web(
    request: Request,
    session: SessionDep,
    ip: Annotated[str, Form()],
    hostname: Annotated[str, Form()] = "",
    name: Annotated[str, Form()] = "",
) -> Response:
    """Tekil IP YA DA URL varlığı elle ekle (taramada keşfedilenlere ek). admin/analyst.

    Girdi http(s) URL ise (ör. https://app.kurum.local:8443) saf URL varlığı oluşturulur
    (ip=NULL, URL kimliği korunur); aksi halde IP doğrulanıp IP varlığı eklenir. İkisi de
    web/normal taramada hedef olarak kullanılabilir (URL host'u tarama anında çözülür).
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role not in (Role.admin, Role.analyst):
        return RedirectResponse("/assets", status_code=status.HTTP_303_SEE_OTHER)
    target = ip.strip()
    if is_url_entry(target):
        await create_url_asset(session, target, name=name.strip() or None)
        await log_action(session, "asset_add_url", user_id=user.id, target=target)
        msg = quote(f"URL varlığı eklendi: {target}")
        return RedirectResponse(f"/assets?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)
    try:
        ipaddress.ip_address(target)
    except ValueError:
        err = quote(f"Geçersiz IP adresi veya URL: {target}")
        return RedirectResponse(f"/assets?err={err}", status_code=status.HTTP_303_SEE_OTHER)
    await upsert_asset(
        session, target, hostname=hostname.strip() or None, name=name.strip() or None
    )
    await log_action(session, "asset_add", user_id=user.id, target=target)
    msg = quote(f"Varlık eklendi: {target}")
    return RedirectResponse(f"/assets?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/assets/{asset_id}/name")
async def asset_rename_web(
    request: Request,
    session: SessionDep,
    asset_id: int,
    name: Annotated[str, Form()] = "",
) -> Response:
    """Varlığa elle cihaz adı atar/temizler (admin/analyst). Boş ad → hostname'e düşer."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role not in (Role.admin, Role.analyst):
        return RedirectResponse("/assets", status_code=status.HTTP_303_SEE_OTHER)
    asset = await get_asset(session, asset_id)
    if asset is None:
        return RedirectResponse("/assets", status_code=status.HTTP_404_NOT_FOUND)
    await set_asset_name(session, asset_id, name)
    await log_action(session, "asset_rename", user_id=user.id, target=asset.ip)
    msg = quote(f"Varlık adı güncellendi: {name.strip() or asset.ip}")
    return RedirectResponse(f"/assets?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/findings", response_class=HTMLResponse)
async def findings_page(request: Request, session: SessionDep) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    sev_raw = (request.query_params.get("severity") or "").strip()
    exploitable = request.query_params.get("exploitable") == "1"
    try:
        sev = Severity(sev_raw) if sev_raw else None
    except ValueError:
        sev = None
    findings = await list_findings_by_risk(session, severity=sev)
    assets = await list_assets(session)
    ip_by_id = {asset.id: asset.ip for asset in assets}
    device_by_id = {asset.id: asset.display_name for asset in assets}
    cve_ids = [f.cve_id for f in findings if f.cve_id]
    cve_map = await cves_by_ids(session, cve_ids)
    exploit_map = await exploit_summary_for_cves(session, cve_ids)
    if exploitable:
        findings = [
            f
            for f in findings
            if f.cve_id and exploit_map.get(f.cve_id, None) and exploit_map[f.cve_id].count > 0
        ]
    return templates.TemplateResponse(
        request,
        "findings.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "findings": findings,
            "ip_by_id": ip_by_id,
            "device_by_id": device_by_id,
            "cve_map": cve_map,
            "exploit_map": exploit_map,
            "severity": sev_raw,
            "exploitable": exploitable,
        },
    )


_VULN_PER_OPTIONS = [10, 100, 1000]


@router.get("/vulnerabilities", response_class=HTMLResponse)
async def vulnerabilities_page(request: Request, session: SessionDep) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    tab = request.query_params.get("tab") or "active"
    if tab not in ("active", "resolved", "compliance"):
        tab = "active"
    resolved = tab == "resolved"
    try:
        per = int(request.query_params.get("per") or 10)
    except ValueError:
        per = 10
    if per not in _VULN_PER_OPTIONS:
        per = 10
    try:
        page = int(request.query_params.get("page") or 1)
    except ValueError:
        page = 1
    page = max(1, page)
    # Kategori filtresi (Zayıf Kimlik / CVE / Web / …) — geçersizse filtre yok.
    cat = request.query_params.get("cat") or None
    if cat is not None and cat not in VULN_CATEGORIES:
        cat = None

    total = await count_vulnerabilities(session, resolved=resolved, category=cat)
    active_total = await count_vulnerabilities(session, resolved=False)
    resolved_total = await count_vulnerabilities(session, resolved=True)
    cat_counts = await category_counts(session, resolved=resolved)
    page_count = max(1, -(-total // per))  # ceil(total/per)
    page = min(page, page_count)

    rows = await list_vulnerabilities_page(
        session, resolved=resolved, per=per, page=page, category=cat
    )
    assets = {a.id: a for a in await list_assets(session)}
    cve_ids = [v.cve_id for v in rows if v.cve_id]
    cve_map = await cves_by_ids(session, cve_ids)
    exploit_map = await exploit_summary_for_cves(session, cve_ids)
    sev_counts = await severity_counts_by_asset(session, resolved=resolved)

    # "Acil" kovası (KEV / EPSS≥0.5 / Metasploit) — satır rozeti için vuln id kümesi.
    urgent_ids: set[int] = set()
    for v in rows:
        cve = cve_map.get(v.cve_id) if v.cve_id else None
        hit = exploit_map.get(v.cve_id) if v.cve_id else None
        if is_urgent(
            cve.kev_flag if cve else False,
            cve.epss_score if cve else None,
            bool(hit and hit.metasploit),
        ):
            urgent_ids.add(v.id)

    # Ardışık aynı-varlık satırları grupla (satırlar zaten asset_id'ye göre sıralı).
    groups: list[dict[str, object]] = []
    for v in rows:
        if not groups or groups[-1]["asset_id"] != v.asset_id:
            groups.append({"asset": assets.get(v.asset_id), "asset_id": v.asset_id, "vulns": [v]})
        else:
            vulns = groups[-1]["vulns"]
            assert isinstance(vulns, list)
            vulns.append(v)

    # X-4: Uyum sekmesi — genel çerçeve duruşu + en çok başarısız kontroller (yalnız o sekmede).
    compliance_data: dict[str, dict[str, int]] = {}
    failed_controls: list[dict[str, object]] = []
    if tab == "compliance":
        compliance_data = await compliance_overview(session)
        failed_controls = await top_failed_controls(session)

    can_triage = user.role.value in ("admin", "analyst")
    # Yerel AI (#183): etkinse CVE'li satırlara "AI ile açıkla" + önceden üretilmişi ön-yükle.
    # Anahtar cve:<id> → rapor (bulgu) üretimiyle paylaşılır (tek üretim, iki yüzey).
    ai_config = AIConfig.from_app_settings(await get_settings(session))
    ai_keys = {
        v.id: ai_cache.finding_cache_key(cve_id=v.cve_id, title="") for v in rows if v.cve_id
    }
    ai_rows_map = await ai_cache.get_many(session, list(set(ai_keys.values())))
    ai_explain_map = {vid: ai_rows_map[k] for vid, k in ai_keys.items() if k in ai_rows_map}
    return templates.TemplateResponse(
        request,
        "vulnerabilities.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "ai_enabled": ai_available(ai_config),
            "ai_explain_map": ai_explain_map,
            "groups": groups,
            "cve_map": cve_map,
            "exploit_map": exploit_map,
            "urgent_ids": urgent_ids,
            "sev_counts": sev_counts,
            "compliance_data": compliance_data,
            "failed_controls": failed_controls,
            "tab": tab,
            "per": per,
            "page": page,
            "page_count": page_count,
            "total": total,
            "active_total": active_total,
            "resolved_total": resolved_total,
            "per_options": _VULN_PER_OPTIONS,
            "can_triage": can_triage,
            # Kategori filtresi: seçili kategori + her kategori adedi + sıra.
            "cat": cat,
            "cat_counts": cat_counts,
            "vuln_categories": VULN_CATEGORIES,
        },
    )


@router.post("/vulnerabilities/{vuln_id}/status")
async def vulnerability_status(
    request: Request,
    session: SessionDep,
    vuln_id: int,
    status_value: Annotated[str, Form(alias="status")],
    note: Annotated[str, Form()] = "",
    tab: Annotated[str, Form()] = "active",
    per: Annotated[int, Form()] = 10,
    page: Annotated[int, Form()] = 1,
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role.value not in ("admin", "analyst"):
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    back = f"/vulnerabilities?tab={tab}&per={per}&page={page}"
    try:
        new_status = FindingStatus(status_value)
    except ValueError:
        return RedirectResponse(back, status_code=status.HTTP_303_SEE_OTHER)
    await set_vuln_status(session, vuln_id, new_status, note=note.strip() or None, user_id=user.id)
    await log_action(session, "vuln_status", user_id=user.id, target=f"{vuln_id}:{status_value}")
    return RedirectResponse(back, status_code=status.HTTP_303_SEE_OTHER)


async def _gather_report_context(
    session: AsyncSession, scan: Scan | None = None, batch: ScanBatch | None = None
) -> dict[str, object]:
    """Rapor (HTML ve PDF) için ortak veri bağlamını toplar.

    scan verilirse o taramanın; batch verilirse o tarama işinin (tüm üye
    taramaların) bulgularını kapsar; ikisi de yoksa birleşik (tüm) rapor.
    """
    if batch is not None:
        bscans = await batch_scans(session, batch.id)
        scan_ids = [s.id for s in bscans]
        findings = await list_findings_by_risk(session, scan_ids=scan_ids or [-1])
        selected_cats = set(batch.categories or [])
        batch_targets = [s.target for s in bscans]
        report_scans = bscans
    else:
        scan_id = scan.id if scan is not None else None
        findings = await list_findings_by_risk(session, scan_id=scan_id)
        selected_cats = set(scan.categories or []) if scan is not None else set()
        batch_targets = []
        report_scans = [scan] if scan is not None else []

    # Kategori filtresi: seçili kategorilerdeki CVE bulguları (CVE'siz bulgular korunur).
    if selected_cats:
        cve_cats = await categories_for_cves(session, [f.cve_id for f in findings if f.cve_id])
        findings = [
            f
            for f in findings
            if (not f.cve_id) or bool(cve_cats.get(f.cve_id, set()) & selected_cats)
        ]

    assets = await list_assets(session)
    ip_by_id = {asset.id: asset.ip for asset in assets}
    service_by_id = {svc.id: svc for svc in await list_services(session)}
    cve_ids = [f.cve_id for f in findings if f.cve_id]
    cve_map = await cves_by_ids(session, cve_ids)
    exploit_map = await exploit_summary_for_cves(session, cve_ids)
    remediation_map = {
        f.id: remediation_for(
            f,
            cve_map.get(f.cve_id) if f.cve_id else None,
            service_by_id.get(f.service_id) if f.service_id else None,
        )
        for f in findings
    }
    # Yerel AI (#183): etkinse butonları göster + önceden üretilmiş açıklamaları ön-yükle
    # (sayfa yenilendiğinde tekrar tıklamadan görünür). Anahtar CVE bazlı → paylaşımlı önbellek.
    ai_config = AIConfig.from_app_settings(await get_settings(session))
    ai_keys = {f.id: ai_cache.finding_cache_key(cve_id=f.cve_id, title=f.title) for f in findings}
    ai_rows = await ai_cache.get_many(session, list(set(ai_keys.values())))
    ai_explain_map = {fid: ai_rows[k] for fid, k in ai_keys.items() if k in ai_rows}
    # Düzeltme script taslağı (Dalga 2b): per-bulgu, ayrı önbellek script:<key> (oto-çalışmaz).
    ai_script_map: dict[int, AIExplanation] = {}
    if ai_available(ai_config):
        script_rows = await ai_cache.get_many(
            session, [f"script:{k}" for k in set(ai_keys.values())]
        )
        ai_script_map = {
            fid: script_rows[f"script:{k}"]
            for fid, k in ai_keys.items()
            if f"script:{k}" in script_rows
        }
    # Rapor yönetici özeti (#184): kapsam-bazlı anahtar; önceden üretilmişse ön-yükle.
    if batch is not None:
        ai_summary_scope, ai_summary_id = "batch", batch.id
    elif scan is not None:
        ai_summary_scope, ai_summary_id = "scan", scan.id
    else:
        ai_summary_scope, ai_summary_id = "all", 0
    ai_summary_key = f"summary:{ai_summary_scope}:{ai_summary_id}"
    ai_summary_row = await ai_cache.get_cached(session, ai_summary_key)
    # Müşteriye-teslim özeti (Dalga 1c): aynı veriden farklı ton; ayrı önbellek (:exec).
    ai_summary_exec_row = await ai_cache.get_cached(session, f"{ai_summary_key}:exec")
    # Düzeltme önceliklendirme anlatısı (Dalga 1b): sıra deterministik, AI yalnız gerekçelendirir.
    ai_priorities_key = f"priorities:{ai_summary_scope}:{ai_summary_id}"
    ai_priorities_row = await ai_cache.get_cached(session, ai_priorities_key)
    # Sömürü-zinciri + uyum anlatısı (Dalga 3): on-demand üretilir; üretilmişse rapora (HTML+PDF)
    # statik gömülür. Eskiden yalnız canlı sayfada HTMX ile görünüp yenilemede kayboluyordu.
    ai_exploit_chain_row = await ai_cache.get_cached(
        session, f"exploit-chain:{ai_summary_scope}:{ai_summary_id}"
    )
    ai_compliance_row = await ai_cache.get_cached(
        session, f"compliance:{ai_summary_scope}:{ai_summary_id}"
    )
    if scan is not None or batch is not None:
        asset_count = len({f.asset_id for f in findings if f.asset_id})
    else:
        asset_count = len(assets)
    if selected_cats or batch is not None:
        severity_counts: dict[str, int] = {}
        for f in findings:
            sv = f.severity.value if not isinstance(f.severity, str) else f.severity
            severity_counts[sv] = severity_counts.get(sv, 0) + 1
    else:
        severity_counts = await count_by_severity(session, scan_id=scan.id if scan else None)

    # Uyum (CIS) özeti + kontrolleri (VII-1a): kimlikli taramalardan türetilir.
    comp_scan_ids = scan_ids if batch is not None else ([scan.id] if scan is not None else [])
    compliance_checks = []
    compliance_data: dict[str, dict[str, int]] = {}
    for sid in comp_scan_ids:
        compliance_checks.extend(await compliance_for_scan(session, sid))
        for fw, bucket in (await compliance_summary(session, sid)).items():
            agg = compliance_data.setdefault(fw, {"pass": 0, "fail": 0, "total": 0, "score": 0})
            agg["pass"] += bucket["pass"]
            agg["fail"] += bucket["fail"]
            agg["total"] += bucket["total"]
    for bucket in compliance_data.values():
        bucket["score"] = round(bucket["pass"] / bucket["total"] * 100) if bucket["total"] else 0

    # Bulunan hostlar — web taramasında iç envanteri DEĞİL, taranan URL'lerin host'unu
    # (çözülen IP + şema/port) göster; diğer türlerde kapsam içi gerçek cihazlar (Asset/Service).
    web_report_scans = [s for s in report_scans if s.scan_type == ScanType.web]
    if report_scans and len(web_report_scans) == len(report_scans):
        # Tüm taramalar web → yalnız taranan hedef host'ları (envanter sızdırma yok).
        report_hosts = web_scan_host_entries(web_report_scans)
    else:
        if batch is not None:
            scope_targets = batch_targets
        elif scan is not None:
            scope_targets = [scan.target]
        else:
            scope_targets = []  # birleşik rapor → tüm envanter
        report_hosts = await hosts_in_scope(session, scope_targets)

    # Dizin/içerik taraması bulgularını AYRI bölümde göster (rapor + PDF); genel "Bulgular
    # ve Çözümler" listesinde tekrar etmesinler (önek tek kaynaktan: scanners.web).
    from cybersectool.scanners.web import DIRSCAN_FINDING_PREFIX

    dir_findings = [f for f in findings if f.title.startswith(DIRSCAN_FINDING_PREFIX)]
    findings_main = [f for f in findings if not f.title.startswith(DIRSCAN_FINDING_PREFIX)]
    # Bulguları SUNUCUYA (host) göre grupla → raporda hangi CVE hangi cihazda net olur.
    asset_by_id = {asset.id: asset for asset in assets}
    findings_main_by_host = _group_by_host(findings_main, asset_by_id, "")
    # Varlık risk hikâyesi (Dalga 2c): per-host, kapsam+asset bazlı önbellek; üretilmişse ön-yükle.
    ai_story_map: dict[int, AIExplanation] = {}
    if ai_available(ai_config):
        host_aids = [
            cast("int", g["asset_id"])
            for g in findings_main_by_host
            if g.get("asset_id") is not None
        ]
        if host_aids:
            story_keys = {
                aid: f"story:{ai_summary_scope}:{ai_summary_id}:asset:{aid}" for aid in host_aids
            }
            story_rows = await ai_cache.get_many(session, list(story_keys.values()))
            ai_story_map = {
                aid: story_rows[key] for aid, key in story_keys.items() if key in story_rows
            }

    # Exploit DENEME özeti (EXPLOIT-TRIED): "exploit var" ≠ "denendi/sömürüldü".
    if batch is not None:
        ex_scan_ids: list[int] | None = scan_ids
    elif scan is not None:
        ex_scan_ids = [scan.id]
    else:
        ex_scan_ids = None  # birleşik rapor → tüm denemeler
    # SR-1: sömürü yalnız Sömürme modunda beklenir (agresif CVE artık yalnız tespit eder).
    ex_expected = any(
        s.scan_type == ScanType.vuln and does_exploitation(s.mode) for s in report_scans
    )
    ex_attempts = await list_exploit_attempts(session, ex_scan_ids)
    exploit_overview = build_exploit_overview(ex_attempts, expected=ex_expected)
    # OSS çekirdek: sömürü ÇALIŞTIRMA eklentide; staged PoC raporu salt-bilgi (Çalıştır yok).
    exploitdb_exec_enabled = False
    exploitdb_staged = await annotate_exploitdb_runnable(
        session, exploitdb_staged_list(ex_attempts), exec_enabled=exploitdb_exec_enabled
    )

    return {
        "app_name": APP_NAME,
        "scan": scan,
        "batch": batch,
        "batch_targets": batch_targets,
        "findings": findings,
        "findings_main": findings_main,
        "findings_main_by_host": findings_main_by_host,
        "exploit_overview": exploit_overview,
        "exploitdb_staged": exploitdb_staged,
        "exploitdb_exec_enabled": exploitdb_exec_enabled,
        "dir_findings": dir_findings,
        "report_hosts": report_hosts,
        "compliance_checks": compliance_checks,
        "compliance_summary": compliance_data,
        "ip_by_id": ip_by_id,
        "cve_map": cve_map,
        "exploit_map": exploit_map,
        # Kullanılabilir exploit cephaneliği (#172) — yalnız BİLGİ; ex_expected False ise (güvenli/
        # agresif CVE) bant "DENENMEDİ" der, True (Sömürme modu) ise deneme durumu ayrı panelde.
        "exploit_arsenal": build_exploit_arsenal(cve_ids, exploit_map),
        "arsenal_runs_exploit": ex_expected,
        "remediation_map": remediation_map,
        "severity_counts": severity_counts,
        "asset_count": asset_count,
        "selected_categories": sorted(selected_cats),
        "kev_count": sum(1 for r in remediation_map.values() if r.kev),
        "exploit_count": sum(1 for e in exploit_map.values() if e.count > 0),
        "generated_at": format_local(datetime.now(UTC), "%Y-%m-%d %H:%M %Z"),
        # Yerel AI (#183-184): buton görünürlüğü + ön-yüklü açıklama/özet önbelleği.
        "ai_enabled": ai_available(ai_config),
        "ai_explain_map": ai_explain_map,
        "ai_summary": ai_summary_row.content if ai_summary_row else None,
        "ai_summary_model": ai_summary_row.model if ai_summary_row else "",
        "ai_summary_scope": ai_summary_scope,
        "ai_summary_id": ai_summary_id,
        "ai_summary_exec": ai_summary_exec_row.content if ai_summary_exec_row else None,
        "ai_summary_exec_model": ai_summary_exec_row.model if ai_summary_exec_row else "",
        "ai_priorities": ai_priorities_row.content if ai_priorities_row else None,
        "ai_priorities_model": ai_priorities_row.model if ai_priorities_row else "",
        "ai_exploit_chain": ai_exploit_chain_row.content if ai_exploit_chain_row else None,
        "ai_exploit_chain_model": ai_exploit_chain_row.model if ai_exploit_chain_row else "",
        "ai_compliance": ai_compliance_row.content if ai_compliance_row else None,
        "ai_compliance_model": ai_compliance_row.model if ai_compliance_row else "",
        "ai_script_map": ai_script_map,
        "ai_story_map": ai_story_map,
    }


def _ai_fragment(
    request: Request,
    *,
    content: str = "",
    model: str = "",
    cached: bool = False,
    error: str | None = None,
) -> Response:
    """Yerel AI üretim parçasını (HTMX yanıtı) render eder (#183)."""
    return templates.TemplateResponse(
        request,
        "_ai_explanation.html",
        {"content": content, "model": model, "cached": cached, "error": error},
    )


async def _ai_rate_guard(
    request: Request, user_id: int, t: Callable[[str], str]
) -> Response | None:
    """AI üretim kotası dolduysa görünür 'biraz sonra dene' parçası, değilse None (DoS koruması).

    Her /ai/* üretim rotasında, önbellek-ıskası + boş-veri erken-dönüşleri geçildikten SONRA,
    ``generate()`` çağrısından HEMEN ÖNCE çağrılır → yalnız gerçek (pahalı) üretim kotaya sayılır.

    NOT: HTMX 2.x varsayılanı 2xx-dışı yanıtı hedefe YAZMAZ (swap etmez); 429 dönersek kullanıcı
    rate-limit mesajını GÖRMEZ. Bu yüzden mevcut tüm AI hata parçaları gibi 200 + parça döneriz —
    asıl koruma zaten üretimin atlanmasıdır (durum kodu burada yalnız kozmetik olurdu).
    """
    wait = await ai_rate_limited(user_id)
    if wait:
        return _ai_fragment(request, error=t("ai_rate_limited").format(sec=wait))
    return None


# Sömürü-zinciri özeti (Dalga 3) için grounded bloklar. ÇIKTI DETERMİNİSTİK (AI yok): host bazında
# bulgular + GERÇEKLEŞMİŞ sömürü denemeleri; AI yalnız bu gerçek veriden zincir anlatısı kurar.
_CHAIN_MAX_HOSTS = 30
_CHAIN_MAX_PER_HOST = 15
_CHAIN_MAX_ATTEMPTS = 50


def _build_chain_blocks(
    findings: list[Finding],
    ip_by_id: dict[int, str],
    cve_map: dict[str, CVE],
    attempts: list[ExploitAttempt],
) -> tuple[str, str, int, int]:
    """(host-bazlı bulgu bloğu, sömürü bloğu, host sayısı, bulgu sayısı) üretir.

    Sömürü-zinciri prompt'unun grounded girdisi: bulgular host'a (asset_id→IP) göre gruplanır,
    her bulgu CVSS/KEV ile etiketlenir ve o host'ta CVE GERÇEKTEN sömürüldüyse 'SÖMÜRÜLDÜ' işareti
    konur (zincirin doğrulanmış dayanağı). ``findings`` zaten risk'e göre sıralı gelir.
    """
    exploited = {(a.host, a.cve_id) for a in attempts if a.success or a.status == "success"}
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        host = (ip_by_id.get(f.asset_id) if f.asset_id else None) or "host-atanmamış"
        groups.setdefault(host, []).append(f)
    host_lines: list[str] = []
    for host, fs in list(groups.items())[:_CHAIN_MAX_HOSTS]:
        # host/başlık ağ-kaynaklı (reverse-DNS/NetBIOS etiketi, servis afişi) → gömülü
        # yeni satır 'Host …:' satırı uydurabilir; sanitize_untrusted yapısal kaçışı keser.
        host_lines.append(f"Host {ai_prompts.sanitize_untrusted(host)}:")
        for f in fs[:_CHAIN_MAX_PER_HOST]:
            cid = f.cve_id or "(CVE yok)"
            sev = f.severity.value if not isinstance(f.severity, str) else f.severity
            cve = cve_map.get(f.cve_id) if f.cve_id else None
            tags: list[str] = []
            if cve is not None and cve.cvss_score is not None:
                tags.append(f"CVSS {cve.cvss_score}")
            if cve is not None and cve.kev_flag:
                tags.append("KEV")
            extra = f" [{', '.join(tags)}]" if tags else ""
            # Sömürü CVE-bağlı (ExploitAttempt.cve_id zorunlu); CVE'siz bulgu
            # sömürü-değerlendirmesine GİRMEZ → 'mevcut/SÖMÜRÜLDÜ' damgası yok
            # (yanlış 'mevcut' grounding'i bozardı).
            if f.cve_id is None:
                mark = ""
            elif (host, f.cve_id) in exploited:
                mark = " — SÖMÜRÜLDÜ"
            else:
                mark = " — mevcut"
            title = ai_prompts.sanitize_untrusted(f.title, empty="?")
            host_lines.append(f"  - {cid} ({title}) — {sev}{extra}{mark}")
    ex_lines: list[str] = []
    for a in attempts[:_CHAIN_MAX_ATTEMPTS]:
        succeeded = a.success or a.status == "success"
        st = "SÖMÜRÜLDÜ" if succeeded else (a.status or "denendi")
        ahost = ai_prompts.sanitize_untrusted(a.host, empty="?")
        amod = ai_prompts.sanitize_untrusted(a.module, empty="?")
        ex_lines.append(f"  - {ahost} — {a.cve_id} ({amod}) — {st} [{a.source}]")
    return "\n".join(host_lines), "\n".join(ex_lines), len(groups), len(findings)


@router.post("/ai/explain")
async def ai_explain_web(
    request: Request,
    session: SessionDep,
    finding_id: Annotated[int, Form()] = 0,
    cve_id: Annotated[str, Form()] = "",
    title: Annotated[str, Form()] = "",
) -> Response:
    """Bir bulgu/CVE için yerel AI açıklaması üretir (talep üzerine, önbellekli) — #183.

    İki giriş: ``finding_id`` (rapor; tam bağlam: servis+Remediation) ya da ``cve_id``
    (Zafiyetler sayfası; CVE-yalnız). Önbellek anahtarı her ikisinde ``cve:<id>`` olduğundan
    üretim paylaşılır. Login gerekli; AI kapalı/erişilemez → graceful hata parçası. Üretim
    grounded'dır (yalnız yerel CVE/servis verisi) → halüsinasyon azaltılır.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    lang = normalize_lang(request.cookies.get(LANG_COOKIE))
    t = translator(lang)
    row = await get_settings(session)
    config = AIConfig.from_app_settings(row)
    if not ai_available(config):
        return _ai_fragment(request, error=t("ai_disabled"))

    if finding_id:
        finding = await session.get(Finding, finding_id)
        if finding is None:
            return _ai_fragment(request, error=t("ai_finding_missing"))
        cve = None
        if finding.cve_id:
            cve = (await cves_by_ids(session, [finding.cve_id])).get(finding.cve_id)
        service = await session.get(Service, finding.service_id) if finding.service_id else None
        remediation = remediation_for(finding, cve, service)
        cache_key = ai_cache.finding_cache_key(cve_id=finding.cve_id, title=finding.title)
        prompt_pair = ai_prompts.build_finding_prompt(finding, cve, service, remediation)
    elif cve_id:
        cve = (await cves_by_ids(session, [cve_id])).get(cve_id)
        if cve is None:
            return _ai_fragment(request, error=t("ai_finding_missing"))
        cache_key = ai_cache.finding_cache_key(cve_id=cve_id, title=title or cve_id)
        prompt_pair = ai_prompts.build_cve_prompt(cve, title=title)
    else:
        return _ai_fragment(request, error=t("ai_finding_missing"))

    hit = await ai_cache.get_cached(session, cache_key)
    if hit is not None:
        return _ai_fragment(request, content=hit.content, model=hit.model, cached=True)
    system, prompt = prompt_pair
    guard = await _ai_rate_guard(request, user.id, t)
    if guard is not None:
        return guard
    text = await ai_service.generate(config, prompt, system=system)
    if not text:
        return _ai_fragment(request, error=t("ai_generate_failed"))
    stored = await ai_cache.store(session, cache_key, text, model=config.model)
    await log_action(session, "ai_explain", user_id=user.id, target=cache_key)
    return _ai_fragment(request, content=stored.content, model=stored.model, cached=False)


@router.post("/ai/ask")
async def ai_ask_web(
    request: Request,
    session: SessionDep,
    question: Annotated[str, Form()] = "",
) -> Response:
    """Uygulama yardımı Q&A (#B/#2c) — kullanıcı 'bunu nasıl yaparım' sorar, AI #A Yardım
    içeriğine GROUNDED yanıtlar (uydurmaz; kapsam dışı = 'yardımda yok' der). Login gerekli;
    AI kapalıysa graceful hata. Yanıt önbeleklenir (soru+içerik hash'i) → tekrar üretilmez.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    lang = normalize_lang(request.cookies.get(LANG_COOKIE))
    t = translator(lang)
    config = AIConfig.from_app_settings(await get_settings(session))
    if not ai_available(config):
        return _ai_fragment(request, error=t("ai_disabled"))
    q = question.strip()
    if not q:
        return _ai_fragment(request, error=t("ai_qa_empty"))
    grounding = help_grounding_text(lang)
    # Cache anahtarı prompt'la AYNI normalize edilmiş metinden türesin (sanitize + lower) →
    # özdeş prompt üreten girdiler tek cache satırını paylaşır (gereksiz üretim olmaz).
    q_norm = ai_prompts.sanitize_untrusted(q, max_len=300).lower()
    cache_key = f"qa:{lang}:{ai_cache.digest(q_norm + '|' + grounding)}"
    hit = await ai_cache.get_cached(session, cache_key)
    if hit is not None:
        return _ai_fragment(request, content=hit.content, model=hit.model, cached=True)
    system, prompt = ai_prompts.build_help_qa_prompt(q, grounding, lang)
    guard = await _ai_rate_guard(request, user.id, t)
    if guard is not None:
        return guard
    text = await ai_service.generate(config, prompt, system=system, lang=lang)
    if not text:
        return _ai_fragment(request, error=t("ai_generate_failed"))
    stored = await ai_cache.store(session, cache_key, text, model=config.model)
    await log_action(session, "ai_ask", user_id=user.id, target=f"qa:{lang}")
    return _ai_fragment(request, content=stored.content, model=stored.model, cached=False)


@router.post("/ai/summary")
async def ai_summary_web(
    request: Request,
    session: SessionDep,
    scope: Annotated[str, Form()] = "all",
    scope_id: Annotated[int, Form()] = 0,
    audience: Annotated[str, Form()] = "internal",
) -> Response:
    """Rapor için yerel AI yönetici özeti üretir (talep üzerine, önbellekli) — #184 + Dalga 1c.

    ``scope``: scan/batch/all. ``audience``: ``customer`` ise müşteriye-teslim tonu (ayrı
    önbellek ``:exec``), aksi halde iç yönetici tonu. İkisi de AYNI grounded veriden üretilir;
    yalnız ton + önbellek anahtarı ayrışır. Login gerekli; AI kapalı → graceful hata parçası.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    lang = normalize_lang(request.cookies.get(LANG_COOKIE))
    t = translator(lang)
    config = AIConfig.from_app_settings(await get_settings(session))
    if not ai_available(config):
        return _ai_fragment(request, error=t("ai_disabled"))
    scan = batch = None
    if scope == "scan":
        scan = await get_scan(session, scope_id)
        if scan is None:
            return _ai_fragment(request, error=t("ai_finding_missing"))
    elif scope == "batch":
        batch = await get_batch(session, scope_id)
        if batch is None:
            return _ai_fragment(request, error=t("ai_finding_missing"))
    ctx = await _gather_report_context(session, scan=scan, batch=batch)
    is_customer = audience == "customer"
    suffix = ":exec" if is_customer else ""
    cache_key = f"summary:{ctx['ai_summary_scope']}:{ctx['ai_summary_id']}{suffix}"
    hit = await ai_cache.get_cached(session, cache_key)
    if hit is not None:
        return _ai_fragment(request, content=hit.content, model=hit.model, cached=True)
    findings = cast("list[Finding]", ctx["findings"])
    if not findings:
        return _ai_fragment(request, error=t("ai_no_findings"))
    cve_map = cast("dict[str, CVE]", ctx["cve_map"])
    # En riskli ilk 8 bulgu (liste zaten risk'e göre sıralı) → özet odaklı kalsın.
    top: list[dict[str, object]] = []
    for f in findings[:8]:
        c = cve_map.get(f.cve_id) if f.cve_id else None
        top.append(
            {
                "title": f.title,
                "cve_id": f.cve_id or "",
                "severity": f.severity.value if not isinstance(f.severity, str) else f.severity,
                "cvss": c.cvss_score if c else None,
                "kev": bool(c and c.kev_flag),
            }
        )
    if scan is not None:
        target = scan.target
    elif batch is not None:
        target = ", ".join(cast("list[str]", ctx["batch_targets"]))
    else:
        target = "Tüm kapsam"
    system, prompt = ai_prompts.build_summary_prompt(
        target=target,
        host_count=cast("int", ctx["asset_count"]),
        severity_counts=cast("dict[str, int]", ctx["severity_counts"]),
        top_findings=top,
        audience=audience,
    )
    guard = await _ai_rate_guard(request, user.id, t)
    if guard is not None:
        return guard
    text = await ai_service.generate(config, prompt, system=system)
    if not text:
        return _ai_fragment(request, error=t("ai_generate_failed"))
    stored = await ai_cache.store(session, cache_key, text, model=config.model)
    await log_action(
        session,
        "ai_summary_exec" if is_customer else "ai_summary",
        user_id=user.id,
        target=cache_key,
    )
    return _ai_fragment(request, content=stored.content, model=stored.model, cached=False)


@router.post("/ai/priorities")
async def ai_priorities_web(
    request: Request,
    session: SessionDep,
    scope: Annotated[str, Form()] = "all",
    scope_id: Annotated[int, Form()] = 0,
) -> Response:
    """Rapor için yerel AI düzeltme önceliklendirme anlatısı (talep üzerine, önbellekli) — Dalga 1b.

    Sıralama DETERMİNİSTİK (``list_findings_by_risk`` — risk skoru) → AI YALNIZ gerekçelendirir,
    yeniden sıralamaz. ``scope``: scan/batch/all. Login gerekli; AI kapalı → graceful hata parçası.
    Grounded (yalnız yerel CVE/CVSS/KEV/EPSS) → halüsinasyon azaltılır.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    lang = normalize_lang(request.cookies.get(LANG_COOKIE))
    t = translator(lang)
    config = AIConfig.from_app_settings(await get_settings(session))
    if not ai_available(config):
        return _ai_fragment(request, error=t("ai_disabled"))
    scan = batch = None
    if scope == "scan":
        scan = await get_scan(session, scope_id)
        if scan is None:
            return _ai_fragment(request, error=t("ai_finding_missing"))
    elif scope == "batch":
        batch = await get_batch(session, scope_id)
        if batch is None:
            return _ai_fragment(request, error=t("ai_finding_missing"))
    ctx = await _gather_report_context(session, scan=scan, batch=batch)
    cache_key = f"priorities:{ctx['ai_summary_scope']}:{ctx['ai_summary_id']}"
    hit = await ai_cache.get_cached(session, cache_key)
    if hit is not None:
        return _ai_fragment(request, content=hit.content, model=hit.model, cached=True)
    findings = cast("list[Finding]", ctx["findings"])
    if not findings:
        return _ai_fragment(request, error=t("ai_no_findings"))
    cve_map = cast("dict[str, CVE]", ctx["cve_map"])
    ip_by_id = cast("dict[int, str]", ctx["ip_by_id"])
    # Liste zaten risk'e göre sıralı (list_findings_by_risk); ilk 10'u DETERMİNİSTİK sırayla geç.
    ranked: list[dict[str, object]] = []
    for f in findings[:10]:
        c = cve_map.get(f.cve_id) if f.cve_id else None
        ranked.append(
            {
                "title": f.title,
                "cve_id": f.cve_id or "",
                "severity": f.severity.value if not isinstance(f.severity, str) else f.severity,
                "cvss": c.cvss_score if c else None,
                "kev": bool(c and c.kev_flag),
                "epss": round(c.epss_score * 100) if c and c.epss_score is not None else None,
                "asset": ip_by_id.get(f.asset_id, "") if f.asset_id else "",
            }
        )
    if scan is not None:
        target = scan.target
    elif batch is not None:
        target = ", ".join(cast("list[str]", ctx["batch_targets"]))
    else:
        target = "Tüm kapsam"
    system, prompt = ai_prompts.build_priorities_prompt(target=target, ranked_findings=ranked)
    guard = await _ai_rate_guard(request, user.id, t)
    if guard is not None:
        return guard
    text = await ai_service.generate(config, prompt, system=system)
    if not text:
        return _ai_fragment(request, error=t("ai_generate_failed"))
    stored = await ai_cache.store(session, cache_key, text, model=config.model)
    await log_action(session, "ai_priorities", user_id=user.id, target=cache_key)
    return _ai_fragment(request, content=stored.content, model=stored.model, cached=False)


@router.post("/ai/exploit-chain")
async def ai_exploit_chain_web(
    request: Request,
    session: SessionDep,
    scope: Annotated[str, Form()] = "all",
    scope_id: Annotated[int, Form()] = 0,
) -> Response:
    """Tarama kapsamı için yerel AI sömürü-zinciri özeti (salt-okunur — Dalga 3).

    Bulguları + GERÇEKLEŞMİŞ sömürü denemelerini birleştirip bir saldırganın izleyebileceği olası
    sömürü zincirini (GİRİŞ NOKTASI / ZİNCİR ADIMLARI / ETKİ / KIRILMA NOKTASI) Türkçe anlatır —
    ÇALIŞTIRILABİLİR komut ÜRETMEZ. ``scope``: scan/batch/all. Login gerekli; AI kapalı veya
    zincirlenecek veri yok → graceful parça. GROUNDING: yalnız taramanın gerçek host/CVE/sömürü
    verisi (SÖMÜRÜLDÜ adımları doğrulanmış, mevcut bulgular olası) → halüsinasyon düşük.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    lang = normalize_lang(request.cookies.get(LANG_COOKIE))
    t = translator(lang)
    config = AIConfig.from_app_settings(await get_settings(session))
    if not ai_available(config):
        return _ai_fragment(request, error=t("ai_disabled"))
    scan = batch = None
    if scope == "scan":
        scan = await get_scan(session, scope_id)
        if scan is None:
            return _ai_fragment(request, error=t("ai_finding_missing"))
    elif scope == "batch":
        batch = await get_batch(session, scope_id)
        if batch is None:
            return _ai_fragment(request, error=t("ai_finding_missing"))
    ctx = await _gather_report_context(session, scan=scan, batch=batch)
    cache_key = f"exploit-chain:{ctx['ai_summary_scope']}:{ctx['ai_summary_id']}"
    hit = await ai_cache.get_cached(session, cache_key)
    if hit is not None:
        return _ai_fragment(request, content=hit.content, model=hit.model, cached=True)
    findings = cast("list[Finding]", ctx["findings"])
    ip_by_id = cast("dict[int, str]", ctx["ip_by_id"])
    cve_map = cast("dict[str, CVE]", ctx["cve_map"])
    if batch is not None:
        chain_scan_ids: list[int] | None = [s.id for s in await batch_scans(session, batch.id)]
    elif scan is not None:
        chain_scan_ids = [scan.id]
    else:
        chain_scan_ids = None
    attempts = await list_exploit_attempts(session, chain_scan_ids)
    # Zincirlenecek hiçbir gerçek veri yoksa AI'yı hiç çağırma (halüsinasyon yok), graceful parça.
    if not findings and not attempts:
        return _ai_fragment(request, error=t("ai_chain_no_data"))
    hosts_block, exploited_block, host_count, finding_count = _build_chain_blocks(
        findings, ip_by_id, cve_map, attempts
    )
    truncated = len(hosts_block) > 8000 or len(exploited_block) > 4000
    if scan is not None:
        scope_label = f"Tarama #{scan.id} — {scan.target}"
    elif batch is not None:
        scope_label = f"Tarama işi: {batch.name}"
    else:
        scope_label = "Tüm bulgular"
    system, prompt = ai_prompts.build_exploit_chain_prompt(
        scope_label=scope_label,
        hosts_block=hosts_block[:8000],
        exploited_block=exploited_block[:4000],
        host_count=host_count,
        finding_count=finding_count,
        truncated=truncated,
    )
    guard = await _ai_rate_guard(request, user.id, t)
    if guard is not None:
        return guard
    text = await ai_service.generate(config, prompt, system=system)
    if not text:
        return _ai_fragment(request, error=t("ai_generate_failed"))
    stored = await ai_cache.store(session, cache_key, text, model=config.model)
    await log_action(session, "ai_exploit_chain", user_id=user.id, target=cache_key)
    return _ai_fragment(request, content=stored.content, model=stored.model, cached=False)


@router.post("/ai/trend")
async def ai_trend_web(request: Request, session: SessionDep) -> Response:
    """Kuruluş geneli zafiyet trend SAYILARINDAN yerel AI yönetici anlatısı (salt-okunur — Dalga 3).

    vuln_lifecycle_stats + vuln_trend'in GERÇEK sayılarından DURUM / SON 7 GÜN / 8 HAFTALIK YÖN /
    ODAK anlatısı üretir — komut/CVE/host ÜRETMEZ. Login gerekli; AI kapalı veya hiç zafiyet yok →
    graceful parça. Önbellek anahtarı sayıların hash'i (``trend:{digest}``): sayılar değişince taze
    anlatı, aynıyken anında önbellek. GROUNDING: yalnız yerel trend sayıları → halüsinasyon düşük.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    lang = normalize_lang(request.cookies.get(LANG_COOKIE))
    t = translator(lang)
    config = AIConfig.from_app_settings(await get_settings(session))
    if not ai_available(config):
        return _ai_fragment(request, error=t("ai_disabled"))
    lifecycle = await vuln_lifecycle_stats(session)
    trend = await vuln_trend(session, weeks=8)
    open_total = cast("int", trend["open_total"])
    resolved_total = cast("int", trend["resolved_total"])
    # Hiç zafiyet yoksa AI'yı çağırma (halüsinasyon yok), graceful parça.
    if not open_total and not resolved_total:
        return _ai_fragment(request, error=t("ai_trend_no_data"))
    # Sayı-hash'li önbellek: trend değişince (yeni/çözülen) taze anlatı; aynı sayılarda anında hit.
    sig = json.dumps({"lc": lifecycle, "tr": trend}, sort_keys=True, default=str)
    digest = ai_cache.digest(sig)
    cache_key = f"trend:{digest}"
    hit = await ai_cache.get_cached(session, cache_key)
    if hit is not None:
        return _ai_fragment(request, content=hit.content, model=hit.model, cached=True)
    system, prompt = ai_prompts.build_trend_prompt(
        open_total=open_total,
        resolved_total=resolved_total,
        new_7d=cast("int", lifecycle["new_7d"]),
        resolved_7d=cast("int", lifecycle["resolved_7d"]),
        regressions=cast("int", lifecycle["regressions"]),
        aging_30d=cast("int", lifecycle["aging_30d"]),
        mttr_days=cast("float | None", trend["mttr_days"]),
        aging=cast("dict[str, int]", trend["aging"]),
        points=cast("list[dict[str, object]]", trend["points"]),
    )
    guard = await _ai_rate_guard(request, user.id, t)
    if guard is not None:
        return guard
    text = await ai_service.generate(config, prompt, system=system)
    if not text:
        return _ai_fragment(request, error=t("ai_generate_failed"))
    stored = await ai_cache.store(session, cache_key, text, model=config.model)
    await log_action(session, "ai_trend", user_id=user.id, target=cache_key)
    return _ai_fragment(request, content=stored.content, model=stored.model, cached=False)


@router.post("/ai/compliance")
async def ai_compliance_web(
    request: Request,
    session: SessionDep,
    scope: Annotated[str, Form()] = "all",
    scope_id: Annotated[int, Form()] = 0,
) -> Response:
    """Rapor için yerel AI uyum anlatısı (salt-okunur — Dalga 3).

    CIS sertleştirme skorları + KVKK/ISO/PCI mevzuat eşlemesi + önem sırasıyla başarısız
    kontrollerden GENEL UYUM / MEVZUAT / KRİTİK AÇIKLAR / ÖNCELİK anlatısı üretir — komut ÜRETMEZ.
    ``scope``: scan/batch/all. Login gerekli; AI kapalı veya uyum verisi yok → graceful parça.
    GROUNDING: yalnız yerel ComplianceCheck skor/kontrol verisi → halüsinasyon düşük.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    lang = normalize_lang(request.cookies.get(LANG_COOKIE))
    t = translator(lang)
    config = AIConfig.from_app_settings(await get_settings(session))
    if not ai_available(config):
        return _ai_fragment(request, error=t("ai_disabled"))
    scan = batch = None
    if scope == "scan":
        scan = await get_scan(session, scope_id)
        if scan is None:
            return _ai_fragment(request, error=t("ai_finding_missing"))
    elif scope == "batch":
        batch = await get_batch(session, scope_id)
        if batch is None:
            return _ai_fragment(request, error=t("ai_finding_missing"))
    ctx = await _gather_report_context(session, scan=scan, batch=batch)
    cache_key = f"compliance:{ctx['ai_summary_scope']}:{ctx['ai_summary_id']}"
    hit = await ai_cache.get_cached(session, cache_key)
    if hit is not None:
        return _ai_fragment(request, content=hit.content, model=hit.model, cached=True)
    compliance_summary = cast("dict[str, dict[str, int]]", ctx["compliance_summary"])
    # Uyum verisi yoksa (kimliksiz tarama → kontrol yok) AI'yı çağırma, graceful parça.
    if not compliance_summary:
        return _ai_fragment(request, error=t("ai_compliance_no_data"))
    checks = cast("list[ComplianceCheck]", ctx["compliance_checks"])
    cis_scores: list[dict[str, object]] = [
        {"framework": fw, "score": b["score"], "passed": b["pass"], "total": b["total"]}
        for fw, b in compliance_summary.items()
    ]
    reg_scores: list[dict[str, object]] = [
        {"regulation": r.regulation, "score": r.score, "passed": r.passed, "failed": r.failed}
        for r in regulation_summary(checks).values()
    ]
    # Başarısız kontroller: önem sırasıyla ilk 12 (somut, eyleme dönük açıklar).
    _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def _sev(c: ComplianceCheck) -> str:
        return c.severity.value if c.severity is not None else "high"

    failed_controls: list[dict[str, object]] = [
        {
            "framework": c.framework,
            "control_id": c.control_id,
            "title": c.title,
            "severity": _sev(c),
        }
        for c in sorted(
            (c for c in checks if c.status == "fail"), key=lambda c: _sev_rank.get(_sev(c), 1)
        )[:12]
    ]
    # scope_label'da yalnız sayısal kimlik (kullanıcı serbest-metni target/name DEĞİL) →
    # prompt-enjeksiyon yüzeyini kapat; uyum anlatısı için hedef IP zaten gereksiz.
    if scan is not None:
        scope_label = f"Tarama #{scan.id}"
    elif batch is not None:
        scope_label = f"Tarama işi #{batch.id}"
    else:
        scope_label = "Tüm kapsam"
    system, prompt = ai_prompts.build_compliance_prompt(
        scope_label=scope_label,
        cis_scores=cis_scores,
        reg_scores=reg_scores,
        failed_controls=failed_controls,
    )
    guard = await _ai_rate_guard(request, user.id, t)
    if guard is not None:
        return guard
    text = await ai_service.generate(config, prompt, system=system)
    if not text:
        return _ai_fragment(request, error=t("ai_generate_failed"))
    stored = await ai_cache.store(session, cache_key, text, model=config.model)
    await log_action(session, "ai_compliance", user_id=user.id, target=cache_key)
    return _ai_fragment(request, content=stored.content, model=stored.model, cached=False)


@router.post("/ai/remediation-script")
async def ai_remediation_script_web(
    request: Request,
    session: SessionDep,
    finding_id: Annotated[int, Form()] = 0,
) -> Response:
    """Bir bulgu için KOPYALANABİLİR düzeltme script TASLAĞI üretir (Dalga 2; önbellekli).

    Çıktı taslaktır — operatör ÇALIŞTIRMADAN inceler, ASLA oto-çalışmaz (salt-metin). Grounded
    (servis/CVE/mevcut Remediation). Login gerekli; AI kapalı → graceful. Önbellek script:<key>.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    lang = normalize_lang(request.cookies.get(LANG_COOKIE))
    t = translator(lang)
    config = AIConfig.from_app_settings(await get_settings(session))
    if not ai_available(config):
        return _ai_fragment(request, error=t("ai_disabled"))
    if not finding_id:
        return _ai_fragment(request, error=t("ai_finding_missing"))
    finding = await session.get(Finding, finding_id)
    if finding is None:
        return _ai_fragment(request, error=t("ai_finding_missing"))
    cache_key = f"script:{ai_cache.finding_cache_key(cve_id=finding.cve_id, title=finding.title)}"
    hit = await ai_cache.get_cached(session, cache_key)
    if hit is not None:
        return _ai_fragment(request, content=hit.content, model=hit.model, cached=True)
    cve = None
    if finding.cve_id:
        cve = (await cves_by_ids(session, [finding.cve_id])).get(finding.cve_id)
    service = await session.get(Service, finding.service_id) if finding.service_id else None
    remediation = remediation_for(finding, cve, service)
    system, prompt = ai_prompts.build_remediation_script_prompt(
        title=finding.title,
        severity=str(getattr(finding.severity, "value", finding.severity) or ""),
        cve_id=finding.cve_id,
        cve=cve,
        service=service,
        remediation=remediation,
    )
    guard = await _ai_rate_guard(request, user.id, t)
    if guard is not None:
        return guard
    text = await ai_service.generate(config, prompt, system=system)
    if not text:
        return _ai_fragment(request, error=t("ai_generate_failed"))
    stored = await ai_cache.store(session, cache_key, text, model=config.model)
    await log_action(session, "ai_remediation_script", user_id=user.id, target=cache_key)
    return _ai_fragment(request, content=stored.content, model=stored.model, cached=False)


@router.post("/ai/asset-story")
async def ai_asset_story_web(
    request: Request,
    session: SessionDep,
    asset_id: Annotated[int, Form()] = 0,
    scope: Annotated[str, Form()] = "all",
    scope_id: Annotated[int, Form()] = 0,
) -> Response:
    """Tek bir cihaz (host) için yalnız o cihazın bulgularına dayalı AI risk hikâyesi (Dalga 2).

    ``scope``: scan/batch/all (bulgu kapsamı). Grounded (yalnız host bulguları). Login gerekli;
    AI kapalı → graceful. Önbellek story:<scope>:<id>:asset:<asset_id>.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    lang = normalize_lang(request.cookies.get(LANG_COOKIE))
    t = translator(lang)
    config = AIConfig.from_app_settings(await get_settings(session))
    if not ai_available(config):
        return _ai_fragment(request, error=t("ai_disabled"))
    if not asset_id:
        return _ai_fragment(request, error=t("ai_finding_missing"))
    scan = batch = None
    if scope == "scan":
        scan = await get_scan(session, scope_id)
        if scan is None:
            return _ai_fragment(request, error=t("ai_finding_missing"))
    elif scope == "batch":
        batch = await get_batch(session, scope_id)
        if batch is None:
            return _ai_fragment(request, error=t("ai_finding_missing"))
    ctx = await _gather_report_context(session, scan=scan, batch=batch)
    cache_key = f"story:{ctx['ai_summary_scope']}:{ctx['ai_summary_id']}:asset:{asset_id}"
    hit = await ai_cache.get_cached(session, cache_key)
    if hit is not None:
        return _ai_fragment(request, content=hit.content, model=hit.model, cached=True)
    groups = cast("list[dict[str, object]]", ctx["findings_main_by_host"])
    grp = next((g for g in groups if g.get("asset_id") == asset_id), None)
    items = cast("list[Finding]", grp["items"]) if grp else []
    if not items:
        return _ai_fragment(request, error=t("ai_no_findings"))
    cve_map = cast("dict[str, CVE]", ctx["cve_map"])
    findings_data: list[dict[str, object]] = []
    for f in items[:12]:
        c = cve_map.get(f.cve_id) if f.cve_id else None
        findings_data.append(
            {
                "title": f.title,
                "cve_id": f.cve_id or "",
                "severity": f.severity.value if not isinstance(f.severity, str) else f.severity,
                "cvss": c.cvss_score if c else None,
                "kev": bool(c and c.kev_flag),
            }
        )
    system, prompt = ai_prompts.build_asset_story_prompt(
        label=str(grp["label"]) if grp else "",
        ip=cast("str | None", grp["ip"]) if grp else None,
        findings=findings_data,
    )
    guard = await _ai_rate_guard(request, user.id, t)
    if guard is not None:
        return guard
    text = await ai_service.generate(config, prompt, system=system)
    if not text:
        return _ai_fragment(request, error=t("ai_generate_failed"))
    stored = await ai_cache.store(session, cache_key, text, model=config.model)
    await log_action(session, "ai_asset_story", user_id=user.id, target=cache_key)
    return _ai_fragment(request, content=stored.content, model=stored.model, cached=False)


def _pdf_response(pdf_bytes: bytes, filename: str) -> Response:
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


_PDF_UNAVAILABLE = PlainTextResponse(
    "PDF üretimi bu ortamda kullanılamıyor (WeasyPrint yerel kütüphaneleri eksik).",
    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
)


@router.get("/report", response_class=HTMLResponse)
async def report_list_page(request: Request, session: SessionDep) -> Response:
    """Rapor listesi: tarama işleri (ScanBatch, isimli tek satır) + tekil taramalar."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    epoch = datetime.min.replace(tzinfo=UTC)
    entries: list[dict[str, object]] = []
    # Tarama işleri (isimli, tek satır)
    batch_counts = await count_findings_by_batch(session)
    for b in await list_batches(session):
        bscans = await batch_scans(session, b.id)
        entries.append(
            {
                "name": b.name,
                "scope": f"{len(bscans)} hedef",
                "type": b.mode.value,
                "status": batch_status(bscans).value,
                "findings": batch_counts.get(b.id, 0),
                "date": b.created_at,
                "view": f"/report/batch/{b.id}",
                "pdf": f"/report/batch/{b.id}/pdf",
                "kind": "batch",
                "del": f"/report/batch/{b.id}/delete",
            }
        )
    # Tekil taramalar (bir batch'e ait olmayanlar — isimsiz eski/tekil kayıtlar)
    scan_counts = await count_findings_by_scan(session)
    for s in await list_scans(session):
        if s.batch_id is not None:
            continue
        entries.append(
            {
                "name": "—",
                "scope": s.target,
                "type": s.scan_type.value,
                "status": s.status.value,
                "findings": scan_counts.get(s.id, 0),
                "date": s.created_at,
                "view": f"/report/{s.id}",
                "pdf": f"/report/{s.id}/pdf",
                "kind": "scan",
                "del": f"/report/{s.id}/delete",
            }
        )
    entries.sort(key=lambda e: e["date"] or epoch, reverse=True)  # type: ignore[arg-type,return-value]
    return templates.TemplateResponse(
        request,
        "report_list.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "entries": entries,
            "can_delete": user.role == Role.admin,
            "message": request.query_params.get("msg"),
        },
    )


@router.get("/report/pdf")
async def report_pdf(request: Request, session: SessionDep) -> Response:
    """Birleşik (tüm taramalar) PDF raporu."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    context = await _gather_report_context(session)
    html = templates.get_template("report_pdf.html").render(context)
    try:
        pdf_bytes = render_html_to_pdf(html)
    except PdfUnavailableError:
        return _PDF_UNAVAILABLE
    return _pdf_response(
        pdf_bytes, f"kangalis-rapor-{datetime.now(UTC).strftime('%Y%m%d-%H%M')}.pdf"
    )


@router.get("/report/{scan_id}", response_class=HTMLResponse)
async def report_scan_page(request: Request, session: SessionDep, scan_id: int) -> Response:
    """Tek bir taramanın raporu (yalnızca o taramanın bulguları)."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    scan = await get_scan(session, scan_id)
    if scan is None:
        return RedirectResponse(
            f"/report?msg={quote('Tarama bulunamadı.')}", status_code=status.HTTP_303_SEE_OTHER
        )
    context = await _gather_report_context(session, scan=scan)
    context["user"] = user  # Kangalis kabuğu (sidebar) için gerekli
    return templates.TemplateResponse(request, "report.html", context)


@router.get("/report/{scan_id}/pdf")
async def report_scan_pdf(request: Request, session: SessionDep, scan_id: int) -> Response:
    """Tek bir taramanın PDF raporu."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    scan = await get_scan(session, scan_id)
    if scan is None:
        return RedirectResponse(
            f"/report?msg={quote('Tarama bulunamadı.')}", status_code=status.HTTP_303_SEE_OTHER
        )
    context = await _gather_report_context(session, scan=scan)
    html = templates.get_template("report_pdf.html").render(context)
    try:
        pdf_bytes = render_html_to_pdf(html)
    except PdfUnavailableError:
        return _PDF_UNAVAILABLE
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    return _pdf_response(pdf_bytes, f"kangalis-rapor-tarama-{scan_id}-{stamp}.pdf")


@router.get("/report/{scan_id}/compliance.pdf")
async def report_compliance_pdf(request: Request, session: SessionDep, scan_id: int) -> Response:
    """Uyum raporu PDF (VII-1c): CIS sonuçları KVKK/ISO 27001/PCI-DSS maddelerine eşlenir."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    scan = await get_scan(session, scan_id)
    if scan is None:
        return RedirectResponse(
            f"/report?msg={quote('Tarama bulunamadı.')}", status_code=status.HTTP_303_SEE_OTHER
        )
    checks = await compliance_for_scan(session, scan_id)
    context = {
        "app_name": APP_NAME,
        "scan": scan,
        "regulations": regulation_summary(checks),
        "generated_at": format_local(datetime.now(UTC), "%Y-%m-%d %H:%M %Z"),
    }
    html = templates.get_template("report_compliance_pdf.html").render(context)
    try:
        pdf_bytes = render_html_to_pdf(html)
    except PdfUnavailableError:
        return _PDF_UNAVAILABLE
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    return _pdf_response(pdf_bytes, f"kangalis-uyum-raporu-{scan_id}-{stamp}.pdf")


@router.get("/report/batch/{batch_id}", response_class=HTMLResponse)
async def report_batch_page(request: Request, session: SessionDep, batch_id: int) -> Response:
    """Bir tarama işinin (ScanBatch) raporu — tüm üye taramaların bulguları toplanır."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    batch = await get_batch(session, batch_id)
    if batch is None:
        return RedirectResponse(
            f"/report?msg={quote('Tarama işi bulunamadı.')}", status_code=status.HTTP_303_SEE_OTHER
        )
    context = await _gather_report_context(session, batch=batch)
    context["user"] = user
    return templates.TemplateResponse(request, "report.html", context)


@router.get("/report/batch/{batch_id}/pdf")
async def report_batch_pdf(request: Request, session: SessionDep, batch_id: int) -> Response:
    """Bir tarama işinin (ScanBatch) PDF raporu."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    batch = await get_batch(session, batch_id)
    if batch is None:
        return RedirectResponse(
            f"/report?msg={quote('Tarama işi bulunamadı.')}", status_code=status.HTTP_303_SEE_OTHER
        )
    context = await _gather_report_context(session, batch=batch)
    html = templates.get_template("report_pdf.html").render(context)
    try:
        pdf_bytes = render_html_to_pdf(html)
    except PdfUnavailableError:
        return _PDF_UNAVAILABLE
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    return _pdf_response(pdf_bytes, f"kangalis-rapor-isi-{batch_id}-{stamp}.pdf")


@router.post("/report/batch/{batch_id}/delete")
async def report_delete_batch(request: Request, session: SessionDep, batch_id: int) -> Response:
    """Bir tarama işi (ScanBatch) raporunu siler — üye taramaları/bulguları cascade ile gider."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await delete_batch(session, batch_id)
    await log_action(session, "report_delete", user_id=user.id, target=f"batch:{batch_id}")
    return RedirectResponse(
        f"/report?msg={quote('Rapor silindi.')}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/report/{scan_id}/delete")
async def report_delete_scan(request: Request, session: SessionDep, scan_id: int) -> Response:
    """Tekil bir tarama raporunu siler — bulguları cascade ile birlikte gider."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await delete_scan(session, scan_id)
    await log_action(session, "report_delete", user_id=user.id, target=f"scan:{scan_id}")
    return RedirectResponse(
        f"/report?msg={quote('Rapor silindi.')}", status_code=status.HTTP_303_SEE_OTHER
    )


async def _render_tokens(
    request: Request,
    session: AsyncSession,
    user: User,
    *,
    new_token: str | None = None,
    error: str | None = None,
    message: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> Response:
    return templates.TemplateResponse(
        request,
        "tokens.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "tokens": await list_user_tokens(session, user.id),
            "new_token": new_token,
            "error": error,
            "message": message,
        },
        status_code=status_code,
    )


@router.get("/tokens", response_class=HTMLResponse)
async def tokens_page(request: Request, session: SessionDep) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    return await _render_tokens(request, session, user, message=request.query_params.get("msg"))


@router.get("/system", response_class=HTMLResponse)
async def system_page(request: Request, session: SessionDep) -> Response:
    """Sistem/Servisler — platform konteynerlerinin durumu + CPU/RAM/disk (yalnız admin)."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "system.html", {"app_name": APP_NAME, "user": user})


@router.get("/system/panel", response_class=HTMLResponse)
async def system_panel(request: Request, session: SessionDep) -> Response:
    """Sistem paneli HTMX parçası (her 5 sn yenilenir) — konteyner durum + kaynak."""
    user = await _current_user(request, session)
    if user is None:
        return PlainTextResponse("", status_code=status.HTTP_401_UNAUTHORIZED)
    if user.role != Role.admin:
        return PlainTextResponse("", status_code=status.HTTP_403_FORBIDDEN)
    return templates.TemplateResponse(
        request, "system_panel.html", {"health": await system_health(), "user": user}
    )


@router.post("/tokens/create")
async def create_token_web(
    request: Request,
    session: SessionDep,
    name: Annotated[str, Form()],
    expires_days: Annotated[int, Form()] = 0,
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    clean_name = name.strip()
    if not clean_name:
        return await _render_tokens(
            request, session, user, error="Token adı boş olamaz.", status_code=400
        )
    expires_at = None
    if expires_days and expires_days > 0:
        expires_at = datetime.now(UTC) + timedelta(days=expires_days)
    _token, raw = await create_api_token(session, user.id, clean_name[:100], expires_at)
    await log_action(session, "token_create", user_id=user.id, target=clean_name)
    return await _render_tokens(request, session, user, new_token=raw)


@router.post("/tokens/{token_id}/revoke")
async def revoke_token_web(request: Request, session: SessionDep, token_id: int) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if await revoke_user_token(session, token_id, user.id):
        await log_action(session, "token_revoke", user_id=user.id, target=str(token_id))
    return RedirectResponse("/tokens?msg=Token+iptal+edildi", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/schedules", response_class=HTMLResponse)
async def schedules_page(request: Request, session: SessionDep) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    return templates.TemplateResponse(
        request,
        "schedules.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "schedules": await list_schedules(session),
            "message": request.query_params.get("msg"),
        },
    )


def _parse_datetime_local(value: str) -> datetime | None:
    """HTML datetime-local ('YYYY-MM-DDTHH:MM') → UTC datetime (boşsa None)."""
    value = value.strip()
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


@router.post("/schedules/{schedule_id}/toggle")
async def toggle_schedule_web(request: Request, session: SessionDep, schedule_id: int) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/schedules", status_code=status.HTTP_303_SEE_OTHER)
    schedule = await get_schedule(session, schedule_id)
    if schedule is not None:
        await set_schedule_active(session, schedule_id, not schedule.is_active)
    return RedirectResponse("/schedules", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/schedules/{schedule_id}/delete")
async def delete_schedule_web(request: Request, session: SessionDep, schedule_id: int) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/schedules", status_code=status.HTTP_303_SEE_OTHER)
    await delete_schedule(session, schedule_id)
    await log_action(session, "schedule_delete", user_id=user.id, target=str(schedule_id))
    return RedirectResponse("/schedules", status_code=status.HTTP_303_SEE_OTHER)


async def _users_page(
    request: Request,
    session: AsyncSession,
    user: User,
    *,
    results: list[object] | None = None,
    query: str = "",
    groups: list[object] | None = None,
    ous: list[object] | None = None,
    error: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> Response:
    return templates.TemplateResponse(
        request,
        "users.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "users": await list_users(session),
            "roles": [r.value for r in Role],
            "ldap_config": await get_ldap_config(session),
            "results": results,
            "query": query,
            "groups": groups,
            "ous": ous,
            "error": error,
            "message": request.query_params.get("msg"),
        },
        status_code=status_code,
    )


@router.get("/users", response_class=HTMLResponse)
async def users_page(
    request: Request, session: SessionDep, q: str = "", show: str = ""
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    results: list[object] | None = None
    groups: list[object] | None = None
    ous: list[object] | None = None
    error: str | None = None
    config = await get_ldap_config(session)
    configured = config is not None and bool(config.server_uri) and bool(config.base_dn)
    verify_cert, ca_cert = await _ldaps_tls(session)
    if q:
        if not configured or config is None:
            error = "Önce LDAP bağlantısını (sunucu + base DN) yapılandırın."
        else:
            try:
                results = list(
                    await ldap_search_users(
                        config,
                        get_bind_password(config),
                        q,
                        verify_cert=verify_cert,
                        ca_cert=ca_cert,
                    )
                )
            except LdapSearchError as exc:
                error = str(exc)
    # 'Grupları gör' → OU + güvenlik grupları (grup seçilince üyeler içe aktarılır).
    if show == "groups":
        if not configured or config is None:
            error = "Önce LDAP bağlantısını (sunucu + base DN) yapılandırın."
        else:
            try:
                pw = get_bind_password(config)
                ous = list(
                    await ldap_list_ous(config, pw, verify_cert=verify_cert, ca_cert=ca_cert)
                )
                groups = list(
                    await ldap_list_groups(config, pw, verify_cert=verify_cert, ca_cert=ca_cert)
                )
            except LdapSearchError as exc:
                error = str(exc)
    return await _users_page(
        request, session, user, results=results, query=q, groups=groups, ous=ous, error=error
    )


@router.post("/users/create")
async def create_user_web(
    request: Request,
    session: SessionDep,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    role: Annotated[str, Form()] = "viewer",
    email: Annotated[str, Form()] = "",
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    if not username.strip() or not password:
        return await _users_page(
            request,
            session,
            user,
            error="Kullanıcı adı ve parola gerekli.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    settings_row = await get_settings(session)
    pw_error = validate_password(
        password,
        min_length=settings_row.password_min_length,
        require_complexity=settings_row.password_require_complexity,
    )
    if pw_error is not None:
        return await _users_page(
            request, session, user, error=pw_error, status_code=status.HTTP_400_BAD_REQUEST
        )
    if await get_user_by_username(session, username) is not None:
        return await _users_page(
            request,
            session,
            user,
            error=f"'{username}' zaten var.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    try:
        new_role = Role(role)
    except ValueError:
        new_role = Role.viewer
    await create_user(session, username, password, role=new_role, email=email.strip() or None)
    await log_action(session, "user_create", user_id=user.id, target=username)
    return RedirectResponse("/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}/role")
async def set_user_role_web(
    request: Request, session: SessionDep, user_id: int, role: Annotated[str, Form()]
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin or user_id == user.id:  # kendi rolünü değiştiremez
        return RedirectResponse("/users", status_code=status.HTTP_303_SEE_OTHER)
    try:
        await set_user_role(session, user_id, Role(role))
        await log_action(session, "user_role", user_id=user.id, target=f"{user_id}->{role}")
    except ValueError:
        pass
    return RedirectResponse("/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}/toggle")
async def toggle_user_web(request: Request, session: SessionDep, user_id: int) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin or user_id == user.id:  # kendini pasifleştiremez
        return RedirectResponse("/users", status_code=status.HTTP_303_SEE_OTHER)
    target = await get_user_by_id(session, user_id)
    if target is not None:
        await set_user_active(session, user_id, not target.is_active)
        await log_action(session, "user_toggle", user_id=user.id, target=str(user_id))
    # Yönetim artık düzenle alanında — işlemden sonra oraya geri dön (X-5).
    return RedirectResponse(f"/users/{user_id}/edit", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}/delete")
async def delete_user_web(request: Request, session: SessionDep, user_id: int) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin or user_id == user.id:  # kendini silemez
        return RedirectResponse("/users", status_code=status.HTTP_303_SEE_OTHER)
    await delete_user(session, user_id)
    await log_action(session, "user_delete", user_id=user.id, target=str(user_id))
    return RedirectResponse("/users", status_code=status.HTTP_303_SEE_OTHER)


# --- LDAP kullanıcı yönetimi (admin): bağlantı + arama + içe aktarma ---


@router.get("/ldap")
async def ldap_page(request: Request, session: SessionDep) -> Response:
    """Eski tek LDAP sayfası bölündü: bağlantı→Ayarlar, kullanıcı arama→Kullanıcılar.

    Geriye dönük uyumluluk için /settings'e yönlendirir.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse("/settings", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/ldap/status", response_class=HTMLResponse)
async def ldap_status_fragment(request: Request, session: SessionDep) -> Response:
    """Ayarlar sayfasındaki canlı bağlantı göstergesi (küçük HTML parçası)."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    config = await get_ldap_config(session)
    if config is None or not config.server_uri:
        return HTMLResponse(
            '<span class="kg-chip" style="color:var(--fg2);">LDAP yapılandırılmamış</span>'
        )
    verify_cert, ca_cert = await _ldaps_tls(session)
    ok, message = await ldap_test_connection(
        config, get_bind_password(config), verify_cert=verify_cert, ca_cert=ca_cert
    )
    if ok:
        return HTMLResponse(
            '<span class="kg-chip" style="color:var(--ok);font-weight:600;">● Bağlı</span>'
        )
    return HTMLResponse(
        '<span class="kg-chip" style="color:var(--sev-critical);">'
        f"● Bağlı değil — {escape(message)}</span>"
    )


@router.post("/ldap/config")
async def ldap_save_config_web(
    request: Request,
    session: SessionDep,
    server_uri: Annotated[str, Form()],
    base_dn: Annotated[str, Form()],
    bind_dn: Annotated[str, Form()] = "",
    bind_password: Annotated[str, Form()] = "",
    user_filter: Annotated[str, Form()] = "(objectClass=person)",
    attr_username: Annotated[str, Form()] = "uid",
    attr_email: Annotated[str, Form()] = "mail",
    attr_display_name: Annotated[str, Form()] = "cn",
    default_role: Annotated[str, Form()] = "viewer",
    use_ssl: Annotated[str, Form()] = "",
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await save_ldap_config(
        session,
        server_uri=server_uri,
        use_ssl=bool(use_ssl),
        bind_dn=bind_dn,
        base_dn=base_dn,
        user_filter=user_filter,
        attr_username=attr_username,
        attr_email=attr_email,
        attr_display_name=attr_display_name,
        default_role=default_role,
        bind_password=bind_password or None,
    )
    await log_action(session, "ldap_config_save", user_id=user.id, target=server_uri)
    msg = quote("LDAP bağlantı ayarları kaydedildi.")
    return RedirectResponse(f"/settings?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/ldap/test", response_class=HTMLResponse)
async def ldap_test_web(
    request: Request,
    session: SessionDep,
    server_uri: Annotated[str, Form()] = "",
    base_dn: Annotated[str, Form()] = "",
    bind_dn: Annotated[str, Form()] = "",
    bind_password: Annotated[str, Form()] = "",
    use_ssl: Annotated[str, Form()] = "",
) -> Response:
    """Bağlantıyı KAYDETMEDEN, formdaki anlık değerlerle test eder; canlı rozet döndürür.

    Parola alanı boşsa (tarayıcıya hiç gönderilmez) ve bind DN değişmemişse kayıtlı
    parolaya düşer — operatör her testte parolayı yeniden yazmak zorunda kalmaz.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    uri = server_uri.strip()
    if not uri:
        return HTMLResponse(
            '<span class="kg-chip" style="color:var(--sev-critical);">'
            "● Bağlı değil — Önce sunucu adresini girin.</span>"
        )
    saved = await get_ldap_config(session)
    # Formdaki anlık değerlerden geçici (oturuma eklenmeyen) bir config kur.
    config = LdapConfig(
        server_uri=uri,
        use_ssl=bool(use_ssl),
        bind_dn=bind_dn.strip(),
        base_dn=base_dn.strip(),
    )
    password = bind_password
    if not password and saved and bind_dn.strip() == (saved.bind_dn or ""):
        password = get_bind_password(saved)
    verify_cert, ca_cert = await _ldaps_tls(session)
    ok, message = await ldap_test_connection(
        config, password, verify_cert=verify_cert, ca_cert=ca_cert
    )
    await log_action(session, "ldap_test", user_id=user.id, target=uri)
    if ok:
        return HTMLResponse(
            '<span class="kg-chip" style="color:var(--ok);font-weight:600;">● Bağlı</span>'
        )
    return HTMLResponse(
        '<span class="kg-chip" style="color:var(--sev-critical);">'
        f"● Bağlı değil — {escape(message)}</span>"
    )


@router.post("/ldap/import")
async def ldap_import_web(
    request: Request,
    session: SessionDep,
    username: Annotated[str, Form()],
    role: Annotated[str, Form()] = "viewer",
    email: Annotated[str, Form()] = "",
    display_name: Annotated[str, Form()] = "",
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    try:
        target_role = Role(role)
    except ValueError:
        target_role = Role.viewer
    _imported, created = await import_ldap_user(session, username, target_role, email=email or None)
    await log_action(session, "ldap_user_import", user_id=user.id, target=username)
    verb = "içe aktarıldı" if created else "güncellendi"
    msg = quote(f"'{username}' {verb} (rol: {target_role.value}).")
    return RedirectResponse(f"/users?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/ldap/import-group")
async def ldap_import_group_web(
    request: Request,
    session: SessionDep,
    group_dn: Annotated[str, Form()],
    group_name: Annotated[str, Form()] = "",
    role: Annotated[str, Form()] = "viewer",
) -> Response:
    """Bir güvenlik grubunun TÜM üyelerini PASİF (is_active=False) olarak içe aktarır.

    Admin sonra Kullanıcılar sayfasından etkinleştirir; rolü orada atar/değiştirir.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    try:
        target_role = Role(role)
    except ValueError:
        target_role = Role.viewer
    config = await get_ldap_config(session)
    if config is None or not config.server_uri:
        return await _users_page(
            request, session, user, error="Önce LDAP bağlantısını yapılandırın.", status_code=400
        )
    verify_cert, ca_cert = await _ldaps_tls(session)
    try:
        members = await ldap_group_members(
            config, get_bind_password(config), group_dn, verify_cert=verify_cert, ca_cert=ca_cert
        )
    except LdapSearchError as exc:
        return await _users_page(request, session, user, error=str(exc), status_code=502)
    created, existing = await import_ldap_users(
        session,
        [(m.username, m.email) for m in members],
        target_role,
        active=False,
    )
    await log_action(session, "ldap_group_import", user_id=user.id, target=group_name or group_dn)
    label = group_name or group_dn
    msg = quote(
        f"'{label}' grubundan {created} yeni (pasif), {existing} mevcut kullanıcı içe aktarıldı. "
        "Kullanıcılar sayfasından etkinleştirin."
    )
    return RedirectResponse(f"/users?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


# --- Kullanıcı düzenle (admin: rol + e-posta + MFA yönetimi) ---


async def _user_edit_page(
    request: Request,
    session: AsyncSession,
    user: User,
    target: User,
    *,
    error: str | None = None,
    message: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> Response:
    """Kullanıcı düzenle sayfası — rol/e-posta formu + MFA paneli (TOTP beklemedeyse QR)."""
    row = await get_settings(session)
    smtp_ready = row.smtp_enabled and bool(row.smtp_host.strip())
    totp_qr: str | None = None
    totp_secret: str | None = None
    if target.mfa_method == "totp" and not target.mfa_enabled:
        secret = get_mfa_secret(target)
        if secret:
            totp_qr = totp_qr_svg(totp_provisioning_uri(secret, target.username))
            totp_secret = secret
    return templates.TemplateResponse(
        request,
        "user_edit.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "target": target,
            "roles": [r.value for r in Role],
            "smtp_ready": smtp_ready,
            "totp_qr": totp_qr,
            "totp_secret": totp_secret,
            "error": error,
            "message": message,
        },
        status_code=status_code,
    )


async def _require_admin_target(
    request: Request, session: AsyncSession, user_id: int
) -> tuple[User, User] | Response:
    """Admin + hedef kullanıcı çözümü; değilse uygun yönlendirme döndürür."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    target = await get_user_by_id(session, user_id)
    if target is None:
        return RedirectResponse("/users", status_code=status.HTTP_303_SEE_OTHER)
    return user, target


@router.get("/users/{user_id}/edit", response_class=HTMLResponse)
async def user_edit_page(request: Request, session: SessionDep, user_id: int) -> Response:
    resolved = await _require_admin_target(request, session, user_id)
    if isinstance(resolved, Response):
        return resolved
    user, target = resolved
    return await _user_edit_page(
        request,
        session,
        user,
        target,
        message=request.query_params.get("msg"),
        error=request.query_params.get("error"),
    )


@router.post("/users/{user_id}/edit")
async def user_edit_save(
    request: Request,
    session: SessionDep,
    user_id: int,
    role: Annotated[str, Form()],
    email: Annotated[str, Form()] = "",
) -> Response:
    resolved = await _require_admin_target(request, session, user_id)
    if isinstance(resolved, Response):
        return resolved
    user, _target = resolved
    # Rol: admin kendi rolünü düşüremez (yetki kaybı koruması) — diğerleri için uygula.
    if user_id != user.id:
        with contextlib.suppress(ValueError):
            await set_user_role(session, user_id, Role(role))
    await set_user_email(session, user_id, email.strip() or None)
    await log_action(session, "user_update", user_id=user.id, target=str(user_id))
    msg = quote("Kullanıcı güncellendi.")
    return RedirectResponse(
        f"/users/{user_id}/edit?msg={msg}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/users/{user_id}/password")
async def user_password_reset(
    request: Request,
    session: SessionDep,
    user_id: int,
    new_password: Annotated[str, Form()],
    new_password_confirm: Annotated[str, Form()],
) -> Response:
    """Admin: başka bir YEREL kullanıcının parolasını sıfırlar (politika + tekrar eşleşmesi)."""
    resolved = await _require_admin_target(request, session, user_id)
    if isinstance(resolved, Response):
        return resolved
    user, target = resolved
    if target.auth_source.value != "local" or target.password_hash is None:
        err = quote("LDAP/dizin kullanıcısının parolası buradan değiştirilemez.")
        return RedirectResponse(
            f"/users/{user_id}/edit?error={err}", status_code=status.HTTP_303_SEE_OTHER
        )
    if new_password != new_password_confirm:
        err = quote("Yeni parolalar eşleşmiyor.")
        return RedirectResponse(
            f"/users/{user_id}/edit?error={err}", status_code=status.HTTP_303_SEE_OTHER
        )
    settings_row = await get_settings(session)
    pw_error = validate_password(
        new_password,
        min_length=settings_row.password_min_length,
        require_complexity=settings_row.password_require_complexity,
    )
    if pw_error is not None:
        return RedirectResponse(
            f"/users/{user_id}/edit?error={quote(pw_error)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    await set_user_password(session, user_id, new_password)
    await log_action(session, "user_password_reset", user_id=user.id, target=str(user_id))
    return RedirectResponse(
        f"/users/{user_id}/edit?msg={quote('Parola güncellendi.')}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/account/password", response_class=HTMLResponse)
async def account_password_page(request: Request, session: SessionDep) -> Response:
    """Self-service: her kullanıcı kendi parolasını değiştirir."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    return templates.TemplateResponse(
        request,
        "account_password.html",
        {
            "user": user,
            "is_local": user.auth_source.value == "local" and user.password_hash is not None,
            "message": request.query_params.get("msg"),
            "error": request.query_params.get("error"),
        },
    )


@router.post("/account/password")
async def account_password_save(
    request: Request,
    session: SessionDep,
    current_password: Annotated[str, Form()],
    new_password: Annotated[str, Form()],
    new_password_confirm: Annotated[str, Form()],
) -> Response:
    """Self-service parola değiştirme: mevcut parola doğrulanır + politika + tekrar eşleşmesi."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.auth_source.value != "local" or user.password_hash is None:
        err = quote("Bu hesabın parolası burada değiştirilemez (LDAP/dizin).")
        return RedirectResponse(
            f"/account/password?error={err}", status_code=status.HTTP_303_SEE_OTHER
        )
    if not verify_password(current_password, user.password_hash):
        err = quote("Mevcut parola yanlış.")
        return RedirectResponse(
            f"/account/password?error={err}", status_code=status.HTTP_303_SEE_OTHER
        )
    if new_password != new_password_confirm:
        err = quote("Yeni parolalar eşleşmiyor.")
        return RedirectResponse(
            f"/account/password?error={err}", status_code=status.HTTP_303_SEE_OTHER
        )
    settings_row = await get_settings(session)
    pw_error = validate_password(
        new_password,
        min_length=settings_row.password_min_length,
        require_complexity=settings_row.password_require_complexity,
    )
    if pw_error is not None:
        return RedirectResponse(
            f"/account/password?error={quote(pw_error)}", status_code=status.HTTP_303_SEE_OTHER
        )
    await set_user_password(session, user.id, new_password)
    await log_action(session, "self_password_change", user_id=user.id, target=str(user.id))
    return RedirectResponse(
        f"/account/password?msg={quote('Parolanız güncellendi.')}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/users/{user_id}/mfa/totp/setup")
async def user_mfa_totp_setup(request: Request, session: SessionDep, user_id: int) -> Response:
    resolved = await _require_admin_target(request, session, user_id)
    if isinstance(resolved, Response):
        return resolved
    _user, target = resolved
    await begin_totp_enrollment(session, target)
    return RedirectResponse(f"/users/{user_id}/edit", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}/mfa/totp/enable")
async def user_mfa_totp_enable(request: Request, session: SessionDep, user_id: int) -> Response:
    resolved = await _require_admin_target(request, session, user_id)
    if isinstance(resolved, Response):
        return resolved
    user, target = resolved
    await enable_mfa(session, target)
    await log_action(session, "mfa_enable", user_id=user.id, target=target.username)
    msg = quote("MFA etkinleştirildi.")
    return RedirectResponse(
        f"/users/{user_id}/edit?msg={msg}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/users/{user_id}/mfa/email/enable")
async def user_mfa_email_enable(request: Request, session: SessionDep, user_id: int) -> Response:
    resolved = await _require_admin_target(request, session, user_id)
    if isinstance(resolved, Response):
        return resolved
    user, target = resolved
    if not (target.email or "").strip():
        error = quote("Kullanıcının e-postası yok.")
        return RedirectResponse(
            f"/users/{user_id}/edit?error={error}", status_code=status.HTTP_303_SEE_OTHER
        )
    row = await get_settings(session)
    if not (row.smtp_enabled and row.smtp_host.strip()):
        error = quote("SMTP yapılandırılmamış.")
        return RedirectResponse(
            f"/users/{user_id}/edit?error={error}", status_code=status.HTTP_303_SEE_OTHER
        )
    await begin_email_enrollment(session, target)
    await enable_mfa(session, target)
    await log_action(session, "mfa_enable", user_id=user.id, target=target.username)
    msg = quote("E-posta OTP etkinleştirildi.")
    return RedirectResponse(
        f"/users/{user_id}/edit?msg={msg}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/users/{user_id}/mfa/disable")
async def user_mfa_disable(request: Request, session: SessionDep, user_id: int) -> Response:
    resolved = await _require_admin_target(request, session, user_id)
    if isinstance(resolved, Response):
        return resolved
    user, target = resolved
    await disable_mfa(session, target)
    await log_action(session, "mfa_disable", user_id=user.id, target=target.username)
    msg = quote("MFA kaldırıldı.")
    return RedirectResponse(
        f"/users/{user_id}/edit?msg={msg}", status_code=status.HTTP_303_SEE_OTHER
    )


# --- Eklentiler (admin-only; data-only çekirdek: nmap + yerel AI) ---


@router.get("/plugins", response_class=HTMLResponse)
async def plugins_page(request: Request, session: SessionDep) -> Response:
    """Eklentiler — çekirdek (data-only) eklenti durumları + yerel AI yapılandırması (#218/#219).

    Canlı satırlar yalnız nmap (imaj derlemesiyle 'kurulu') ve AI (app_settings.ai_enabled).
    Sömürü eklentileri (searchsploit/Metasploit/sandbox) bu çekirdekte yoktur — ayrı ticari
    eklentide (kangalis-exploit) gelir; sayfada yalnız nötr bir tanıtım kartı gösterilir.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    row = await get_settings(session)
    ai_active = bool(getattr(row, "ai_enabled", False))
    # Sömürü eklentisi (ticari kangalis-exploit) kurulu mu — yan-etkisiz import tespiti (#F Faz 0).
    exploitation_available = exploit_plugin_available()
    # Sömürü için İKİ kapı: eklenti (yukarıda) + geçerli ``exploit`` lisansı (kartta ayrı satır).
    exploit_licensed = await feature_licensed(session, "exploit")
    return templates.TemplateResponse(
        request,
        "plugins.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "ai_active": ai_active,
            "exploitation_available": exploitation_available,
            "exploit_licensed": exploit_licensed,
            "s": row,
            "message": request.query_params.get("msg"),
            "error": request.query_params.get("error"),
        },
    )


@router.get("/help", response_class=HTMLResponse)
async def help_page(request: Request, session: SessionDep) -> Response:
    """Yardım & Dokümanlar — statik kullanım kılavuzu (tüm giriş yapan kullanıcılar).

    İçerik web/help_content.py'de TEK KAYNAK olarak tutulur; (ileride) yerel AI Q&A
    ekranı (#2c) aynı içeriği grounding bağlamı olarak kullanacak.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    return templates.TemplateResponse(
        request,
        "help.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "sections": HELP_SECTIONS,
            "ai_active": ai_available(AIConfig.from_app_settings(await get_settings(session))),
        },
    )


# --- Ayarlar (admin-only güvenlik/operasyon ayarları) ---


async def _settings_page(
    request: Request,
    session: AsyncSession,
    user: User,
    *,
    error: str | None = None,
    message: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> Response:
    """Ayarlar sayfasını (tüm bölümler tek satır app_settings'ten) döndürür."""
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "s": await get_settings(session),
            "syslog_protocols": SYSLOG_PROTOCOLS,
            "syslog_formats": SYSLOG_FORMATS,
            "timezones": COMMON_TIMEZONES,
            "ldap_config": await get_ldap_config(session),
            "roles": [r.value for r in Role],
            # Zafiyet veritabanı durum paneli (CVE-COVERAGE FE)
            "vulndb_cve_count": await count_cves(session),
            "vulndb_cpe_count": await count_cpe_matches(session),
            "cve_fresh": _cve_freshness(await get_settings(session)),
            "nvd_sync_days_min": NVD_SYNC_DAYS_MIN,
            "nvd_sync_days_max": NVD_SYNC_DAYS_MAX,
            # Yetkili tarama kapsamı (ScopePolicy) — #C web formu için aktif politikayı göster
            "active_policy": await get_active_policy(session),
            "error": error,
            "message": message,
        },
        status_code=status_code,
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, session: SessionDep) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return await _settings_page(request, session, user, message=request.query_params.get("msg"))


@router.post("/settings/scope")
async def settings_scope_web(
    request: Request,
    session: SessionDep,
    name: Annotated[str, Form()] = "ic-ag",
    allowed_cidrs: Annotated[str, Form()] = "",
    denied_cidrs: Annotated[str, Form()] = "",
) -> Response:
    """Yetkili tarama kapsamı (ScopePolicy) web formu — set_scope CLI yerine (#C, admin).

    İzinli/yasak CIDR'leri doğrular (geçersiz satırlar atlanır), eski politikayı pasifleştirip
    yenisini aktif eder (scope.set_active_scope; validate_target bunu okur — okuma mantığına
    DOKUNULMAZ). Genel web-CLI/komut kutusu YOKTUR (RCE riski) — yalnız bu özel form. En az bir
    izinli CIDR zorunlu (yanlışlıkla tüm-reddi/kilitlemeyi önler).
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    lang = normalize_lang(request.cookies.get(LANG_COOKIE))
    t = translator(lang)
    allowed = parse_asset_scope_cidrs(allowed_cidrs)
    denied = parse_asset_scope_cidrs(denied_cidrs)
    if not allowed:
        return await _settings_page(
            request,
            session,
            user,
            error=t("set_scope_error_empty"),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    await set_active_scope(
        session, name=name.strip() or "ic-ag", allowed_cidrs=allowed, denied_cidrs=denied
    )
    await log_action(session, "settings_update", user_id=user.id, target="scope")
    return _settings_saved_redirect()


def _settings_saved_redirect() -> RedirectResponse:
    msg = quote("Ayarlar kaydedildi.")
    return RedirectResponse(f"/settings?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/settings/ratelimit")
async def settings_ratelimit_web(
    request: Request,
    session: SessionDep,
    max_attempts: Annotated[int, Form()] = 5,
    window_sec: Annotated[int, Form()] = 300,
    lockout_sec: Annotated[int, Form()] = 900,
    enabled: Annotated[str, Form()] = "",
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await save_ratelimit_settings(
        session,
        enabled=bool(enabled),
        max_attempts=max_attempts,
        window_sec=window_sec,
        lockout_sec=lockout_sec,
    )
    await log_action(session, "settings_update", user_id=user.id, target="ratelimit")
    return _settings_saved_redirect()


# --- Lisans (ayrı admin sekmesi: ticari lisans girişi + çevrimdışı imza doğrulama) ---


async def _license_page(
    request: Request,
    session: AsyncSession,
    user: User,
    *,
    error: str | None = None,
    message: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> Response:
    """Lisans sayfasını (açık anahtar + lisans kodu girişi + imza doğrulama durumu) döndürür."""
    return templates.TemplateResponse(
        request,
        "license.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "s": await get_settings(session),
            # Ticari lisans durumu: geçerli/süresi-dolmuş/geçersiz/yok/devre-dışı
            "license_info": await active_license(session),
            # env LICENSE_PUBLIC_KEY tanımlı mı — DB alanı boşken fallback olduğunu UI'da göster
            "pubkey_env_set": bool(settings.license_public_key.strip()),
            "error": error,
            "message": message,
        },
        status_code=status_code,
    )


@router.get("/license", response_class=HTMLResponse)
async def license_page(request: Request, session: SessionDep) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return await _license_page(request, session, user, message=request.query_params.get("msg"))


@router.post("/license")
async def license_save_web(
    request: Request,
    session: SessionDep,
    license_public_key: Annotated[str, Form()] = "",
    license_key: Annotated[str, Form()] = "",
) -> Response:
    """Doğrulama açık anahtarını + ticari lisans kodunu kaydeder (admin, tek form).

    Açık anahtar gizli DEĞİL; imza bununla doğrulanır (boşsa env LICENSE_PUBLIC_KEY fallback).
    Doğrulama core/licensing.py'de (çevrimdışı imza); kaydetme her zaman kabul edilir —
    geçersiz/boş anahtar veya kod Lisans sayfasında durum olarak gösterilir."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await save_license_public_key(session, public_key=license_public_key)
    await save_license_key(session, license_key=license_key)
    await log_action(session, "settings_update", user_id=user.id, target="license")
    lang = normalize_lang(request.cookies.get(LANG_COOKIE))
    msg = quote(translator(lang)("license_saved"))
    return RedirectResponse(f"/license?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


# --- Güncelleme (bileşen sürümleri + yeni-sürüm denetimi) ---
# GÜVENLİK: "uygula" adımı yalnız host KOMUTUNU GÖSTERİR (kopyalanabilir); uygulama Docker'a
# ya da host'a ERİŞMEZ → RCE/host-escape yok. Denetim = tek dış-erişim (egress), kapatılabilir.

# Host'ta çalıştırılacak güncelleme komutları (iki dağıtım yolu için sabit; kullanıcı girdisi yok).
_UPDATE_APPLY_CMDS = {
    "image": "docker compose pull && docker compose up -d",
    "source": "git pull && docker compose up -d --build",
}


async def _update_page(
    request: Request, session: AsyncSession, user: User, *, message: str | None = None
) -> Response:
    """Güncelleme sayfası: bileşen sürümleri + son denetim durumu + uygulama komutları."""
    row = await get_settings(session)
    return templates.TemplateResponse(
        request,
        "update.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "versions": await gather_versions(session, row),
            "update": stored_status(row),
            "s": row,
            "apply_cmds": _UPDATE_APPLY_CMDS,
            # Eklenti kuruluysa "guncelle" sonrasi re-bake hatirlatmasi (--build eklentiyi siler).
            "exploitation_available": exploit_plugin_available(),
            "message": message,
        },
    )


@router.get("/update", response_class=HTMLResponse)
async def update_page(request: Request, session: SessionDep) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return await _update_page(request, session, user, message=request.query_params.get("msg"))


@router.post("/update/check")
async def update_check_now(request: Request, session: SessionDep) -> Response:
    """Admin "Şimdi denetle" → uzak sürüm denetimini ZORLA çalıştırır (toggle'ı yok sayar)."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    result = await run_update_check(session, force=True)
    await log_action(
        session,
        "update_check",
        user_id=user.id,
        target=f"{result.current} -> {result.latest or '?'} ({result.status})",
    )
    return RedirectResponse("/update?msg=checked", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/update/settings")
async def update_settings_save(
    request: Request,
    session: SessionDep,
    update_check_enabled: Annotated[bool, Form()] = False,
    update_check_url: Annotated[str, Form()] = "",
) -> Response:
    """Güncelleme denetimi ayarlarını kaydeder (egress aç/kapa + sürüm-kaynak URL)."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await save_update_settings(session, enabled=update_check_enabled, url=update_check_url)
    await log_action(session, "settings_update", user_id=user.id, target="update")
    return RedirectResponse("/update?msg=saved", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/settings/smtp")
async def settings_smtp_web(
    request: Request,
    session: SessionDep,
    host: Annotated[str, Form()] = "",
    port: Annotated[int, Form()] = 587,
    username: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
    sender: Annotated[str, Form()] = "",
    alert_to: Annotated[str, Form()] = "",
    enabled: Annotated[str, Form()] = "",
    use_tls: Annotated[str, Form()] = "",
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await save_smtp_settings(
        session,
        enabled=bool(enabled),
        host=host,
        port=port,
        username=username,
        sender=sender,
        use_tls=bool(use_tls),
        alert_to=alert_to,
        password=password or None,
    )
    await log_action(session, "settings_update", user_id=user.id, target="smtp")
    return _settings_saved_redirect()


@router.post("/settings/smtp/test")
async def settings_smtp_test_web(request: Request, session: SessionDep) -> Response:
    """Kayıtlı SMTP ayarıyla deneme e-postası gönderir (uyarı alıcısına ya da From'a)."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    row = await get_settings(session)
    if not row.smtp_host.strip():
        return await _settings_page(
            request, session, user, error="Önce SMTP sunucusunu kaydedin.", status_code=400
        )
    recipient = row.alert_email_to.strip() or smtp_sender(row)
    try:
        await send_email(
            row,
            recipient,
            "Kangalis — SMTP test e-postası",
            "Bu bir test e-postasıdır. SMTP ayarlarınız çalışıyor.",
        )
    except MailError as exc:
        return await _settings_page(request, session, user, error=str(exc), status_code=502)
    await log_action(session, "settings_update", user_id=user.id, target="smtp_test")
    msg = quote(f"Test e-postası gönderildi: {recipient}")
    return RedirectResponse(f"/settings?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/settings/syslog")
async def settings_syslog_web(
    request: Request,
    session: SessionDep,
    host: Annotated[str, Form()] = "",
    port: Annotated[int, Form()] = 514,
    protocol: Annotated[str, Form()] = "udp",
    fmt: Annotated[str, Form()] = "rfc5424",
    enabled: Annotated[str, Form()] = "",
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await save_syslog_settings(
        session,
        enabled=bool(enabled),
        host=host,
        port=port,
        protocol=protocol,
        fmt=fmt,
    )
    await log_action(session, "settings_update", user_id=user.id, target="syslog")
    return _settings_saved_redirect()


@router.post("/settings/hardening")
async def settings_hardening_web(
    request: Request,
    session: SessionDep,
    session_timeout_min: Annotated[int, Form()] = 0,
    password_min_length: Annotated[int, Form()] = 8,
    ldaps_ca_cert: Annotated[str, Form()] = "",
    password_require_complexity: Annotated[str, Form()] = "",
    ldaps_verify_cert: Annotated[str, Form()] = "",
) -> Response:
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await save_hardening_settings(
        session,
        session_timeout_min=session_timeout_min,
        password_min_length=password_min_length,
        password_require_complexity=bool(password_require_complexity),
        ldaps_verify_cert=bool(ldaps_verify_cert),
        ldaps_ca_cert=ldaps_ca_cert,
    )
    await log_action(session, "settings_update", user_id=user.id, target="hardening")
    return _settings_saved_redirect()


@router.post("/settings/network")
async def settings_network_web(
    request: Request,
    session: SessionDep,
    dns_servers: Annotated[str, Form()] = "",
    reverse_dns_enabled: Annotated[str, Form()] = "",
) -> Response:
    """Ağ/DNS ayarları (VI-6): DNS sunucuları + reverse-DNS. Tarama hızı/dağıtımı AYRI form."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await save_network_settings(
        session,
        dns_servers=dns_servers,
        reverse_dns_enabled=bool(reverse_dns_enabled),
    )
    await log_action(session, "settings_update", user_id=user.id, target="network")
    return _settings_saved_redirect()


@router.post("/settings/scan")
async def settings_scan_web(
    request: Request,
    session: SessionDep,
    scan_speed: Annotated[str, Form()] = "",
    scan_fanout: Annotated[str, Form()] = "",
    fanout_workers: Annotated[str, Form()] = "",
) -> Response:
    """Tarama hızı + worker dağıtımı (SCAN-SPEED + fan-out): nmap paralellik + bloklara bölme.

    DNS'ten AYRI form. ``scan_fanout`` (checkbox) tek taramanın worker'lara dağıtılıp
    dağıtılmayacağını; ``fanout_workers`` (1-32'ye kısılır) kaç parçaya bölüneceğini belirler.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    try:
        workers = int(fanout_workers) if fanout_workers.strip() else None
    except ValueError:
        workers = None
    await save_scan_settings(
        session,
        scan_speed=scan_speed,
        scan_fanout=bool(scan_fanout),
        fanout_workers=workers,
    )
    await log_action(session, "settings_update", user_id=user.id, target="scan")
    return _settings_saved_redirect()


@router.post("/plugins/ai")
async def settings_ai_web(
    request: Request,
    session: SessionDep,
    ai_endpoint_url: Annotated[str, Form()] = "",
    ai_model_name: Annotated[str, Form()] = "",
    ai_timeout_sec: Annotated[int, Form()] = 300,
    ai_enabled: Annotated[str, Form()] = "",
) -> Response:
    """Yerel AI (OpenAI-uyumlu motor) ayarları (#182): aç/kapa + endpoint + model + timeout.

    endpoint/model boş bırakılırsa config.py env varsayılanı kullanılır. AI kapalı iken
    UI butonları görünmez (graceful). Sıfır egress: endpoint internal yerel motordur.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await save_ai_settings(
        session,
        ai_enabled=bool(ai_enabled),
        ai_endpoint_url=ai_endpoint_url,
        ai_model_name=ai_model_name,
        ai_timeout_sec=ai_timeout_sec,
    )
    await log_action(session, "settings_update", user_id=user.id, target="ai")
    msg = quote("AI ayarları kaydedildi.")
    return RedirectResponse(f"/plugins?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/plugins/ai/test")
async def settings_ai_test_web(request: Request, session: SessionDep) -> Response:
    """Kayıtlı AI endpoint'ine bağlanıp kurulu modelleri sorgular (etkin olmasa da test eder)."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    row = await get_settings(session)
    result = await probe_ai_endpoint(row)
    await log_action(session, "settings_update", user_id=user.id, target="ai_test")
    if not result["ok"]:
        endpoint = (row.ai_endpoint_url or settings.ai_endpoint).strip()
        err = quote(f"AI endpoint'ine ulaşılamadı: {endpoint} (yerel motor çalışıyor mu?)")
        return RedirectResponse(f"/plugins?error={err}", status_code=status.HTTP_303_SEE_OTHER)
    model = result["model"]
    models = result["models"]
    if result["has_model"]:
        msg = quote(f"AI bağlantısı başarılı — '{model}' modeli hazır.")
    else:
        installed = ", ".join(models) if models else "yok"  # type: ignore[arg-type]
        msg = quote(
            f"AI endpoint'ine ulaşıldı (sunulan modeller: {installed}). "
            f"Ayarlardaki model '{model}' listede yok — model adını sunulanlarla eşleştirin "
            "(Ollama, ad etiket olabilir)."
        )
    return RedirectResponse(f"/plugins?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/plugins/ai/detect")
async def settings_ai_detect_web(request: Request, session: SessionDep) -> Response:
    """Kurulum sihirbazı (Faz 1 çatısı): ortamı yoklayıp erişilebilir yerel-AI motorlarını döndürür.

    Host-native (Ollama/LM Studio) + gömülü container + kayıtlı endpoint'i EŞZAMANLI yoklar; sıfır
    egress (hepsi müşteri ağı içi). Salt-okuma — hiçbir şeyi etkinleştirmez. HTMX parçası döner.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    row = await get_settings(session)
    detect = await detect_ai_paths(row)
    await log_action(session, "settings_update", user_id=user.id, target="ai_detect")
    return templates.TemplateResponse(request, "_ai_detect.html", {"detect": detect})


@router.post("/settings/asset-scope")
async def settings_asset_scope_web(
    request: Request,
    session: SessionDep,
    asset_scope_cidrs: Annotated[str, Form()] = "",
) -> Response:
    """Varlık kapsamı (F1): yalnız bu CIDR'lerdeki IP'ler envantere (Varlıklar) eklenir."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await save_asset_scope_settings(session, raw_cidrs=asset_scope_cidrs)
    await log_action(session, "settings_update", user_id=user.id, target="asset_scope")
    return _settings_saved_redirect()


@router.post("/settings/nvd")
async def settings_nvd_web(
    request: Request,
    session: SessionDep,
    nvd_sync_days: Annotated[int, Form()] = 7,
    nvd_api_key: Annotated[str, Form()] = "",
) -> Response:
    """NVD senkron kapsamı (gün) + opsiyonel API anahtarı (CVE-COVERAGE FE).

    API anahtarı boş bırakılırsa mevcut (varsa) korunur — UI anahtarı asla göstermez.
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await save_nvd_settings(session, sync_days=nvd_sync_days, api_key=nvd_api_key or None)
    await log_action(session, "settings_update", user_id=user.id, target="nvd")
    return _settings_saved_redirect()


@router.post("/settings/nvd/backfill")
async def settings_nvd_backfill_web(
    request: Request,
    session: SessionDep,
    backfill_years: Annotated[int, Form()] = 2,
) -> Response:
    """Tek seferlik geçmiş CVE/CPE yükleme (admin). Günlük 120-günlük pencereye DOKUNMAZ —
    arka planda bir kez geniş aralıktan çeker (yıl → gün; 120-günlük parçalara bölünür).
    """
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    if await cve_backfill.is_active():
        busy = quote("Zaten bir geçmiş yükleme çalışıyor — bitmesini bekleyin ya da iptal edin.")
        return RedirectResponse(f"/settings?msg={busy}", status_code=status.HTTP_303_SEE_OTHER)
    years = max(1, min(5, backfill_years))  # 1..5 yıl güvenli sınır
    days = years * 365
    await cve_backfill.mark_queued(years=years)  # UI hemen "başlatılıyor" göstersin
    nvd_backfill_task.delay(days=days)
    await log_action(session, "nvd_backfill_start", user_id=user.id, target=f"days={days}")
    msg = quote(
        f"Geçmiş CVE/CPE yükleme başlatıldı ({years} yıl) — arka planda çalışıyor, "
        "sayılar zamanla artacak (anahtarsız onlarca dakika sürebilir)."
    )
    return RedirectResponse(f"/settings?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/settings/nvd/backfill/status", response_class=HTMLResponse)
async def settings_nvd_backfill_status(request: Request, session: SessionDep) -> Response:
    """Geçmiş yükleme canlı durumu (HTMX hx-get; çalışırken parça kendini 3 sn'de bir yeniler)."""
    user = await _current_user(request, session)
    if user is None or user.role != Role.admin:
        return PlainTextResponse("", status_code=status.HTTP_401_UNAUTHORIZED)
    st = await cve_backfill.state()
    return templates.TemplateResponse(request, "_nvd_backfill_status.html", {"bf": st})


@router.post("/settings/nvd/backfill/cancel", response_class=HTMLResponse)
async def settings_nvd_backfill_cancel(request: Request, session: SessionDep) -> Response:
    """Çalışan geçmiş yüklemeyi iptal eder (kooperatif: mevcut pencere bitince temiz durur)."""
    user = await _current_user(request, session)
    if user is None or user.role != Role.admin:
        return PlainTextResponse("", status_code=status.HTTP_401_UNAUTHORIZED)
    if await cve_backfill.request_cancel():
        await log_action(session, "nvd_backfill_cancel", user_id=user.id)
    st = await cve_backfill.state()
    return templates.TemplateResponse(request, "_nvd_backfill_status.html", {"bf": st})


@router.post("/settings/timezone")
async def settings_timezone_web(
    request: Request,
    session: SessionDep,
    timezone: Annotated[str, Form()] = "Europe/Istanbul",
) -> Response:
    """Uygulama geneli saat dilimi (IX-1): tüm tarih/saat gösterimleri buna çevrilir."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await save_timezone_settings(session, timezone=timezone)
    await log_action(session, "settings_update", user_id=user.id, target="timezone")
    return _settings_saved_redirect()


@router.post("/settings/ldap-sync")
async def settings_ldap_sync_web(
    request: Request,
    session: SessionDep,
    period: Annotated[str, Form()] = "daily",
    hour: Annotated[int, Form()] = 3,
    enabled: Annotated[str, Form()] = "",
) -> Response:
    """LDAP periyodik kullanıcı senkron zamanlaması (X-6): aç/kapa + period + saat."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    await save_ldap_sync_settings(session, enabled=bool(enabled), period=period, hour=hour)
    await log_action(session, "settings_update", user_id=user.id, target="ldap_sync")
    return _settings_saved_redirect()


_AUDIT_RANGES = ("day", "week", "month", "all")


def _parse_audit_date(value: str | None, *, end_of_day: bool = False) -> datetime | None:
    """``YYYY-MM-DD`` metnini UTC datetime'a çevirir (geçersiz/boş → None).

    ``end_of_day=True`` ise gün sonunu (23:59:59) döndürür — 'bitiş' filtresi dahil olsun.
    """
    if not value:
        return None
    with contextlib.suppress(ValueError):
        day = datetime.strptime(value.strip(), "%Y-%m-%d").replace(tzinfo=UTC)
        if end_of_day:
            return day.replace(hour=23, minute=59, second=59, microsecond=999999)
        return day
    return None


@router.get("/audit", response_class=HTMLResponse)
async def audit_page(
    request: Request,
    session: SessionDep,
    range: str = "all",
    date_from: str = "",
    date_to: str = "",
    q: str = "",
    event_id: str = "",
) -> Response:
    """Denetim günlüğü: zaman/tarih, anahtar kelime ve event_id filtreleri (X-7)."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)

    range_key = range if range in _AUDIT_RANGES else "all"
    keyword = q.strip()[:120]
    # event_id metni → int (geçersizse yok say).
    event_id_val: int | None = None
    if event_id.strip().isdigit():
        event_id_val = int(event_id.strip())

    users = await list_users(session)
    name_by_id = {u.id: u.username for u in users}
    # Anahtar kelime kullanıcı adıyla da eşleşsin: eşleşen kullanıcı id'lerini çöz.
    matched_user_ids: list[int] = []
    if keyword:
        kw_low = keyword.lower()
        matched_user_ids = [u.id for u in users if kw_low in u.username.lower()]

    # Tarih aralığı verilmişse onu kullan; yoksa hızlı zaman-dilimi (range) düğmesi.
    explicit_from = _parse_audit_date(date_from)
    explicit_to = _parse_audit_date(date_to, end_of_day=True)
    df = explicit_from if explicit_from is not None else range_since(range_key)

    logs = await query_audit_logs(
        session,
        date_from=df,
        date_to=explicit_to,
        keyword=keyword or None,
        event_id=event_id_val,
        matched_user_ids=matched_user_ids,
        limit=500,
    )

    # SIEM parser regex'leri: aktif biçim + her iki ana biçim (kopyalanabilir).
    settings_row = await get_settings(session)
    active_fmt = settings_row.syslog_format
    parser_regexes = {f: parser_regex_for_format(f) for f in SYSLOG_FORMATS}
    # event_id açılır menüsü için bilinen (action, event_id, kategori) listesi.
    event_choices = [
        {"action": a, "event_id": m.event_id, "category": m.category}
        for a, m in sorted(AUDIT_EVENTS.items(), key=lambda kv: kv[1].event_id)
    ]

    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "app_name": APP_NAME,
            "user": user,
            "logs": logs,
            "name_by_id": name_by_id,
            "range": range_key,
            "date_from": date_from.strip(),
            "date_to": date_to.strip(),
            "q": keyword,
            "event_id_sel": event_id.strip(),
            "event_choices": event_choices,
            "active_syslog_fmt": active_fmt,
            "parser_regexes": parser_regexes,
        },
    )


def _csv_safe(value: str) -> str:
    """CSV formül-enjeksiyonunu etkisizleştirir (denetim hedef/eylem alanı kullanıcı-kontrollü).

    Excel/LibreOffice ``=``/``+``/``-``/``@`` (ya da tab/CR) ile başlayan hücreyi FORMÜL sayıp
    çalıştırır. Böyle bir değerin başına tek tırnak konarak metin olarak kalması sağlanır (OWASP).
    """
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


@router.get("/audit/export")
async def audit_export(
    request: Request, session: SessionDep, range: str = "all", fmt: str = "csv"
) -> Response:
    """Seçili zaman dilimindeki denetim kayıtlarını CSV/JSON indirir."""
    user = await _current_user(request, session)
    if user is None:
        return _redirect_login()
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    range_key = range if range in _AUDIT_RANGES else "all"
    logs = await export_audit_logs(session, since=range_since(range_key))
    users = await list_users(session)
    name_by_id = {u.id: u.username for u in users}
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    rows = [
        {
            "id": log.id,
            "event_id": log.event_id,
            "created_at": log.created_at.isoformat() if log.created_at else "",
            "user": name_by_id.get(log.user_id, "") if log.user_id is not None else "",
            "action": log.action,
            "target": log.target or "",
        }
        for log in logs
    ]
    fname = f"kangalis-audit-{range_key}-{stamp}"
    if fmt == "json":
        return Response(
            content=json.dumps(rows, ensure_ascii=False, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{fname}.json"'},
        )
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer, fieldnames=["id", "event_id", "created_at", "user", "action", "target"]
    )
    writer.writeheader()
    # JSON dışa aktarımı (yukarıda) ham kalır — yalnız CSV hücreleri formül-enjeksiyonuna karşı
    # nötrlenir (kullanıcı-kontrollü user/action/target alanları).
    for row in rows:
        writer.writerow(
            {
                **row,
                "user": _csv_safe(str(row["user"])),
                "action": _csv_safe(str(row["action"])),
                "target": _csv_safe(str(row["target"])),
            }
        )
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}.csv"'},
    )
