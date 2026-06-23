"""Denetim olayları kayıt defteri (AUDIT_EVENTS) — anlamlı log mesajları.

Her eylem tipi (``action``) için:

* **event_id** — stabil, kategoriye göre bloklanmış benzersiz kod (Windows Event ID
  benzeri). SIEM/loglama tarafında filtrelemeyi kolaylaştırır. *Asla değiştirilmez*;
  yeni eylemler bloğun sonuna eklenir.
* **category** — ``auth`` / ``scan`` / ``exploit`` / ``user`` / ``compliance`` /
  ``system`` gibi kaba sınıf. Filtreleme ve renklendirme için.
* **tr / en mesaj şablonu** — AuditLog alanlarından (``target`` / ``user``) okunaklı
  bir cümle üretir. Örn. ``login_failed`` → "Başarısız giriş denemesi: {target}".

event_id blokları (kategori ↔ aralık):

* 1xxx — taramalar (scan)
* 2xxx — zone / varlık / uyum (compliance: db/smb/ldap/telnet/snmp denetimleri burada)
* 3xxx — kimlik bilgileri (credentials → kategori ``user``)
* 4xxx — kullanıcılar / kimlik doğrulama (auth + user)
* 5xxx — API token (kategori ``user``)
* 6xxx — zamanlama (schedule → kategori ``system``)
* 7xxx — LDAP içe aktarma (kategori ``user``)
* 8xxx — sistem / senkron / ayarlar (system)
* 9xxx — exploit (gerçek müdahale; kategori ``exploit``)
* 9000 — bilinmeyen/kayıtsız eylem (UNKNOWN_EVENT_ID)
"""

from __future__ import annotations

from dataclasses import dataclass

UNKNOWN_EVENT_ID = 9000


@dataclass(frozen=True, slots=True)
class AuditEventMeta:
    """Bir eylem tipinin denetim meta verisi (stabil kod + kategori + mesaj şablonu)."""

    event_id: int
    category: str  # auth | scan | exploit | user | compliance | system
    message_tr: str  # "{target}" / "{user}" yer tutucularını içerebilir
    message_en: str


# Eylem tipi → meta. event_id'ler kategori bloklarına göre stabil + benzersizdir.
# (Mesaj şablonları AuditLog.target/user'dan okunaklı cümle üretir.)
AUDIT_EVENTS: dict[str, AuditEventMeta] = {
    # ---- 1xxx — taramalar (scan) ----
    "scan_start": AuditEventMeta(
        1001, "scan", "Tarama başlatıldı: {target}", "Scan started: {target}"
    ),
    "aggressive_scan_start": AuditEventMeta(
        1002,
        "scan",
        "Agresif (müdahaleci) tarama başlatıldı: {target}",
        "Aggressive (intrusive) scan started: {target}",
    ),
    "credentialed_scan_start": AuditEventMeta(
        1003,
        "scan",
        "Kimlikli tarama başlatıldı: {target}",
        "Credentialed scan started: {target}",
    ),
    "web_scan": AuditEventMeta(
        1004, "scan", "Web taraması tamamlandı: {target}", "Web scan completed: {target}"
    ),
    "sca_start": AuditEventMeta(
        1005,
        "scan",
        "SCA (bağımlılık) taraması başlatıldı: {target}",
        "SCA (dependency) scan started: {target}",
    ),
    "hardening_start": AuditEventMeta(
        1006,
        "scan",
        "Sıkılaştırma denetimi başlatıldı: {target}",
        "Hardening audit started: {target}",
    ),
    "scan_start_mcp": AuditEventMeta(
        1007,
        "scan",
        "Tarama başlatıldı (MCP üzerinden): {target}",
        "Scan started (via MCP): {target}",
    ),
    "credential_zone_scan": AuditEventMeta(
        1008,
        "scan",
        "Kimlik bölgesi taraması başlatıldı: {target}",
        "Credential-zone scan started: {target}",
    ),
    "scan_stop": AuditEventMeta(
        1009, "scan", "Tarama durduruldu: {target}", "Scan stopped: {target}"
    ),
    "report_delete": AuditEventMeta(
        1010, "scan", "Rapor silindi: {target}", "Report deleted: {target}"
    ),
    "scan_delete": AuditEventMeta(
        1011, "scan", "Tarama kaydı silindi: {target}", "Scan record deleted: {target}"
    ),
    "scan_rescan": AuditEventMeta(
        1012, "scan", "Tarama yeniden çalıştırıldı: {target}", "Scan re-run: {target}"
    ),
    "ping_scan_start": AuditEventMeta(
        1013,
        "scan",
        "Ayakta-host (ping) taraması başlatıldı: {target}",
        "Live-host (ping) scan started: {target}",
    ),
    "ping_scan": AuditEventMeta(
        1014, "scan", "Ping taraması tamamlandı: {target}", "Ping scan completed: {target}"
    ),
    "network_scan": AuditEventMeta(
        1015, "scan", "Ağ taraması tamamlandı: {target}", "Network scan completed: {target}"
    ),
    "sca_scan": AuditEventMeta(
        1016, "scan", "SCA taraması tamamlandı: {target}", "SCA scan completed: {target}"
    ),
    "network_scan_host_queue": AuditEventMeta(
        1017,
        "scan",
        "Ağ taraması canlı host'lara dağıtıldı (iş kuyruğu): {target}",
        "Network scan fanned out to live hosts (work queue): {target}",
    ),
    "network_scan_port_fanout": AuditEventMeta(
        1018,
        "scan",
        "Ağ taraması portlara dağıtıldı (iş kuyruğu): {target}",
        "Network scan fanned out across ports (work queue): {target}",
    ),
    # 109x — tarama reddi / başarısızlığı (scan; uyarı niteliğinde)
    "network_scan_denied": AuditEventMeta(
        1090,
        "scan",
        "Ağ taraması kapsam (scope) dışı reddedildi: {target}",
        "Network scan denied (out of scope): {target}",
    ),
    "web_scan_denied": AuditEventMeta(
        1091,
        "scan",
        "Web taraması kapsam dışı reddedildi: {target}",
        "Web scan denied (out of scope): {target}",
    ),
    "ping_scan_denied": AuditEventMeta(
        1092,
        "scan",
        "Ping taraması kapsam dışı reddedildi: {target}",
        "Ping scan denied (out of scope): {target}",
    ),
    "network_scan_failed": AuditEventMeta(
        1093, "scan", "Ağ taraması başarısız: {target}", "Network scan failed: {target}"
    ),
    "ping_scan_failed": AuditEventMeta(
        1094, "scan", "Ping taraması başarısız: {target}", "Ping scan failed: {target}"
    ),
    "aggressive_downgraded": AuditEventMeta(
        1095,
        "scan",
        "Agresif tarama güvenli moda düşürüldü: {target}",
        "Aggressive scan downgraded to safe mode: {target}",
    ),
    # ---- 2xxx — zone / varlık / uyum denetimleri (compliance) ----
    "zone_create": AuditEventMeta(
        2001, "system", "IP bölgesi oluşturuldu: {target}", "IP zone created: {target}"
    ),
    "zone_delete": AuditEventMeta(
        2002, "system", "IP bölgesi silindi: {target}", "IP zone deleted: {target}"
    ),
    "zone_update": AuditEventMeta(
        2003, "system", "IP bölgesi güncellendi: {target}", "IP zone updated: {target}"
    ),
    "asset_add": AuditEventMeta(
        2010, "system", "Varlık eklendi: {target}", "Asset added: {target}"
    ),
    "asset_rename": AuditEventMeta(
        2011, "system", "Varlık yeniden adlandırıldı: {target}", "Asset renamed: {target}"
    ),
    "asset_add_url": AuditEventMeta(
        2012, "system", "URL varlığı eklendi: {target}", "URL asset added: {target}"
    ),
    "vuln_status": AuditEventMeta(
        2020,
        "system",
        "Zafiyet durumu güncellendi: {target}",
        "Vulnerability status updated: {target}",
    ),
    "default_cred_check": AuditEventMeta(
        2030,
        "compliance",
        "Varsayılan kimlik denetimi: {target}",
        "Default-credential check: {target}",
    ),
    "exposed_service_check": AuditEventMeta(
        2031,
        "compliance",
        "Kimliksiz açık-servis denetimi: {target}",
        "Unauthenticated exposed-service check: {target}",
    ),
    "rpc_probe": AuditEventMeta(
        2032,
        "compliance",
        "RPC/servis açık denetimi: {target}",
        "RPC/service exposure probe: {target}",
    ),
    "db_audit": AuditEventMeta(
        2040, "compliance", "Veritabanı denetimi: {target}", "Database audit: {target}"
    ),
    "smb_audit": AuditEventMeta(
        2041, "compliance", "SMB denetimi: {target}", "SMB audit: {target}"
    ),
    "ldap_audit": AuditEventMeta(
        2042, "compliance", "LDAP/AD denetimi: {target}", "LDAP/AD audit: {target}"
    ),
    "telnet_audit": AuditEventMeta(
        2043, "compliance", "Telnet/Cisco denetimi: {target}", "Telnet/Cisco audit: {target}"
    ),
    "snmp_audit": AuditEventMeta(
        2044, "compliance", "SNMP denetimi: {target}", "SNMP audit: {target}"
    ),
    "cisco_ios_audit": AuditEventMeta(
        2045, "compliance", "Cisco IOS SSH denetimi: {target}", "Cisco IOS SSH audit: {target}"
    ),
    "esxi_audit": AuditEventMeta(
        2046, "compliance", "ESXi/vCenter denetimi: {target}", "ESXi/vCenter audit: {target}"
    ),
    # ---- 3xxx — kimlik bilgileri (kategori user) ----
    "credential_create": AuditEventMeta(
        3001, "user", "Kimlik bilgisi oluşturuldu: {target}", "Credential created: {target}"
    ),
    "credential_delete": AuditEventMeta(
        3002, "user", "Kimlik bilgisi silindi: {target}", "Credential deleted: {target}"
    ),
    "credential_zone_create": AuditEventMeta(
        3003,
        "user",
        "Kimlik bölgesi oluşturuldu: {target}",
        "Credential zone created: {target}",
    ),
    "credential_zone_delete": AuditEventMeta(
        3004, "user", "Kimlik bölgesi silindi: {target}", "Credential zone deleted: {target}"
    ),
    "credential_update": AuditEventMeta(
        3005, "user", "Kimlik bilgisi güncellendi: {target}", "Credential updated: {target}"
    ),
    "credential_zone_update": AuditEventMeta(
        3006,
        "user",
        "Kimlik bölgesi güncellendi: {target}",
        "Credential zone updated: {target}",
    ),
    "wordlist_create": AuditEventMeta(
        3007, "user", "Kelime listesi oluşturuldu: {target}", "Wordlist created: {target}"
    ),
    "wordlist_delete": AuditEventMeta(
        3008, "user", "Kelime listesi silindi: {target}", "Wordlist deleted: {target}"
    ),
    "wordlist_update": AuditEventMeta(
        3009, "user", "Kelime listesi güncellendi: {target}", "Wordlist updated: {target}"
    ),
    "wordlist_generate_usernames": AuditEventMeta(
        3010,
        "user",
        "Kullanıcı adı listesi üretildi: {target}",
        "Username wordlist generated: {target}",
    ),
    "wordlist_generate_passwords": AuditEventMeta(
        3011,
        "user",
        "Parola listesi üretildi: {target}",
        "Password wordlist generated: {target}",
    ),
    "wordlist_ldap_users": AuditEventMeta(
        3012,
        "user",
        "LDAP'tan kullanıcı adı listesi çekildi: {target}",
        "Usernames pulled from LDAP into wordlist: {target}",
    ),
    # ---- 4xxx — kullanıcılar (user) / kimlik doğrulama (auth) ----
    "user_create": AuditEventMeta(
        4001, "user", "Kullanıcı oluşturuldu: {target}", "User created: {target}"
    ),
    "user_delete": AuditEventMeta(
        4002, "user", "Kullanıcı silindi: {target}", "User deleted: {target}"
    ),
    "user_role": AuditEventMeta(
        4003, "user", "Kullanıcı rolü değiştirildi: {target}", "User role changed: {target}"
    ),
    "user_active": AuditEventMeta(
        4004,
        "user",
        "Kullanıcı etkin/pasif durumu değiştirildi: {target}",
        "User active state toggled: {target}",
    ),
    "mfa_enable": AuditEventMeta(
        4005,
        "user",
        "Kullanıcı için MFA etkinleştirildi: {target}",
        "MFA enabled for user: {target}",
    ),
    "mfa_disable": AuditEventMeta(
        4006, "user", "Kullanıcı için MFA kaldırıldı: {target}", "MFA disabled for user: {target}"
    ),
    "user_update": AuditEventMeta(
        4007, "user", "Kullanıcı güncellendi: {target}", "User updated: {target}"
    ),
    "user_toggle": AuditEventMeta(
        4008,
        "user",
        "Kullanıcı etkin/pasif durumu değiştirildi: {target}",
        "User active state toggled: {target}",
    ),
    # 409x — kimlik doğrulama olayları (auth; güvenlik açısından kritik)
    "login_failed": AuditEventMeta(
        4090, "auth", "Başarısız giriş denemesi: {target}", "Failed login attempt: {target}"
    ),
    "login_locked": AuditEventMeta(
        4091,
        "auth",
        "Hesap kaba-kuvvet nedeniyle kilitlendi: {target}",
        "Account locked due to brute-force: {target}",
    ),
    "mcp_rbac_denied": AuditEventMeta(
        4092,
        "auth",
        "MCP yetki (RBAC) reddi: {target}",
        "MCP authorization (RBAC) denied: {target}",
    ),
    # ---- 5xxx — API token (kategori user) ----
    "token_create": AuditEventMeta(
        5001, "user", "API token oluşturuldu: {target}", "API token created: {target}"
    ),
    "token_revoke": AuditEventMeta(
        5002, "user", "API token iptal edildi: {target}", "API token revoked: {target}"
    ),
    # ---- 6xxx — zamanlama (system) ----
    "schedule_create": AuditEventMeta(
        6001, "system", "Zamanlanmış görev oluşturuldu: {target}", "Schedule created: {target}"
    ),
    "schedule_delete": AuditEventMeta(
        6002, "system", "Zamanlanmış görev silindi: {target}", "Schedule deleted: {target}"
    ),
    "schedule_toggle": AuditEventMeta(
        6003,
        "system",
        "Zamanlanmış görev açıldı/kapatıldı: {target}",
        "Schedule toggled: {target}",
    ),
    # ---- 7xxx — LDAP içe aktarma (kategori user) ----
    "ldap_config_save": AuditEventMeta(
        7001, "system", "LDAP yapılandırması kaydedildi: {target}", "LDAP config saved: {target}"
    ),
    "ldap_user_import": AuditEventMeta(
        7002, "user", "LDAP kullanıcısı içe aktarıldı: {target}", "LDAP user imported: {target}"
    ),
    "ldap_group_import": AuditEventMeta(
        7003, "user", "LDAP grubu içe aktarıldı: {target}", "LDAP group imported: {target}"
    ),
    "ldap_test": AuditEventMeta(
        7004, "system", "LDAP bağlantısı test edildi: {target}", "LDAP connection tested: {target}"
    ),
    "ldap_sync": AuditEventMeta(
        7005,
        "user",
        "LDAP periyodik senkronu tamamlandı: {target}",
        "LDAP periodic sync completed: {target}",
    ),
    # ---- 8xxx — sistem / senkron / ayarlar (system) ----
    "exploit_sync_start": AuditEventMeta(
        8001,
        "system",
        "Exploit veritabanı senkronu başlatıldı: {target}",
        "Exploit DB sync started: {target}",
    ),
    "cpe_sync": AuditEventMeta(
        8002, "system", "CPE/CVE senkronu tamamlandı: {target}", "CPE/CVE sync completed: {target}"
    ),
    "settings_update": AuditEventMeta(
        8003, "system", "Ayarlar güncellendi: {target}", "Settings updated: {target}"
    ),
    "epss_refresh": AuditEventMeta(
        8004, "system", "EPSS skorları tazelendi: {target}", "EPSS scores refreshed: {target}"
    ),
    "exploit_sync": AuditEventMeta(
        8005,
        "system",
        "Exploit veritabanı senkronu tamamlandı: {target}",
        "Exploit DB sync completed: {target}",
    ),
    "cve_sync_start": AuditEventMeta(
        8006,
        "system",
        "CVE/CPE senkronu başlatıldı: {target}",
        "CVE/CPE sync started: {target}",
    ),
    "nvd_backfill_start": AuditEventMeta(
        8007,
        "system",
        "Geçmiş CVE/CPE yükleme (backfill) başlatıldı: {target}",
        "Historical CVE/CPE backfill started: {target}",
    ),
    "ai_explain": AuditEventMeta(
        8010, "system", "AI bulgu açıklaması üretildi: {target}", "AI finding explanation: {target}"
    ),
    "ai_summary": AuditEventMeta(
        8011, "system", "AI yönetici özeti üretildi: {target}", "AI executive summary: {target}"
    ),
    "ai_summary_exec": AuditEventMeta(
        8013,
        "system",
        "AI müşteri özeti üretildi: {target}",
        "AI customer-facing summary: {target}",
    ),
    "ai_priorities": AuditEventMeta(
        8012,
        "system",
        "AI düzeltme önceliklendirmesi üretildi: {target}",
        "AI remediation prioritization: {target}",
    ),
    "ai_remediation_script": AuditEventMeta(
        8015,
        "system",
        "AI düzeltme script taslağı üretildi: {target}",
        "AI remediation script draft generated: {target}",
    ),
    "ai_asset_story": AuditEventMeta(
        8016,
        "system",
        "AI varlık risk hikâyesi üretildi: {target}",
        "AI asset risk story generated: {target}",
    ),
    "ai_exploit_chain": AuditEventMeta(
        8019,
        "system",
        "AI sömürü-zinciri özeti üretildi: {target}",
        "AI exploit-chain summary generated: {target}",
    ),
    "ai_trend": AuditEventMeta(
        8020,
        "system",
        "AI tarama-trendi anlatısı üretildi: {target}",
        "AI scan-trend narrative generated: {target}",
    ),
    "ai_compliance": AuditEventMeta(
        8021,
        "system",
        "AI uyum anlatısı üretildi: {target}",
        "AI compliance narrative generated: {target}",
    ),
    "ai_ask": AuditEventMeta(
        8022,
        "system",
        "AI yardım sorusu yanıtlandı: {target}",
        "AI help question answered: {target}",
    ),
    "update_check": AuditEventMeta(
        8024,
        "system",
        "Güncelleme denetimi yapıldı: {target}",
        "Update check performed: {target}",
    ),
    "demo_task": AuditEventMeta(
        8999, "system", "Demo görevi çalıştırıldı: {target}", "Demo task executed: {target}"
    ),
    # ---- 9xxx — exploit (gerçek müdahale; kategori exploit) ----
    "privesc_attempt": AuditEventMeta(
        9001,
        "exploit",
        "Yetki yükseltme denemesi: {target}",
        "Privilege-escalation attempt: {target}",
    ),
    "exploit_attempt": AuditEventMeta(
        9002, "exploit", "Exploit denemesi: {target}", "Exploit attempt: {target}"
    ),
    "exploit_success": AuditEventMeta(
        9003,
        "exploit",
        "Exploit BAŞARILI (kod çalıştırma): {target}",
        "Exploit SUCCEEDED (code execution): {target}",
    ),
    "bruteforce_start": AuditEventMeta(
        9004,
        "exploit",
        "Kimlik brute force başlatıldı: {target}",
        "Credential brute force started: {target}",
    ),
    "bruteforce_found": AuditEventMeta(
        9005,
        "exploit",
        "Zayıf kimlik bulundu (brute force): {target}",
        "Weak credential found (brute force): {target}",
    ),
    "exploitdb_staged": AuditEventMeta(
        9006,
        "exploit",
        "Exploit-DB PoC eşleşmesi hazırlandı (staged): {target}",
        "Exploit-DB PoC match staged: {target}",
    ),
    "exploitdb_run_start": AuditEventMeta(
        9007,
        "exploit",
        "Exploit-DB PoC çalıştırma başlatıldı (sandbox): {target}",
        "Exploit-DB PoC run started (sandbox): {target}",
    ),
    "exploitdb_stop": AuditEventMeta(
        9008,
        "exploit",
        "Exploit-DB PoC durduruldu: {target}",
        "Exploit-DB PoC stopped: {target}",
    ),
    "exploitdb_run": AuditEventMeta(
        9009,
        "exploit",
        "Exploit-DB PoC çalıştırma tamamlandı (sandbox): {target}",
        "Exploit-DB PoC run completed (sandbox): {target}",
    ),
}

# Bilinmeyen eylem için yedek meta (event_id = 9000).
_UNKNOWN_META = AuditEventMeta(
    UNKNOWN_EVENT_ID,
    "system",
    "Kayıtsız eylem: {action} ({target})",
    "Unregistered action: {action} ({target})",
)


def meta_for(action: str) -> AuditEventMeta:
    """Eylem tipinin meta verisini döndürür (bilinmeyen → UNKNOWN_EVENT_ID)."""
    return AUDIT_EVENTS.get(action, _UNKNOWN_META)


def event_id_for(action: str) -> int:
    """Eylem tipinin stabil event_id'sini döndürür (bilinmeyen → 9000)."""
    return meta_for(action).event_id


def category_for(action: str) -> str:
    """Eylem tipinin kategorisini döndürür (auth/scan/exploit/user/compliance/system)."""
    return meta_for(action).category


def render_message(action: str, target: str | None, user: str | None, lang: str = "tr") -> str:
    """Eylemden okunaklı (anlamlı) bir cümle üretir.

    Şablondaki ``{target}`` / ``{user}`` / ``{action}`` yer tutucuları doldurulur.
    Boş ``target`` "-" ile gösterilir; bilinmeyen yer tutucular ham bırakılır.
    """
    meta = meta_for(action)
    template = meta.message_en if lang == "en" else meta.message_tr
    fields = {"target": target or "-", "user": user or "-", "action": action}
    try:
        return template.format(**fields)
    except (KeyError, IndexError, ValueError):
        # Şablonda beklenmeyen yer tutucu → ham şablonu döndür (asla patlamasın).
        return template
