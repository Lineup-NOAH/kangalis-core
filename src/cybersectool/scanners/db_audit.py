"""Veritabanı kimlikli config/güvenlik denetimi (VII-2a / IX-4) — SALT-OKUNUR.

PostgreSQL ``pg_settings`` ve MySQL ``GLOBAL VARIABLES``'tan güvenlikle ilgili ayarları
okuyup CIS-tarzı denetler; hedefe YAZMAZ (yalnız SELECT/SHOW). ``eval_*`` fonksiyonları
saftır (birim testi edilebilir); ``audit_postgres``/``audit_mysql`` ağ erişimi yapar
(canlı sunucuya karşı doğrulanır).

Desteklenen motorlar: PostgreSQL + MySQL + MSSQL + Oracle (hepsi gerçek hedefe karşı
doğrulanmıştır — kalite ilkesi).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.compliance import derive_compliance, store_compliance
from cybersectool.core.findings import create_finding
from cybersectool.core.models import Severity


@dataclass
class DbFinding:
    title: str
    severity: Severity
    detail: str


# Bir DB denetim sözlüğü: değişken adı → (bulgu başlığı, saf değerlendirme fonksiyonu).
DbCheckMap = dict[str, tuple[str, Callable[[str], tuple[Severity, str] | None]]]


def eval_pg_ssl(value: str) -> tuple[Severity, str] | None:
    """PostgreSQL ssl kapalıysa şifresiz bağlantı riski (CIS PG 6.8)."""
    if value.strip().lower() != "on":
        return (Severity.medium, f"PostgreSQL ssl '{value}' — şifreli bağlantı (TLS) kapalı.")
    return None


def eval_pg_log_connections(value: str) -> tuple[Severity, str] | None:
    """log_connections kapalıysa bağlantı denetim izi yok (CIS PG 3.1.x)."""
    if value.strip().lower() != "on":
        return (Severity.low, "PostgreSQL log_connections kapalı — bağlantı denetim izi yok.")
    return None


def eval_pg_password_encryption(value: str) -> tuple[Severity, str] | None:
    """password_encryption scram-sha-256 değilse zayıf parola saklama (CIS PG 4.x)."""
    if "scram" not in value.strip().lower():
        return (
            Severity.medium,
            f"PostgreSQL password_encryption '{value}' — scram-sha-256 önerilir.",
        )
    return None


# pg_settings adı → (bulgu başlığı, saf değerlendirme)
PG_CHECKS: DbCheckMap = {
    "ssl": ("PostgreSQL SSL/TLS", eval_pg_ssl),
    "log_connections": ("PostgreSQL bağlantı günlüğü", eval_pg_log_connections),
    "password_encryption": ("PostgreSQL parola şifreleme", eval_pg_password_encryption),
}


def evaluate_pg_settings(settings: dict[str, str]) -> list[DbFinding]:
    """pg_settings değerlerinden bulguları üretir (saf; ağ gerektirmez)."""
    findings: list[DbFinding] = []
    for name, (title, evaluate) in PG_CHECKS.items():
        verdict = evaluate(settings.get(name, ""))
        if verdict is not None:
            severity, detail = verdict
            findings.append(DbFinding(title, severity, detail))
    return findings


async def audit_postgres(
    host: str,
    port: int,
    user: str,
    password: str,
    database: str = "postgres",
    timeout: float = 10.0,
) -> tuple[str, list[DbFinding]]:
    """PostgreSQL'e salt-okunur bağlanıp güvenlik ayarlarını denetler. (sürüm, bulgular) döner."""
    import asyncpg

    conn = await asyncpg.connect(
        host=host, port=port, user=user, password=password, database=database, timeout=timeout
    )
    try:
        version = str(await conn.fetchval("SELECT version()") or "")
        rows = await conn.fetch(
            "SELECT name, setting FROM pg_settings WHERE name = ANY($1::text[])",
            list(PG_CHECKS.keys()),
        )
        settings = {r["name"]: str(r["setting"]) for r in rows}
        return version, evaluate_pg_settings(settings)
    finally:
        await conn.close()


# --- MySQL / MariaDB (IX-4) — GLOBAL VARIABLES üzerinden CIS-tarzı denetim ---


def eval_mysql_secure_transport(value: str) -> tuple[Severity, str] | None:
    """require_secure_transport kapalıysa TLS zorunlu değil (şifresiz bağlantı riski)."""
    if value.strip().lower() not in ("on", "1"):
        return (
            Severity.medium,
            f"MySQL require_secure_transport '{value or '—'}' — TLS zorunlu değil.",
        )
    return None


def eval_mysql_local_infile(value: str) -> tuple[Severity, str] | None:
    """local_infile açıksa LOAD DATA LOCAL ile istemci/sunucu dosya okuma riski."""
    if value.strip().lower() in ("on", "1"):
        return (Severity.medium, "MySQL local_infile açık — LOAD DATA LOCAL ile dosya okuma riski.")
    return None


def eval_mysql_auth_plugin(value: str) -> tuple[Severity, str] | None:
    """Varsayılan kimlik doğrulama eklentisi zayıfsa (mysql_native_password) uyarır."""
    if "native" in value.strip().lower():
        return (
            Severity.medium,
            f"MySQL default_authentication_plugin '{value}' — caching_sha2_password önerilir.",
        )
    return None


# MySQL global değişkeni → (bulgu başlığı, saf değerlendirme)
MYSQL_CHECKS: DbCheckMap = {
    "require_secure_transport": ("MySQL TLS zorunluluğu", eval_mysql_secure_transport),
    "local_infile": ("MySQL local_infile", eval_mysql_local_infile),
    "default_authentication_plugin": ("MySQL kimlik doğrulama eklentisi", eval_mysql_auth_plugin),
}


def evaluate_mysql_settings(settings: dict[str, str]) -> list[DbFinding]:
    """MySQL global değişken değerlerinden bulguları üretir (saf; ağ gerektirmez).

    Sunucuda BULUNMAYAN değişken değerlendirilmez. ``require_secure_transport`` eski MySQL
    5.6/5.7 ve birçok MariaDB sürümünde YOKTUR; yokluğu "kapalı/zayıf" sanılırsa o sunucularda
    sahte "TLS zorunlu değil" bulgusu çıkardı. ``audit_mysql`` sözlüğe yalnız sunucudan dönen
    değişkenleri koyar → burada da sözlükte olmayan ölçüt atlanır (yanlış-pozitif önlenir).
    """
    findings: list[DbFinding] = []
    for name, (title, evaluate) in MYSQL_CHECKS.items():
        if name not in settings:
            continue  # sunucuda yok → değerlendirme yapma
        verdict = evaluate(settings[name])
        if verdict is not None:
            severity, detail = verdict
            findings.append(DbFinding(title, severity, detail))
    return findings


async def audit_mysql(
    host: str,
    port: int,
    user: str,
    password: str,
    database: str = "",
    timeout: float = 10.0,
) -> tuple[str, list[DbFinding]]:
    """MySQL/MariaDB'ye salt-okunur bağlanıp güvenlik global değişkenlerini denetler."""
    import aiomysql

    conn = await aiomysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        db=database or None,
        connect_timeout=timeout,
    )
    try:
        async with conn.cursor() as cur:
            await cur.execute("SELECT VERSION()")
            row = await cur.fetchone()
            version = f"MySQL {row[0]}" if row else "MySQL"
            settings: dict[str, str] = {}
            for name in MYSQL_CHECKS:
                await cur.execute("SHOW GLOBAL VARIABLES LIKE %s", (name,))
                var = await cur.fetchone()
                if var is not None:
                    settings[str(var[0])] = str(var[1])
        return version, evaluate_mysql_settings(settings)
    finally:
        conn.close()


# --- MSSQL / SQL Server (IX-5) — sys.configurations + SERVERPROPERTY üzerinden ---


def eval_mssql_xp_cmdshell(value: str) -> tuple[Severity, str] | None:
    """xp_cmdshell açıksa OS komut çalıştırma yüzeyi (yüksek risk)."""
    if value.strip() == "1":
        return (Severity.high, "MSSQL xp_cmdshell açık — DB üzerinden OS komutu çalıştırılabilir.")
    return None


def eval_mssql_ole_automation(value: str) -> tuple[Severity, str] | None:
    """Ole Automation Procedures açıksa COM nesne erişimi (saldırı yüzeyi)."""
    if value.strip() == "1":
        return (Severity.medium, "MSSQL 'Ole Automation Procedures' açık — saldırı yüzeyi artar.")
    return None


def eval_mssql_clr(value: str) -> tuple[Severity, str] | None:
    """CLR entegrasyonu açıksa imzasız .NET kodu riski."""
    if value.strip() == "1":
        return (Severity.medium, "MSSQL 'clr enabled' açık — imzasız CLR derlemeleri risk taşır.")
    return None


def eval_mssql_auth_mode(value: str) -> tuple[Severity, str] | None:
    """IsIntegratedSecurityOnly=0 ise karışık mod (SQL kimlik doğrulama açık)."""
    if value.strip() == "0":
        return (
            Severity.medium,
            "MSSQL karışık mod (SQL kimlik doğrulama açık) — yalnız Windows "
            "kimlik doğrulama önerilir.",
        )
    return None


# MSSQL ayar anahtarı → (bulgu başlığı, saf değerlendirme). 'auth_mode' SERVERPROPERTY'den.
MSSQL_CHECKS: DbCheckMap = {
    "xp_cmdshell": ("MSSQL xp_cmdshell", eval_mssql_xp_cmdshell),
    "Ole Automation Procedures": ("MSSQL OLE Automation", eval_mssql_ole_automation),
    "clr enabled": ("MSSQL CLR", eval_mssql_clr),
    "auth_mode": ("MSSQL kimlik doğrulama modu", eval_mssql_auth_mode),
}


def evaluate_mssql_settings(settings: dict[str, str]) -> list[DbFinding]:
    """MSSQL ayar değerlerinden bulguları üretir (saf; ağ gerektirmez)."""
    findings: list[DbFinding] = []
    for name, (title, evaluate) in MSSQL_CHECKS.items():
        verdict = evaluate(settings.get(name, ""))
        if verdict is not None:
            severity, detail = verdict
            findings.append(DbFinding(title, severity, detail))
    return findings


def _read_mssql(
    host: str, port: int, user: str, password: str, db: str, timeout: float
) -> tuple[str, dict[str, str]]:
    """pytds ile salt-okunur MSSQL config okuması (senkron; to_thread içinde çağrılır)."""
    import pytds

    conn = pytds.connect(
        dsn=host,
        port=port,
        user=user,
        password=password,
        database=db or "master",
        login_timeout=timeout,
        timeout=timeout,
    )
    try:
        cur = conn.cursor()
        cur.execute("SELECT @@VERSION")
        row = cur.fetchone()
        version = str(row[0]).splitlines()[0] if row and row[0] else "MSSQL"
        settings: dict[str, str] = {}
        cur.execute(
            "SELECT name, CAST(value_in_use AS varchar(20)) FROM sys.configurations "
            "WHERE name IN ('xp_cmdshell', 'Ole Automation Procedures', 'clr enabled')"
        )
        for name, val in cur.fetchall():
            settings[str(name)] = str(val)
        cur.execute("SELECT CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS varchar(10))")
        auth = cur.fetchone()
        settings["auth_mode"] = str(auth[0]) if auth and auth[0] is not None else ""
        return version, settings
    finally:
        conn.close()


async def audit_mssql(
    host: str,
    port: int,
    user: str,
    password: str,
    database: str = "",
    timeout: float = 10.0,
) -> tuple[str, list[DbFinding]]:
    """MSSQL/SQL Server'a salt-okunur bağlanıp güvenlik ayarlarını denetler (pytds, to_thread)."""
    version, settings = await asyncio.to_thread(
        _read_mssql, host, port, user, password, database, timeout
    )
    return version, evaluate_mssql_settings(settings)


# --- Oracle (IX-6) — v$parameter üzerinden CIS-tarzı denetim ---


def eval_oracle_remote_os_authent(value: str) -> tuple[Severity, str] | None:
    """remote_os_authent TRUE ise uzaktan OS kimlik doğrulama (yüksek risk)."""
    if value.strip().upper() == "TRUE":
        return (Severity.high, "Oracle remote_os_authent=TRUE — uzaktan OS kimlik doğrulama açık.")
    return None


def eval_oracle_dict_accessibility(value: str) -> tuple[Severity, str] | None:
    """O7_DICTIONARY_ACCESSIBILITY TRUE ise veri sözlüğüne geniş erişim (yüksek risk)."""
    if value.strip().upper() == "TRUE":
        return (
            Severity.high,
            "Oracle O7_DICTIONARY_ACCESSIBILITY=TRUE — veri sözlüğüne aşırı erişim.",
        )
    return None


def eval_oracle_sql92_security(value: str) -> tuple[Severity, str] | None:
    """sql92_security FALSE ise UPDATE/DELETE için SELECT yetkisi zorunlu değil."""
    if value.strip().upper() == "FALSE":
        return (Severity.low, "Oracle sql92_security=FALSE — SQL92 güvenlik kısıtı kapalı.")
    return None


def eval_oracle_case_sensitive_logon(value: str) -> tuple[Severity, str] | None:
    """sec_case_sensitive_logon FALSE ise parola harf duyarsız (zayıf)."""
    if value.strip().upper() == "FALSE":
        return (
            Severity.medium,
            "Oracle sec_case_sensitive_logon=FALSE — parolalar harf duyarsız (zayıf).",
        )
    return None


# Oracle v$parameter adı → (bulgu başlığı, saf değerlendirme)
ORACLE_CHECKS: DbCheckMap = {
    "remote_os_authent": ("Oracle remote_os_authent", eval_oracle_remote_os_authent),
    "o7_dictionary_accessibility": ("Oracle dictionary erişimi", eval_oracle_dict_accessibility),
    "sql92_security": ("Oracle SQL92 güvenlik", eval_oracle_sql92_security),
    "sec_case_sensitive_logon": (
        "Oracle parola harf duyarlılığı",
        eval_oracle_case_sensitive_logon,
    ),
}


def evaluate_oracle_settings(settings: dict[str, str]) -> list[DbFinding]:
    """Oracle parametre değerlerinden bulguları üretir (saf; ağ gerektirmez)."""
    findings: list[DbFinding] = []
    for name, (title, evaluate) in ORACLE_CHECKS.items():
        verdict = evaluate(settings.get(name, ""))
        if verdict is not None:
            severity, detail = verdict
            findings.append(DbFinding(title, severity, detail))
    return findings


def _read_oracle(
    host: str, port: int, user: str, password: str, service: str, timeout: float
) -> tuple[str, dict[str, str]]:
    """oracledb (thin mode) ile salt-okunur Oracle parametre okuması (senkron; to_thread)."""
    import oracledb

    dsn = f"{host}:{port}/{service}" if service else f"{host}:{port}"
    conn = oracledb.connect(user=user, password=password, dsn=dsn, tcp_connect_timeout=timeout)
    try:
        cur = conn.cursor()
        cur.execute("SELECT banner FROM v$version WHERE ROWNUM = 1")
        row = cur.fetchone()
        version = str(row[0]) if row and row[0] else "Oracle"
        settings: dict[str, str] = {}
        cur.execute(
            "SELECT name, value FROM v$parameter WHERE name IN "
            "('remote_os_authent', 'o7_dictionary_accessibility', 'sql92_security', "
            "'sec_case_sensitive_logon')"
        )
        for name, val in cur.fetchall():
            settings[str(name)] = str(val) if val is not None else ""
        return version, settings
    finally:
        conn.close()


async def audit_oracle(
    host: str,
    port: int,
    user: str,
    password: str,
    database: str = "",
    timeout: float = 10.0,
) -> tuple[str, list[DbFinding]]:
    """Oracle'a salt-okunur bağlanıp güvenlik parametrelerini denetler (oracledb thin, to_thread).

    ``database`` Oracle servis adıdır (ör. FREEPDB1 / XEPDB1 / ORCL).
    """
    version, settings = await asyncio.to_thread(
        _read_oracle, host, port, user, password, database, timeout
    )
    return version, evaluate_oracle_settings(settings)


# Motor anahtarı → (gösterim etiketi, denetim sözlüğü).
ENGINE_CHECKS: dict[str, tuple[str, DbCheckMap]] = {
    "postgres": ("PostgreSQL", PG_CHECKS),
    "mysql": ("MySQL", MYSQL_CHECKS),
    "mssql": ("MSSQL", MSSQL_CHECKS),
    "oracle": ("Oracle", ORACLE_CHECKS),
}


async def store_db_audit(
    session: AsyncSession,
    scan_id: int,
    version: str,
    findings: list[DbFinding],
    *,
    engine: str = "postgres",
) -> None:
    """DB envanteri (info) + denetim bulgularını + CIS uyumunu Finding olarak kaydeder."""
    label, checks = ENGINE_CHECKS.get(engine, ENGINE_CHECKS["postgres"])
    await create_finding(
        session,
        scan_id,
        f"Veritabanı envanteri: {version[:120] or 'bilinmiyor'}",
        severity=Severity.info,
        description=f"{label} salt-okunur konfig denetimi.",
    )
    for finding in findings:
        await create_finding(
            session, scan_id, finding.title, severity=finding.severity, description=finding.detail
        )
    # Uyum (CIS): çalışan denetimleri kontrollere eşle → geçti/kaldı sakla.
    ran_titles = [title for title, _ in checks.values()]
    failed = {f.title: (f.severity, f.detail) for f in findings}
    await store_compliance(session, scan_id, derive_compliance(ran_titles, failed))
