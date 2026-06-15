"""PostgreSQL kimlikli DB denetimi testleri (VII-2a)."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.credentials import create_credential
from cybersectool.core.models import CredentialType, Role, Severity
from cybersectool.core.users import create_user
from cybersectool.scanners.db_audit import (
    MSSQL_CHECKS,
    MYSQL_CHECKS,
    ORACLE_CHECKS,
    PG_CHECKS,
    eval_mssql_auth_mode,
    eval_mssql_clr,
    eval_mssql_ole_automation,
    eval_mssql_xp_cmdshell,
    eval_mysql_auth_plugin,
    eval_mysql_local_infile,
    eval_mysql_secure_transport,
    eval_oracle_case_sensitive_logon,
    eval_oracle_dict_accessibility,
    eval_oracle_remote_os_authent,
    eval_oracle_sql92_security,
    eval_pg_log_connections,
    eval_pg_password_encryption,
    eval_pg_ssl,
    evaluate_mssql_settings,
    evaluate_mysql_settings,
    evaluate_oracle_settings,
    evaluate_pg_settings,
)


def test_eval_pg_ssl() -> None:
    assert eval_pg_ssl("on") is None
    verdict = eval_pg_ssl("off")
    assert verdict is not None and verdict[0] == Severity.medium


def test_eval_pg_log_connections() -> None:
    assert eval_pg_log_connections("on") is None
    assert eval_pg_log_connections("off") is not None


def test_eval_pg_password_encryption() -> None:
    assert eval_pg_password_encryption("scram-sha-256") is None
    verdict = eval_pg_password_encryption("md5")
    assert verdict is not None and verdict[0] == Severity.medium


def test_evaluate_pg_settings() -> None:
    """Güvenli ayarlar → bulgu yok; zayıf ayarlar → her biri bulgu."""
    secure = {"ssl": "on", "log_connections": "on", "password_encryption": "scram-sha-256"}
    assert evaluate_pg_settings(secure) == []
    weak = {"ssl": "off", "log_connections": "off", "password_encryption": "md5"}
    findings = evaluate_pg_settings(weak)
    assert len(findings) == len(PG_CHECKS) == 3


def test_pg_controls_mapped_to_cis() -> None:
    """VII-2a: tüm PG denetim başlıkları CIS PostgreSQL kontrolüne eşlenmiş olmalı."""
    from cybersectool.core.compliance import HARDENING_TO_CONTROL

    for title, _ in PG_CHECKS.values():
        assert title in HARDENING_TO_CONTROL
        assert HARDENING_TO_CONTROL[title].framework == "CIS PostgreSQL"


# --- MySQL (IX-4) ---


def test_eval_mysql_secure_transport() -> None:
    assert eval_mysql_secure_transport("ON") is None
    verdict = eval_mysql_secure_transport("OFF")
    assert verdict is not None and verdict[0] == Severity.medium


def test_eval_mysql_local_infile() -> None:
    assert eval_mysql_local_infile("OFF") is None
    assert eval_mysql_local_infile("ON") is not None


def test_eval_mysql_auth_plugin() -> None:
    assert eval_mysql_auth_plugin("caching_sha2_password") is None
    verdict = eval_mysql_auth_plugin("mysql_native_password")
    assert verdict is not None and verdict[0] == Severity.medium


def test_evaluate_mysql_settings() -> None:
    """Güvenli ayarlar → bulgu yok; zayıf ayarlar → her biri bulgu."""
    secure = {
        "require_secure_transport": "ON",
        "local_infile": "OFF",
        "default_authentication_plugin": "caching_sha2_password",
    }
    assert evaluate_mysql_settings(secure) == []
    weak = {
        "require_secure_transport": "OFF",
        "local_infile": "ON",
        "default_authentication_plugin": "mysql_native_password",
    }
    assert len(evaluate_mysql_settings(weak)) == len(MYSQL_CHECKS) == 3


def test_evaluate_mysql_settings_skips_missing_var() -> None:
    """ORTA fix: sunucuda BULUNMAYAN değişken değerlendirilmez (MariaDB/MySQL 5.6-5.7'de
    require_secure_transport YOK) → sahte 'TLS zorunlu değil' yanlış-pozitifi üretilmez."""
    # require_secure_transport YOK; diğerleri güvenli → hiç bulgu olmamalı (eskiden FP verirdi).
    partial = {"local_infile": "OFF", "default_authentication_plugin": "caching_sha2_password"}
    assert evaluate_mysql_settings(partial) == []
    # Hiç değişken dönmedi (tamamen boş) → bulgu yok.
    assert evaluate_mysql_settings({}) == []


def test_mysql_controls_mapped_to_cis() -> None:
    """IX-4: tüm MySQL denetim başlıkları CIS MySQL kontrolüne eşlenmiş olmalı."""
    from cybersectool.core.compliance import HARDENING_TO_CONTROL

    for title, _ in MYSQL_CHECKS.values():
        assert title in HARDENING_TO_CONTROL
        assert HARDENING_TO_CONTROL[title].framework == "CIS MySQL"


# --- MSSQL (IX-5) ---


def test_eval_mssql_xp_cmdshell() -> None:
    assert eval_mssql_xp_cmdshell("0") is None
    verdict = eval_mssql_xp_cmdshell("1")
    assert verdict is not None and verdict[0] == Severity.high


def test_eval_mssql_ole_and_clr() -> None:
    assert eval_mssql_ole_automation("0") is None
    assert eval_mssql_ole_automation("1") is not None
    assert eval_mssql_clr("0") is None
    assert eval_mssql_clr("1") is not None


def test_eval_mssql_auth_mode() -> None:
    assert eval_mssql_auth_mode("1") is None  # yalnız Windows kimlik doğrulama → iyi
    verdict = eval_mssql_auth_mode("0")  # karışık mod → bulgu
    assert verdict is not None and verdict[0] == Severity.medium


def test_evaluate_mssql_settings() -> None:
    """Güvenli ayarlar → bulgu yok; zayıf ayarlar → her biri bulgu."""
    secure = {
        "xp_cmdshell": "0",
        "Ole Automation Procedures": "0",
        "clr enabled": "0",
        "auth_mode": "1",
    }
    assert evaluate_mssql_settings(secure) == []
    weak = {
        "xp_cmdshell": "1",
        "Ole Automation Procedures": "1",
        "clr enabled": "1",
        "auth_mode": "0",
    }
    assert len(evaluate_mssql_settings(weak)) == len(MSSQL_CHECKS) == 4


def test_mssql_controls_mapped_to_cis() -> None:
    """IX-5: tüm MSSQL denetim başlıkları CIS MSSQL kontrolüne eşlenmiş olmalı."""
    from cybersectool.core.compliance import HARDENING_TO_CONTROL

    for title, _ in MSSQL_CHECKS.values():
        assert title in HARDENING_TO_CONTROL
        assert HARDENING_TO_CONTROL[title].framework == "CIS MSSQL"


# --- Oracle (IX-6) ---


def test_eval_oracle_remote_os_authent_and_dict() -> None:
    assert eval_oracle_remote_os_authent("FALSE") is None
    v = eval_oracle_remote_os_authent("TRUE")
    assert v is not None and v[0] == Severity.high
    assert eval_oracle_dict_accessibility("FALSE") is None
    assert eval_oracle_dict_accessibility("TRUE") is not None


def test_eval_oracle_sql92_and_case() -> None:
    assert eval_oracle_sql92_security("TRUE") is None
    assert eval_oracle_sql92_security("FALSE") is not None
    assert eval_oracle_case_sensitive_logon("TRUE") is None
    v = eval_oracle_case_sensitive_logon("FALSE")
    assert v is not None and v[0] == Severity.medium


def test_evaluate_oracle_settings() -> None:
    """Güvenli ayarlar → bulgu yok; zayıf ayarlar → her biri bulgu."""
    secure = {
        "remote_os_authent": "FALSE",
        "o7_dictionary_accessibility": "FALSE",
        "sql92_security": "TRUE",
        "sec_case_sensitive_logon": "TRUE",
    }
    assert evaluate_oracle_settings(secure) == []
    weak = {
        "remote_os_authent": "TRUE",
        "o7_dictionary_accessibility": "TRUE",
        "sql92_security": "FALSE",
        "sec_case_sensitive_logon": "FALSE",
    }
    assert len(evaluate_oracle_settings(weak)) == len(ORACLE_CHECKS) == 4


def test_oracle_controls_mapped_to_cis() -> None:
    """IX-6: tüm Oracle denetim başlıkları CIS Oracle kontrolüne eşlenmiş olmalı."""
    from cybersectool.core.compliance import HARDENING_TO_CONTROL

    for title, _ in ORACLE_CHECKS.values():
        assert title in HARDENING_TO_CONTROL
        assert HARDENING_TO_CONTROL[title].framework == "CIS Oracle"


async def _login(
    client: AsyncClient, fac: async_sessionmaker[AsyncSession], u: str, r: Role
) -> None:
    async with fac() as s:
        await create_user(s, u, "pass1234", role=r)
    await client.post(
        "/login", data={"username": u, "password": "pass1234"}, follow_redirects=False
    )


async def test_db_audit_route_non_admin_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "an_db", Role.analyst)
    resp = await client.post(
        "/scans/db", data={"host": "10.0.0.20", "credential_id": "1"}, follow_redirects=False
    )
    assert resp.status_code == 403


async def test_db_audit_route_wrong_cred_type(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """SSH tipi kimlikle DB denetimi → 400 (postgres bekleniyor)."""
    async with session_factory() as s:
        await create_user(s, "adm_db", "pass1234", role=Role.admin)
        cred = await create_credential(s, "ssh-cred", CredentialType.ssh, "root", "x")
        cred_id = cred.id
    await client.post(
        "/login", data={"username": "adm_db", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post(
        "/scans/db",
        data={"host": "10.0.0.20", "credential_id": str(cred_id)},
        follow_redirects=False,
    )
    assert resp.status_code == 400


async def test_db_audit_route_postgres_cred_scope_denied(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Postgres kimliği + kapsam dışı host → 303 (scope guard içeride durdurur, çökmez)."""
    async with session_factory() as s:
        await create_user(s, "adm_db2", "pass1234", role=Role.admin)
        cred = await create_credential(s, "pg-cred", CredentialType.postgres, "cyber", "cyber")
        cred_id = cred.id
    await client.post(
        "/login", data={"username": "adm_db2", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post(
        "/scans/db",
        data={"host": "10.0.0.20", "credential_id": str(cred_id), "database": "postgres"},
        follow_redirects=False,
    )
    assert resp.status_code == 303  # kapsam dışı → scan failed kaydı, çökme yok


async def test_db_audit_route_mysql_wrong_cred_type(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """engine=mysql ama postgres kimliği → 400 (mysql tipi bekleniyor)."""
    async with session_factory() as s:
        await create_user(s, "adm_my", "pass1234", role=Role.admin)
        cred = await create_credential(s, "pg-for-my", CredentialType.postgres, "cyber", "x")
        cred_id = cred.id
    await client.post(
        "/login", data={"username": "adm_my", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post(
        "/scans/db",
        data={"host": "10.0.0.20", "credential_id": str(cred_id), "engine": "mysql"},
        follow_redirects=False,
    )
    assert resp.status_code == 400


async def test_db_audit_route_mysql_scope_denied(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """MySQL kimliği + kapsam dışı host → 303 (scope guard içeride durdurur, çökmez)."""
    async with session_factory() as s:
        await create_user(s, "adm_my2", "pass1234", role=Role.admin)
        cred = await create_credential(s, "my-cred", CredentialType.mysql, "audit", "x")
        cred_id = cred.id
    await client.post(
        "/login", data={"username": "adm_my2", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post(
        "/scans/db",
        data={"host": "10.0.0.20", "credential_id": str(cred_id), "engine": "mysql"},
        follow_redirects=False,
    )
    assert resp.status_code == 303


async def test_db_audit_route_mssql_scope_denied(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """MSSQL kimliği + kapsam dışı host → 303 (scope guard içeride durdurur, çökmez)."""
    async with session_factory() as s:
        await create_user(s, "adm_ms", "pass1234", role=Role.admin)
        cred = await create_credential(s, "ms-cred", CredentialType.mssql, "sa", "x")
        cred_id = cred.id
    await client.post(
        "/login", data={"username": "adm_ms", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post(
        "/scans/db",
        data={"host": "10.0.0.20", "credential_id": str(cred_id), "engine": "mssql"},
        follow_redirects=False,
    )
    assert resp.status_code == 303


async def test_db_audit_route_oracle_scope_denied(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Oracle kimliği + kapsam dışı host → 303 (scope guard içeride durdurur, çökmez)."""
    async with session_factory() as s:
        await create_user(s, "adm_or", "pass1234", role=Role.admin)
        cred = await create_credential(s, "or-cred", CredentialType.oracle, "system", "x")
        cred_id = cred.id
    await client.post(
        "/login", data={"username": "adm_or", "password": "pass1234"}, follow_redirects=False
    )
    resp = await client.post(
        "/scans/db",
        data={"host": "10.0.0.20", "credential_id": str(cred_id), "engine": "oracle"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
