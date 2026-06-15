"""Host sıkılaştırma tarayıcı — SSH ile CIS-tarzı yapılandırma denetimi.

Kimlik bilgileri yalnızca istek anında kullanılır, **kalıcı saklanmaz** (güvenli kimlik
saklama bir sonraki adım). `eval_*` fonksiyonları saftır (birim testi edilebilir).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

import asyncssh

from cybersectool.core.models import Severity


@dataclass
class HardeningFinding:
    title: str
    severity: Severity
    detail: str
    validated: bool = False  # aktif doğrulandı mı (ör. priv-esc DENEMESİ root verdi, VIII-3b)


@dataclass
class HardeningCheck:
    title: str
    command: str
    evaluate: Callable[[str], tuple[Severity, str] | None]


def eval_root_login(output: str) -> tuple[Severity, str] | None:
    if "yes" in output.lower():
        return (Severity.high, "SSH PermitRootLogin 'yes' — root ile doğrudan giriş açık.")
    return None


def eval_empty_password(output: str) -> tuple[Severity, str] | None:
    accounts = output.strip()
    if accounts:
        joined = accounts.replace("\n", ", ")
        return (Severity.critical, f"Boş parolalı hesap(lar): {joined}")
    return None


def eval_tmp_sticky(output: str) -> tuple[Severity, str] | None:
    perms = output.strip().split(" ", 1)[0] if output.strip() else ""
    if len(perms) >= 10 and perms[9].lower() != "t":
        return (Severity.medium, f"/tmp sticky bit yok ({perms}).")
    return None


def eval_empty_pw_ssh(output: str) -> tuple[Severity, str] | None:
    """SSH PermitEmptyPasswords 'yes' → boş parolayla giriş açık (CIS 5.2.10)."""
    if "yes" in output.lower():
        return (Severity.high, "SSH PermitEmptyPasswords 'yes' — boş parolayla giriş açık.")
    return None


def eval_max_auth_tries(output: str) -> tuple[Severity, str] | None:
    """SSH MaxAuthTries 4'ten büyük ya da ayarlanmamış → kaba-kuvvet riski (CIS 5.2.5)."""
    match = re.search(r"MaxAuthTries\s+(\d+)", output, re.IGNORECASE)
    if match is None:
        return (Severity.low, "SSH MaxAuthTries ayarlanmamış (varsayılan 6, >4).")
    if int(match.group(1)) > 4:
        return (Severity.low, f"SSH MaxAuthTries {match.group(1)} (>4).")
    return None


CHECKS: list[HardeningCheck] = [
    HardeningCheck(
        "SSH root girişi",
        "grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo none",
        eval_root_login,
    ),
    HardeningCheck(
        "Boş parolalı hesaplar",
        "awk -F: '($2==\"\"){print $1}' /etc/passwd 2>/dev/null",
        eval_empty_password,
    ),
    HardeningCheck(
        "/tmp sticky bit",
        "ls -ld /tmp",
        eval_tmp_sticky,
    ),
    HardeningCheck(
        "SSH boş parola izni",
        "grep -i '^PermitEmptyPasswords' /etc/ssh/sshd_config 2>/dev/null || echo none",
        eval_empty_pw_ssh,
    ),
    HardeningCheck(
        "SSH MaxAuthTries",
        "grep -i '^MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null || echo none",
        eval_max_auth_tries,
    ),
]


async def run_hardening(
    host: str, port: int, username: str, password: str
) -> list[HardeningFinding]:
    """SSH ile bağlanıp sıkılaştırma denetimlerini çalıştırır; başarısız olanları döndürür."""
    findings: list[HardeningFinding] = []
    async with asyncssh.connect(
        host, port=port, username=username, password=password, known_hosts=None
    ) as conn:
        for check in CHECKS:
            result = await conn.run(check.command, check=False)
            verdict = check.evaluate(str(result.stdout or ""))
            if verdict is not None:
                severity, detail = verdict
                findings.append(HardeningFinding(check.title, severity, detail))
    return findings
