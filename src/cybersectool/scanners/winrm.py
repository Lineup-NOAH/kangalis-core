"""Credentialed Windows taraması — WinRM (NTLM) ile içeriden CIS-tarzı denetim.

SSH credentialed taramasının (``credentialed.py``) Windows karşılığı. PowerShell
ile **salt-okunur** güvenlik kontrolleri çalıştırır; sisteme sızmaz, değişiklik
yapmaz (kullanıcının "ürüne sızıp içeride kullanıcı oluşturma" endişesine uygun).

Kontroller:
- Host envanteri (OS / sürüm / hotfix sayısı),
- SMBv1 etkin mi (EternalBlue riski),
- Windows Defender gerçek zamanlı koruma kapalı mı,
- Güvenlik duvarı profili kapalı mı,
- RDP NLA (ağ düzeyi kimlik doğrulama) kapalı mı,
- kayıt defterinde açık AutoLogon parolası,
- aşırı yerel yönetici sayısı.

``parse_*`` / ``eval_*`` fonksiyonları saftır (birim testi edilebilir; WinRM gerekmez).
Kimlik bilgileri yalnızca istek anında kullanılır, **kalıcı SAKLANMAZ**.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.compliance import derive_compliance, store_compliance
from cybersectool.core.findings import create_finding
from cybersectool.core.models import Severity
from cybersectool.core.privesc import (
    eval_always_install_elevated,
    eval_unquoted_services,
    eval_win_privileges,
)
from cybersectool.scanners.hardening import HardeningCheck, HardeningFinding

WINRM_PORT = 5985  # WinRM HTTP (NTLM şifreli)


class WinRMScanError(Exception):
    """WinRM bağlantısı/komutu başarısız (kimlik hatası, erişilemez host vb.)."""


@dataclass
class WindowsFacts:
    """Kimlikli WinRM erişimiyle toplanan Windows host bilgileri."""

    os: str | None = None
    version: str | None = None
    hostname: str | None = None
    hotfix_count: int | None = None


# PowerShell: host bilgilerini ayrıştırılabilir anahtar=değer satırları olarak döker.
FACTS_PS = (
    "$os = Get-CimInstance Win32_OperatingSystem; "
    "Write-Output ('OS=' + $os.Caption); "
    "Write-Output ('VERSION=' + $os.Version); "
    "Write-Output ('HOSTNAME=' + $env:COMPUTERNAME); "
    "Write-Output ('HOTFIX_COUNT=' + (Get-HotFix | Measure-Object).Count)"
)


def parse_windows_facts(output: str) -> WindowsFacts:
    """FACTS_PS çıktısındaki anahtar=değer satırlarını WindowsFacts'e çevirir."""
    data: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            data[key.strip()] = value.strip()
    hotfix: int | None = None
    if data.get("HOTFIX_COUNT", "").isdigit():
        hotfix = int(data["HOTFIX_COUNT"])
    return WindowsFacts(
        os=data.get("OS") or None,
        version=data.get("VERSION") or None,
        hostname=data.get("HOSTNAME") or None,
        hotfix_count=hotfix,
    )


# --- saf eval fonksiyonları (PowerShell çıktısı → bulgu) ---


def eval_smb1(output: str) -> tuple[Severity, str] | None:
    if "true" in output.lower():
        return (
            Severity.high,
            "SMBv1 etkin — eski/güvensiz protokol (EternalBlue/WannaCry riski); kapatın.",
        )
    return None


def eval_defender_rtp(output: str) -> tuple[Severity, str] | None:
    if "false" in output.lower():
        return (
            Severity.high,
            "Windows Defender gerçek zamanlı koruma KAPALI — kötü amaçlı yazılım koruması yok.",
        )
    return None


def eval_firewall(output: str) -> tuple[Severity, str] | None:
    """'Domain=True/False' gibi satırlardan kapalı profilleri bulur."""
    disabled = [
        line.split("=", 1)[0].strip()
        for line in output.splitlines()
        if "=" in line and line.split("=", 1)[1].strip().lower() == "false"
    ]
    if disabled:
        return (Severity.high, f"Güvenlik duvarı profili kapalı: {', '.join(disabled)}")
    return None


def eval_rdp_nla(output: str) -> tuple[Severity, str] | None:
    """RDP UserAuthentication=0 ise Ağ Düzeyi Kimlik Doğrulama (NLA) kapalıdır."""
    if output.strip() == "0":
        return (
            Severity.medium,
            "RDP Ağ Düzeyi Kimlik Doğrulama (NLA) kapalı — kimlik doğrulamasız RDP el sıkışması.",
        )
    return None


def eval_autologon(output: str) -> tuple[Severity, str] | None:
    if output.strip():
        return (
            Severity.high,
            "Kayıt defterinde açık AutoLogon parolası bulundu (Winlogon DefaultPassword).",
        )
    return None


def eval_local_admins(output: str) -> tuple[Severity, str] | None:
    count = output.strip()
    if count.isdigit() and int(count) > 5:
        return (
            Severity.medium,
            f"Yerel Administrators grubunda çok sayıda üye ({count}) — saldırı yüzeyini artırır.",
        )
    return None


WIN_CHECKS: list[HardeningCheck] = [
    HardeningCheck(
        "SMBv1 protokolü",
        "(Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol",
        eval_smb1,
    ),
    HardeningCheck(
        "Defender gerçek zamanlı koruma",
        "(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled",
        eval_defender_rtp,
    ),
    HardeningCheck(
        "Güvenlik duvarı profilleri",
        "Get-NetFirewallProfile | ForEach-Object { $_.Name + '=' + $_.Enabled }",
        eval_firewall,
    ),
    HardeningCheck(
        "RDP NLA",
        "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server"
        "\\WinStations\\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication",
        eval_rdp_nla,
    ),
    HardeningCheck(
        "AutoLogon açık parola",
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        "\\Winlogon' -ErrorAction SilentlyContinue).DefaultPassword",
        eval_autologon,
    ),
    HardeningCheck(
        "Yerel yönetici sayısı",
        "(Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue "
        "| Measure-Object).Count",
        eval_local_admins,
    ),
]


# Yetki yükseltme (privilege escalation) ENUMERASYONU — SALT-OKUNUR (VIII-3a).
# Yalnızca FIRSATLARI raporlar (token istismarı / AlwaysInstallElevated / tırnaksız
# servis yolu); hiçbir şey DENEMEZ, değiştirmez. CIS uyumuna SAYILMAZ (ran_titles dışı).
WIN_PRIVESC_CHECKS: list[HardeningCheck] = [
    HardeningCheck(
        "Yetki yükseltme: tehlikeli ayrıcalıklar",
        "whoami /priv",
        eval_win_privileges,
    ),
    HardeningCheck(
        "Yetki yükseltme: AlwaysInstallElevated",
        "$h=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' "
        "-ErrorAction SilentlyContinue).AlwaysInstallElevated; "
        "$u=(Get-ItemProperty 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' "
        "-ErrorAction SilentlyContinue).AlwaysInstallElevated; "
        "Write-Output ('HKLM=' + $h); Write-Output ('HKCU=' + $u)",
        eval_always_install_elevated,
    ),
    HardeningCheck(
        "Yetki yükseltme: tırnaksız servis yolları",
        "Get-CimInstance Win32_Service | Where-Object { $_.PathName -and "
        "$_.PathName -notlike '\"*' -and $_.PathName -like '* *' } | "
        "ForEach-Object { $_.Name + '|' + $_.PathName }",
        eval_unquoted_services,
    ),
]

# Çalıştırılacak tüm kontroller (CIS + priv-esc). Uyum yalnız WIN_CHECKS'ten türetilir.
_ALL_WIN_CHECKS: list[HardeningCheck] = [*WIN_CHECKS, *WIN_PRIVESC_CHECKS]


def _winrm_collect(
    host: str, port: int, username: str, password: str, transport: str
) -> tuple[str, list[str]]:
    """WinRM ile (senkron, thread içinde) facts + her kontrolün çıktısını toplar.

    pywinrm senkrondur; bu fonksiyon ``asyncio.to_thread`` ile çağrılır. winrm
    yalnızca burada (lazy) import edilir.
    """
    import winrm

    session = winrm.Session(
        f"http://{host}:{port}/wsman", auth=(username, password), transport=transport
    )
    facts_out = session.run_ps(FACTS_PS).std_out.decode("utf-8", errors="replace")
    outputs: list[str] = []
    for check in _ALL_WIN_CHECKS:
        result = session.run_ps(check.command)
        outputs.append(result.std_out.decode("utf-8", errors="replace"))
    return facts_out, outputs


async def run_winrm_scan(
    host: str,
    port: int,
    username: str,
    password: str,
    *,
    transport: str = "ntlm",
) -> tuple[WindowsFacts, list[HardeningFinding]]:
    """WinRM ile bağlanıp Windows envanteri + salt-okunur güvenlik denetimlerini çalıştırır.

    Herhangi bir bağlantı/kimlik hatasını :class:`WinRMScanError` olarak yükseltir.
    Kimlik bilgileri yalnızca bu çağrı süresince kullanılır; hiçbir yere yazılmaz.
    """
    try:
        facts_out, outputs = await asyncio.to_thread(
            _winrm_collect, host, port, username, password, transport
        )
    except Exception as exc:  # winrm/requests/OSError → tek tip hata
        raise WinRMScanError(str(exc)) from exc

    facts = parse_windows_facts(facts_out)
    findings: list[HardeningFinding] = []
    for check, output in zip(_ALL_WIN_CHECKS, outputs, strict=True):
        verdict = check.evaluate(output)
        if verdict is not None:
            severity, detail = verdict
            findings.append(HardeningFinding(check.title, severity, detail))
    return facts, findings


async def store_winrm(
    session: AsyncSession,
    scan_id: int,
    facts: WindowsFacts,
    findings: list[HardeningFinding],
    asset_id: int | None = None,
) -> None:
    """Windows host envanterini (info) ve bulguları Finding olarak kaydeder.

    ``asset_id`` verilirse bulgular o varlığa bağlanır (tek taramada çok host ayrımı için).
    """
    await create_finding(
        session,
        scan_id,
        f"Windows envanteri: {facts.os or 'bilinmiyor'}",
        severity=Severity.info,
        asset_id=asset_id,
        description=f"Sürüm {facts.version or '?'} · {facts.hotfix_count or 0} hotfix · "
        f"{facts.hostname or '?'}",
    )
    for finding in findings:
        await create_finding(
            session,
            scan_id,
            finding.title,
            severity=finding.severity,
            asset_id=asset_id,
            description=finding.detail,
            validated=finding.validated,
        )
    # Uyum (CIS Windows): çalışan denetimleri kontrollere eşle → geçti/kaldı sakla (VII-1b).
    ran_titles = [check.title for check in WIN_CHECKS]
    failed = {f.title: (f.severity, f.detail) for f in findings}
    await store_compliance(session, scan_id, derive_compliance(ran_titles, failed))
