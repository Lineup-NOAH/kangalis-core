"""Yetki yükseltme enumerasyonu (VIII-3a) — SAF eval birim testleri (SSH/WinRM gerekmez)."""

from __future__ import annotations

from cybersectool.core.models import Severity
from cybersectool.core.privesc import (
    PRIVESC_ATTEMPTS,
    confirmed_root,
    eval_always_install_elevated,
    eval_capabilities,
    eval_cron_writable,
    eval_kernel_privesc,
    eval_suid,
    eval_unquoted_services,
    eval_win_privileges,
)

# --- Linux ---


def test_eval_suid_flags_gtfobins_and_pkexec() -> None:
    out = "/usr/bin/nmap\n/bin/ping\n/usr/bin/find\n/usr/bin/pkexec\n/usr/lib/x/helper\n"
    verdict = eval_suid(out)
    assert verdict is not None
    sev, detail = verdict
    assert sev == Severity.high
    assert "nmap" in detail and "find" in detail
    assert "PwnKit" in detail  # pkexec → PwnKit notu
    assert "ping" not in detail  # zararsız SUID listelenmez


def test_eval_suid_none_when_safe() -> None:
    assert eval_suid("/bin/ping\n/usr/bin/passwd\n") is None
    assert eval_suid("") is None


def test_eval_capabilities_flags_dangerous() -> None:
    out = "/usr/bin/python3.8 = cap_setuid+ep\n/usr/bin/ping = cap_net_raw+ep\n"
    verdict = eval_capabilities(out)
    assert verdict is not None
    assert verdict[0] == Severity.high
    assert "cap_setuid" in verdict[1].lower()
    # net_raw tek başına tehlikeli listede değil
    assert eval_capabilities("/usr/bin/ping = cap_net_raw+ep\n") is None


def test_eval_cron_writable() -> None:
    assert eval_cron_writable("") is None
    verdict = eval_cron_writable("/etc/cron.d/backup\n/etc/crontab\n")
    assert verdict is not None and verdict[0] == Severity.high
    assert "backup" in verdict[1]


def test_eval_kernel_privesc_ranges() -> None:
    # DirtyCow aralığı (eski kernel)
    dc = eval_kernel_privesc("3.13.0-24-generic")
    assert dc is not None and dc[0] == Severity.medium
    assert "DirtyCow" in dc[1]
    # DirtyPipe aralığı
    dp = eval_kernel_privesc("5.10.0-8-amd64")
    assert dp is not None and "DirtyPipe" in dp[1]
    # Güncel kernel → bulgu yok
    assert eval_kernel_privesc("6.5.0-15-generic") is None
    # Ayrıştırılamayan → None
    assert eval_kernel_privesc("") is None
    assert eval_kernel_privesc("bilinmiyor") is None


# --- Windows ---


def test_eval_win_privileges_flags_token_privs() -> None:
    out = (
        "PRIVILEGES INFORMATION\n----\n"
        "SeImpersonatePrivilege        Impersonate a client   Enabled\n"
        "SeChangeNotifyPrivilege       Bypass traverse        Enabled\n"
    )
    verdict = eval_win_privileges(out)
    assert verdict is not None and verdict[0] == Severity.high
    assert "SeImpersonatePrivilege" in verdict[1]
    # Yalnız zararsız ayrıcalıklar → None
    assert eval_win_privileges("SeChangeNotifyPrivilege  Enabled\n") is None


def test_eval_always_install_elevated_both_required() -> None:
    assert eval_always_install_elevated("HKLM=1\nHKCU=1\n") is not None
    assert eval_always_install_elevated("HKLM=0x1\nHKCU=0x1\n") is not None
    # Yalnız biri → priv-esc değil
    assert eval_always_install_elevated("HKLM=1\nHKCU=\n") is None
    assert eval_always_install_elevated("HKLM=\nHKCU=\n") is None


def test_confirmed_root() -> None:
    """uid=0 çıktısı root doğrular; normal kullanıcı doğrulamaz (VIII-3b)."""
    assert confirmed_root("uid=0(root) gid=0(root) groups=0(root)")
    assert confirmed_root("uid=0 gid=0")
    assert not confirmed_root("uid=1000(msfadmin) gid=1000(msfadmin)")
    assert not confirmed_root("")
    assert not confirmed_root("permission denied")


def test_privesc_attempts_are_readonly_id() -> None:
    """Her deneme komutu salt-okunur 'id' ile doğrular (sistemi değiştirmez)."""
    assert len(PRIVESC_ATTEMPTS) >= 3
    for vector, command in PRIVESC_ATTEMPTS:
        assert vector and "id" in command  # her vektör id ile root doğrular
        # yıkıcı komut yok (rm/echo>/chmod vb. değil)
        assert not any(bad in command for bad in ("rm ", "rm -", "> /", "chmod", "mkfs", "dd "))


def test_eval_unquoted_services() -> None:
    out = (
        "VulnSvc|C:\\Program Files\\My App\\svc.exe\n"
        'GoodSvc|"C:\\Program Files\\Other\\ok.exe"\n'
        "WinSvc|C:\\Windows\\system32\\svchost.exe -k netsvcs\n"
    )
    verdict = eval_unquoted_services(out)
    assert verdict is not None and verdict[0] == Severity.medium
    assert "VulnSvc" in verdict[1]
    assert "GoodSvc" not in verdict[1]  # tırnaklı → güvenli
    assert "WinSvc" not in verdict[1]  # C:\Windows → hariç
    assert eval_unquoted_services("") is None
