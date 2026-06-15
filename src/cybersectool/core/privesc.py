"""Yetki yükseltme (privilege escalation) ENUMERASYONU — SALT-OKUNUR (VIII-3a).

Kimlikli (SSH/WinRM) erişim sonrası, hedefte yetki yükseltme FIRSATLARINI tespit edip
RAPORLAR — hiçbir şey DENEMEZ, değiştirmez (gerçek deneme VIII-3b, gated). Bu modül
yalnızca SAF eval fonksiyonları + sabitler içerir (komut çıktısı → bulgu); komut
çalıştırma ``scanners`` katmanındadır. Böylece SSH/WinRM olmadan birim testi yapılır.

Linux vektörleri: GTFOBins SUID ikilileri, tehlikeli dosya capabilities, yazılabilir
cron, eski kernel (DirtyCow/DirtyPipe), SUID pkexec (PwnKit). Windows vektörleri:
tehlikeli token ayrıcalıkları (SeImpersonate vb.), AlwaysInstallElevated, tırnaksız
servis yolları.
"""

from __future__ import annotations

from cybersectool.core.models import Severity

# GTFOBins — SUID iken kabuk/komut çalıştırıp root'a yükseltilebilen yaygın ikililer.
GTFO_SUID: frozenset[str] = frozenset(
    {
        "nmap",
        "vim",
        "vi",
        "find",
        "bash",
        "sh",
        "dash",
        "more",
        "less",
        "nano",
        "cp",
        "mv",
        "awk",
        "gawk",
        "python",
        "python2",
        "python3",
        "perl",
        "ruby",
        "php",
        "env",
        "tar",
        "zip",
        "gdb",
        "ed",
        "man",
        "tee",
        "sed",
        "make",
        "rsync",
        "wget",
        "curl",
        "busybox",
        "strace",
        "ltrace",
        "ftp",
        "socat",
    }
)

# Yetki yükseltmeye elverişli dosya capabilities (getcap çıktısında aranır).
DANGEROUS_CAPS: tuple[str, ...] = (
    "cap_setuid",
    "cap_setgid",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_sys_admin",
    "cap_sys_ptrace",
    "cap_sys_module",
    "cap_chown",
)

# Token/priv-esc'e elverişli Windows ayrıcalıkları (whoami /priv çıktısında aranır).
DANGEROUS_WIN_PRIVS: tuple[str, ...] = (
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeDebugPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeTcbPrivilege",
    "SeManageVolumePrivilege",
)


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1].strip()


def _kernel_tuple(kernel: str) -> tuple[int, int, int] | None:
    """'5.4.0-42-generic' → (5, 4, 0). Ayrıştırılamazsa None."""
    head = (kernel or "").strip().split("-", 1)[0]
    parts = head.split(".")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
        return None
    major = int(parts[0])
    minor = int(parts[1])
    patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
    return (major, minor, patch)


# --- Linux saf eval fonksiyonları ---


def eval_suid(output: str) -> tuple[Severity, str] | None:
    """SUID ikili listesinde (find -perm -4000) GTFOBins/pkexec tespit eder."""
    paths = [ln.strip() for ln in output.splitlines() if ln.strip()]
    dangerous = sorted({p for p in paths if _basename(p) in GTFO_SUID})
    pwnkit = any(_basename(p) == "pkexec" for p in paths)
    msgs: list[str] = []
    if dangerous:
        msgs.append("GTFOBins SUID → root: " + ", ".join(dangerous[:8]))
    if pwnkit:
        msgs.append("SUID pkexec → PwnKit (CVE-2021-4034) olası")
    if msgs:
        return (Severity.high, "; ".join(msgs))
    return None


def eval_capabilities(output: str) -> tuple[Severity, str] | None:
    """getcap çıktısında yetki yükseltmeye elverişli capabilities arar."""
    hits = [
        ln.strip()
        for ln in output.splitlines()
        if ln.strip() and any(c in ln.lower() for c in DANGEROUS_CAPS)
    ]
    if hits:
        return (Severity.high, "Tehlikeli dosya capabilities: " + "; ".join(hits[:8]))
    return None


def eval_cron_writable(output: str) -> tuple[Severity, str] | None:
    """Dünya-yazılabilir cron dosyaları (root olarak çalışır → priv-esc)."""
    files = [ln.strip() for ln in output.splitlines() if ln.strip()]
    if files:
        joined = ", ".join(files[:10])
        suffix = " …" if len(files) > 10 else ""
        return (Severity.high, f"Yazılabilir cron dosya(lar)ı (root çalıştırır): {joined}{suffix}")
    return None


def eval_kernel_privesc(kernel: str) -> tuple[Severity, str] | None:
    """Kernel sürümünü bilinen yerel-root exploit aralıklarıyla karşılaştırır (heuristik)."""
    t = _kernel_tuple(kernel)
    if t is None:
        return None
    notes: list[str] = []
    if t < (4, 8, 3):
        notes.append("DirtyCow (CVE-2016-5195) olası")
    if (5, 8, 0) <= t < (5, 16, 11):
        notes.append("DirtyPipe (CVE-2022-0847) olası")
    if t < (4, 0, 0):
        notes.append("çok eski kernel — çok sayıda yerel-root exploit")
    if notes:
        return (Severity.medium, f"Kernel {kernel}: " + "; ".join(notes) + " — manuel doğrulayın.")
    return None


# --- Yetki yükseltme DENEMELERİ (VIII-3b, GATED — admin + açık onay) ---
# Her deneme bir vektörle root olup salt-okunur `id` çalıştırır (sistemi DEĞİŞTİRMEZ).
# Vektör yoksa komut normal kullanıcıyla çalışır → uid≠0 → onaylanmaz (yanlış-pozitif yok).
# `|| true` ile her komut 0 döner (SSH run hatası taramayı bozmaz).
PRIVESC_ATTEMPTS: tuple[tuple[str, str], ...] = (
    ("parolasız sudo", "sudo -n id 2>/dev/null || true"),
    ("SUID find", "find /etc/hostname -exec id \\; -quit 2>/dev/null || true"),
    ("SUID bash", "bash -p -c id 2>/dev/null || true"),
    # Eski nmap (<5.20) --interactive 'shell escape' ile SUID iken root komut çalıştırır.
    ("SUID nmap", "echo '!id' | nmap --interactive 2>/dev/null || true"),
    (
        "cap_setuid python",
        "python3 -c 'import os;os.setuid(0);os.system(\"id\")' 2>/dev/null || true",
    ),
)


def confirmed_root(output: str) -> bool:
    """Komut çıktısı root (uid=0) ürettiyse True — yetki yükseltme DOĞRULANDI."""
    text = output.strip()
    return "uid=0(" in text or text.startswith("uid=0 ")


# --- Windows saf eval fonksiyonları ---


def eval_win_privileges(output: str) -> tuple[Severity, str] | None:
    """whoami /priv çıktısında token-istismarına elverişli ayrıcalıklar arar."""
    found = sorted({p for p in DANGEROUS_WIN_PRIVS if p in output})
    if found:
        detail = "Tehlikeli Windows ayrıcalık(ları) (token priv-esc): " + ", ".join(found)
        return (Severity.high, detail)
    return None


def eval_always_install_elevated(output: str) -> tuple[Severity, str] | None:
    """'HKLM=..\\nHKCU=..' çıktısında her ikisi de 1 ise herkes SYSTEM olarak MSI kurar."""
    vals: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            vals[key.strip().upper()] = value.strip().lower()

    def _is_one(v: str) -> bool:
        return v in ("1", "0x1", "true")

    if _is_one(vals.get("HKLM", "")) and _is_one(vals.get("HKCU", "")):
        return (
            Severity.high,
            "AlwaysInstallElevated HKLM+HKCU = 1 → herhangi bir kullanıcı SYSTEM olarak "
            "MSI kurabilir (yetki yükseltme).",
        )
    return None


def eval_unquoted_services(output: str) -> tuple[Severity, str] | None:
    """'Ad|Yol' satırlarında tırnaksız + boşluklu (Windows dışı) servis yollarını bulur."""
    hits: list[str] = []
    for line in output.splitlines():
        if "|" not in line:
            continue
        name, _, path = line.partition("|")
        path = path.strip()
        if not path or path.startswith('"'):
            continue
        low = path.lower()
        if " " in path and "\\" in path and not low.startswith("c:\\windows"):
            hits.append(f"{name.strip()} → {path}")
    if hits:
        return (
            Severity.medium,
            "Tırnaksız servis yolu (yazılabilir dizinde priv-esc): " + "; ".join(hits[:8]),
        )
    return None
