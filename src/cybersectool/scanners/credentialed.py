"""Credentialed (authenticated) host taraması — SSH ile sunucuya girip içeriden denetim.

Hardening (CIS) denetimlerine ek olarak, yalnızca **kimlikli erişimle** mümkün olan
zenginleştirilmiş denetimler yapar:

- Host envanteri (OS / kernel / paket sayısı),
- bekleyen güvenlik güncellemeleri (gecikmiş yamalar),
- parolasız sudo (NOPASSWD) kuralları,
- dünya-yazılabilir hassas (/etc) dosyalar.

Kimlik bilgileri **yalnızca istek anında** kullanılır, kalıcı **SAKLANMAZ** (Redis/DB'ye
yazılmaz; bu yüzden tarama eşzamanlı/inline çalışır, kuyruğa alınmaz).

`parse_*` / `eval_*` / `count_*` fonksiyonları saftır (birim testi edilebilir; SSH gerekmez).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import asyncssh
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.compliance import derive_compliance, store_compliance
from cybersectool.core.findings import create_finding
from cybersectool.core.models import Severity
from cybersectool.core.privesc import (
    PRIVESC_ATTEMPTS,
    confirmed_root,
    eval_capabilities,
    eval_cron_writable,
    eval_kernel_privesc,
    eval_suid,
)
from cybersectool.core.vuln import enrich_cves
from cybersectool.intel.osv import query_osv_packages
from cybersectool.scanners.hardening import CHECKS, HardeningCheck, HardeningFinding

# Bir kimlikli taramada yazılacak azami "zafiyetli paket" bulgusu (gürültü/akın koruması).
MAX_PACKAGE_FINDINGS = 100


@dataclass
class PackageVuln:
    """Kimlikli taramada kurulu bir OS paketinde bulunan zafiyet (OSV.dev eşleşmesi)."""

    package: str
    version: str
    vuln_id: str  # OSV/GHSA/DSA kimliği
    cve: str | None
    severity: Severity
    summary: str | None = None


@dataclass
class HostFacts:
    """Kimlikli erişimle toplanan host bilgileri."""

    os: str | None = None
    kernel: str | None = None
    package_count: int | None = None
    package_vulns: list[PackageVuln] = field(default_factory=list)


def parse_os_release(output: str) -> str | None:
    """/etc/os-release çıktısından PRETTY_NAME değerini çeker."""
    for line in output.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"') or None
    return None


def _os_release_kv(output: str) -> dict[str, str]:
    """/etc/os-release'i key=value sözlüğüne çevirir (tırnaksız)."""
    kv: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, val = line.partition("=")
            kv[key.strip()] = val.strip().strip('"')
    return kv


def osv_ecosystem_for(os_release_output: str) -> str | None:
    """/etc/os-release → OSV OS ekosistem dizesi. Desteklenmeyen dağıtım → None.

    Desteklenen (OSV v1): Debian + Ubuntu (dpkg), RPM ailesi — Rocky Linux, AlmaLinux,
    RHEL/CentOS (#138) — ve **Alpine** (apk, #146 BUG-4b). RHEL/CentOS, AlmaLinux'a ABI-uyumlu
    yeniden derleme olduğundan (aynı paket sürümleri + aynı RHSA/CVE'ler) ``AlmaLinux:{majör}``
    ile eşlenir. Alpine OSV ekosistemi RELEASE DALINA göre sürümlenir (``Alpine:v3.19``) — host'un
    ``VERSION_ID``'sinden majör.minör alınır (apk sürüm formatı ``1.2.4-r2`` OSV ile uyumlu).
    """
    kv = _os_release_kv(os_release_output)
    osid = (kv.get("ID") or "").lower()
    id_like = (kv.get("ID_LIKE") or "").lower()
    ver = kv.get("VERSION_ID") or ""
    if not ver:
        return None
    major = ver.split(".")[0]
    if osid == "ubuntu":
        return f"Ubuntu:{ver}:LTS"
    if osid == "debian" or "debian" in id_like:
        return f"Debian:{major}"
    if osid == "rocky":
        return f"Rocky Linux:{major}"
    if osid in ("almalinux", "alma"):
        return f"AlmaLinux:{major}"
    # RHEL/CentOS (ve diğer "rhel" tabanlı yeniden derlemeler) → AlmaLinux (ABI-uyumlu).
    if osid in ("rhel", "centos") or "rhel" in id_like:
        return f"AlmaLinux:{major}"
    # Alpine: OSV release-dalına göre sürümler (Alpine:v3.19). VERSION_ID "3.19.1" → "v3.19".
    if osid == "alpine" or "alpine" in id_like:
        parts = ver.split(".")
        branch = f"{parts[0]}.{parts[1]}" if len(parts) >= 2 else parts[0]
        return f"Alpine:v{branch}"
    return None


def os_package_command(os_release_output: str) -> str:
    """Dağıtıma göre 'ad sürüm' listesi üreten paket sorgu komutu (dpkg vs rpm).

    RPM ailesinde (RHEL/CentOS/Rocky/Alma) ``rpm -qa`` ile VERSION-RELEASE; Alpine'da apk
    veritabanı (``/lib/apk/db/installed``) P:/V: satırlarından awk ile 'ad sürüm' üretilir
    (#146 BUG-4b); aksi halde Debian/Ubuntu ``dpkg-query``. Çıktı her üçünde de
    ``parse_packages`` ('ad sürüm') ile uyumludur.
    """
    kv = _os_release_kv(os_release_output)
    osid = (kv.get("ID") or "").lower()
    id_like = (kv.get("ID_LIKE") or "").lower()
    if osid == "alpine" or "alpine" in id_like:
        # apk'nın boşluk-ayrımlı 'ad sürüm' formatı yok (apk info -v 'ad-sürüm' verir, tire
        # belirsiz). Kurulu paket veritabanındaki P:(ad) ve V:(sürüm) satırlarını awk ile
        # eşleştir → 'ad sürüm' (busybox awk Alpine'da yerleşik). Salt-okunur.
        return "awk -F: '/^P:/{n=$2} /^V:/{print n, $2}' /lib/apk/db/installed 2>/dev/null || true"
    rpm_family = osid in ("rocky", "almalinux", "alma", "rhel", "centos", "fedora") or (
        "rhel" in id_like
    )
    if rpm_family:
        return "rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\\n' 2>/dev/null || true"
    return "dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null || true"


def parse_packages(output: str, limit: int = 5000) -> list[tuple[str, str]]:
    """'ad sürüm' satırlarını (dpkg-query -W -f='${Package} ${Version}\\n') ayrıştırır."""
    pkgs: list[tuple[str, str]] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            pkgs.append((parts[0], parts[1]))
            if len(pkgs) >= limit:
                break
    return pkgs


def count_packages(output: str) -> int:
    """Paket listesi çıktısındaki (boş olmayan) satır sayısı."""
    return len([ln for ln in output.splitlines() if ln.strip()])


def eval_pending_updates(output: str) -> tuple[Severity, str] | None:
    """`apt-get -s upgrade` çıktısındaki 'Inst' satırları = bekleyen güncellemeler."""
    pending = [ln for ln in output.splitlines() if ln.startswith("Inst ")]
    n = len(pending)
    if n > 0:
        severity = Severity.high if n >= 20 else Severity.medium
        return (severity, f"{n} paket güncelleme bekliyor — güvenlik yamaları gecikmiş olabilir.")
    return None


def eval_sudo_nopasswd(output: str) -> tuple[Severity, str] | None:
    """sudoers içinde parolasız (NOPASSWD) kural varsa yükseltme riski."""
    hits = [
        ln.strip()
        for ln in output.splitlines()
        if "NOPASSWD" in ln and not ln.strip().startswith("#")
    ]
    if hits:
        return (Severity.high, f"Parolasız sudo (NOPASSWD): {'; '.join(hits)[:200]}")
    return None


def eval_world_writable(output: str) -> tuple[Severity, str] | None:
    """/etc altında dünya-yazılabilir dosyalar (yetki yükseltme/tampering riski)."""
    files = [ln.strip() for ln in output.splitlines() if ln.strip()]
    if files:
        joined = ", ".join(files[:10])
        suffix = " …" if len(files) > 10 else ""
        return (Severity.medium, f"Dünya-yazılabilir hassas dosya(lar): {joined}{suffix}")
    return None


# Yetki yükseltme (privilege escalation) ENUMERASYONU — SALT-OKUNUR (VIII-3a).
# Yalnızca FIRSATLARI raporlar (root'a yükseltme yollarını); hiçbir şey DENEMEZ.
# Komutlar yalnız listeler/okur (find/getcap). Gerçek deneme VIII-3b'de (gated).
# Bu bulgular CIS uyumuna SAYILMAZ (compliance ran_titles'a eklenmezler).
PRIVESC_SSH_CHECKS: list[HardeningCheck] = [
    HardeningCheck(
        "Yetki yükseltme: SUID ikilileri",
        "find / -perm -4000 -type f 2>/dev/null | head -200 || true",
        eval_suid,
    ),
    HardeningCheck(
        "Yetki yükseltme: dosya capabilities",
        "getcap -r / 2>/dev/null | head -100 || true",
        eval_capabilities,
    ),
    HardeningCheck(
        "Yetki yükseltme: yazılabilir cron",
        "find /etc/cron* -type f -perm -0002 2>/dev/null | head -50 || true",
        eval_cron_writable,
    ),
]


# Yalnızca kimlikli erişimle anlamlı ek denetimler.
AUTH_CHECKS: list[HardeningCheck] = [
    HardeningCheck(
        "Bekleyen güvenlik güncellemeleri",
        "apt-get -s upgrade 2>/dev/null | grep '^Inst' || true",
        eval_pending_updates,
    ),
    HardeningCheck(
        "Parolasız sudo (NOPASSWD)",
        "grep -rhs NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true",
        eval_sudo_nopasswd,
    ),
    HardeningCheck(
        "Dünya-yazılabilir /etc dosyaları",
        "find /etc -xdev -type f -perm -0002 2>/dev/null | head -20 || true",
        eval_world_writable,
    ),
]


async def _gather_facts(conn: asyncssh.SSHClientConnection) -> HostFacts:
    os_result = await conn.run("cat /etc/os-release 2>/dev/null || true", check=False)
    kernel_result = await conn.run("uname -r 2>/dev/null || true", check=False)
    pkg_result = await conn.run(
        "dpkg-query -f '.\\n' -W 2>/dev/null || rpm -qa 2>/dev/null "
        "|| apk info 2>/dev/null || true",
        check=False,
    )
    kernel = str(kernel_result.stdout or "").strip() or None
    return HostFacts(
        os=parse_os_release(str(os_result.stdout or "")),
        kernel=kernel,
        package_count=count_packages(str(pkg_result.stdout or "")),
    )


_SEV_ORDER = {
    Severity.critical: 0,
    Severity.high: 1,
    Severity.medium: 2,
    Severity.low: 3,
    Severity.info: 4,
}


async def _scan_os_packages(conn: asyncssh.SSHClientConnection) -> list[PackageVuln]:
    """Kurulu OS paketlerini enumere edip OSV.dev ile eşleyerek zafiyetli paketleri döndürür.

    SALT-OKUNUR (yalnız paket listesini okur, sistemi değiştirmez). Ekosistem desteklenmiyorsa
    boş döner. Önemden (kritik→info) sıralı döner.
    """
    osr = await conn.run("cat /etc/os-release 2>/dev/null || true", check=False)
    os_release = str(osr.stdout or "")
    ecosystem = osv_ecosystem_for(os_release)
    if ecosystem is None:
        return []
    # Dağıtıma göre paket sorgusu (dpkg vs rpm) — RPM ailesi artık desteklenir (#138).
    pkg_res = await conn.run(os_package_command(os_release), check=False)
    packages = parse_packages(str(pkg_res.stdout or ""))
    if not packages:
        return []
    matches = await query_osv_packages(packages, ecosystem)
    out: list[PackageVuln] = [
        PackageVuln(
            package=name,
            version=version,
            vuln_id=v.id,
            cve=v.cve,
            severity=v.severity,
            summary=v.summary,
        )
        for (name, version), vulns in matches.items()
        for v in vulns
    ]
    out.sort(key=lambda p: _SEV_ORDER.get(p.severity, 5))
    return out


async def _run_privesc_attempts(conn: asyncssh.SSHClientConnection) -> list[HardeningFinding]:
    """GATED yetki yükseltme DENEMELERİ (VIII-3b) — vektörle root olup `id` ile doğrular.

    Yalnız ``attempt_privesc=True`` (admin + açık onay) iken çağrılır. Önce mevcut kimliğin
    zaten root olup olmadığına bakar (root ise deneme yapmaz, yanlış-pozitif önlenir). Her
    vektör salt-okunur ``id`` çalıştırır; root onaylanırsa KRİTİK + doğrulanmış bulgu üretir.
    """
    findings: list[HardeningFinding] = []
    whoami = await conn.run("id 2>/dev/null || true", check=False)
    if confirmed_root(str(whoami.stdout or "")):
        findings.append(
            HardeningFinding(
                "Yetki yükseltme: kimlik zaten root",
                Severity.info,
                "Oturum açan kimlik zaten root (uid=0) — yetki yükseltme denenmedi.",
            )
        )
        return findings
    for vector, command in PRIVESC_ATTEMPTS:
        result = await conn.run(command, check=False)
        output = str(result.stdout or "")
        if confirmed_root(output):
            findings.append(
                HardeningFinding(
                    f"Yetki yükseltme DOĞRULANDI: {vector} → root",
                    Severity.critical,
                    f"'{vector}' vektörüyle ROOT'a yükseltme DOĞRULANDI (uid=0). "
                    f"Kanıt: {output.strip()[:200]}",
                    validated=True,
                )
            )
    return findings


async def run_credentialed_scan(
    host: str, port: int, username: str, password: str, *, attempt_privesc: bool = False
) -> tuple[HostFacts, list[HardeningFinding]]:
    """SSH ile bağlanıp host envanteri + (hardening + auth + priv-esc enum) denetimlerini yapar.

    ``attempt_privesc=True`` (admin + açık onay) ise ek olarak GERÇEK yetki yükseltme
    DENEMESİ yapılır (VIII-3b, salt `id` ile doğrulama; sistem değiştirilmez). Kimlik
    bilgileri yalnızca bu çağrı süresince kullanılır; hiçbir yere yazılmaz.
    """
    findings: list[HardeningFinding] = []
    async with asyncssh.connect(
        host, port=port, username=username, password=password, known_hosts=None
    ) as conn:
        facts = await _gather_facts(conn)
        # Kimlikli OS-paket zafiyet kontrolü (dpkg → OSV.dev) — salt-okunur.
        facts.package_vulns = await _scan_os_packages(conn)
        for check in [*CHECKS, *AUTH_CHECKS, *PRIVESC_SSH_CHECKS]:
            result = await conn.run(check.command, check=False)
            verdict = check.evaluate(str(result.stdout or ""))
            if verdict is not None:
                severity, detail = verdict
                findings.append(HardeningFinding(check.title, severity, detail))
        # Kernel sürümü → bilinen yerel-root exploit aralıkları (priv-esc, salt-okunur).
        kernel_verdict = eval_kernel_privesc(facts.kernel or "")
        if kernel_verdict is not None:
            findings.append(
                HardeningFinding("Yetki yükseltme: kernel", kernel_verdict[0], kernel_verdict[1])
            )
        # GATED: gerçek yetki yükseltme denemesi (VIII-3b).
        if attempt_privesc:
            findings.extend(await _run_privesc_attempts(conn))
    return facts, findings


async def store_credentialed(
    session: AsyncSession,
    scan_id: int,
    facts: HostFacts,
    findings: list[HardeningFinding],
    asset_id: int | None = None,
) -> None:
    """Host envanterini (info) + bulguları Finding olarak + CIS uyum sonuçlarını kaydeder.

    ``asset_id`` verilirse bulgular o varlığa bağlanır (tek taramada çok host ayrımı için).
    """
    await create_finding(
        session,
        scan_id,
        f"Host envanteri: {facts.os or 'bilinmiyor'}",
        severity=Severity.info,
        asset_id=asset_id,
        description=f"Kernel {facts.kernel or '?'} · {facts.package_count or 0} paket",
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
    # Zafiyetli OS paketleri (OSV.dev eşleşmesi) → CVE'li bulgu (yaşam döngüsü + öncelik).
    pkg_cves: list[str] = []
    for pv in facts.package_vulns[:MAX_PACKAGE_FINDINGS]:
        label = pv.cve or pv.vuln_id
        await create_finding(
            session,
            scan_id,
            f"Zafiyetli paket: {pv.package} {pv.version} ({label})",
            severity=pv.severity,
            asset_id=asset_id,
            cve_id=pv.cve,
            description=(pv.summary or f"OSV kaydı: {pv.vuln_id}")
            + f"\nPaket: {pv.package} {pv.version} · Kaynak: OSV.dev ({pv.vuln_id})",
        )
        if pv.cve:
            pkg_cves.append(pv.cve)
    if pkg_cves:
        await enrich_cves(session, pkg_cves)  # CVSS/EPSS/KEV/exploit zenginleştirme
    # Uyum (CIS): çalışan denetimleri kontrollere eşle → geçti/kaldı sakla (VII-1a).
    ran_titles = [check.title for check in (*CHECKS, *AUTH_CHECKS)]
    failed = {f.title: (f.severity, f.detail) for f in findings}
    await store_compliance(session, scan_id, derive_compliance(ran_titles, failed))
