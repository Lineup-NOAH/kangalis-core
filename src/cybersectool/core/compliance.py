"""Uyum/benchmark motoru (VII-1a) — host sertleştirme bulgularını CIS kontrollerine eşler.

Mevcut sertleştirme denetimleri (scanners.hardening + credentialed AUTH_CHECKS) burada
CIS kontrol kimliklerine eşlenir; her CONTROL geçti/kaldı olarak değerlendirilir ve
``ComplianceCheck`` olarak saklanır. Formatlı uyum raporları (KVKK/ISO/PCI, VII-1c) bunun
üstüne kurulur. ``derive_compliance`` saftır (scanner bağımlılığı yok, test edilebilir).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.models import ComplianceCheck, Severity


@dataclass(frozen=True)
class Control:
    """Bir benchmark kontrolü (çerçeve + kimlik + başlık)."""

    framework: str
    control_id: str
    title: str


# Sertleştirme denetimi BAŞLIĞI → CIS kontrolü. Linux (SSH) + Windows (WinRM) CIS Level 1.
HARDENING_TO_CONTROL: dict[str, Control] = {
    # --- CIS Linux (SSH kimlikli) ---
    "SSH root girişi": Control("CIS Linux", "5.2.8", "SSH root girişi devre dışı bırakılmalı"),
    "Boş parolalı hesaplar": Control("CIS Linux", "6.2.1", "Parola alanları boş olmamalı"),
    "/tmp sticky bit": Control(
        "CIS Linux", "1.1.2", "Dünya-yazılabilir dizinlerde sticky bit ayarlı olmalı"
    ),
    "Bekleyen güvenlik güncellemeleri": Control(
        "CIS Linux", "1.9", "Güvenlik güncellemeleri kurulu olmalı"
    ),
    "Parolasız sudo (NOPASSWD)": Control(
        "CIS Linux", "5.3.4", "Yetki yükseltmede parola zorunlu olmalı"
    ),
    "Dünya-yazılabilir /etc dosyaları": Control(
        "CIS Linux", "6.1.10", "Dünya-yazılabilir dosya bulunmamalı"
    ),
    "SSH boş parola izni": Control(
        "CIS Linux", "5.2.10", "SSH PermitEmptyPasswords devre dışı bırakılmalı"
    ),
    "SSH MaxAuthTries": Control("CIS Linux", "5.2.5", "SSH MaxAuthTries 4 veya altı olmalı"),
    # --- CIS Windows (WinRM kimlikli) ---
    "SMBv1 protokolü": Control("CIS Windows", "18.3.1", "SMBv1 istemci/sunucu devre dışı"),
    "Defender gerçek zamanlı koruma": Control(
        "CIS Windows", "18.9.47", "Defender gerçek zamanlı koruma açık olmalı"
    ),
    "Güvenlik duvarı profilleri": Control(
        "CIS Windows", "9.1.1", "Windows Güvenlik Duvarı tüm profillerde açık"
    ),
    "RDP NLA": Control("CIS Windows", "18.9.65", "RDP için Ağ Düzeyinde Kimlik Doğrulama (NLA)"),
    "AutoLogon açık parola": Control(
        "CIS Windows", "18.4.7", "AutoLogon açık-metin parola saklanmamalı"
    ),
    "Yerel yönetici sayısı": Control(
        "CIS Windows", "2.2.x", "Yerel Administrators üyeliği sınırlı tutulmalı"
    ),
    # --- CIS PostgreSQL (DB kimlikli, VII-2a) ---
    "PostgreSQL SSL/TLS": Control("CIS PostgreSQL", "6.8", "SSL/TLS açık olmalı"),
    "PostgreSQL bağlantı günlüğü": Control(
        "CIS PostgreSQL", "3.1.4", "log_connections etkin olmalı"
    ),
    "PostgreSQL parola şifreleme": Control(
        "CIS PostgreSQL", "4.2", "password_encryption scram-sha-256 olmalı"
    ),
    # --- CIS MySQL (DB kimlikli, IX-4) ---
    "MySQL TLS zorunluluğu": Control(
        "CIS MySQL", "7.1", "TLS (require_secure_transport) açık olmalı"
    ),
    "MySQL local_infile": Control("CIS MySQL", "6.1.3", "local_infile devre dışı olmalı"),
    "MySQL kimlik doğrulama eklentisi": Control(
        "CIS MySQL", "1.5", "Güçlü kimlik doğrulama eklentisi (caching_sha2_password)"
    ),
    # --- CIS MSSQL (DB kimlikli, IX-5) ---
    "MSSQL xp_cmdshell": Control("CIS MSSQL", "2.1", "xp_cmdshell devre dışı olmalı"),
    "MSSQL OLE Automation": Control("CIS MSSQL", "2.2", "Ole Automation Procedures devre dışı"),
    "MSSQL CLR": Control("CIS MSSQL", "2.3", "CLR Integration devre dışı / imzalı olmalı"),
    "MSSQL kimlik doğrulama modu": Control(
        "CIS MSSQL", "1.1", "Windows kimlik doğrulama modu tercih edilmeli"
    ),
    # --- CIS Oracle (DB kimlikli, IX-6) ---
    "Oracle remote_os_authent": Control("CIS Oracle", "3.2", "remote_os_authent FALSE olmalı"),
    "Oracle dictionary erişimi": Control(
        "CIS Oracle", "3.3", "O7_DICTIONARY_ACCESSIBILITY FALSE olmalı"
    ),
    "Oracle SQL92 güvenlik": Control("CIS Oracle", "3.4", "sql92_security TRUE olmalı"),
    "Oracle parola harf duyarlılığı": Control(
        "CIS Oracle", "3.5", "sec_case_sensitive_logon TRUE olmalı"
    ),
    # --- CIS Windows / SMB (ağ SMB denetimi, IX-7a) — 'SMBv1 protokolü' 18.3.1 ile paylaşılır ---
    "SMB imzalama": Control("CIS Windows", "2.3.9.2", "SMB sunucu imzalama (her zaman) etkin"),
    "SMB anonim oturum": Control(
        "CIS Windows", "2.3.10.5", "Anonim kullanıcılara Everyone izinleri uygulanmamalı"
    ),
    "SMB misafir erişimi": Control("CIS Windows", "2.3.1.1", "Misafir (Guest) hesabı devre dışı"),
    "SMB anonim paylaşım listeleme": Control(
        "CIS Windows", "2.3.10.9", "Anonim Named Pipe/paylaşım erişimi kısıtlanmalı"
    ),
    # --- CIS LDAP / Active Directory (ağ LDAP denetimi, IX-7b) ---
    "LDAP anonim bind": Control("CIS LDAP", "L1.1", "Anonim bind devre dışı olmalı"),
    "LDAP anonim dizin okuma": Control("CIS LDAP", "L1.2", "Anonim dizin okuma kısıtlanmalı"),
    "LDAP şifreleme": Control("CIS LDAP", "L2.1", "LDAPS/StartTLS ile şifreli taşıma zorunlu"),
    "LDAP parola uzunluğu": Control("CIS LDAP", "L3.1", "Asgari parola uzunluğu >= 8 olmalı"),
    "LDAP hesap kilitleme": Control("CIS LDAP", "L3.2", "Hesap kilitleme eşiği tanımlı olmalı"),
    # --- CIS Cisco IOS (ağ cihazı Telnet/CLI denetimi, IX-7c) ---
    "Telnet şifresiz yönetim": Control("CIS Cisco", "2.1.1", "Telnet kapalı, yalnız SSH"),
    "Telnet uyarı banner": Control("CIS Cisco", "1.1.1", "Yetkisiz erişim uyarı banner'ı tanımlı"),
    "Cisco parola şifreleme": Control("CIS Cisco", "1.1.5", "service password-encryption etkin"),
    "Cisco enable secret": Control("CIS Cisco", "1.1.3", "enable secret kullanılmalı"),
    "Cisco VTY transport": Control("CIS Cisco", "1.2.2", "VTY transport input ssh olmalı"),
    "Cisco HTTP sunucu": Control("CIS Cisco", "1.3.1", "HTTP sunucu kapalı / HTTPS kullanılmalı"),
    # --- CIS Cisco IOS — yalnız-SSH bağlamı (SSH denetimi, VII-2d) ---
    "Cisco SSH sürümü": Control("CIS Cisco", "1.2.1", "Yalnız SSHv2 zorunlu (ip ssh version 2)"),
    "Cisco zayıf SNMP community": Control(
        "CIS Cisco", "3.1.1", "Varsayılan/zayıf SNMP community kullanılmamalı"
    ),
    "Cisco AAA new-model": Control(
        "CIS Cisco", "1.6.1", "aaa new-model ile merkezi kimlik doğrulama"
    ),
    # --- CIS VMware ESXi / vCenter (kimliksiz HTTPS duruş denetimi, VII-2c) ---
    "ESXi/vCenter MOB açık": Control(
        "CIS VMware", "V1.1", "Managed Object Browser (/mob/) devre dışı bırakılmalı"
    ),
    "ESXi/vCenter zayıf TLS": Control(
        "CIS VMware", "V2.1", "Yalnız TLS 1.2+ ve güçlü şifre paketleri etkin olmalı"
    ),
}


@dataclass
class ComplianceResult:
    framework: str
    control_id: str
    title: str
    status: str  # "pass" | "fail"
    severity: Severity | None
    detail: str | None


def derive_compliance(
    ran_titles: list[str], failed: dict[str, tuple[Severity, str]]
) -> list[ComplianceResult]:
    """Çalışan denetim başlıkları + başarısızları → kontrol başına geçti/kaldı (saf).

    ``ran_titles``: bu taramada ÇALIŞAN sertleştirme denetimi başlıkları.
    ``failed``: {başlık: (severity, detay)} — bulgu üreten (KALAN) denetimler.
    Eşlemesi olmayan başlık atlanır.
    """
    results: list[ComplianceResult] = []
    for title in ran_titles:
        control = HARDENING_TO_CONTROL.get(title)
        if control is None:
            continue
        if title in failed:
            severity, detail = failed[title]
            results.append(
                ComplianceResult(
                    control.framework, control.control_id, control.title, "fail", severity, detail
                )
            )
        else:
            results.append(
                ComplianceResult(
                    control.framework, control.control_id, control.title, "pass", None, None
                )
            )
    return results


async def store_compliance(
    session: AsyncSession, scan_id: int, results: list[ComplianceResult]
) -> int:
    """Bir taramanın uyum sonuçlarını yazar (önce eskileri siler — idempotent)."""
    await session.execute(delete(ComplianceCheck).where(ComplianceCheck.scan_id == scan_id))
    for r in results:
        session.add(
            ComplianceCheck(
                scan_id=scan_id,
                framework=r.framework,
                control_id=r.control_id,
                title=r.title,
                status=r.status,
                severity=r.severity,
                detail=r.detail,
            )
        )
    await session.commit()
    return len(results)


async def compliance_for_scan(session: AsyncSession, scan_id: int) -> list[ComplianceCheck]:
    stmt = (
        select(ComplianceCheck)
        .where(ComplianceCheck.scan_id == scan_id)
        .order_by(ComplianceCheck.framework, ComplianceCheck.control_id)
    )
    return list((await session.execute(stmt)).scalars().all())


# Düzenleyici çerçeveler (VII-1c) — TR pazarı satış kozu.
REGULATIONS: tuple[str, ...] = ("KVKK", "ISO 27001", "PCI-DSS")

# CIS kontrol id'si → düzenleyici madde referansları. KVKK teknik güvenlik
# yükümlülükleri md.12'den doğar; ISO 27001:2022 Annex A + PCI-DSS v4 gereksinimleri.
REGULATION_MAP: dict[str, dict[str, str]] = {
    "5.2.8": {"KVKK": "md.12", "ISO 27001": "A.8.2", "PCI-DSS": "7.2.1"},
    "6.2.1": {"KVKK": "md.12", "ISO 27001": "A.5.17", "PCI-DSS": "8.3.1"},
    "1.1.2": {"KVKK": "md.12", "ISO 27001": "A.8.9", "PCI-DSS": "2.2.1"},
    "1.9": {"KVKK": "md.12", "ISO 27001": "A.8.8", "PCI-DSS": "6.3.3"},
    "5.3.4": {"KVKK": "md.12", "ISO 27001": "A.8.2", "PCI-DSS": "7.2.1"},
    "6.1.10": {"KVKK": "md.12", "ISO 27001": "A.8.3", "PCI-DSS": "7.1"},
    "5.2.10": {"KVKK": "md.12", "ISO 27001": "A.5.17", "PCI-DSS": "8.3.1"},
    "5.2.5": {"KVKK": "md.12", "ISO 27001": "A.8.5", "PCI-DSS": "8.3.4"},
    "18.3.1": {"KVKK": "md.12", "ISO 27001": "A.8.9", "PCI-DSS": "2.2.4"},
    "18.9.47": {"KVKK": "md.12", "ISO 27001": "A.8.7", "PCI-DSS": "5.2"},
    "9.1.1": {"KVKK": "md.12", "ISO 27001": "A.8.20", "PCI-DSS": "1.2.1"},
    "18.9.65": {"KVKK": "md.12", "ISO 27001": "A.8.5", "PCI-DSS": "8.3.6"},
    "18.4.7": {"KVKK": "md.12", "ISO 27001": "A.5.17", "PCI-DSS": "8.3.1"},
    "2.2.x": {"KVKK": "md.12", "ISO 27001": "A.8.2", "PCI-DSS": "7.2.1"},
    "6.8": {"KVKK": "md.12", "ISO 27001": "A.8.24", "PCI-DSS": "4.2.1"},
    "3.1.4": {"KVKK": "md.12", "ISO 27001": "A.8.15", "PCI-DSS": "10.2.1"},
    "4.2": {"KVKK": "md.12", "ISO 27001": "A.5.17", "PCI-DSS": "8.3.2"},
    # CIS MySQL (IX-4)
    "7.1": {"KVKK": "md.12", "ISO 27001": "A.8.24", "PCI-DSS": "4.2.1"},
    "6.1.3": {"KVKK": "md.12", "ISO 27001": "A.8.9", "PCI-DSS": "2.2.1"},
    "1.5": {"KVKK": "md.12", "ISO 27001": "A.5.17", "PCI-DSS": "8.3.2"},
    # CIS MSSQL (IX-5)
    "2.1": {"KVKK": "md.12", "ISO 27001": "A.8.9", "PCI-DSS": "2.2.1"},
    "2.2": {"KVKK": "md.12", "ISO 27001": "A.8.9", "PCI-DSS": "2.2.1"},
    "2.3": {"KVKK": "md.12", "ISO 27001": "A.8.9", "PCI-DSS": "2.2.1"},
    "1.1": {"KVKK": "md.12", "ISO 27001": "A.8.5", "PCI-DSS": "8.3.1"},
    # CIS Oracle (IX-6)
    "3.2": {"KVKK": "md.12", "ISO 27001": "A.8.5", "PCI-DSS": "8.3.1"},
    "3.3": {"KVKK": "md.12", "ISO 27001": "A.8.3", "PCI-DSS": "7.1"},
    "3.4": {"KVKK": "md.12", "ISO 27001": "A.8.9", "PCI-DSS": "2.2.1"},
    "3.5": {"KVKK": "md.12", "ISO 27001": "A.5.17", "PCI-DSS": "8.3.1"},
    # CIS Windows / SMB (IX-7a) — 18.3.1 (SMBv1) zaten yukarıda eşli
    "2.3.9.2": {"KVKK": "md.12", "ISO 27001": "A.8.24", "PCI-DSS": "4.2.1"},
    "2.3.10.5": {"KVKK": "md.12", "ISO 27001": "A.8.3", "PCI-DSS": "7.1"},
    "2.3.1.1": {"KVKK": "md.12", "ISO 27001": "A.5.16", "PCI-DSS": "8.2.2"},
    "2.3.10.9": {"KVKK": "md.12", "ISO 27001": "A.8.3", "PCI-DSS": "7.1"},
    # CIS LDAP / AD (IX-7b)
    "L1.1": {"KVKK": "md.12", "ISO 27001": "A.5.16", "PCI-DSS": "8.2.2"},
    "L1.2": {"KVKK": "md.12", "ISO 27001": "A.8.3", "PCI-DSS": "7.1"},
    "L2.1": {"KVKK": "md.12", "ISO 27001": "A.8.24", "PCI-DSS": "4.2.1"},
    "L3.1": {"KVKK": "md.12", "ISO 27001": "A.5.17", "PCI-DSS": "8.3.6"},
    "L3.2": {"KVKK": "md.12", "ISO 27001": "A.8.5", "PCI-DSS": "8.3.4"},
    # CIS Cisco IOS (IX-7c) — '1.1.5' parola-şifr. (1.1.2 CIS Linux ile çakışmasın)
    "2.1.1": {"KVKK": "md.12", "ISO 27001": "A.8.24", "PCI-DSS": "2.2.7"},
    "1.1.1": {"KVKK": "md.12", "ISO 27001": "A.5.10", "PCI-DSS": "7.1"},
    "1.1.5": {"KVKK": "md.12", "ISO 27001": "A.8.24", "PCI-DSS": "8.3.2"},
    "1.1.3": {"KVKK": "md.12", "ISO 27001": "A.8.5", "PCI-DSS": "8.3.2"},
    "1.2.2": {"KVKK": "md.12", "ISO 27001": "A.8.24", "PCI-DSS": "2.2.7"},
    "1.3.1": {"KVKK": "md.12", "ISO 27001": "A.8.24", "PCI-DSS": "4.2.1"},
    # CIS Cisco IOS — yalnız-SSH bağlamı (SSH denetimi, VII-2d)
    "1.2.1": {"KVKK": "md.12", "ISO 27001": "A.8.24", "PCI-DSS": "2.2.7"},
    "3.1.1": {"KVKK": "md.12", "ISO 27001": "A.8.20", "PCI-DSS": "2.2.2"},
    "1.6.1": {"KVKK": "md.12", "ISO 27001": "A.8.2", "PCI-DSS": "8.3.1"},
    # CIS VMware ESXi / vCenter (VII-2c)
    "V1.1": {"KVKK": "md.12", "ISO 27001": "A.8.9", "PCI-DSS": "2.2.1"},
    "V2.1": {"KVKK": "md.12", "ISO 27001": "A.8.24", "PCI-DSS": "4.2.1"},
}


@dataclass
class RegulationResult:
    """Bir düzenleyici çerçeve (KVKK/ISO/PCI) için eşlenmiş uyum özeti."""

    regulation: str
    passed: int = 0
    failed: int = 0
    controls: list[dict[str, str]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.passed + self.failed

    @property
    def score(self) -> int:
        return round(self.passed / self.total * 100) if self.total else 0


def regulation_summary(checks: list[ComplianceCheck]) -> dict[str, RegulationResult]:
    """CIS sonuçlarını KVKK/ISO 27001/PCI-DSS maddelerine eşler (VII-1c).

    Eşlemesi olmayan CIS kayıtları ilgili düzenleyiciye dahil edilmez; boş düzenleyici elenir.
    """
    out = {reg: RegulationResult(reg) for reg in REGULATIONS}
    for check in checks:
        # 'manual' (elle inceleme gerektiren) kontrol ne geçer ne kalır → mevzuat skoruna
        # dahil edilmez (aksi halde skor haksızca düşer, yanlış 'başarısız' sayımı).
        if check.status not in ("pass", "fail"):
            continue
        mapping = REGULATION_MAP.get(check.control_id, {})
        for reg in REGULATIONS:
            article = mapping.get(reg)
            if not article:
                continue
            result = out[reg]
            if check.status == "pass":
                result.passed += 1
            else:
                result.failed += 1
            result.controls.append(
                {
                    "cis_id": check.control_id,
                    "title": check.title,
                    "status": check.status,
                    "article": article,
                    "framework": check.framework,
                }
            )
    return {reg: r for reg, r in out.items() if r.total > 0}


async def compliance_summary(session: AsyncSession, scan_id: int) -> dict[str, dict[str, int]]:
    """{framework: {pass, fail, total, score}} — uyum raporu özeti (skor = %geçen)."""
    stmt = (
        select(ComplianceCheck.framework, ComplianceCheck.status, func.count())
        .where(ComplianceCheck.scan_id == scan_id)
        .group_by(ComplianceCheck.framework, ComplianceCheck.status)
    )
    out: dict[str, dict[str, int]] = {}
    for framework, st, cnt in (await session.execute(stmt)).all():
        bucket = out.setdefault(framework, {"pass": 0, "fail": 0, "total": 0, "score": 0})
        bucket[st] = int(cnt)
        bucket["total"] += int(cnt)
    for bucket in out.values():
        bucket["score"] = round(bucket["pass"] / bucket["total"] * 100) if bucket["total"] else 0
    return out


async def compliance_overview(session: AsyncSession) -> dict[str, dict[str, int]]:
    """Tüm taramalar geneli çerçeve-bazlı uyum özeti {framework: {pass, fail, total, score}}.

    Zafiyetler sayfasındaki "Uyum" sekmesi için genel duruş. Skor = geçen/total oranı;
    tekrar taramalar mutlak sayıları artırsa da oran anlamlı kalır.
    """
    stmt = select(ComplianceCheck.framework, ComplianceCheck.status, func.count()).group_by(
        ComplianceCheck.framework, ComplianceCheck.status
    )
    out: dict[str, dict[str, int]] = {}
    for framework, st, cnt in (await session.execute(stmt)).all():
        bucket = out.setdefault(framework, {"pass": 0, "fail": 0, "total": 0, "score": 0})
        bucket[st] = bucket.get(st, 0) + int(cnt)
        bucket["total"] += int(cnt)
    for bucket in out.values():
        bucket["score"] = round(bucket["pass"] / bucket["total"] * 100) if bucket["total"] else 0
    return dict(sorted(out.items()))


async def top_failed_controls(session: AsyncSession, limit: int = 25) -> list[dict[str, object]]:
    """En çok başarısız olan benchmark kontrolleri (çerçeve+kontrol bazında sayım).

    {framework, control_id, title, fails} — operatöre "önce neyi düzelt" rehberi.
    """
    stmt = (
        select(
            ComplianceCheck.framework,
            ComplianceCheck.control_id,
            func.min(ComplianceCheck.title),
            func.count(),
        )
        .where(ComplianceCheck.status == "fail")
        .group_by(ComplianceCheck.framework, ComplianceCheck.control_id)
        .order_by(func.count().desc())
        .limit(limit)
    )
    return [
        {"framework": fw, "control_id": cid, "title": title, "fails": int(n)}
        for fw, cid, title, n in (await session.execute(stmt)).all()
    ]
