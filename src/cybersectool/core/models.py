"""ORM modelleri (SQLAlchemy) — kullanıcı, varlık/servis, tarama/bulgu, zafiyet,
kimlik, zone, kelime listesi, uyum, exploit, uygulama ayarları ve denetim kayıtları.
"""

from __future__ import annotations

import enum
import json
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import expression

from cybersectool.core.db import Base


class Role(enum.StrEnum):
    """Kullanıcı rolleri (RBAC)."""

    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class AuthSource(enum.StrEnum):
    """Kimliğin nereden doğrulandığı."""

    local = "local"
    ldap = "ldap"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(255), default=None)
    # LDAP kullanıcılarında NULL olabilir (şifre dizinde tutulur).
    password_hash: Mapped[str | None] = mapped_column(String(255), default=None)
    role: Mapped[Role] = mapped_column(
        Enum(Role, native_enum=False, length=20), default=Role.viewer
    )
    auth_source: Mapped[AuthSource] = mapped_column(
        Enum(AuthSource, native_enum=False, length=10), default=AuthSource.local
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # MFA (ikinci doğrulama): yöntem none|totp|email. TOTP sırrı Fernet ile şifreli.
    mfa_method: Mapped[str] = mapped_column(String(10), default="none")
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(Text, default=None)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # Sorumluluk reddi (DISCLAIMER.md) kabul zamanı; NULL = henüz kabul etmedi → tarama kapalı
    # (uygulama-içi onay ekranı bunu doldurur; her operatörün kabulü zaman-damgalı kayıt olur).
    disclaimer_accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )


class ApiToken(Base):
    """API / MCP erişimi için kişisel erişim token'ı. Yalnızca hash saklanır."""

    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScanType(enum.StrEnum):
    network = "network"
    ping = "ping"  # ping taraması: yalnız host keşfi (nmap -sn), port taraması YOK
    vuln = "vuln"  # zafiyet taraması: ağ taraması + derin CVE eşleştirme (KEV/EPSS odağı)
    web = "web"
    sca = "sca"
    hardening = "hardening"
    credentialed = "credentialed"  # SSH ile kimlikli (authenticated) host taraması


class ScanStatus(enum.StrEnum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"  # kullanıcı taramayı durdurdu


class ScanMode(enum.StrEnum):
    """Tarama yoğunluğu (müdahale derecesi).

    - ``safe``: yalnızca tespit (servis/versiyon → CVE çıkarımı). Hedefe müdahale etmez.
    - ``aggressive``: nmap NSE vuln/exploit scriptleri + OS parmak izi. Hedef servislerle
      etkileşime girer; kesintiye yol açabilir veya iz bırakabilir. **Sömürmez** (SR-1):
      yalnızca tespit eder ve hangi exploit'lerin kullanılabileceğini gösterir. Çift kilitli
      (bkz. ``scan_policy``): global ayar + admin rolü gerekir.
    - ``exploit``: agresif gibi tarar AMA sonrasında eşleşen exploit'leri (Metasploit +
      Exploit-DB) hedefe UYGULAR — gerçek içeri-sızma denemesi (SR-1). En yüksek müdahale;
      agresif kilitlerine EK olarak msfrpcd / ``ALLOW_EXPLOITDB_EXECUTION`` kapıları gerekir.
    """

    safe = "safe"
    aggressive = "aggressive"
    exploit = "exploit"


class Severity(enum.StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingStatus(enum.StrEnum):
    open = "open"
    confirmed = "confirmed"
    resolved = "resolved"
    false_positive = "false_positive"
    accepted_risk = "accepted_risk"


class Asset(Base):
    """Keşfedilen host (iç ağdaki bir cihaz)."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    # IP, taramayla keşfedilen cihazlar için anahtardır. Elle eklenen URL varlıklarında
    # (aşağıdaki ``url``) IP BOŞ olabilir (patron isteği: tekil URL varlığı). Postgres
    # unique indeks çoklu NULL'a izin verir → birden çok URL varlığı (ip=NULL) bir arada durur.
    ip: Mapped[str | None] = mapped_column(String(45), unique=True, index=True, default=None)
    # Elle eklenen WEB/URL hedefi (ör. https://app.kurum.local:8443/portal). Tarama anında
    # web denetimine + host'u çözülerek ağ/CVE taramasına gider (IP varlıklarıyla aynı akış).
    url: Mapped[str | None] = mapped_column(String(512), unique=True, index=True, default=None)
    name: Mapped[str | None] = mapped_column(String(255), default=None)
    hostname: Mapped[str | None] = mapped_column(String(255), default=None)
    os: Mapped[str | None] = mapped_column(String(255), default=None)
    # Host bir tarama/ping ile AYAKTA doğrulandı mı? (yanıt veren gerçek cihaz → envanterde
    # gösterilir; ham/karşılıksız bare IP'ler is_up=False kalır ve gizlenir).
    is_up: Mapped[bool] = mapped_column(default=False, server_default="false")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    @property
    def display_name(self) -> str:
        """Gösterim adı önceliği: kullanıcı adı > hostname > URL > ip."""
        return self.name or self.hostname or self.url or self.ip or "?"


class Service(Base):
    """Bir host üzerinde tespit edilen açık port / servis."""

    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("asset_id", "port", "protocol", name="uq_service_asset_port_proto"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    port: Mapped[int] = mapped_column()
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    service_name: Mapped[str | None] = mapped_column(String(100), default=None)
    product: Mapped[str | None] = mapped_column(String(255), default=None)
    version: Mapped[str | None] = mapped_column(String(100), default=None)
    cpe: Mapped[str | None] = mapped_column(String(255), default=None)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Scan(Base):
    """Bir tarama işi."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType, native_enum=False, length=20))
    target: Mapped[str] = mapped_column(String(255))
    # Tek isimli 'tarama işi' (ScanBatch) — sihirbazdan çok hedefli tarama gruplanır.
    batch_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_batches.id", ondelete="CASCADE"), default=None, index=True
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, native_enum=False, length=20), default=ScanStatus.pending
    )
    mode: Mapped[ScanMode] = mapped_column(
        Enum(ScanMode, native_enum=False, length=20), default=ScanMode.safe
    )
    # Seçili ürün/CVE kategorileri (windows/linux/database/...); boş = tümü (filtre yok).
    categories: Mapped[list[str]] = mapped_column(JSON, default=list)
    # Port seçimi: None/"" = genel (nmap top-1000), "all" = tüm portlar (-p-),
    # "80,443,..." = elle girilen liste (nmap -p). Yalnızca ağ/zafiyet taramasında kullanılır.
    ports: Mapped[str | None] = mapped_column(String(255), default=None)
    # Canlı ilerleme: 0-100, faz metni, Celery görev kimliği (durdurma/revoke için).
    progress: Mapped[int] = mapped_column(default=0, server_default="0")
    phase: Mapped[str | None] = mapped_column(String(120), default=None)
    task_id: Mapped[str | None] = mapped_column(String(64), default=None)
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    # Atama + tamamlanma bildirimi: atanan kullanıcıya tarama bitince e-posta (ops. PDF rapor).
    assigned_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    notify_on_complete: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=expression.false()
    )
    attach_report: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=expression.false()
    )
    # Dış (public internet) web hedefine izin: YALNIZ web taraması + admin + açık onayla set
    # edilir. Set ise web görevi iç-IP scope guard yerine "yalnız-public" guard uygular
    # (loopback/iç/link-local/metadata yine reddedilir). Diğer tarama türlerini etkilemez.
    allow_external: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=expression.false()
    )
    # Web taramasında dizin/içerik keşfi (gobuster benzeri kelime-listesi probu) açık mı.
    # Moddan bağımsız ayrı kutucuk; yalnız web taramasını etkiler.
    dir_scan: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=expression.false()
    )
    # UDP servis taraması (#143): açıksa nmap'e hedeflenmiş -sU eklenir → SNMP/DNS/NTP/IPMI/
    # NetBIOS gibi UDP servisleri de keşfedilir. Yalnız ağ/zafiyet taramasında anlamlı.
    include_udp: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=expression.false()
    )
    # Dizin taramasında kullanılacak özel kelime listesi (Wordlist.id). None ise yerleşik
    # DIRSCAN_WORDLIST kullanılır. Yalnız web + dir_scan açıkken anlamlıdır.
    wordlist_id: Mapped[int | None] = mapped_column(default=None)
    # Başarısızlık sebebi (ör. "kapsam dışı") — arayüzde 'failed' durumunun yanında gösterilir.
    error_reason: Mapped[str | None] = mapped_column(String(255), default=None)
    # Web taramasında hedef URL'in çözülen IP'si (rapor/canlı görünüm taranan host'u gösterir;
    # envanter yerine). Diğer türlerde None (host bilgisi Asset/Service'ten gelir).
    resolved_ip: Mapped[str | None] = mapped_column(String(45), default=None)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScanBatch(Base):
    """Tek isimli 'tarama işi' — sihirbazdan başlatılan çok hedefli taramayı gruplar.

    Raporlar bölümünde tek satır olarak (verilen isimle) görünür; içindeki tüm
    hedef taramalarının (Scan) bulguları toplanır.
    """

    __tablename__ = "scan_batches"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150))
    mode: Mapped[ScanMode] = mapped_column(
        Enum(ScanMode, native_enum=False, length=20), default=ScanMode.safe
    )
    categories: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    # Atama + tamamlanma bildirimi (batch düzeyi): tüm üye taramalar terminal olunca BİR kez.
    assigned_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    notify_on_complete: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=expression.false()
    )
    attach_report: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=expression.false()
    )
    # Bildirimin yalnızca bir kez gönderildiğini garanti eden dedupe muhafızı.
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Finding(Base):
    """Bir taramada bulunan zafiyet / bulgu."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), default=None, index=True
    )
    service_id: Mapped[int | None] = mapped_column(
        ForeignKey("services.id", ondelete="SET NULL"), default=None
    )
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, native_enum=False, length=10), default=Severity.info
    )
    cve_id: Mapped[str | None] = mapped_column(String(30), default=None, index=True)
    risk_score: Mapped[float | None] = mapped_column(default=None)
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, native_enum=False, length=20), default=FindingStatus.open
    )
    # Doğrulama güveni: True = aktif NSE vuln/exploit script'i GERÇEKTEN doğruladı
    # (agresif mod); False = yalnız versiyon→CVE çıkarımı (false-positive olabilir).
    validated: Mapped[bool] = mapped_column(default=False, server_default="false")
    description: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ExploitAttempt(Base):
    """Agresif CVE exploitation sırasında yapılan TEK bir Metasploit deneme kaydı.

    Her deneme (başarılı/başarısız) yazılır → raporda ve canlı görünümde bir CVE için
    exploit'in yalnızca MEVCUT olduğu mu yoksa gerçekten DENENDİĞİ/SÖMÜRÜLDÜĞÜ mü
    ayırt edilir. Audit log'dan farkı: scan_id + cve_id + asset_id ile YAPISAL sorgulanır.
    Yalnız exploit/runner.py (operatör tarafından açılan msfrpcd ile) yazar.
    """

    __tablename__ = "exploit_attempts"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), default=None, index=True
    )
    host: Mapped[str] = mapped_column(String(45))
    cve_id: Mapped[str] = mapped_column(String(30), index=True)
    module: Mapped[str] = mapped_column(String(255))  # MSF modül yolu VEYA Exploit-DB EDB-ID
    # Sömürü kaynağı: "metasploit" (msfrpcd auto-run) | "exploitdb" (PoC; searchsploit/sandbox).
    source: Mapped[str] = mapped_column(
        String(20), default="metasploit", server_default="metasploit"
    )
    # Durum: "staged" (eşleşti, denenmedi) | "attempted" | "success" | "failed".
    status: Mapped[str] = mapped_column(String(20), default="attempted", server_default="attempted")
    command: Mapped[str | None] = mapped_column(Text, default=None)  # Exploit-DB önerilen komut
    # Oturumu açan MSF payload = sömürü KANALI (bind/reverse). Başarılı denemede dolu, yoksa None.
    payload: Mapped[str | None] = mapped_column(String(255), default=None)
    success: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    error: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Vulnerability(Base):
    """Tekilleştirilmiş güncel zafiyet durumu (asset_id + fingerprint).

    Finding tarama-başına kanıt/geçmiş olarak kalır; bu tablo kopya üretmeden
    güncel durumu tutar. Oto-çözüm: re-scan'de görünmeyen açık zafiyet resolved'a
    geçer; tekrar çıkarsa reopened (reopened_count artar).
    """

    __tablename__ = "vulnerabilities"
    __table_args__ = (UniqueConstraint("asset_id", "fingerprint", name="uq_vuln_asset_fp"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(255), index=True)
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType, native_enum=False, length=20))
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, native_enum=False, length=10), default=Severity.info
    )
    cve_id: Mapped[str | None] = mapped_column(String(30), default=None, index=True)
    risk_score: Mapped[float | None] = mapped_column(default=None)
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, native_enum=False, length=20), default=FindingStatus.open
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), default=None
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    reopened_count: Mapped[int] = mapped_column(default=0, server_default="0")
    # Doğrulama güveni: katkıda bulunan bulgulardan en az biri aktif NSE ile
    # doğrulandıysa True (yapışkan), aksi halde versiyon-bazlı çıkarım.
    validated: Mapped[bool] = mapped_column(default=False, server_default="false")
    # Vuln'ün en son GÖRÜLDÜĞÜ tarama port-kapsamı sıralaması: 0=elle port listesi
    # (kısmi), 1=top-1000/varsayılan, 2=tüm portlar (-p-). Oto-çözüm, daha GENİŞ
    # kapsamda görülmüş bir zafiyeti daha DAR bir taramayla çözmez (yanlış-çözme koruması).
    coverage: Mapped[int] = mapped_column(default=1, server_default="1")
    # Kaba kategori (Zafiyetler sayfası filtre/rozet): weak_credential/cve/web/config/sca/
    # other. core.vuln_category.derive_vuln_category ile türetilir; sync'te doldurulur.
    category: Mapped[str | None] = mapped_column(String(20), default=None, index=True)
    note: Mapped[str | None] = mapped_column(Text, default=None)
    updated_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ComplianceCheck(Base):
    """Bir taramada bir uyum/benchmark kontrolünün sonucu (CIS/STIG vb.).

    Mevcut host sertleştirme bulguları benchmark kontrollerine eşlenir; her kontrol
    geçti/kaldı olarak işaretlenir → formatlı uyum raporu (KVKK/ISO/PCI) bunun üstüne kurulur.
    """

    __tablename__ = "compliance_checks"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    framework: Mapped[str] = mapped_column(String(50), index=True)  # "CIS Linux" vb.
    control_id: Mapped[str] = mapped_column(String(20))  # "5.2.8"
    title: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(10))  # pass | fail | manual
    severity: Mapped[Severity | None] = mapped_column(
        Enum(Severity, native_enum=False, length=10), default=None
    )
    detail: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    """Denetim kaydı: kim, neyi, ne zaman yaptı (+ eylem tipine göre stabil event_id)."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None, index=True
    )
    event_id: Mapped[int] = mapped_column(default=0, server_default="0", index=True)
    action: Mapped[str] = mapped_column(String(100))
    target: Mapped[str | None] = mapped_column(String(255), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScopePolicy(Base):
    """Yetkili tarama kapsamı: izinli ve yasak IP/CIDR aralıkları."""

    __tablename__ = "scope_policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    allowed_cidrs: Mapped[list[str]] = mapped_column(JSON, default=list)
    denied_cidrs: Mapped[list[str]] = mapped_column(JSON, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CredentialType(enum.StrEnum):
    """Kimlik bilgisi bağlantı tipi (hangi protokolle giriş denenecek)."""

    ssh = "ssh"  # Linux/Unix — SSH (varsayılan port 22)
    winrm = "winrm"  # Windows — WinRM (varsayılan port 5985)
    rdp = "rdp"  # Windows — RDP (varsayılan port 3389)
    postgres = "postgres"  # PostgreSQL — salt-okunur config denetimi (varsayılan 5432)
    mysql = "mysql"  # MySQL/MariaDB — salt-okunur config denetimi (varsayılan 3306)
    mssql = "mssql"  # MSSQL/SQL Server — salt-okunur config denetimi (varsayılan 1433)
    oracle = "oracle"  # Oracle DB — salt-okunur config denetimi (varsayılan 1521)
    snmp = "snmp"  # Ağ cihazı — SNMP topluluk dizesi, salt-okunur (varsayılan 161/udp)
    smb = "smb"  # Windows/Samba — SMB paylaşım/imza/oturum denetimi (varsayılan 445)
    ldap = "ldap"  # LDAP/AD — anonim bind/okuma + şifreleme + parola politikası (varsayılan 389)
    telnet = "telnet"  # Ağ cihazı — Telnet/Cisco CLI sertleştirme denetimi (varsayılan 23)


class Credential(Base):
    """Kimlik kasasındaki bir giriş bilgisi. Parola **şifreli** saklanır (bkz. core/crypto)."""

    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    cred_type: Mapped[CredentialType] = mapped_column(
        Enum(CredentialType, native_enum=False, length=20)
    )
    username: Mapped[str] = mapped_column(String(150))
    secret_encrypted: Mapped[str] = mapped_column(Text)  # Fernet ile şifreli parola
    domain: Mapped[str | None] = mapped_column(String(150), default=None)  # Windows domain (ops.)
    port: Mapped[int | None] = mapped_column(default=None)  # tipin varsayılanını ezer (ops.)
    description: Mapped[str | None] = mapped_column(String(255), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CredentialZone(Base):
    """Kimlik bölgesi: isimli bir Credential grubu (IP zone mantığının kimlik karşılığı)."""

    __tablename__ = "credential_zones"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(String(255), default=None)
    credential_ids: Mapped[list[int]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Zone(Base):
    """Tarama bölgesi: isimli bir IP/CIDR blok grubu.

    Hedefleri ORGANİZE eder; yetkilendirme hâlâ scope guard'a tabidir (zone taranırken
    her blok scope'tan geçer, kapsam dışı bloklar atlanır).
    """

    __tablename__ = "zones"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(String(255), default=None)
    cidrs: Mapped[list[str]] = mapped_column(JSON, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class WordlistKind(enum.StrEnum):
    """Kelime listesinin kullanım amacı (hangi tarama tüketir)."""

    web_dir = "web_dir"  # Web dizin/içerik keşfi (gobuster benzeri)
    smb_share = "smb_share"  # SMB paylaşım adı keşfi/enum
    username = "username"  # Kullanıcı adı listesi (brute force)
    password = "password"  # Parola listesi (brute force)
    snmp_community = "snmp_community"  # SNMP topluluk dizesi denemeleri
    subdomain = "subdomain"  # Subdomain/vhost keşfi


class Wordlist(Base):
    """Yeniden kullanılabilir kelime listesi (dizin/SMB/brute force için TEK kaynak).

    Satırlar JSON dizi olarak saklanır. ``kind`` listeyi hangi taramanın tüketeceğini
    belirler; taramalar yalnız kendi türüne uygun listeleri seçtirir. ``is_builtin``
    yerleşik (silinemez/düzenlenemez) listeleri işaretler.
    """

    __tablename__ = "wordlists"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    kind: Mapped[WordlistKind] = mapped_column(Enum(WordlistKind, native_enum=False, length=20))
    description: Mapped[str | None] = mapped_column(String(255), default=None)
    entries: Mapped[list[str]] = mapped_column(JSON, default=list)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[int | None] = mapped_column(default=None)  # oluşturan kullanıcı (ops.)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CVE(Base):
    """NVD'den çekilen zafiyet kaydı (cve_id birincil anahtar)."""

    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String(30), primary_key=True)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    cvss_score: Mapped[float | None] = mapped_column(default=None)
    severity: Mapped[Severity | None] = mapped_column(
        Enum(Severity, native_enum=False, length=10), default=None
    )
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    # Sömürülebilirlik sinyalleri
    kev_flag: Mapped[bool] = mapped_column(Boolean, default=False)  # CISA KEV: aktif sömürü
    epss_score: Mapped[float | None] = mapped_column(default=None)  # EPSS: sömürülme olasılığı
    # Platform/kullanım kategorisi (açıklamadan türetilir; Zafiyet DB kategori çipleri için).
    # Tek BİRİNCİL kategori (windows/linux/web/...) — hızlı GROUP BY sayımı + filtre.
    category: Mapped[str | None] = mapped_column(String(16), default=None, index=True)


class CpeMatch(Base):
    """Bir CVE'nin NVD ``configurations`` bloğundaki tek CPE eşleşme ölçütü.

    Offline (ağsız) zafiyet eşleştirme için yerel indeks: (vendor, product) →
    hangi CVE'ler, hangi sürüm aralığında geçerli. NVD senkronunda doldurulur.
    """

    __tablename__ = "cpe_matches"
    __table_args__ = (Index("ix_cpe_vendor_product", "vendor", "product"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(30), index=True)
    part: Mapped[str] = mapped_column(String(2), default="a")  # a/o/h
    vendor: Mapped[str] = mapped_column(String(128))
    product: Mapped[str] = mapped_column(String(128))
    version: Mapped[str] = mapped_column(String(128), default="*")
    vulnerable: Mapped[bool] = mapped_column(Boolean, default=True)
    version_start_including: Mapped[str | None] = mapped_column(String(64), default=None)
    version_start_excluding: Mapped[str | None] = mapped_column(String(64), default=None)
    version_end_including: Mapped[str | None] = mapped_column(String(64), default=None)
    version_end_excluding: Mapped[str | None] = mapped_column(String(64), default=None)
    criteria: Mapped[str] = mapped_column(String(255))


class ExploitSource(enum.StrEnum):
    """Yerel zafiyet/exploit deposundaki kaydın kaynağı."""

    exploitdb = "exploitdb"
    metasploit = "metasploit"
    nvd = "nvd"  # NVD CVE kayıtları (CVSS skorlu zafiyet)


class Exploit(Base):
    """Yerel exploit veritabanı kaydı (Exploit-DB / Metasploit'ten içe aktarılır)."""

    __tablename__ = "exploits"
    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_exploit_source_extid"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[ExploitSource] = mapped_column(Enum(ExploitSource, native_enum=False, length=20))
    external_id: Mapped[str] = mapped_column(String(255), index=True)  # EDB-ID / modül yolu
    title: Mapped[str] = mapped_column(String(500))
    type: Mapped[str | None] = mapped_column(String(50), default=None)  # remote/local/dos...
    platform: Mapped[str | None] = mapped_column(String(80), default=None)
    author: Mapped[str | None] = mapped_column(String(255), default=None)
    date: Mapped[str | None] = mapped_column(String(30), default=None)  # yayın/açıklanma
    rank: Mapped[str | None] = mapped_column(String(30), default=None)  # metasploit rank
    severity: Mapped[Severity | None] = mapped_column(  # kritiklik (sınıflandırma)
        Enum(Severity, native_enum=False, length=10), default=None, index=True
    )
    categories: Mapped[list[str]] = mapped_column(JSON, default=list)  # windows/database/web...
    category_text: Mapped[str | None] = mapped_column(Text, default=None)  # kategori LIKE araması
    cve_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    cve_text: Mapped[str | None] = mapped_column(Text, default=None)  # CVE araması (LIKE) için
    url: Mapped[str | None] = mapped_column(String(500), default=None)
    # Exploit-DB OffSec doğrulama bayrağı (PoC işlevsel tekrar testi geçti; MSF için False).
    verified: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=expression.false(), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScheduledScan(Base):
    """Tekrarlı (zamanlanmış) tarama tanımı.

    period: daily | weekly | monthly | once | interval. ``interval`` modunda
    ``interval_minutes`` kullanılır; diğerlerinde periyot sabittir. ``start_at``
    verilirse tarama bu tarih/saatten önce çalışmaz (tek-seferlik için bu an).
    """

    __tablename__ = "scheduled_scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType, native_enum=False, length=20))
    # Tekil hedef (eski/legacy zamanlama). Şablon modunda boş kalır; hedefler aşağıdaki
    # zone/asset id'lerinden çözülür.
    target: Mapped[str] = mapped_column(String(255), default="", server_default="")
    period: Mapped[str] = mapped_column(String(20), default="daily", server_default="interval")
    interval_minutes: Mapped[int] = mapped_column(default=1440)  # 'interval' modunda kullanılır
    start_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # --- Batch şablonu (sihirbazdan zamanlama): çoklu hedef + kimlik + mod + kategori ---
    name: Mapped[str] = mapped_column(String(150), default="", server_default="")
    zone_ids: Mapped[list[int]] = mapped_column(JSON, default=list, server_default="[]")
    asset_ids: Mapped[list[int]] = mapped_column(JSON, default=list, server_default="[]")
    credential_zone_ids: Mapped[list[int]] = mapped_column(JSON, default=list, server_default="[]")
    credential_ids: Mapped[list[int]] = mapped_column(JSON, default=list, server_default="[]")
    mode: Mapped[ScanMode] = mapped_column(
        Enum(ScanMode, native_enum=False, length=20), default=ScanMode.safe, server_default="safe"
    )
    categories: Mapped[list[str]] = mapped_column(JSON, default=list, server_default="[]")
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )


class LdapConfig(Base):
    """LDAP/AD bağlantı yapılandırması (tek satır, id=1) — kullanıcı arama/içe aktarma.

    Bind (servis hesabı) parolası Fernet ile şifreli saklanır. Bu yapılandırma
    LDAP'tan kullanıcı ARAMAK ve İÇE AKTARMAK için kullanılır; giriş (login)
    doğrulaması ayrıca ortam değişkenleriyle (config.py) yapılır.
    """

    __tablename__ = "ldap_config"

    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    server_uri: Mapped[str] = mapped_column(String(255), default="")
    use_ssl: Mapped[bool] = mapped_column(Boolean, default=False)
    bind_dn: Mapped[str] = mapped_column(String(255), default="")  # servis hesabı DN
    bind_password_encrypted: Mapped[str | None] = mapped_column(Text, default=None)
    base_dn: Mapped[str] = mapped_column(String(255), default="")  # arama tabanı
    user_filter: Mapped[str] = mapped_column(String(255), default="(objectClass=person)")
    attr_username: Mapped[str] = mapped_column(String(64), default="uid")
    attr_email: Mapped[str] = mapped_column(String(64), default="mail")
    attr_display_name: Mapped[str] = mapped_column(String(64), default="cn")
    default_role: Mapped[str] = mapped_column(String(20), default="viewer")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# Varlık (asset) kapsamı varsayılanı: yalnız bu aralıklardaki IP'ler envantere (Varlıklar)
# eklenir. Default = özel/iç ağlar (RFC1918) + loopback (IPv4/IPv6). Operatör Ayarlar'dan
# dış IP/aralık ekleyebilir; eklenmemiş (dış/public) hedeflere yapılan taramalar Varlıklar'ı
# KİRLETMEZ (bulgular yine raporlanır, sadece asset yaratılmaz). Tarama scope'undan AYRIDIR.
DEFAULT_ASSET_SCOPE_CIDRS: list[str] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]


class AppSettings(Base):
    """Uygulama geneli güvenlik/operasyon ayarları (tek satır, id=1).

    Admin panelinden (``/settings``) yönetilir; ortam değişkenleri (config.py)
    yalnızca varsayılan/fallback olarak kullanılır. Sırlar (SMTP parolası)
    Fernet ile şifreli saklanır; ham değer yalnızca gönderim anında çözülür.
    """

    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(primary_key=True, default=1)

    # --- Giriş kaba-kuvvet koruması (rate-limit / lockout) ---
    ratelimit_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    ratelimit_max_attempts: Mapped[int] = mapped_column(default=5)
    ratelimit_window_sec: Mapped[int] = mapped_column(default=300)
    ratelimit_lockout_sec: Mapped[int] = mapped_column(default=900)

    # --- SMTP / e-posta uyarıları ---
    smtp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    smtp_host: Mapped[str] = mapped_column(String(255), default="")
    smtp_port: Mapped[int] = mapped_column(default=587)
    smtp_username: Mapped[str] = mapped_column(String(255), default="")
    smtp_password_encrypted: Mapped[str | None] = mapped_column(Text, default=None)
    smtp_from: Mapped[str] = mapped_column(String(255), default="")
    smtp_use_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    alert_email_to: Mapped[str] = mapped_column(String(255), default="")

    # --- Syslog / SIEM forward ---
    syslog_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    syslog_host: Mapped[str] = mapped_column(String(255), default="")
    syslog_port: Mapped[int] = mapped_column(default=514)
    syslog_protocol: Mapped[str] = mapped_column(String(8), default="udp")  # udp | tcp
    syslog_format: Mapped[str] = mapped_column(String(16), default="rfc5424")  # rfc5424|rfc3164|cef

    # --- Oturum / parola / LDAPS sertleştirme ---
    session_timeout_min: Mapped[int] = mapped_column(default=0)  # 0 = kapalı (tarayıcı oturumu)
    password_min_length: Mapped[int] = mapped_column(default=8)
    password_require_complexity: Mapped[bool] = mapped_column(Boolean, default=False)
    ldaps_verify_cert: Mapped[bool] = mapped_column(Boolean, default=False)
    ldaps_ca_cert: Mapped[str | None] = mapped_column(Text, default=None)  # PEM (opsiyonel)

    # --- MFA (org düzeyi anahtar; kullanıcı kaydı Kullanıcılar bölümünde) ---
    mfa_required: Mapped[bool] = mapped_column(Boolean, default=False)

    # --- Ağ / DNS (VI-6; nmap hostname çözümü) ---
    # Özel DNS sunucu(ları), virgülle (nmap --dns-servers). Boş = sistem çözücü.
    dns_servers: Mapped[str] = mapped_column(String(255), default="", server_default="")
    # Reverse-DNS (PTR): açık = hostname çöz; kapalı = nmap -n (çözme, daha hızlı/sessiz).
    reverse_dns_enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    # Tarama hızı (nmap paralellik): normal | fast | insane. nmap ağ-bound olduğundan hız
    # RAM/CPU değil PARALELLİK ile artar; bu ayar --min-hostgroup/--min-parallelism/--min-rate
    # bayraklarını belirler (boştaki kaynağı çok-hostlu taramalarda kullanır). Varsayılan fast
    # (düşük risk, doğruluğu büyük ölçüde korur); insane daha hızlı ama paket-kaybı riski artar.
    scan_speed: Mapped[str] = mapped_column(String(16), default="fast", server_default="fast")
    # Worker dağıtımı (fan-out): tek tarama bloklara bölünüp worker'lara dağıtılır mı + en çok
    # kaç parçaya. ``scan_fanout`` açık/kapalı; ``fanout_workers`` tek-host büyük-port (-p-)
    # taramasında port-bloğu sayısı (CIDR taramaları NAT güvenliği için /27 bloklara ayrı bölünür).
    # Tarama HIZINDAN bağımsız (operatör kontrolü); her child yine yapılandırılan hızı kullanır.
    scan_fanout: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    fanout_workers: Mapped[int] = mapped_column(default=8, server_default="8")  # 1=bölme yok

    # --- Varlık kapsamı (F1; yalnız iç/kapsam-içi IP'ler Varlıklar'a eklensin) ---
    # Bu CIDR'lerdeki IP'ler envantere (asset) eklenir; dışındakiler EKLENMEZ (dış tarama
    # Varlıklar'ı kirletmesin — bulgular yine raporlanır). Boş liste = kapsam zorlanmaz
    # (tüm IP'ler asset olabilir). Tarama scope'undan (ScopePolicy) AYRIDIR.
    asset_scope_cidrs: Mapped[list[str]] = mapped_column(
        JSON,
        default=lambda: list(DEFAULT_ASSET_SCOPE_CIDRS),
        server_default=json.dumps(DEFAULT_ASSET_SCOPE_CIDRS),
    )

    # --- Görünüm / yerelleştirme (IX-1) ---
    # Uygulama geneli saat dilimi (IANA, ör. "Europe/Istanbul"). Zamanlar UTC
    # saklanır; gösterimde bu dilime çevrilir (küresel kullanım için şart).
    timezone: Mapped[str] = mapped_column(
        String(64), default="Europe/Istanbul", server_default="Europe/Istanbul"
    )

    # --- Güncelleme denetimi (her gün beat kontrol eder; /update sayfası gösterir) ---
    # DIŞ-ERİŞİM (egress): YALNIZ bu denetim internete çıkar; kapatılabilir (air-gap/sıfır-egress)
    # + URL değiştirilebilir (kendi ayna/sürüm sunucusu). Uygulamanın geri kalanı tamamen yereldir.
    update_check_enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    # Sürüm kaynağı (GitHub Releases API). core/update_check.DEFAULT_UPDATE_CHECK_URL ile AYNI.
    update_check_url: Mapped[str] = mapped_column(
        String(500),
        default="https://api.github.com/repos/Lineup-NOAH/kangalis-core/releases/latest",
        server_default="https://api.github.com/repos/Lineup-NOAH/kangalis-core/releases/latest",
    )
    # Son denetimde bulunan en güncel sürüm (boş = henüz bilinmiyor; yalnız denetim yazar).
    latest_version: Mapped[str] = mapped_column(String(64), default="", server_default="")
    update_last_checked: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    # Son denetim durumu: ok | unreachable | no_release | error | disabled (UI dürüst gösterir).
    update_last_status: Mapped[str] = mapped_column(String(16), default="", server_default="")

    # --- Exploit veritabanı tazelik durumu (VI-9; saatlik beat günceller) ---
    exploit_last_sync: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    exploit_last_check: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    exploit_up_to_date: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")

    # --- CVE/CPE bilgi bankası tazeliği (cpe_sync/backfill günceller; exploit'ten AYRI) ---
    cve_last_sync: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    # --- NVD/CVE senkron kapsamı (CVE-COVERAGE #197 frontend) ---
    # Günlük oto-senkronun geriye gideceği GÜN sayısı; küçük (varsayılan 1 hafta) ki her gün
    # ucuz koşsun (geçmiş yükleme ayrı backfill ile yapılır). >120 ise 120-günlük pencerelere
    # bölünür (NVD sınırı). config.NVD_SYNC_DAYS yalnız fallback; DB değeri önceliklidir.
    nvd_sync_days: Mapped[int] = mapped_column(default=7, server_default="7")
    # NVD API anahtarı (opsiyonel; rate-limit'i 5/30sn → 50/30sn yükseltir). Fernet ile
    # şifreli saklanır (SMTP parolası deseni); ham değer yalnız senkron anında çözülür.
    nvd_api_key_encrypted: Mapped[str | None] = mapped_column(Text, default=None)

    # --- LDAP periyodik kullanıcı senkronu (X-6) ---
    # LDAP bağlıyken kullanıcıları zamanlanmış çek (yeni üyeler pasif; var olanın rolü/durumu
    # KORUNUR). Beat saatlik kontrol eder; period + saat'e göre tetiklenir.
    ldap_sync_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    ldap_sync_period: Mapped[str] = mapped_column(  # hourly | daily | weekly
        String(10), default="daily", server_default="daily"
    )
    ldap_sync_hour: Mapped[int] = mapped_column(  # 0-23 (yerel saat) — daily/weekly için
        default=3, server_default="3"
    )
    ldap_sync_last: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    # --- Yerel AI asistanı (OpenAI-uyumlu motor, on-prem; #181-184) ---
    # Çalışma-anı kaynağı: bu satır (admin UI). Boş alanlar config.py env varsayılanına düşer.
    # ai_enabled KAPALI iken AI tamamen devre dışı (butonlar görünmez, statik Remediation sürer).
    # Sıfır egress: endpoint internal yerel motordur (compose 'ai' profili); veri ağdan çıkmaz.
    ai_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    ai_endpoint_url: Mapped[str] = mapped_column(
        String(255), default="", server_default=""
    )  # boş → config.ai_endpoint (http://ollama:11434/v1)
    ai_model_name: Mapped[str] = mapped_column(
        String(128), default="", server_default=""
    )  # boş → config.ai_model (qwen3:8b)
    ai_timeout_sec: Mapped[int] = mapped_column(default=300, server_default="300")  # CPU yavaş

    # --- Ticari lisans (çevrimdışı, imza-temelli) ---
    # Patronun ürettiği lisans kodu (base64url(payload).base64url(sig)); uzun olabilir.
    # core/licensing.py açık anahtarla imzayı doğrular → ``exploit`` özelliğini açar. Boş = yok.
    license_key: Mapped[str] = mapped_column(String(2048), default="", server_default="")
    # Doğrulama AÇIK anahtarı (patronun Ed25519 public key'i, base64). GİZLİ DEĞİLDİR.
    # İmza bununla doğrulanır. Boş ise config.license_public_key (env LICENSE_PUBLIC_KEY)
    # fallback olur — böylece açık anahtar .env'e dokunmadan UI'dan girilebilir.
    license_public_key: Mapped[str] = mapped_column(String(255), default="", server_default="")

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AIExplanation(Base):
    """Yerel AI üretiminin önbelleği (#183) — aynı içerik tekrar üretilmez (CPU pahalı).

    ``cache_key`` üretimin neyi açıkladığını belirler ve tekildir:
      * ``cve:CVE-2021-42013``  — per-bulgu açıklama (CVE'ler arası tekrar kullanılır)
      * ``finding:<slug>``      — CVE'siz bulgu (zayıf kimlik/açık servis); başlıktan türetilir
      * ``summary:scan:{id}``   — tarama yönetici özeti
      * ``summary:batch:{id}``  — toplu tarama yönetici özeti
    Önbellek, modeli de saklar (model değişirse operatör temizleyebilir). Halüsinasyon
    riskine karşı içerik UI'da "AI üretti — doğrula" notuyla gösterilir.
    """

    __tablename__ = "ai_explanations"

    id: Mapped[int] = mapped_column(primary_key=True)
    cache_key: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    content: Mapped[str] = mapped_column(Text)
    model: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
