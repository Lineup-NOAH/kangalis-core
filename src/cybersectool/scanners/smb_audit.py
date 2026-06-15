"""SMB paylaşım/güvenlik denetimi (IX-7a) — SALT-OKUNUR.

impacket ile bir SMB sunucusuna (Windows ya da Samba) bağlanıp güvenlik duruşunu
denetler: SMB imzalama zorunluluğu, SMBv1 desteği, anonim (null) oturum, misafir (guest)
erişimi ve kimliksiz paylaşım listeleme. Hedefe YAZMAZ — yalnız negotiate + login denemesi
+ paylaşım listeleme (ENUM). ``eval_*`` fonksiyonları SAFtır (birim testi edilebilir);
``audit_smb`` ağ erişimi yapar (gerçek SMB sunucusuna karşı doğrulanır).

Kimlik OPSİYONELDİR: kimliksiz de en kritik bulgular (null/guest/imza/SMBv1) tespit edilir;
kimlik verilirse ek olarak yetkili paylaşım envanteri çıkarılır.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.compliance import derive_compliance, store_compliance
from cybersectool.core.findings import create_finding
from cybersectool.core.models import Severity

SMB_PORT = 445


class SmbAuditError(Exception):
    """SMB denetimi sırasında kurtarılamayan hata (hedefe hiç erişilemedi)."""


@dataclass
class SmbFinding:
    title: str
    severity: Severity
    detail: str


@dataclass
class SmbInfo:
    """SMB denetim sonucu envanteri (okunabildiği/denenebildiği kadarıyla)."""

    server_os: str = ""
    server_name: str = ""
    domain: str = ""
    dialect: str = ""  # ör. "SMB 3.1.1"
    signing_required: bool = True  # bilinmiyorsa güvenli varsay (yanlış pozitifi düşür)
    smbv1_supported: bool = False
    null_session: bool = False  # anonim ("", "") oturum açıldı mı?
    guest_access: bool = False  # guest hesabıyla oturum açıldı mı?
    authenticated: bool = False  # verilen kimlikle oturum açıldı mı?
    shares: list[str] = field(default_factory=list)  # erişilebilen tüm paylaşımlar
    anon_shares: list[str] = field(default_factory=list)  # YALNIZ null (anonim) oturumla listelenen
    guest_shares: list[str] = field(
        default_factory=list
    )  # guest hesabıyla listelenen (anonim DEĞİL)
    # Kelime listesiyle ADIYLA erişilebilen ama listelemede GÖRÜNMEYEN (gizli) paylaşımlar.
    probed_shares: list[str] = field(default_factory=list)

    def summary(self) -> str:
        """Kısa tek satır özet (sunucu — dialect)."""
        parts = [p for p in (self.server_name, self.server_os, self.dialect) if p]
        return " — ".join(parts) or "bilinmiyor"


# Denetimde HER ZAMAN çalışan kontrollerin kanonik başlıkları (uyum eşlemesi bunlara dayanır).
SMB_CHECK_TITLES: tuple[str, ...] = (
    "SMB imzalama",
    "SMBv1 protokolü",
    "SMB anonim oturum",
    "SMB misafir erişimi",
    "SMB anonim paylaşım listeleme",
)


def eval_smb_signing(required: bool) -> SmbFinding | None:
    """İmzalama zorunlu değilse SMB relay/MITM riski (CIS Windows 2.3.9.2)."""
    if not required:
        return SmbFinding(
            "SMB imzalama",
            Severity.medium,
            "SMB sunucu imzalaması zorunlu değil — saldırgan ağ üzerinde oturumu araya "
            "girip değiştirebilir (SMB relay / MITM). Sunucu tarafında imzalamayı 'her "
            "zaman' zorunlu yapın.",
        )
    return None


def eval_smb_v1(supported: bool) -> SmbFinding | None:
    """SMBv1 destekleniyorsa EternalBlue/WannaCry sınıfı risk (CIS Windows 18.3.1)."""
    if supported:
        return SmbFinding(
            "SMBv1 protokolü",
            Severity.high,
            "Sunucu eski SMBv1 protokolünü destekliyor — EternalBlue (MS17-010) / WannaCry "
            "sınıfı saldırılara açık ve imzalama/şifreleme zayıftır. SMBv1'i istemci ve "
            "sunucuda devre dışı bırakın.",
        )
    return None


def eval_smb_null_session(allowed: bool) -> SmbFinding | None:
    """Anonim (null) oturum açılabiliyorsa kimliksiz bilgi sızıntısı (CIS Windows 2.3.10.5)."""
    if allowed:
        return SmbFinding(
            "SMB anonim oturum",
            Severity.high,
            "Sunucu anonim (null) SMB oturumuna izin veriyor — kimlik bilgisi olmadan "
            "paylaşım/kullanıcı/grup bilgisi sıralanabilir. Anonim erişimi kısıtlayın "
            "(RestrictAnonymous / 'Everyone' izinlerini anonime uygulama).",
        )
    return None


def eval_smb_guest(allowed: bool) -> SmbFinding | None:
    """Misafir (guest) erişimi açıksa yetkisiz erişim yüzeyi (CIS Windows 2.3.1.1)."""
    if allowed:
        return SmbFinding(
            "SMB misafir erişimi",
            Severity.medium,
            "Sunucu misafir (guest) hesabıyla SMB oturumuna izin veriyor — parolasız "
            "yetkisiz erişim mümkün. Guest hesabını devre dışı bırakın ve guest geri "
            "dönüşünü (GuestLogon) kapatın.",
        )
    return None


def eval_smb_anon_shares(shares: list[str]) -> SmbFinding | None:
    """Kimliksiz listelenebilen (IPC$ hariç) paylaşım varsa bilgi sızıntısı (CIS 2.3.10.9)."""
    listable = [s for s in shares if s.strip().upper() not in ("IPC$",)]
    if listable:
        shown = ", ".join(listable[:10])
        more = "" if len(listable) <= 10 else f" (+{len(listable) - 10})"
        return SmbFinding(
            "SMB anonim paylaşım listeleme",
            Severity.high,
            f"Paylaşımlar kimlik bilgisi olmadan listelenebiliyor: {shown}{more}. Ağdaki "
            "herkes paylaşım yapısını görebilir; içerik izinleri de gevşekse veri sızar. "
            "Anonim paylaşım/Named Pipe erişimini kısıtlayın.",
        )
    return None


# Gizli (listelenmeyen) paylaşım keşfi bulgusunun kanonik başlığı — kelime listesi tüketir.
SMB_PROBED_SHARES_TITLE = "SMB gizli paylaşım keşfi (kelime listesi)"


def eval_smb_probed_shares(probed: list[str]) -> SmbFinding | None:
    """Kelime listesiyle ADIYLA erişilen ama listelemede görünmeyen paylaşım varsa bulgu."""
    if not probed:
        return None
    shown = ", ".join(probed[:15])
    more = "" if len(probed) <= 15 else f" (+{len(probed) - 15})"
    return SmbFinding(
        SMB_PROBED_SHARES_TITLE,
        Severity.medium,
        f"Sunucu paylaşım listelemesini kısıtlasa da şu paylaşımlara adıyla erişilebildi: "
        f"{shown}{more}. 'Gizli' paylaşımlar güvenlik sağlamaz (security through obscurity); "
        "erişim izinlerini ve paylaşım gereksinimini gözden geçirin.",
    )


def evaluate_smb(info: SmbInfo) -> list[SmbFinding]:
    """SMB denetim envanterinden bulguları üretir (saf; ağ gerektirmez)."""
    candidates = (
        eval_smb_signing(info.signing_required),
        eval_smb_v1(info.smbv1_supported),
        eval_smb_null_session(info.null_session),
        eval_smb_guest(info.guest_access),
        eval_smb_anon_shares(info.anon_shares),
        eval_smb_probed_shares(info.probed_shares),
    )
    return [f for f in candidates if f is not None]


# --- Ağ erişimi (impacket) — senkron yardımcılar to_thread içinde çağrılır ---


def _safe_close(conn: Any) -> None:
    """Bağlantıyı sessizce kapatır (hata yutulur)."""
    with contextlib.suppress(Exception):
        conn.close()


def _dialect_label(dialect: int) -> str:
    """impacket dialect kimliğini insan-okunur etikete çevirir."""
    from impacket.smb import SMB_DIALECT

    labels = {
        SMB_DIALECT: "SMB 1.0",
        0x0202: "SMB 2.0.2",
        0x0210: "SMB 2.1",
        0x0300: "SMB 3.0",
        0x0302: "SMB 3.0.2",
        0x0311: "SMB 3.1.1",
    }
    return labels.get(dialect, f"0x{dialect:04x}")


def _list_shares(conn: Any) -> list[str]:
    """Oturum açık bir bağlantıda paylaşımları listeler (null-terminated isimleri temizler)."""
    out: list[str] = []
    for share in conn.listShares():
        name = str(share["shi1_netname"]).rstrip("\x00")
        if name:
            out.append(name)
    return out


def _negotiate(host: str, port: int, timeout: float) -> tuple[str, bool]:
    """Yalnız negotiate: (dialect etiketi, imzalama zorunlu mu). Erişilemezse SmbAuditError."""
    from impacket.smbconnection import SMBConnection

    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
    except Exception as exc:  # her bağlantı hatasını sarmala (erişilemedi)
        raise SmbAuditError(f"SMB bağlantısı kurulamadı: {exc}") from exc
    try:
        dialect = ""
        with contextlib.suppress(Exception):
            dialect = _dialect_label(conn.getDialect())
        signing = True  # bilinmiyorsa güvenli varsay (yanlış pozitifi düşür)
        with contextlib.suppress(Exception):
            signing = bool(conn.isSigningRequired())
        return dialect, signing
    finally:
        _safe_close(conn)


def _smb_v1_supported(host: str, port: int, timeout: float) -> bool:
    """SMBv1 dialect'i zorlayarak bağlanmayı dener; başarılıysa SMBv1 etkindir."""
    from impacket.smb import SMB_DIALECT
    from impacket.smbconnection import SMBConnection

    try:
        conn = SMBConnection(
            host, host, sess_port=port, preferredDialect=SMB_DIALECT, timeout=timeout
        )
    except Exception:  # SMBv1 reddedildi / desteklenmiyor
        return False
    _safe_close(conn)
    return True


def _login_and_inspect(
    host: str, port: int, user: str, password: str, domain: str, timeout: float
) -> tuple[bool, list[str], dict[str, str]]:
    """Oturum açmayı dener; (başarılı?, paylaşımlar, sunucu bilgisi) döner. Asla hata fırlatmaz."""
    from impacket.smbconnection import SMBConnection

    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
    except Exception:  # hedefe bağlanılamadı
        return False, [], {}
    try:
        conn.login(user, password, domain)
    except Exception:  # kimlik tutmadı / oturum reddedildi
        _safe_close(conn)
        return False, [], {}
    server: dict[str, str] = {}
    shares: list[str] = []
    with contextlib.suppress(Exception):
        server = {
            "os": str(conn.getServerOS() or ""),
            "name": str(conn.getServerName() or ""),
            "domain": str(conn.getServerDomain() or ""),
        }
    with contextlib.suppress(Exception):  # oturum açıldı ama listeleme reddedilebilir
        shares = _list_shares(conn)
    _safe_close(conn)
    return True, shares, server


# Kelime listesiyle denenecek azami paylaşım adı sayısı (hedefi sel altında bırakmamak için).
MAX_SMB_SHARE_PROBES = 2000


def _probe_share_names(
    host: str,
    port: int,
    user: str,
    password: str,
    domain: str,
    share_names: list[str],
    timeout: float,
) -> list[str]:
    """Verilen paylaşım adlarına ADIYLA bağlanmayı dener; erişilebilenleri döndürür.

    Tek oturum açar (kimliksiz/null ya da verilen kimlikle), her adı ``connectTree`` ile
    dener. Salt-okunur: yalnız ağaca bağlanır, hemen bırakır; içerik okumaz/yazmaz.
    """
    from impacket.smbconnection import SMBConnection

    if not share_names:
        return []
    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
        conn.login(user, password, domain)
    except Exception:  # oturum açılamadı → paylaşım denemesi yapılamaz
        return []
    found: list[str] = []
    seen: set[str] = set()
    try:
        for raw in share_names[:MAX_SMB_SHARE_PROBES]:
            name = raw.strip()
            key = name.upper()
            if not name or key in seen:
                continue
            seen.add(key)
            try:
                tid = conn.connectTree(name)
                conn.disconnectTree(tid)
            except Exception:  # paylaşım yok / erişim reddedildi
                continue
            found.append(name)
    finally:
        _safe_close(conn)
    return found


def _probe_smb(
    host: str,
    port: int,
    user: str,
    password: str,
    domain: str,
    timeout: float,
    share_names: list[str] | None = None,
) -> SmbInfo:
    """SMB sunucusunu salt-okunur denetler (senkron; to_thread içinde çağrılır)."""
    info = SmbInfo()
    # 1) Negotiate — dialect + imzalama (erişilemezse SmbAuditError fırlatır).
    info.dialect, info.signing_required = _negotiate(host, port, timeout)
    # 2) SMBv1 desteği (ayrı bağlantı, dialect zorlanır).
    info.smbv1_supported = _smb_v1_supported(host, port, timeout)
    # 3) Anonim oturumlar: null ve guest (her biri ayrı bağlantı).
    null_ok, null_shares, null_srv = _login_and_inspect(host, port, "", "", "", timeout)
    guest_ok, guest_shares, guest_srv = _login_and_inspect(host, port, "guest", "", "", timeout)
    info.null_session = null_ok
    # Guest erişimi YALNIZ null oturum KAPALIYKEN anlamlıdır: null'a izin veren sunucularda
    # "guest"/boş-parola da null oturuma maplenir → guest_ok=True olur ama guest HESABI gerçekte
    # açık olmayabilir. Null zaten ayrı (HIGH) bulgu olarak raporlanıyor; burada guest'i
    # bastırarak çift/yanıltıcı "guest erişimi" (MEDIUM) bulgusunu önleriz.
    info.guest_access = guest_ok and not null_ok
    # anon_shares YALNIZ gerçek null oturumdan türetilir; guest bir KİMLİKTİR (anonim değil)
    # → guest paylaşımları ayrı tutulur, 'anonim listeleme' (HIGH) bulgusuna dahil edilmez.
    info.anon_shares = null_shares
    info.guest_shares = guest_shares
    server = null_srv or guest_srv
    # 4) Kimlikli (verilmişse) — yetkili paylaşım envanteri.
    if user:
        ok, shares, srv = _login_and_inspect(host, port, user, password, domain, timeout)
        info.authenticated = ok
        if ok:
            server = srv or server
            if shares:
                info.shares = shares
    if not info.shares:
        info.shares = info.anon_shares or info.guest_shares
    # 5) Kelime listesi verildiyse: ADIYLA erişilebilen ama listelemede GÖRÜNMEYEN paylaşımlar.
    if share_names:
        p_user, p_pass, p_dom = (user, password, domain) if user else ("", "", "")
        accessible = _probe_share_names(host, port, p_user, p_pass, p_dom, share_names, timeout)
        known = {s.strip().upper() for s in info.shares}
        info.probed_shares = [s for s in accessible if s.strip().upper() not in known]
    info.server_os = server.get("os", "")
    info.server_name = server.get("name", "")
    info.domain = server.get("domain", "")
    return info


async def audit_smb(
    host: str,
    port: int = SMB_PORT,
    *,
    user: str = "",
    password: str = "",
    domain: str = "",
    share_names: list[str] | None = None,
    timeout: float = 10.0,
) -> tuple[SmbInfo, list[SmbFinding]]:
    """SMB sunucusuna salt-okunur bağlanıp güvenlik duruşunu denetler (impacket, to_thread).

    Kimlik (``user``) boş bırakılabilir — kimliksiz denetimde de null/guest/imza/SMBv1
    bulguları üretilir. ``share_names`` verilirse (kelime listesi) listelemede görünmeyen
    ama adıyla erişilebilen 'gizli' paylaşımlar da denenir. ``(envanter, bulgular)`` döner.
    """
    info = await asyncio.to_thread(
        _probe_smb, host, port, user, password, domain, timeout, share_names
    )
    return info, evaluate_smb(info)


async def store_smb_audit(
    session: AsyncSession,
    scan_id: int,
    info: SmbInfo,
    findings: list[SmbFinding],
) -> None:
    """SMB envanteri (info) + denetim bulgularını + CIS uyumunu Finding olarak kaydeder."""
    access_bits = []
    if info.authenticated:
        access_bits.append("kimlikli")
    if info.null_session:
        access_bits.append("null")
    if info.guest_access:
        access_bits.append("guest")
    access = "/".join(access_bits) or "yok"
    shares = ", ".join(info.shares[:15]) or "—"
    guest_extra = (
        f" · guest paylaşımlar: {', '.join(info.guest_shares[:10])}"
        if info.guest_shares and not info.null_session
        else ""
    )
    await create_finding(
        session,
        scan_id,
        f"SMB envanteri: {info.summary()[:140]}",
        severity=Severity.info,
        description=(
            f"dialect={info.dialect or '—'} · imzalama="
            f"{'zorunlu' if info.signing_required else 'zorunlu değil'} · "
            f"domain={info.domain or '—'} · erişim={access} · paylaşımlar: {shares}{guest_extra}"
        ),
    )
    for finding in findings:
        await create_finding(
            session, scan_id, finding.title, severity=finding.severity, description=finding.detail
        )
    # Uyum (CIS Windows): her zaman çalışan kontrolleri geçti/kaldı eşle.
    ran_titles = list(SMB_CHECK_TITLES)
    failed = {f.title: (f.severity, f.detail) for f in findings}
    await store_compliance(session, scan_id, derive_compliance(ran_titles, failed))
