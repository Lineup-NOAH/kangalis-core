"""LDAP / Active Directory güvenlik denetimi (IX-7b) — SALT-OKUNUR.

ldap3 ile bir LDAP/AD sunucusuna bağlanıp güvenlik duruşunu denetler: anonim bind,
anonim dizin okuma (enumerasyon), şifreli taşıma (LDAPS/StartTLS) eksikliği ve
best-effort olarak AD parola politikası (asgari uzunluk, hesap kilitleme eşiği).
Hedefe YAZMAZ — yalnız bind denemesi + rootDSE/dizin OKUMA. ``eval_*`` fonksiyonları
SAFtır (birim testi edilebilir); ``audit_ldap`` ağ erişimi yapar (gerçek OpenLDAP'a
karşı doğrulanır).

Bu, Ayarlar'daki LDAP **kimlik doğrulama entegrasyonundan** (core/ldap.py) AYRI bir
DENETİMDİR. Kimlik OPSİYONELDİR: kimliksiz de anonim bind/okuma + şifreleme tespit edilir.
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

LDAP_PORT = 389
LDAPS_PORT = 636
STARTTLS_OID = "1.3.6.1.4.1.1466.20037"  # RFC 4511 StartTLS uzantısı


class LdapAuditError(Exception):
    """LDAP denetimi sırasında kurtarılamayan hata (hedefe hiç erişilemedi)."""


@dataclass
class LdapFinding:
    title: str
    severity: Severity
    detail: str


@dataclass
class LdapInfo:
    """LDAP denetim sonucu envanteri (okunabildiği/denenebildiği kadarıyla)."""

    server_uri: str = ""
    vendor: str = ""
    naming_contexts: list[str] = field(default_factory=list)
    rootdse_read: bool = False  # rootDSE (kimliksiz) okunabildi mi?
    anonymous_bind: bool = False  # kimliksiz bind başarılı mı?
    anonymous_search: bool = False  # kimliksiz dizin girdileri okunabiliyor mu?
    anon_entry_sample: list[str] = field(default_factory=list)  # örnek okunabilen DN'ler
    ldaps_available: bool = False  # 636/LDAPS TLS el sıkışması mümkün mü?
    starttls_supported: bool = False  # rootDSE StartTLS uzantısını ilan ediyor mu?
    authenticated: bool = False  # verilen kimlikle bind başarılı mı?
    # AD parola politikası (best-effort — yalnız okunabildiğinde dolar)
    min_password_length: int | None = None
    lockout_threshold: int | None = None

    def summary(self) -> str:
        """Kısa tek satır özet (sunucu — vendor)."""
        parts = [p for p in (self.server_uri, self.vendor.strip()) if p]
        return " — ".join(parts) or "bilinmiyor"


# Çekirdek (her zaman çalışan) kontrollerin kanonik başlıkları. Parola politikası
# kontrolleri yalnız ilgili öznitelik okunabildiğinde çalışır (ran_titles dinamik).
LDAP_CORE_TITLES: tuple[str, ...] = (
    "LDAP anonim bind",
    "LDAP anonim dizin okuma",
    "LDAP şifreleme",
)
LDAP_POLICY_TITLES: tuple[str, ...] = (
    "LDAP parola uzunluğu",
    "LDAP hesap kilitleme",
)


def eval_ldap_anonymous_bind(allowed: bool) -> LdapFinding | None:
    """Anonim bind açıksa kimliksiz dizin erişimi (yüksek risk)."""
    if allowed:
        return LdapFinding(
            "LDAP anonim bind",
            Severity.high,
            "Sunucu anonim (kimliksiz) bind'e izin veriyor — kimlik bilgisi olmadan dizine "
            "bağlanılabiliyor. Anonim bind'i kapatın (OpenLDAP: 'disallow bind_anon'; AD: "
            "anonim erişimi kısıtlayın).",
        )
    return None


def eval_ldap_anonymous_search(allowed: bool) -> LdapFinding | None:
    """Anonim olarak dizin girdileri okunabiliyorsa bilgi sızıntısı (yüksek risk)."""
    if allowed:
        return LdapFinding(
            "LDAP anonim dizin okuma",
            Severity.high,
            "Dizin girdileri (kullanıcı/grup/OU) kimlik bilgisi olmadan okunabiliyor — "
            "kullanıcı sıralama (enumeration) ve bilgi toplama mümkün. Anonim okumayı "
            "kısıtlayın (ACL ile yalnız kimlikli erişime izin verin).",
        )
    return None


def eval_ldap_encryption(ldaps_available: bool, starttls_supported: bool) -> LdapFinding | None:
    """Ne LDAPS ne de StartTLS varsa kimlik/veri düz metin gider (orta risk)."""
    if not ldaps_available and not starttls_supported:
        return LdapFinding(
            "LDAP şifreleme",
            Severity.medium,
            "Sunucu şifreli taşıma sunmuyor (636/LDAPS kapalı ve StartTLS ilan edilmiyor) — "
            "bind parolaları ve dizin verisi ağ üzerinde düz metin gider. LDAPS'i etkinleştirin "
            "veya StartTLS'i zorunlu kılın.",
        )
    return None


def eval_ldap_min_password_length(min_len: int) -> LdapFinding | None:
    """AD asgari parola uzunluğu 8'in altındaysa zayıf parola politikası (orta risk)."""
    if min_len < 8:
        return LdapFinding(
            "LDAP parola uzunluğu",
            Severity.medium,
            f"Asgari parola uzunluğu {min_len} — zayıf. En az 8 (tercihen 14) karakter "
            "zorunlu kılınmalı (AD: Default Domain Policy 'Minimum password length').",
        )
    return None


def eval_ldap_lockout(threshold: int) -> LdapFinding | None:
    """AD hesap kilitleme eşiği 0 ise kaba-kuvvet koruması yok (orta risk)."""
    if threshold == 0:
        return LdapFinding(
            "LDAP hesap kilitleme",
            Severity.medium,
            "Hesap kilitleme eşiği 0 (kilitleme yok) — parola kaba-kuvvet denemelerine karşı "
            "koruma yok. Bir kilitleme eşiği tanımlayın (ör. 5–10 başarısız deneme).",
        )
    return None


def evaluate_ldap(info: LdapInfo) -> list[LdapFinding]:
    """LDAP denetim envanterinden bulguları üretir (saf; ağ gerektirmez)."""
    findings: list[LdapFinding] = []
    for candidate in (
        eval_ldap_anonymous_bind(info.anonymous_bind),
        eval_ldap_anonymous_search(info.anonymous_search),
    ):
        if candidate is not None:
            findings.append(candidate)
    # Şifreleme kararı yalnız rootDSE okunabildiğinde güvenilir (StartTLS oradan öğrenilir);
    # aksi halde 'BİLİNMİYOR' iken FP üretmemek için atlanır (ran_titles_for ile tutarlı).
    if info.rootdse_read:
        enc = eval_ldap_encryption(info.ldaps_available, info.starttls_supported)
        if enc is not None:
            findings.append(enc)
    if info.min_password_length is not None:
        verdict = eval_ldap_min_password_length(info.min_password_length)
        if verdict is not None:
            findings.append(verdict)
    if info.lockout_threshold is not None:
        verdict = eval_ldap_lockout(info.lockout_threshold)
        if verdict is not None:
            findings.append(verdict)
    return findings


def ran_titles_for(info: LdapInfo) -> list[str]:
    """Bu denetimde GERÇEKTEN çalışan kontrol başlıkları (uyum eşlemesi için)."""
    titles = list(LDAP_CORE_TITLES)
    if not info.rootdse_read:
        # rootDSE okunamadıysa şifreleme kararı güvenilir değil → kontrolü dahil etme.
        titles.remove("LDAP şifreleme")
    if info.min_password_length is not None:
        titles.append("LDAP parola uzunluğu")
    if info.lockout_threshold is not None:
        titles.append("LDAP hesap kilitleme")
    return titles


# --- Ağ erişimi (ldap3) — senkron yardımcılar to_thread içinde çağrılır ---


def _entry_values(entry: Any, attr: str) -> list[str]:
    """ldap3 girdisinden bir özniteliğin tüm değerlerini güvenle okur."""
    try:
        values = entry[attr].values
    except Exception:
        return []
    return [str(v) for v in values] if values else []


def _first(entry: Any, attr: str) -> str:
    values = _entry_values(entry, attr)
    return values[0] if values else ""


def _read_rootdse(conn: Any, info: LdapInfo) -> None:
    """Kimliksiz rootDSE okuması (namingContexts/StartTLS/vendor)."""
    import ldap3

    with contextlib.suppress(Exception):
        conn.search(
            "",
            "(objectClass=*)",
            search_scope=ldap3.BASE,
            attributes=["namingContexts", "supportedExtension", "vendorName", "vendorVersion"],
        )
        if not conn.entries:
            return
        entry = conn.entries[0]
        info.rootdse_read = True
        info.naming_contexts = _entry_values(entry, "namingContexts")
        info.starttls_supported = STARTTLS_OID in _entry_values(entry, "supportedExtension")
        vendor = " ".join(
            p for p in (_first(entry, "vendorName"), _first(entry, "vendorVersion")) if p
        )
        info.vendor = vendor


def _anon_search(conn: Any, info: LdapInfo) -> None:
    """Anonim olarak ilk naming context altında girdi okunabiliyor mu (enumerasyon)?"""
    import ldap3

    base = info.naming_contexts[0] if info.naming_contexts else ""
    if not base:
        return
    with contextlib.suppress(Exception):
        conn.search(
            base, "(objectClass=*)", search_scope=ldap3.SUBTREE, size_limit=5, attributes=["cn"]
        )
        dns = [str(e.entry_dn) for e in conn.entries]
        extra = [d for d in dns if d.lower() != base.lower()]
        info.anonymous_search = len(extra) > 0
        info.anon_entry_sample = (extra or dns)[:5]


def _read_ad_policy(conn: Any, info: LdapInfo) -> None:
    """AD parola politikası özniteliklerini (best-effort) okur; yoksa sessizce atlar."""
    import ldap3

    for base in info.naming_contexts:
        with contextlib.suppress(Exception):
            conn.search(
                base,
                "(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=["minPwdLength", "lockoutThreshold"],
            )
            if not conn.entries:
                continue
            entry = conn.entries[0]
            mpl, lt = _first(entry, "minPwdLength"), _first(entry, "lockoutThreshold")
            if mpl.isdigit():
                info.min_password_length = int(mpl)
            if lt.isdigit():
                info.lockout_threshold = int(lt)
            if info.min_password_length is not None or info.lockout_threshold is not None:
                return


def _ldaps_available(host: str, timeout: float) -> bool:
    """636/LDAPS portunda TLS el sıkışması mümkün mü (sertifika doğrulanmaz)?"""
    import ssl

    import ldap3

    with contextlib.suppress(Exception):
        server = ldap3.Server(
            f"ldaps://{host}:{LDAPS_PORT}",
            use_ssl=True,
            connect_timeout=timeout,
            tls=ldap3.Tls(validate=ssl.CERT_NONE),
        )
        conn = ldap3.Connection(server)
        conn.open()  # soket + TLS el sıkışması
        with contextlib.suppress(Exception):
            conn.unbind()
        return True
    return False


def _probe_ldap(host: str, port: int, user: str, password: str, timeout: float) -> LdapInfo:
    """LDAP sunucusunu salt-okunur denetler (senkron; to_thread içinde çağrılır)."""
    import ldap3

    uri = f"ldap://{host}:{port}"
    info = LdapInfo(server_uri=uri)
    server = ldap3.Server(uri, get_info=ldap3.NONE, connect_timeout=timeout)
    # Erişilebilirlik: soketi aç (başarısızsa LdapAuditError).
    try:
        probe = ldap3.Connection(server)
        probe.open()
    except Exception as exc:
        raise LdapAuditError(f"LDAP bağlantısı kurulamadı: {exc}") from exc
    # rootDSE'yi (kimliksiz) oku — namingContexts + StartTLS + vendor.
    _read_rootdse(probe, info)
    with contextlib.suppress(Exception):
        probe.unbind()
    # Anonim bind + anonim dizin okuma.
    with contextlib.suppress(Exception):
        anon = ldap3.Connection(server, read_only=True)
        if anon.bind():
            info.anonymous_bind = True
            if not info.naming_contexts:
                _read_rootdse(anon, info)
            _anon_search(anon, info)
        with contextlib.suppress(Exception):
            anon.unbind()
    # LDAPS (636) erişilebilirliği.
    info.ldaps_available = _ldaps_available(host, timeout)
    # Kimlikli (verilmişse) — AD parola politikası best-effort.
    if user:
        with contextlib.suppress(Exception):
            authed = ldap3.Connection(server, user=user, password=password, read_only=True)
            if authed.bind():
                info.authenticated = True
                if not info.naming_contexts:
                    _read_rootdse(authed, info)
                _read_ad_policy(authed, info)
            with contextlib.suppress(Exception):
                authed.unbind()
    return info


async def audit_ldap(
    host: str,
    port: int = LDAP_PORT,
    *,
    user: str = "",
    password: str = "",
    timeout: float = 10.0,
) -> tuple[LdapInfo, list[LdapFinding]]:
    """LDAP/AD sunucusuna salt-okunur bağlanıp güvenlik duruşunu denetler (ldap3, to_thread).

    Kimlik (``user``) boş bırakılabilir — kimliksiz denetimde de anonim bind/okuma ve
    şifreleme bulguları üretilir. ``(envanter, bulgular)`` döner.
    """
    info = await asyncio.to_thread(_probe_ldap, host, port, user, password, timeout)
    return info, evaluate_ldap(info)


async def store_ldap_audit(
    session: AsyncSession,
    scan_id: int,
    info: LdapInfo,
    findings: list[LdapFinding],
) -> None:
    """LDAP envanteri (info) + denetim bulgularını + CIS uyumunu Finding olarak kaydeder."""
    access_bits = []
    if info.authenticated:
        access_bits.append("kimlikli")
    if info.anonymous_bind:
        access_bits.append("anonim")
    access = "/".join(access_bits) or "yok"
    transport = (
        "LDAPS" if info.ldaps_available else ("StartTLS" if info.starttls_supported else "düz")
    )
    sample = ", ".join(info.anon_entry_sample[:5]) or "—"
    await create_finding(
        session,
        scan_id,
        f"LDAP envanteri: {info.summary()[:140]}",
        severity=Severity.info,
        description=(
            f"naming context: {', '.join(info.naming_contexts[:3]) or '—'} · taşıma={transport} · "
            f"erişim={access} · anonim örnek: {sample}"
        ),
    )
    for finding in findings:
        await create_finding(
            session, scan_id, finding.title, severity=finding.severity, description=finding.detail
        )
    # Uyum (CIS LDAP): bu denetimde gerçekten çalışan kontrolleri geçti/kaldı eşle.
    failed = {f.title: (f.severity, f.detail) for f in findings}
    await store_compliance(session, scan_id, derive_compliance(ran_titles_for(info), failed))
