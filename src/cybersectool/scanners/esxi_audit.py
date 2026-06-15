"""VMware ESXi / vCenter kimliksiz HTTPS duruş denetimi (VII-2c) — SALT-OKUNUR.

ESXi/vCenter yönetim ucunu (TCP 443) **KİMLİKSİZ** yoklar:
- erişim + ürün/sürüm tanımı (welcome page + /sdk),
- sürüm ifşası (``/sdk/vimServiceVersions.xml`` kimliksiz vim sürümünü verir),
- MOB (Managed Object Browser ``/mob/``) açıklığı (envanter keşfi + CVE-2021-21972 yüzeyi),
- TLS duruşu (zayıf protokol/şifre).

Kimlik GEREKMEZ; hedefe YAZMAZ (yalnız GET). ``eval_*``/yardımcı fonksiyonlar SAFtır
(birim testi edilebilir); ``audit_esxi_https`` ağ erişimi yapar. ``web.py``'nin
``fetch_page`` (httpx, verify=False) + ``check_tls`` (#140) yardımcıları yeniden kullanılır.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.compliance import derive_compliance, store_compliance
from cybersectool.core.findings import create_finding
from cybersectool.core.models import Severity
from cybersectool.scanners.web import PageResult, WebFinding, check_tls, fetch_page

ESXI_HTTPS_PORT = 443


class EsxiAuditError(Exception):
    """ESXi/vCenter denetimi sırasında kurtarılamayan hata (443 HTTPS ucuna hiç erişilemedi)."""


@dataclass
class EsxiInfo:
    """ESXi/vCenter kimliksiz HTTPS duruş envanteri (okunabildiği kadarıyla)."""

    host: str = ""
    port: int = ESXI_HTTPS_PORT
    reachable: bool = False  # 443'e HTTPS bağlanıldı mı?
    is_vmware: bool = False  # yanıt VMware/ESXi/vCenter olarak tanımlandı mı?
    product: str = ""  # "VMware ESXi" / "VMware vCenter" / "VMware vSphere"
    version_banner: str = ""  # /sdk'tan çıkarılan vim sürümü (varsa)
    mob_status: int | None = None  # /mob/ HTTP durumu (None = denenmedi/erişilemedi)
    tls_checked: bool = False  # check_tls GERÇEKTEN tamamlandı mı? (uyumda 'çalıştı' işareti)
    tls_weaknesses: list[str] = field(
        default_factory=list
    )  # check_tls zayıf-protokol/şifre başlıkları

    def summary(self) -> str:
        if not self.reachable:
            return f"{self.host}:{self.port} — HTTPS erişilemedi"
        what = self.product or ("VMware?" if self.is_vmware else "VMware değil")
        ver = f" {self.version_banner}" if self.version_banner else ""
        return f"{self.host}:{self.port} — {what}{ver}"


ESXI_VERSION_TITLE = "ESXi/vCenter sürüm ifşası"
ESXI_MOB_TITLE = "ESXi/vCenter MOB açık"
ESXI_TLS_TITLE = "ESXi/vCenter zayıf TLS"

# Uyum (CIS VMware) eşlemeli kontrol başlıkları (sürüm ifşası bilgi amaçlı, uyuma girmez).
ESXI_CONFIG_TITLES: tuple[str, ...] = (ESXI_MOB_TITLE, ESXI_TLS_TITLE)

# Yalnız AYIRT-EDİCİ işaretler; tek başına genel "vmware" YOK (VMware'den bahseden
# VMware-olmayan sayfada yanlış-pozitif + sahte CIS VMware uyumu üretirdi — #277 review).
# Gerçek ESXi/vCenter yine yakalanır: audit her zaman /sdk'yi çeker → yanıt "urn:vim25" içerir.
_VMWARE_MARKERS = (
    "vmware esxi",
    "vmware vcenter",
    "vmware vsphere",
    "vsphere",
    "id_eesx_welcome",
    "vim25",
)
# /mob/ "mevcut/etkin" sayılan HTTP durumları: 200=kimlikli, 401=Basic auth ister (#277 review).
# 503/404 = devre dışı; 403 = rhttpproxy yasakladı / uzaktan erişilemez (mevcut DEĞİL).
_MOB_PRESENT_STATUSES = {200, 401}


def identify_vmware(text: str) -> tuple[bool, str]:
    """Birleşik yanıt metninden (Server başlığı + gövde) VMware ürününü tanımlar.

    Döner ``(is_vmware, product)``; product: 'VMware ESXi' / 'VMware vCenter' /
    'VMware vSphere' / '' (VMware değilse).
    """
    low = text.lower()
    if not any(marker in low for marker in _VMWARE_MARKERS):
        return False, ""
    if "esxi" in low:
        return True, "VMware ESXi"
    if "vcenter" in low:
        return True, "VMware vCenter"
    return True, "VMware vSphere"


def extract_vim_version(sdk_xml: str) -> str:
    """``vimServiceVersions.xml`` gövdesinden en yüksek vim sürümünü çıkarır ('' yoksa)."""
    versions: list[str] = re.findall(r"<version>\s*([\d.]+)\s*</version>", sdk_xml)
    if not versions:
        return ""
    return str(max(versions, key=lambda v: [int(p) for p in v.split(".") if p.isdigit()]))


def eval_esxi_version_disclosure(info: EsxiInfo) -> WebFinding | None:
    """Yönetim ucu kimliksiz istemcilere kesin ürün/sürümü ifşa ediyorsa (düşük risk)."""
    if info.version_banner:
        return WebFinding(
            ESXI_VERSION_TITLE,
            Severity.low,
            f"Yönetim ucu kimliksiz istemcilere kesin sürümü ifşa ediyor "
            f"('{info.product} {info.version_banner}', /sdk/vimServiceVersions.xml). Saldırgan "
            "sürüme özgü CVE'leri (ör. vCenter CVE-2021-21972 / Log4Shell) hedefleyebilir; "
            "yönetim arayüzünü erişimi kısıtlı ayrı bir ağ segmentine alın.",
        )
    return None


def eval_esxi_mob(info: EsxiInfo) -> WebFinding | None:
    """MOB (/mob/) etkinse envanter keşfi + RCE-zincir saldırı yüzeyi (orta risk)."""
    if info.mob_status in _MOB_PRESENT_STATUSES:
        return WebFinding(
            ESXI_MOB_TITLE,
            Severity.medium,
            f"Managed Object Browser (/mob/) etkin görünüyor (HTTP {info.mob_status}) — "
            "kimliksiz/az-yetkili envanter keşfi ve bazı RCE zincirlerinin (CVE-2021-21972 "
            "bağlamı) saldırı yüzeyidir. 'Config.HostAgent.plugins.solo.enableMob=false' ile "
            "MOB'u devre dışı bırakın.",
        )
    return None


def eval_esxi_tls(info: EsxiInfo) -> WebFinding | None:
    """check_tls zayıf protokol/şifre saptadıysa tek özet bulgu (orta risk)."""
    if info.tls_weaknesses:
        return WebFinding(
            ESXI_TLS_TITLE,
            Severity.medium,
            "Zayıf TLS duruşu: "
            + "; ".join(info.tls_weaknesses[:6])
            + ". Yalnız TLS 1.2+ ve güçlü şifre paketlerini etkinleştirin; eski protokolleri "
            "(SSLv3 / TLSv1.0 / TLSv1.1) kapatın.",
        )
    return None


def evaluate_esxi(info: EsxiInfo) -> list[WebFinding]:
    """ESXi denetim envanterinden bulguları üretir (saf; ağ gerektirmez).

    Yalnız hedef VMware olarak tanımlandıysa değerlendirir — değilse (443 açık ama VMware
    değil) ESXi'ye özgü bulgu/uyum üretmez (yanlış etiketleme önlenir).
    """
    if not info.is_vmware:
        return []
    out: list[WebFinding] = []
    for verdict in (eval_esxi_version_disclosure(info), eval_esxi_mob(info), eval_esxi_tls(info)):
        if verdict is not None:
            out.append(verdict)
    return out


def ran_titles_for(info: EsxiInfo) -> list[str]:
    """Bu denetimde GERÇEKTEN tamamlanan uyum-kontrol başlıkları (#277 review).

    MOB ve TLS AYRI ağ probudur ve bağımsız başarısız olabilir; yalnız is_vmware'e bakıp
    ikisini de 'çalıştı' saymak, başarısız bir probu uyumda yanlış 'pass' yapardı. Her başlık
    yalnız ilgili prob gerçekten tamamlandıysa raporlanır (aksi halde 'değerlendirilmedi').
    """
    if not info.is_vmware:
        return []
    titles: list[str] = []
    if info.mob_status is not None:  # /mob/ probu erişip bir durum aldı
        titles.append(ESXI_MOB_TITLE)
    if info.tls_checked:  # check_tls gerçekten tamamlandı
        titles.append(ESXI_TLS_TITLE)
    return titles


# --- Saf yardımcılar ---


def _combine(page: PageResult | None) -> str:
    """Bir yanıtın Server başlığı + gövdesini tanımlama için tek dizede birleştirir."""
    if page is None:
        return ""
    return f"{page.headers.get('server', '')} {page.body}"


def _is_weak_tls_finding(finding: WebFinding) -> bool:
    """check_tls bulgusu zayıf protokol/şifre mi? (beklenen self-signed/expired hariç)."""
    title = finding.title.lower()
    return "zayıf" in title or "etkin" in title


# --- Ağ erişimi (httpx — web.py yardımcıları) ---


async def audit_esxi_https(
    host: str, port: int = ESXI_HTTPS_PORT
) -> tuple[EsxiInfo, list[WebFinding]]:
    """ESXi/vCenter 443 ucunu kimliksiz yoklayıp duruşunu denetler (YAZMAZ, yalnız GET).

    443 HTTPS'e hiç erişilemezse ``EsxiAuditError``. VMware tanımlanırsa MOB + TLS + sürüm
    ifşası denetlenir; tanımlanmazsa yalnız 'VMware değil' bilgisi döner. ``(envanter, bulgular)``.
    """
    info = EsxiInfo(host=host, port=port)
    base = f"https://{host}:{port}"
    home = await fetch_page(f"{base}/")
    sdk = await fetch_page(f"{base}/sdk/vimServiceVersions.xml")
    if home is None and sdk is None:
        raise EsxiAuditError(f"{host}:{port} HTTPS yönetim ucuna erişilemedi")
    info.reachable = True
    info.is_vmware, info.product = identify_vmware(f"{_combine(home)} {_combine(sdk)}")
    if sdk is not None and sdk.status == 200:
        info.version_banner = extract_vim_version(sdk.body)
    if info.is_vmware:
        mob = await fetch_page(f"{base}/mob/")
        info.mob_status = mob.status if mob is not None else None
        with contextlib.suppress(Exception):
            tls = await asyncio.to_thread(check_tls, host, port)
            info.tls_weaknesses = [f.title for f in tls if _is_weak_tls_finding(f)]
            info.tls_checked = True  # check_tls istisna atmadan tamamlandı (uyumda 'çalıştı')
    return info, evaluate_esxi(info)


async def store_esxi_audit(
    session: AsyncSession,
    scan_id: int,
    info: EsxiInfo,
    findings: list[WebFinding],
) -> None:
    """ESXi envanteri (info) + denetim bulgularını + CIS VMware uyumunu Finding olarak kaydeder."""
    mob = info.mob_status if info.mob_status is not None else "—"
    await create_finding(
        session,
        scan_id,
        f"ESXi/vCenter envanteri: {info.summary()[:140]}",
        severity=Severity.info,
        description=(
            f"erişim={'var' if info.reachable else 'yok'} · "
            f"VMware={'evet' if info.is_vmware else 'hayır'} · ürün: {info.product or '—'} · "
            f"sürüm: {info.version_banner or '—'} · MOB: {mob} · "
            f"TLS-zayıflık: {len(info.tls_weaknesses)}"
        ),
    )
    for finding in findings:
        await create_finding(
            session,
            scan_id,
            finding.title,
            severity=finding.severity,
            description=finding.description,
        )
    # Uyum (CIS VMware): bu denetimde çalışan kontrolleri (MOB + TLS) geçti/kaldı eşle.
    failed = {
        f.title: (f.severity, f.description or "")
        for f in findings
        if f.title in ESXI_CONFIG_TITLES
    }
    await store_compliance(session, scan_id, derive_compliance(ran_titles_for(info), failed))
