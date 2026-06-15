"""Kimliksiz (unauthenticated) exposed servis denetimleri (#142) — SALT-OKUNUR.

Açık portlarda kimlik-doğrulamasız erişime izin veren yüksek-değerli servisleri tespit eder
(Redis, Elasticsearch). Yalnız OKUR (Redis ``INFO`` / Elasticsearch ``GET /``) — hiçbir şey
değiştirmez/silmez. Bulgu üretir. Ağ taramasında, ilgili port açık bulunan hostlarda çalışır.

Parse fonksiyonları SAF (ağsız, birim testi edilebilir); ``check_*`` ağ erişimi yapar.
MongoDB/Docker-API/Kubernetes/IPMI gibi ikili-protokol gerektirenler ayrı follow-up.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass

import httpx

from cybersectool.core.models import Severity

REDIS_PORTS = (6379,)
ELASTIC_PORTS = (9200,)
# COV-1b (#148): ek kimliksiz açık-servisler.
DOCKER_PORTS = (2375,)  # Docker Engine API (şifresiz TCP) — kimliksizse host'ta tam RCE
K8S_KUBELET_PORTS = (10250,)  # kubelet API — anonim erişim = pod exec/RCE (kritik)
K8S_API_PORTS = (8080, 6443)  # kube-apiserver (8080 eski şifresiz; 6443 anonim erişim)
FTP_PORTS = (21,)


@dataclass
class ExposedFinding:
    """Kimliksiz erişilebilir bir servis bulgusu."""

    title: str
    severity: Severity
    description: str | None = None


def parse_redis_unauth(response: str) -> bool:
    """Redis INFO yanıtı KİMLİKSİZ erişimi gösteriyor mu? (SAF).

    ``-NOAUTH``/``-ERR ... auth`` → kimlik doğrulama AÇIK (güvenli, False). INFO çıktısı
    (``redis_version`` / ``# Server``) ya da ``+`` ile başlayan basit yanıt → kimliksiz okundu.
    """
    r = response.strip()
    if not r:
        return False
    if r.startswith("-NOAUTH") or "NOAUTH Authentication required" in r:
        return False
    if r.startswith("-ERR") and "auth" in r.lower():
        return False
    return "redis_version" in r or "# Server" in r or r.startswith("+")


def parse_elastic_unauth(status: int, body: str) -> bool:
    """Elasticsearch kök (``GET /``) yanıtı kimliksiz erişimi gösteriyor mu? (SAF)."""
    if status != 200:
        return False
    return '"cluster_name"' in body or '"lucene_version"' in body or '"tagline"' in body


async def check_redis(host: str, port: int = 6379, *, timeout: float = 4.0) -> list[ExposedFinding]:
    """Redis'e kimliksiz ``INFO`` gönderir; yanıt verirse KRİTİK bulgu (salt-okunur)."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, TimeoutError):
        return []
    try:
        writer.write(b"INFO\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout)
    except (OSError, TimeoutError):
        return []
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    if parse_redis_unauth(data.decode("utf-8", "ignore")):
        return [
            ExposedFinding(
                f"Kimlik doğrulamasız Redis ({host}:{port})",
                Severity.critical,
                "Redis kimlik doğrulaması OLMADAN komut kabul ediyor (INFO yanıt verdi). "
                "Saldırgan tüm veriyi okuyabilir/silebilir, hatta CONFIG SET ile RCE elde "
                "edebilir. `requirepass` ayarlayın ve servisi dışa kapatın.",
            )
        ]
    return []


async def check_elasticsearch(
    host: str, port: int = 9200, *, timeout: float = 6.0
) -> list[ExposedFinding]:
    """Elasticsearch köküne kimliksiz ``GET /`` yapar; cluster bilgisi açıksa YÜKSEK bulgu."""
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.get(f"http://{host}:{port}/")
    except httpx.HTTPError:
        return []
    if parse_elastic_unauth(resp.status_code, resp.text):
        return [
            ExposedFinding(
                f"Kimlik doğrulamasız Elasticsearch ({host}:{port})",
                Severity.high,
                "Elasticsearch kimlik doğrulaması OLMADAN yanıt veriyor (cluster bilgisi açık). "
                "Tüm indeksler okunabilir/silinebilir. Güvenlik (X-Pack) + kimlik doğrulamayı "
                "açın ve servisi dışa kapatın.",
            )
        ]
    return []


def parse_docker_unauth(status: int, body: str) -> bool:
    """Docker Engine API ``/version`` yanıtı kimliksiz erişimi gösteriyor mu? (SAF).

    Kimliksiz açık bir Docker daemon ``/version``'a 200 + ``ApiVersion``/``GoVersion`` alanlı
    JSON döner. Kimlik/TLS gerekiyorsa 401/403 ya da bağlantı reddi olur.
    """
    if status != 200:
        return False
    return '"ApiVersion"' in body and ('"GoVersion"' in body or '"Version"' in body)


def parse_kubelet_unauth(status: int, body: str) -> bool:
    """kubelet ``/pods`` yanıtı ANONİM erişimi gösteriyor mu? (SAF).

    Anonim-auth açık bir kubelet ``/pods``'a 200 + ``"kind":"PodList"`` döner (pod listesi).
    Bu, ``/exec`` ile konteyner içinde komut çalıştırmaya kadar gidebilen kritik bir ifşadır.
    """
    if status != 200:
        return False
    return '"kind"' in body and "PodList" in body


def parse_k8s_api_unauth(status: int, body: str) -> bool:
    """kube-apiserver ``/version`` yanıtı kimliksiz erişimi gösteriyor mu? (SAF)."""
    if status != 200:
        return False
    return '"gitVersion"' in body and ('"major"' in body or '"buildDate"' in body)


def parse_ftp_anonymous(login_response: str) -> bool:
    """FTP ``PASS`` yanıtı anonim girişi KABUL etti mi (kod 230)? (SAF).

    230 = "User logged in" (anonim açık). 530/421 = reddedildi/erişilemez. Yanıt satırlarının
    başındaki 3 haneli koda bakılır (banner/çok-satırlı yanıtlara dayanıklı).
    """
    for line in login_response.splitlines():
        code = line[:3]
        if code == "230":
            return True
        if code in ("530", "421"):
            return False
    return False


async def check_docker(
    host: str, port: int = 2375, *, timeout: float = 6.0
) -> list[ExposedFinding]:
    """Docker Engine API'ye kimliksiz ``GET /version`` yapar; yanıt verirse KRİTİK (salt-okunur)."""
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.get(f"http://{host}:{port}/version")
    except httpx.HTTPError:
        return []
    if parse_docker_unauth(resp.status_code, resp.text):
        return [
            ExposedFinding(
                f"Kimlik doğrulamasız Docker API ({host}:{port})",
                Severity.critical,
                "Docker Engine API kimlik doğrulaması/TLS OLMADAN dışa açık (/version yanıt "
                "verdi). Saldırgan konteyner oluşturup host kök dosya sistemini bağlayarak "
                "SUNUCUDA tam yetkiyle (root) kod çalıştırabilir. API'yi dışa kapatın; TLS + "
                "istemci sertifikası zorunlu kılın (yalnız yerel soket kullanın).",
            )
        ]
    return []


async def check_kubelet(
    host: str, port: int = 10250, *, timeout: float = 6.0
) -> list[ExposedFinding]:
    """kubelet'e anonim ``GET /pods`` yapar; pod listesi dönerse KRİTİK (salt-okunur)."""
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.get(f"https://{host}:{port}/pods")
    except httpx.HTTPError:
        return []
    if parse_kubelet_unauth(resp.status_code, resp.text):
        return [
            ExposedFinding(
                f"Anonim kubelet erişimi ({host}:{port})",
                Severity.critical,
                "kubelet API anonim erişime açık (/pods pod listesini döndü). Saldırgan "
                "/exec ile çalışan konteynerlerde komut çalıştırıp node'u/cluster'ı ele "
                "geçirebilir. kubelet'te anonim kimlik doğrulamayı kapatın "
                "(--anonymous-auth=false) ve yetkilendirmeyi Webhook'a alın.",
            )
        ]
    return []


async def check_k8s_api(host: str, port: int, *, timeout: float = 6.0) -> list[ExposedFinding]:
    """kube-apiserver'a kimliksiz ``GET /version`` yapar; yanıt verirse YÜKSEK (salt-okunur).

    8080 (eski insecure-port) düz HTTP; 6443 HTTPS (anonim erişim açıksa yanıt verir).
    """
    scheme = "http" if port == 8080 else "https"
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.get(f"{scheme}://{host}:{port}/version")
    except httpx.HTTPError:
        return []
    if parse_k8s_api_unauth(resp.status_code, resp.text):
        return [
            ExposedFinding(
                f"Kimlik doğrulamasız Kubernetes API ({host}:{port})",
                Severity.high,
                "kube-apiserver kimlik doğrulaması olmadan sürüm/bilgi sızdırıyor (/version "
                "yanıt verdi). Anonim erişim açıksa cluster kaynakları okunabilir/değiştirilir. "
                "Anonim erişimi kapatın (--anonymous-auth=false), eski insecure-port'u (8080) "
                "devre dışı bırakın, RBAC uygulayın.",
            )
        ]
    return []


async def check_ftp_anonymous(
    host: str, port: int = 21, *, timeout: float = 5.0
) -> list[ExposedFinding]:
    """Anonim FTP girişini dener (USER anonymous); kabul edilirse YÜKSEK bulgu (salt-okunur).

    Anonim, herkese AÇIK olması amaçlanan standart bir hesaptır → tek deneme = ifşa kontrolü
    (brute-force DEĞİL). Giriş kabul edilse bile dosya listelenmez/indirilmez; hemen QUIT edilir.
    """
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, TimeoutError):
        return []
    try:
        await asyncio.wait_for(reader.read(512), timeout)  # 220 banner
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(512), timeout)  # 331 parola iste
        writer.write(b"PASS anonymous@example.com\r\n")
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(512), timeout)  # 230 (kabul) / 530 (ret)
    except (OSError, TimeoutError):
        return []
    finally:
        with contextlib.suppress(Exception):
            writer.write(b"QUIT\r\n")
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    if parse_ftp_anonymous(resp.decode("utf-8", "ignore")):
        return [
            ExposedFinding(
                f"Anonim FTP erişimi ({host}:{port})",
                Severity.high,
                "Sunucu anonim (anonymous) FTP girişini kabul ediyor. Kimlik bilgisi olmadan "
                "dosyalar okunabilir (ve yazma açıksa yüklenebilir) — veri sızıntısı/içerik "
                "tahrifatı riski. Anonim erişimi kapatın ya da yalnız gerekli salt-okunur "
                "dizinle sınırlandırın.",
            )
        ]
    return []


async def scan_exposed_services(host: str, open_ports: set[int]) -> list[ExposedFinding]:
    """Açık portlara göre kimliksiz servis denetimlerini çalıştırır (salt-okunur, best-effort)."""
    findings: list[ExposedFinding] = []
    for p in REDIS_PORTS:
        if p in open_ports:
            with contextlib.suppress(Exception):
                findings.extend(await check_redis(host, p))
    for p in ELASTIC_PORTS:
        if p in open_ports:
            with contextlib.suppress(Exception):
                findings.extend(await check_elasticsearch(host, p))
    for p in DOCKER_PORTS:  # COV-1b
        if p in open_ports:
            with contextlib.suppress(Exception):
                findings.extend(await check_docker(host, p))
    for p in K8S_KUBELET_PORTS:
        if p in open_ports:
            with contextlib.suppress(Exception):
                findings.extend(await check_kubelet(host, p))
    for p in K8S_API_PORTS:
        if p in open_ports:
            with contextlib.suppress(Exception):
                findings.extend(await check_k8s_api(host, p))
    for p in FTP_PORTS:
        if p in open_ports:
            with contextlib.suppress(Exception):
                findings.extend(await check_ftp_anonymous(host, p))
    return findings
