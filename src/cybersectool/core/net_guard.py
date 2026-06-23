"""Giden (egress) URL'ler için dar kapsamlı SSRF koruması — link-local / bulut-metadata bloğu.

Admin tarafından ayarlanabilen dış URL'ler (güncelleme denetimi aynası, yerel AI motoru endpoint'i)
için kullanılır. Yalnızca **asla meşru bir hedef olmayan** adresleri engeller:

- ``169.254.0.0/16`` — IPv4 link-local (metadata servisi 169.254.169.254 dahil: AWS/GCP/Azure)
- ``fe80::/10``       — IPv6 link-local
- ``fd00:ec2::254``   — AWS IMDS IPv6

**Bilinçli olarak ENGELLENMEYENLER:** RFC1918 özel ağlar (``10/8``, ``172.16/12``, ``192.168/16``)
ve hostname'ler. Yerel AI motoru (``http://ollama:11434/v1`` ya da bir özel-ağ IP'si) ve şirket-içi
güncelleme aynası bu adreslere **meşru** biçimde bağlanır — onları engellemek özelliği bozardı.
Kısacası: bu, on-prem iç-ağ aracında metadata-SSRF'i kapatan ucuz bir derinlemesine-savunma katmanı,
genel bir "iç IP yasağı" DEĞİL.

DNS çözümü YAPILMAZ (ucuz, hot-path güvenli): yalnız URL'de **literal IP** varsa kontrol edilir.
Hostname tabanlı rebinding bu katmanın kapsamı dışıdır (tarayıcı tarafı scope/IP-pin guard'ları o
işi ayrıca yapar); buradaki amaç yanlış-yapılandırılmış/kötü-niyetli admin URL'lerini hızla elemek.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

# Bu ağlara giden istek bir SSRF'tir (meşru güncelleme aynası / AI motoru burada olmaz).
_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("169.254.0.0/16"),  # IPv4 link-local + bulut metadata
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IMDS IPv6
)


def _host_to_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Host'u bir IP adresine indirir; gerçek hostname (DNS adı) ise ``None``.

    İki aşama, çünkü ``169.254.169.254`` literali yeniden-kodlamayla atlatılabilir:
    1. ``ipaddress.ip_address`` — noktalı IPv4 + tüm IPv6 formları.
    2. ``socket.inet_aton`` — sayısal IPv4 atlatma formlarını (ondalık ``2852039166``, hex
       ``0xA9FEA9FE``, oktal ``0251.0376...``, kısmi) OS'in çözeceği kanonik IPv4'e indirir.
    Böylece sayısal formlar fail-OPEN değil, doğru IP'ye çözülüp kontrol edilir; yalnız gerçek
    DNS adları ``None`` döner (onlar bu katmanın değil, scope/şema guard'larının işi).
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        return ipaddress.IPv4Address(socket.inet_aton(host))
    except (OSError, ValueError):
        return None  # gerçek hostname (DNS) — kapsam dışı


def is_blocked_url(url: str) -> bool:
    """URL host'u link-local / bulut-metadata aralığında bir IP'ye mi çözülüyor?

    Hostname (``ollama``, ``github.com``, iç-ayna) ya da RFC1918 özel IP → ``False`` (engellenmez).
    Link-local/metadata IP (her sayısal kodlamada: noktalı/ondalık/hex/oktal + IPv4-eşlemli IPv6)
    → ``True``. Gerçek DNS adı → ``False`` (DNS çözülmez; asıl koruma scope + http(s) şema).
    """
    # sondaki nokta (FQDN, ör. "169.254.169.254.") normalize edilir
    host = (urlsplit(url).hostname or "").strip().rstrip(".")
    if not host:
        return False
    ip = _host_to_ip(host)
    if ip is None:
        return False
    # IPv4-eşlemli IPv6'yı temel IPv4'e indir (``::ffff:169.254.169.254`` gibi klasik atlatma);
    # aksi halde IPv6 olarak görünüp IPv4 metadata bloğunu by-pass ederdi.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return any(ip in net for net in _BLOCKED_NETWORKS)
