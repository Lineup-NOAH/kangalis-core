"""Tarama yoğunluğu (mod) politikası: güvenli / agresif / sömürme + güvenlik kilidi.

Üç mod vardır (agresif artık SÖMÜRMEZ; sömürü ayrı ``exploit`` moduna taşındı — SR-1):

- **Güvenli (``safe``)** — varsayılan. Açık port + servis/versiyon bilgisini toplar, bundan
  CVE çıkarımı yapar. Ek olarak nmap'in **default** NSE script kümesini (``-sC``) çalıştırır:
  banner/başlık/TLS sertifikası/SMB OS keşfi gibi **bilgi toplayıcı** scriptler — daha zengin
  tespit sağlar ama ``vuln``/``exploit``/``brute`` gibi müdahaleci scriptleri **çalıştırmaz**.
- **Agresif (``aggressive``)** — nmap NSE ``vuln``/``exploit``/``discovery`` scriptlerini ve OS
  parmak izini çalıştırır. Hedef servislerle aktif etkileşime girer; bir servisi kesintiye
  uğratabilir ya da iz/log bırakabilir.

Agresif mod **çift kilitlidir** (güvenlik gerekçesi: müdahaleci taramalar bir ürüne zarar
verebilir — ör. servis çökmesi, beklenmedik yan etki):

1. Global ayar ``ALLOW_AGGRESSIVE_SCANS`` açık olmalı (varsayılan **kapalı**).
2. Yalnızca ``admin`` rolü başlatabilir (web/api katmanında uygulanır).

DoS ve brute kategorisindeki scriptler bilerek hariç tutulur (``not dos and not brute``) —
amaç zafiyeti doğrulamak; hedefi düşürmek ya da hesapları kilitlemek değil.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from cybersectool.core.models import ScanMode, ScanType

# Mod -> nmap seçenek dizesi.
# -sC (= --script=default): nmap'in "default" NSE kümesi — banner/başlık/TLS/SMB OS keşfi
# gibi BİLGİ TOPLAYICI scriptler. Tespit zenginliğini artırır; default kümesi tasarımı gereği
# müdahaleci (vuln/exploit/brute) scriptleri içermez → güvenli mod güvenliğini bozmaz.
SAFE_NMAP_OPTIONS = "-sV -sC -T4"
# -A: OS/sürüm/script/traceroute. --script kategorileri: zafiyet + exploit + keşif (discovery).
# Hariç tutulanlar: DoS (hedefi düşürür) ve brute (hesap kilitler / çok yavaş) — bilerek dışlanır.
_AGGRESSIVE_NSE = '"(vuln or exploit or discovery) and not dos and not brute"'
AGGRESSIVE_NMAP_OPTIONS = f"-sV -T4 -A --script {_AGGRESSIVE_NSE}"
# Ping taraması (host keşfi): port taraması YOK (-sn) — yalnız "host ayakta mı".
# Yalnız GERÇEK-POZİTİF sinyaller kullanılır (düşük FP): ICMP echo + timestamp (-PE/-PP)
# ve yaygın cihaz portlarına TCP SYN (-PS). TCP ACK (-PA) BİLEREK kullanılmaz:
# NAT/stateful firewall, var olmayan IP'lere giden ACK'lere RST döndürerek nmap'in
# her hostu "ayakta" sanmasına yol açar (klasik yanlış-pozitif kaynağı).
# --max-rtt-timeout: NAT/router var olmayan IP'lere ÇOK GECİKMELİ (ör. 21sn) sahte ICMP
# yanıtı dönebiliyor; gerçek LAN host'u <100ms yanıt verir. RTT'yi 1.5sn'ye sınırlamak bu
# yavaş sahte-pozitifleri eler, gerçek hostları korur. Retry sayısı DÜŞÜRÜLMEZ (-T4
# varsayılanı) — paket kaybı altında gerçek hostları kaçırmamak için. Çok-bloklu hedefler
# ping görevinde blok-blok taranır (tasks/ping_scan) → büyük var-olmayan aralıklar gerçek
# aralığın probelarını boğmaz (NAT/WSL2'de güvenilir).
DISCOVERY_NMAP_OPTIONS = (
    "-sn -PE -PP -PS22,80,135,139,443,445,3389,8080 --max-rtt-timeout 1500ms -T4"
)

# UDP servis keşfi (#143): hedeflenmiş yaygın UDP servis portları (DNS/DHCP/TFTP/NTP/NetBIOS/
# SNMP/ISAKMP/RIP/IPMI/SSDP/mDNS…). nmap -sU YAVAŞ olduğundan tüm portlar değil, yüksek-değerli
# küçük bir set taranır → SNMP/DNS/NTP/IPMI gibi UDP servisleri otomatik keşifte görünür.
UDP_TOP_PORTS = "53,67,69,123,137,138,161,162,500,514,520,623,1434,1900,4500,5353"
# UDP ile BİRLİKTE taranınca kullanılan TCP portları. nmap birleşik -p sözdizimi (T:..,U:..)
# saf TCP'deki "top-1000"i ifade EDEMEDİĞİNDEN, düşük aralık + önemli yüksek servis portları
# açıkça listelenir (8080/3306/3389/5432/6379/9200/27017… kaçmasın).
_UDP_COMBINED_TCP_PORTS = (
    "1-1024,1433,1521,2049,2375,3306,3389,5432,5601,5900,5985,6379,7001,"
    "8000,8008,8080,8081,8443,8888,9000,9092,9200,9300,11211,27017"
)


# --- Tarama hızı (nmap paralellik) ----------------------------------------------------------
# nmap AĞ-bound'dur (paket gönder → cevap bekle); hızı RAM değil PARALELLİK belirler. Boştaki
# CPU/soket/ağ kaynağını kullanmak = aynı anda daha çok host/prob taramak. Bu bayraklar zaten
# var olan ``-T4`` zamanlamasına EKLENİR (``-T`` çakışması olmadan):
#   --min-hostgroup N   : en az N hostu paralel grupla (çok-hostlu /24 taramada büyük kazanç).
#   --min-parallelism N : en az N probu aynı anda uçur (tek host port taramasını da hızlandırır).
#   --min-rate N        : saniyede en az N paket gönder (en agresif; paket-kaybı riskini artırır).
# Boş dize = ek bayrak yok (saf -T4, en doğru). Bilinmeyen/boş değer güvenli "fast"a düşer.
#
# "slow" (Uzak / VPN) — YÜKSEK GECİKMELİ / KAYIPLI hatlar için (ör. müşteri ağını VPN'den
# taramak). LAN hızları (fast/insane) tek uzak hedefe onlarca paralel probe atınca VPN'i boğar
# → probe'lar düşer/reset olur → nmap servis-sürümünü okuyamadan "tcpwrapped" der (port açık ama
# sürüm boş). Bu profil: paralellik şişirmesi YOK + ``-T2`` (nazik zamanlama, gecikmeye toleranslı)
# + ``--max-retries 4`` (kayıpta tekrar dene) + ``--host-timeout`` (takılı kalma). ``-T2``, base
# şablondaki ``-T4``'ün SONUNA eklenir; nmap birden çok ``-T`` verilince SONUNCUYU kullanır →
# ``-T2`` etkin olur (canlı doğrulandı: VPN'de tcpwrapped → gerçek sürüm).
SCAN_SPEEDS: tuple[str, ...] = ("normal", "fast", "insane", "slow")
DEFAULT_SCAN_SPEED = "fast"
_SCAN_SPEED_OPTIONS: dict[str, str] = {
    "normal": "",  # saf -T4 — en doğru, paralellik zorlaması yok
    "fast": "--min-hostgroup 64 --min-parallelism 64",  # boştaki kaynağı kullan, düşük risk
    "insane": "--min-hostgroup 128 --min-parallelism 128 --min-rate 1500",  # en hızlı, FP riski↑
    # Uzak/VPN: paralellik YOK + nazik -T2 + retry + host-timeout (yüksek gecikme/kayıp hatları).
    "slow": "-T2 --max-retries 4 --host-timeout 20m",
}


def scan_speed_options(speed: str | None) -> str:
    """Tarama hızı ayarından nmap zamanlama/paralellik bayrakları üretir.

    Bilinmeyen/boş değer güvenli ``fast``a düşer. Çıktı, mod seçenek dizesine (``-T4`` içeren)
    EKLENİR. normal/fast/insane ``-T`` template'ini EZMEZ (yalnız paralellik tabanını yükseltir);
    ``slow`` (Uzak/VPN) ise ``-T2`` ekler — nmap çok ``-T`` verilince sonuncuyu kullandığından
    bu, base ``-T4``'ü nazik ``-T2`` ile ezer (yüksek-gecikmeli hatlarda tcpwrapped'i önler).
    """
    key = (speed or DEFAULT_SCAN_SPEED).strip().lower()
    return _SCAN_SPEED_OPTIONS.get(key, _SCAN_SPEED_OPTIONS[DEFAULT_SCAN_SPEED])


def normalize_scan_speed(speed: str | None) -> str:
    """Serbest metni geçerli bir hız anahtarına çevirir (geçersiz → ``fast``)."""
    key = (speed or "").strip().lower()
    return key if key in SCAN_SPEEDS else DEFAULT_SCAN_SPEED


class AggressiveScanNotAllowed(Exception):
    """Agresif tarama istendi ama global güvenlik kilidi kapalı."""


def parse_mode(value: str | ScanMode | None) -> ScanMode:
    """Serbest metni (form/JSON) ``ScanMode``'a çevirir; geçersizse güvenli moda düşer."""
    if isinstance(value, ScanMode):
        return value
    try:
        return ScanMode(value) if value else ScanMode.safe
    except ValueError:
        return ScanMode.safe


def is_aggressive(mode: str | ScanMode | None) -> bool:
    """Müdahaleci yoğunlukta mı (agresif NSE + OS parmak izi + varsayılan-kimlik denetimi).

    Hem ``aggressive`` (Agresif CVE) hem ``exploit`` (Sömürme) bu yoğunlukta tarar; ikisi de
    güvenlik kilitlerine (ALLOW_AGGRESSIVE + admin + onay) tabidir. Aradaki fark **sömürü
    yapıp yapmaması**dır → o ayrım ``does_exploitation`` ile yapılır (SR-1).
    """
    return parse_mode(mode) in (ScanMode.aggressive, ScanMode.exploit)


def does_exploitation(mode: str | ScanMode | None) -> bool:
    """Yalnız ``exploit`` (Sömürme) modu gerçek sömürü dener (Metasploit + Exploit-DB, SR-1).

    Agresif CVE artık SÖMÜRMEZ — yalnızca tespit eder ve hangi exploit'lerin kullanılabileceğini
    gösterir. Gerçek içeri-sızma yalnızca bu moda özeldir; sömürü ayrıca msfrpcd yapılandırması
    ve/veya ``ALLOW_EXPLOITDB_EXECUTION`` kill-switch'i ile ikinci kez kapılıdır.
    """
    return parse_mode(mode) == ScanMode.exploit


def sanitize_ports(ports: str | None) -> str | None:
    """Elle girilen port listesini güvenli hale getirir (yalnızca rakam, virgül, tire).

    ``None``/``""``/``"top"`` → genel portlar (nmap top-1000, varsayılan) → ``None`` döner.
    ``"all"``/``"-p-"`` → tüm portlar → ``"all"`` döner.
    Aksi halde ``"80,443,8000-8100"`` gibi liste; geçersiz karakterler atılır; boşsa ``None``.
    """
    if ports is None:
        return None
    value = ports.strip().lower()
    if value in ("", "top", "top-ports", "general"):
        return None
    if value in ("all", "-p-", "*"):
        return "all"
    # Yalnızca rakam, virgül, tire (port aralığı) kalır; boşluk ve diğer her şey atılır
    # (kabuk metakarakteri / harf enjeksiyonu önlenir — nmap argümanına güvenle gider).
    cleaned = "".join(ch for ch in ports if ch.isdigit() or ch in ",-")
    cleaned = ",".join(part for part in cleaned.split(",") if part)
    return cleaned or None


def nmap_port_options(ports: str | None) -> str:
    """Port seçiminden nmap port argümanı üretir (genel → boş, tüm → -p-, liste → -p ...)."""
    spec = sanitize_ports(ports)
    if spec is None:
        return ""  # nmap varsayılanı: en yaygın 1000 port
    if spec == "all":
        return "-p-"
    return f"-p {spec}"


def nmap_options_for(
    mode: str | ScanMode | None, ports: str | None = None, *, include_udp: bool = False
) -> str:
    """Tarama moduna (+ opsiyonel port seçimi / UDP) karşılık gelen nmap seçenek dizesi.

    ``include_udp=True`` ise hedeflenmiş UDP servis taraması (``-sU``) eklenir
    (SNMP/DNS/NTP/IPMI/NetBIOS…). nmap birleşik ``T:/U:`` port sözdizimi gerektiğinden TCP
    tarafı açıkça belirlenir (verilen portlar ya da yaygın servis seti) — saf TCP'deki
    "top-1000" bu birleşik sözdiziminde ifade edilemez (#143).
    """
    base = AGGRESSIVE_NMAP_OPTIONS if is_aggressive(mode) else SAFE_NMAP_OPTIONS
    if include_udp:
        spec = sanitize_ports(ports)
        if spec == "all":
            tcp = "1-65535"
        elif spec:
            tcp = spec
        else:
            tcp = _UDP_COMBINED_TCP_PORTS
        # KRİTİK: ``-sU`` ile birlikte AÇIK bir TCP tarama tipi (``-sS``) verilmeli. Aksi halde
        # ``-pT:..,U:..`` sözdiziminde nmap "TCP tarama tipi belirtmedin" uyarısı verip TÜM TCP
        # portlarını ATLAR (yalnız UDP tarar) → Apache/Redis/SSH gibi TCP servisleri + CVE'leri
        # sessizce kaybolur ("port taranmadı"). ``-sU`` zaten raw-soket (root) gerektirdiğinden
        # ``-sS`` de aynı ortamda çalışır; UDP'siz yolda nmap zaten kök iken -sS'i otomatik seçer.
        return f"{base} -sS -sU -pT:{tcp},U:{UDP_TOP_PORTS}"
    port_opt = nmap_port_options(ports)
    return f"{base} {port_opt}".strip() if port_opt else base


def _ports_to_set(spec: str) -> set[int]:
    """``"80,443,8000-8100"`` → ``{80, 443, 8000..8100}``. Geçersiz parçalar atlanır."""
    out: set[int] = set()
    for raw in spec.split(","):
        part = raw.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            if lo.isdigit() and hi.isdigit():
                out.update(range(int(lo), int(hi) + 1))
        elif part.isdigit():
            out.add(int(part))
    return out


def examined_port_scope(
    ports: str | None, *, include_udp: bool = False
) -> dict[str, set[int] | None]:
    """Bir taramanın incelediği ``protokol → port kümesi`` kapsamı (STALE-PRUNE için).

    Eskimiş servisleri budarken "bu taramanın gerçekten baktığı portlar" gerekir; sözlük bunu
    verir:

    * Değer ``None`` → o protokolde TÜM portlar incelendi sayılır (host için tam yetkili).
      Varsayılan ``top-1000`` ve ``-p-`` böyle değerlendirilir. Bu BİLİNÇLİ bir karardır:
      ``top-1000`` aslında tüm portlar değildir, ama re-scan semantiği (Nessus/OpenVAS gibi —
      yeni tarama host'un servis durumunu EZER) ve aracın iç-ağ/standart-servis kullanımı için
      doğru varsayılandır. Yan etki: ``-p-`` ile bulunmuş, top-1000 dışı bir TCP servisi, sonraki
      varsayılan taramada budanabilir; ilgili port yeniden tarandığında geri gelir.
    * Değer bir küme → yalnız o portlar incelendi (hedefli ``-p 80,443`` taraması) → yalnız bu
      portlardaki eskimiş servisler budanır, diğer portlara DOKUNULMAZ.
    * Protokol sözlükte YOKSA o protokol hiç incelenmedi → o protokoldeki servisler ASLA budanmaz
      (ör. saf TCP taraması daha önce bulunmuş UDP servislerini silmez).
    """
    spec = sanitize_ports(ports)
    if include_udp:
        if spec == "all":
            tcp: set[int] | None = None
        elif spec:
            tcp = _ports_to_set(spec)
        else:
            tcp = _ports_to_set(_UDP_COMBINED_TCP_PORTS)
        return {"tcp": tcp, "udp": _ports_to_set(UDP_TOP_PORTS)}
    if spec and spec != "all":
        return {"tcp": _ports_to_set(spec)}
    # Varsayılan (top-1000) ya da ``all`` (-p-) → TCP için tam yetkili (bkz. docstring).
    return {"tcp": None}


# --- PORT-FANOUT: tek host'un PORT uzayını worker'lara böl (büyük port taraması) ----------------
# CIDR-fanout host'a göre böler; PORT-fanout aynı host'u port aralıklarına bölüp child'lara dağıtır.
# ``-p-`` (65535 port) tek worker'da yavaş → N parçaya böl → ~N× hız. Karar TARAMA HIZINDAN
# BAĞIMSIZ (operatör isteği): fan-out'u ``scan_fanout`` ayarı kontrol eder, hız değil. Her child
# yine yapılandırılan hız profilini kullanır (slow'da her biri nazik ``-T2``) → slow'da bile tek
# tek scan'ler nazik kalır; yalnız eşzamanlı koşarlar. Patron isteği "TÜM taramalar worker
# kullansın" → eşik artık sabit bir port-sayısı DEĞİL, ``fanout_workers``: her worker'a en az 1
# port düşüyorsa (port-sayısı ≥ worker-sayısı) bölünür → varsayılan top-1000 (1000 port) dahil.
PORT_FANOUT_MAX_CHILDREN = 8  # varsayılan port-bloğu sayısı (Ayarlar'dan ``fanout_workers`` ezer)
FANOUT_WORKERS_MIN = 1  # 1 = bölme yok (tek worker)
FANOUT_WORKERS_MAX = 32  # üst sınır (worker/CPU eşzamanlılığı + aşırı bölmeyi engelle)


def normalize_fanout_workers(n: int | None) -> int:
    """Operatörün girdiği worker bölme sayısını güvenli aralığa (1-32) kısar.

    Geçersiz/None → varsayılan (``PORT_FANOUT_MAX_CHILDREN``); negatif/0 → 1; >32 → 32.
    """
    if n is None:
        return PORT_FANOUT_MAX_CHILDREN
    try:
        value = int(n)
    except (TypeError, ValueError):
        return PORT_FANOUT_MAX_CHILDREN
    return max(FANOUT_WORKERS_MIN, min(value, FANOUT_WORKERS_MAX))


def _port_count(ports: str | None) -> int:
    """Taranacak yaklaşık port sayısı. ``None`` → top-1000 (1000), ``all`` → 65535, liste → adet."""
    spec = sanitize_ports(ports)
    if spec is None:
        return len(_ports_to_set(_UDP_COMBINED_TCP_PORTS))  # varsayılan fan-out port seti (~1048)
    if spec == "all":
        return 65535
    return len(_ports_to_set(spec))


def should_port_fanout(ports: str | None, *, include_udp: bool, workers: int) -> bool:
    """Tek host'u PORT'a göre ``workers`` parçaya bölmek mantıklı mı? (TÜM taramalar worker.)

    Tarama HIZINDAN BAĞIMSIZ (operatör isteği): açma/kapama ``scan_fanout`` ayarındadır, hız değil.
    Her child yine yapılandırılan hız profilini kullanır (slow'da her biri nazik ``-T2``). Bölünür
    eğer **port-sayısı ≥ worker-sayısı** (her worker'a en az 1 port düşer) → varsayılan top-1000
    (1000 port) DAHİL bölünür; ``-p 80,443`` gibi worker'dan az portlu küçük taramalarda bölmenin
    overhead'i faydadan çok → tek worker'da kalır. UDP birleşik ``T:/U:`` sözdizimi temiz
    bölünemez → yalnız saf TCP.
    """
    if include_udp:
        return False
    return _port_count(ports) >= max(2, workers)


def _collapse_ports(ints: list[int]) -> str:
    """Sıralı int listesini kompakt nmap port spec'ine sıkıştırır: ``[1,2,3,5,10] → "1-3,5,10"``."""
    if not ints:
        return ""
    parts: list[str] = []
    start = prev = ints[0]
    for p in ints[1:]:
        if p == prev + 1:
            prev = p
            continue
        parts.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = p
    parts.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(parts)


def split_port_specs(ports: str | None, n: int) -> list[str]:
    """Port uzayını ROUND-ROBIN (strided) ``n`` worker'a dağıtır → her parça için ``-p`` spec.

    KRİTİK: bitişik bölme (1-1024 → tek worker) AÇIK portları (ve ağır NSE yükünü) TEK blokta
    yoğunlaştırıyordu → exploit/agresif taramada o blok darboğaz. Round-robin (worker i → indeks
    i, i+n, ...) ardışık portları FARKLI worker'lara koyar → açık portlar bloklara YAYILIR → her
    worker ~eşit (az) açık port = ~eşit NSE yükü → exploit ~N× hızlanır.

    Aynı portları kapsar (kayıp yok). ``all`` → 1-65535; **varsayılan (None)** → nmap top-1000'i
    açıkça bölemediğimizden yaygın TCP port seti (``_UDP_COMBINED_TCP_PORTS``: 1-1024 + yüksek
    servis portları, AD 3389 dahil). Aksi halde verilen liste/aralık. Boş/az port → tek parça.
    """
    spec = sanitize_ports(ports)
    if spec == "all":
        all_ports = list(range(1, 65536))  # 'all' (-p-) → tüm TCP portları
    elif spec is None:
        all_ports = sorted(_ports_to_set(_UDP_COMBINED_TCP_PORTS))  # varsayılan: yaygın TCP seti
    else:
        all_ports = sorted(_ports_to_set(spec))
    if not all_ports:
        return []
    n = max(1, min(n, len(all_ports)))
    # ROUND-ROBIN: worker i → indeks i, i+n, i+2n, ... → ardışık portlar farklı worker'a (açık
    # portlar yayılır). all_ports sıralı → her dilim de sıralı → _collapse_ports doğru çalışır.
    return [_collapse_ports(all_ports[i::n]) for i in range(n) if all_ports[i::n]]


# --- PORT-QUEUE (#171): dinamik iş-kuyruğu fan-out (müdür + çalışan modeli) ----------------------
# PORT-FANOUT portları BAŞTAN SABİT N=worker parçaya böler (N child = N parça). Bir parçanın
# portları çok açıksa (ağır NSE) o child uzun sürer, diğer worker'lar BOŞ BEKLER → son-ağır-blok
# takılması (özellikle exploit/agresif modda belirgin). PORT-QUEUE bunu çözer: portları N yerine
# **M >> N KÜÇÜK partiye** böler. Müdür = Celery broker kuyruğu (Redis); çalışanlar = prefork
# havuzu (eşzamanlılık = CPU); iş birimi = küçük port partisi. Havuz partileri DİNAMİK çeker — bir
# çalışan partisini bitirince kuyruktan sıradakini alır → kimse boş durmaz, ağır partiler doğal
# olarak yayılır (work-stealing). chord(M children)(merge) zaten M sonucu bekler/birleştirir
# (``_merge_host_results`` #252 ile uyumlu). M, port sayısından BAĞIMSIZ ~sabit tutulur ki nmap
# açılış maliyeti (parti başına ~1-2sn) patlamasın; granülerlik oversubscribe katsayısıyla ayarlanır
# (ağır NSE'de daha çok parti = daha iyi denge; hafif -sV'de daha az parti = düşük açılış maliyeti).
PORT_QUEUE_OVERSUBSCRIBE_LIGHT = 3  # safe/network (-sV hafif): ölçülü denge, düşük nmap açılış payı
PORT_QUEUE_OVERSUBSCRIBE_HEAVY = 8  # aggressive/exploit (ağır NSE): maksimum denge (ASIL kazanç)
PORT_QUEUE_MAX_BATCHES = 64  # parti üst sınırı (nmap açılış patlamasını + chord boyutunu sınırla)


def port_queue_batch_count(ports: str | None, workers: int, *, heavy: bool) -> int:
    """PORT-QUEUE: kaç KÜÇÜK port partisi (M) üretilecek — dinamik iş kuyruğu için (M >> N).

    ``workers`` (N) operatörün hedef paralelliği; ``heavy`` = ağır NSE modu (agresif/exploit) mi.
    M = N × oversubscribe; üstten ``PORT_QUEUE_MAX_BATCHES`` (nmap açılış patlaması) ve port sayısı
    (partiden çok port olamaz) ile kısılır. Oversubscribe ağır modda yüksek (denge kazancı orada
    kritik), hafif modda düşük (açılış maliyeti baskın). count ≥ N olduğunda M ≥ N (her çalışana iş
    düşer); port sayısı N'den azsa M = port sayısı (split zaten bu kadar parça üretebilir).
    """
    n = normalize_fanout_workers(workers)
    over = PORT_QUEUE_OVERSUBSCRIBE_HEAVY if heavy else PORT_QUEUE_OVERSUBSCRIBE_LIGHT
    count = _port_count(ports)
    return max(1, min(n * over, count, PORT_QUEUE_MAX_BATCHES))


def split_port_queue(ports: str | None, workers: int, *, heavy: bool) -> list[str]:
    """Portları M >> N küçük strided partiye böler (Celery havuzu dinamik çeker — iş kuyruğu).

    ``split_port_specs`` ROUND-ROBIN bölmesini yeniden kullanır (açık portlar yayılır); tek fark
    parça sayısının N=worker değil M=``port_queue_batch_count`` olmasıdır → çok daha ince granül →
    havuz boşaldıkça çeker → son-ağır-blok takılması biter. Aynı portları kapsar (kayıp yok).
    """
    return split_port_specs(ports, port_queue_batch_count(ports, workers, heavy=heavy))


# --- HOST-QUEUE: keşif sonrası canlı host'ları worker havuzuna dinamik dağıt (Birleşik Dispatcher)
# CIDR fan-out ESKİDEN her /27 bloğu için keşif+derin taramayı TEK child'a koyuyordu → boş bloklar
# worker israf ediyor, host-yoğun blok tek child'da SERİ taranıyordu (efektif paralellik = host'lu
# blok sayısı, çekirdek sayısı DEĞİL — yoğun /24'te 16 çekirdeğin yalnız 1-2'si dolar). BİRLEŞİK
# DİSPATCHER: önce TÜM canlı host'lar keşfedilir (Faz 1, ``_discover_hosts_chunked``), sonra canlı
# host LİSTESİ ``split_port_queue`` gibi M>>N küçük partiye bölünür (Faz 2) → Celery havuzu DİNAMİK
# çeker (work-stealing): biten worker sıradakini alır, kimse boş durmaz. Bu, PORT-QUEUE'nun (#171)
# host boyutundaki İKİZİDİR — kör IP bloğu değil, gerçek yük birimi (canlı host) dağıtılır.


def host_batch_count(n_hosts: int, workers: int, *, heavy: bool) -> int:
    """HOST-QUEUE: kaç host partisi (M) üretilecek — canlı host'ları dinamik dağıtmak için (M ≥ N).

    PORT-QUEUE'nun host-boyutu karşılığı: M = N × oversubscribe, üstten host sayısı (partiden çok
    host olamaz) ve ``PORT_QUEUE_MAX_BATCHES`` (chord boyutu) ile kısılır. Oversubscribe ağır modda
    (agresif/exploit) yüksek — derin tarama süresi host'tan host'a çok değişir (açık port sayısı,
    NSE yükü), ince granül dengeyi düzeltir; hafif modda düşük (nmap açılış payı baskın).
    """
    n = normalize_fanout_workers(workers)
    over = PORT_QUEUE_OVERSUBSCRIBE_HEAVY if heavy else PORT_QUEUE_OVERSUBSCRIBE_LIGHT
    return max(1, min(n * over, max(n_hosts, 1), PORT_QUEUE_MAX_BATCHES))


def split_host_queue(hosts: list[str], workers: int, *, heavy: bool) -> list[list[str]]:
    """Canlı host'ları M >> N küçük strided partiye böler (Celery havuzu dinamik çeker).

    ``split_port_queue``ın host-boyutu ikizi: round-robin (strided) dağıtım host'ları partilere
    eşit yayar (i. host → ``i % M`` partisi); M = ``host_batch_count``. Her parti bir child task
    olur ve ``-Pn`` ile derin taranır (keşif Faz 1'de bitti). Boş parti döndürülmez; host/sıra
    kaybı yok. Her host TEK partide (overlap yok) → ``_merge_host_results`` no-op, prune güvenli.
    """
    m = host_batch_count(len(hosts), workers, heavy=heavy)
    batches: list[list[str]] = [[] for _ in range(m)]
    for i, host in enumerate(hosts):
        batches[i % m].append(host)
    return [b for b in batches if b]


def _count_target_hosts(target: str) -> int:
    """Hedef dizesindeki (boşlukla ayrık blok) tahmini host sayısı (CIDR genişletilir).

    nmap canlı ilerleme bildirmediğinden (pipe tampon + yalnız çok-uzun görevlerde stats),
    ilerleme/ETA hedef-boyutu + mod'a göre tahmin edilir. Çok büyük bloklar (örn. /16)
    için süre/UI gerçekçi kalsın diye blok başına 4096 ile sınırlanır.
    """
    total = 0
    for block in (target or "").split():
        try:
            net = ipaddress.ip_network(block, strict=False)
            total += min(net.num_addresses, 4096)
        except ValueError:
            total += 1  # hostname/URL host vb. → tek hedef say
    return max(total, 1)


def estimate_scan_seconds(
    target: str, mode: str | ScanMode | None, ports: str | None = None, *, include_udp: bool = False
) -> int:
    """Tarama süresini (saniye) hedef-boyutu + mod + port + UDP'ye göre KABA tahmin eder.

    nmap'in kendi canlı ilerlemesi bu kurulumda (pipe tampon) güvenilir alınamadığından,
    canlı ilerleme çubuğu ve ETA bu tahminden türetilir (stabil + azalan; donma/zıplama yok).
    Tahmin yaklaşıktır — amaç doğru saniye değil, MAKUL ve STABİL bir gösterim.
    """
    hosts = _count_target_hosts(target)
    per_host = 10.0 if is_aggressive(mode) else 2.0  # agresif/exploit NSE ağır → host başına yavaş
    if include_udp:
        per_host += 4.0  # -sU yavaş (ICMP rate-limit)
    if sanitize_ports(ports) == "all":
        per_host *= 3.0  # -p- (65535 port)
    return int(15 + hosts * per_host)  # +15s sabit (başlatma/keşif/işleme payı)


# --- Parçalı keşif (SCAN-NET Faz 1): büyük CIDR'i küçük bloklara böl ------------------------
# Tek nmap çağrısıyla büyük bir CIDR (ör. /24) süpürmek, araya giren NAT/gateway katmanlarında
# bağlantı tablosunu boğup gerçek hostların cevaplarını bile düşürebiliyor (canlı ölçüm:
# Docker Desktop NAT'ında /24 → 0 host, oysa /27 blok → gerçek hostlar bulunuyor). Çözüm: büyük
# CIDR'i küçük bloklara böl, blok-blok host KEŞFİ yap, sonra yalnız CANLI host'ları derinlemesine
# tara. Açıkça yazılan tek host'lar / küçük CIDR'ler bu yoldan GEÇMEZ (kullanıcı niyeti = mutlaka
# tara → doğrudan -Pn). Worker'lar arası dağıtımın (fan-out, Faz 2) da temeli budur.
SCAN_BLOCK_PREFIX = 27  # büyük CIDR bu boyuttaki (/27 = 32 adres) bloklara bölünür
SCAN_CHUNK_THRESHOLD = 64  # bu kadardan ÇOK adresli (>/26) CIDR'ler parçalanır; küçükler dokunulmaz
_MAX_BLOCK_SPLIT_BITS = 7  # ağ başına en çok 2^7=128 blok (blok patlamasını sınırla; ör. /16 → /23)


def target_needs_chunking(target: str) -> bool:
    """Hedef, parçalı keşfi hak eden BÜYÜK bir CIDR (> ``SCAN_CHUNK_THRESHOLD`` adres) içerir mi?"""
    for token in (target or "").split():
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if net.version == 4 and net.num_addresses > SCAN_CHUNK_THRESHOLD:
            return True
    return False


def partition_scan_targets(
    target: str, *, block_prefix: int = SCAN_BLOCK_PREFIX
) -> tuple[list[str], list[str]]:
    """Hedefi (explicit_targets, discovery_blocks) olarak ayırır (parçalı keşif için).

    - **explicit_targets**: tek IP / hostname / küçük CIDR (≤ eşik) → kullanıcı açıkça istedi;
      keşif ATLANIR, doğrudan (-Pn) taranır (asla kaçırılmaz).
    - **discovery_blocks**: büyük CIDR'lerin ``block_prefix`` boyutundaki blokları → önce host
      keşfi, sonra yalnız canlı olanlar taranır. Ağ başına blok 2^7 ile sınırlı (patlama koruması:
      ör. /16 → 128×/23). Saf/test edilebilir; nmap GEREKTİRMEZ.
    """
    explicit: list[str] = []
    blocks: list[str] = []
    for token in (target or "").split():
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            explicit.append(token)  # hostname / URL host → doğrudan tara
            continue
        if net.version != 4 or net.num_addresses <= SCAN_CHUNK_THRESHOLD:
            explicit.append(str(net))
            continue
        eff_prefix = min(block_prefix, net.prefixlen + _MAX_BLOCK_SPLIT_BITS)
        blocks.extend(str(sub) for sub in net.subnets(new_prefix=eff_prefix))
    return explicit, blocks


def dns_nmap_options(dns_servers: str, reverse_dns: bool) -> str:
    """Ayarlardan nmap DNS argümanları üretir (VI-6). Komut-enjeksiyonuna karşı güvenli.

    - ``dns_servers``: yalnızca GEÇERLİ IP'ler ``--dns-servers a,b`` olur (geçersiz atılır).
    - ``reverse_dns`` kapalıysa ``-n`` (DNS çözme yok → hızlı/sessiz); açıksa nmap'in
      varsayılan PTR çözümü kullanılır (ek argüman yok).
    """
    parts: list[str] = []
    valid: list[str] = []
    for token in (dns_servers or "").replace(";", ",").split(","):
        candidate = token.strip()
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if candidate not in valid:
            valid.append(candidate)
    if valid:
        parts.append("--dns-servers " + ",".join(valid[:3]))
    if not reverse_dns:
        parts.append("-n")
    return " ".join(parts)


def nmap_exclude_option(exclude_ips: set[str] | list[str]) -> str:
    """Aracın kendi altyapı IP'lerini taramadan dışlamak için nmap ``--exclude`` argümanı (VI-7).

    Yalnızca GEÇERLİ IP'ler eklenir (komut-enjeksiyonu koruması). Boşsa boş döner.
    Böylece bir /24 taraması aracın kendi db/redis/app container'larını PROBLAMAZ.
    """
    valid: list[str] = []
    for token in exclude_ips:
        candidate = str(token).strip()
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if candidate not in valid:
            valid.append(candidate)
    if not valid:
        return ""
    return "--exclude " + ",".join(sorted(valid))


def ensure_mode_allowed(mode: str | ScanMode | None, *, allow_aggressive: bool) -> None:
    """Agresif mod global ayarla kapalıyken istenirse ``AggressiveScanNotAllowed`` fırlatır."""
    if is_aggressive(mode) and not allow_aggressive:
        raise AggressiveScanNotAllowed(
            "Agresif (müdahaleci) tarama yönetici tarafından kapalı. "
            "Açmak için sunucuda ALLOW_AGGRESSIVE_SCANS=true ayarlanmalıdır."
        )


# --- Sihirbaz/Hızlı tarama PAYLAŞILAN mod seçimi (FAZ VIII) ------------------------------
# Patron isteği: tek bir "Mod seç" alanı, kullanıcıya yönelik 4 mod. Her iki UI da (sihirbaz +
# hızlı tarama) AYNI backend'i kullanır: bir mod anahtarı → (scan_type, nmap modu, ek alanlar).
#
# NESSUS MODELİ (VIII-5): "Kimlikli" AYRI BİR MOD DEĞİLDİR. Kimlik, Ping hariç HER moda
# eklenebilen OPSİYONEL bir zenginleştirmedir (route katmanı yönetir): kimlik verilince tarama
# tekniğine EK olarak içeriden kimlikli denetim (CIS) + priv-esc çalışır. Böylece "kimlik seçtim
# ama kullanılmadı" karışıklığı ortadan kalkar.


@dataclass(frozen=True)
class WizardModeSpec:
    """Kullanıcıya yönelik tarama modunun backend karşılığı (paylaşılan)."""

    key: str
    scan_type: ScanType
    nmap_mode: ScanMode
    needs_ports: bool = False  # Ağ taraması: yanında port seçici belirir
    needs_ack: bool = False  # Agresif: açık "kabul ediyorum" onayı
    admin_only: bool = False  # yalnız admin başlatabilir
    exploit: bool = False  # VIII-2: agresif CVE exploitation niyeti


# Sıra = UI'da gösterim sırası. (Kimlik herhangi bir modda opsiyonel olarak eklenir.)
WIZARD_MODES: dict[str, WizardModeSpec] = {
    "network": WizardModeSpec("network", ScanType.network, ScanMode.safe, needs_ports=True),
    "ping": WizardModeSpec("ping", ScanType.ping, ScanMode.safe),
    "cve_safe": WizardModeSpec("cve_safe", ScanType.vuln, ScanMode.safe),
    # Agresif CVE (SR-1): derin/müdahaleci TESPİT + "kullanılabilir exploit'leri göster" —
    # artık SÖMÜRMEZ (exploit=False). Güvenlik onayı yine gerekir (agresif NSE müdahaleci).
    "cve_aggressive": WizardModeSpec(
        "cve_aggressive",
        ScanType.vuln,
        ScanMode.aggressive,
        needs_ack=True,
        admin_only=True,
        exploit=False,
    ),
}

# Eski form/şablon değerleri (geri uyumluluk): safe→ağ, aggressive→agresif CVE,
# credentialed→ağ (kimlik artık add-on; kimlik de seçildiyse route içeriden denetler).
_LEGACY_MODE_ALIASES = {
    "safe": "network",
    "aggressive": "cve_aggressive",
    "exploit": "network",
    "credentialed": "network",
}


def resolve_wizard_mode(value: str | None) -> WizardModeSpec:
    """Form 'mode' alanını ``WizardModeSpec``'e çevirir; bilinmeyen → ağ taraması."""
    key = (value or "").strip()
    key = _LEGACY_MODE_ALIASES.get(key, key)
    return WIZARD_MODES.get(key, WIZARD_MODES["network"])
