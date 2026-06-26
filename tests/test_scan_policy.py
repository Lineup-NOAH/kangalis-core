"""Tarama modu (güvenli/agresif) politikası ve güvenlik kilidi testleri."""

from __future__ import annotations

import pytest

from cybersectool.core.models import ScanMode
from cybersectool.core.scan_policy import (
    AGGRESSIVE_NMAP_OPTIONS,
    SAFE_NMAP_OPTIONS,
    WIZARD_MODES,
    AggressiveScanNotAllowed,
    dns_nmap_options,
    does_exploitation,
    ensure_mode_allowed,
    estimate_scan_seconds,
    examined_port_scope,
    is_aggressive,
    nmap_exclude_option,
    nmap_options_for,
    nmap_port_options,
    normalize_fanout_workers,
    normalize_scan_speed,
    parse_mode,
    partition_scan_targets,
    resolve_wizard_mode,
    sanitize_ports,
    scan_speed_options,
    should_port_fanout,
    split_port_specs,
    target_needs_chunking,
)


def test_estimate_scan_seconds() -> None:
    """Canlı ilerleme/ETA için kaba süre tahmini: host-sayısı × mod × UDP × port."""
    # Tek host güvenli: 15 + 1*2 = 17
    assert estimate_scan_seconds("172.28.0.24", ScanMode.safe) == 17
    # /24 (256 host) güvenli: 15 + 256*2 = 527
    assert estimate_scan_seconds("172.28.0.0/24", ScanMode.safe) == 527
    # Agresif tek host UDP: 15 + 1*(10+4) = 29
    assert estimate_scan_seconds("10.0.0.5", ScanMode.aggressive, include_udp=True) == 29
    # 'all' port çarpanı (×3): safe tek host = 15 + 1*(2*3) = 21
    assert estimate_scan_seconds("10.0.0.5", ScanMode.safe, "all") == 21
    # Çok blok host sayısı toplanır: 2 tekil host güvenli = 15 + 2*2 = 19
    assert estimate_scan_seconds("10.0.0.5 10.0.0.6", ScanMode.safe) == 19
    # Agresif > güvenli (büyük menzilde fark belirgin).
    assert estimate_scan_seconds("172.28.0.0/24", ScanMode.aggressive) > estimate_scan_seconds(
        "172.28.0.0/24", ScanMode.safe
    )


def test_nmap_exclude_option() -> None:
    """VI-7: geçerli IP'ler --exclude; geçersiz/boş atılır; boş küme → boş dize."""
    assert nmap_exclude_option(set()) == ""
    assert nmap_exclude_option({"172.28.0.2"}) == "--exclude 172.28.0.2"
    # Sıralı + tekil + geçersiz elenir.
    out = nmap_exclude_option(["172.28.0.3", "172.28.0.2", "not-ip", "172.28.0.2"])
    assert out == "--exclude 172.28.0.2,172.28.0.3"


def test_dns_nmap_options() -> None:
    """VI-6: geçerli IP'ler --dns-servers; reverse kapalı → -n; enjeksiyon token atılır."""
    # Reverse açık + geçerli DNS → yalnız --dns-servers.
    assert (
        dns_nmap_options("10.0.0.1, 10.0.0.2", reverse_dns=True)
        == "--dns-servers 10.0.0.1,10.0.0.2"
    )
    # Reverse kapalı → -n eklenir.
    assert dns_nmap_options("", reverse_dns=False) == "-n"
    assert dns_nmap_options("10.0.0.1", reverse_dns=False) == "--dns-servers 10.0.0.1 -n"
    # Reverse açık + DNS yok → boş (nmap varsayılanı).
    assert dns_nmap_options("", reverse_dns=True) == ""
    # Komut enjeksiyonu / geçersiz token elenir (yalnız geçerli IP kalır).
    assert (
        dns_nmap_options("8.8.8.8; rm -rf /, not-an-ip", reverse_dns=True)
        == "--dns-servers 8.8.8.8"
    )
    # En fazla 3 sunucu (4.'sü atılır).
    capped = dns_nmap_options("1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4", reverse_dns=True)
    assert capped == "--dns-servers 1.1.1.1,2.2.2.2,3.3.3.3"
    assert "4.4.4.4" not in capped


def test_parse_mode_valid() -> None:
    assert parse_mode("safe") == ScanMode.safe
    assert parse_mode("aggressive") == ScanMode.aggressive
    assert parse_mode(ScanMode.aggressive) == ScanMode.aggressive


def test_parse_mode_invalid_defaults_to_safe() -> None:
    # Geçersiz/boş değerler güvenli moda düşmeli (fail-safe).
    assert parse_mode("bogus") == ScanMode.safe
    assert parse_mode("") == ScanMode.safe
    assert parse_mode(None) == ScanMode.safe


def test_is_aggressive() -> None:
    assert is_aggressive("aggressive") is True
    assert is_aggressive("safe") is False
    assert is_aggressive(None) is False
    # SR-1: Sömürme modu da müdahaleci yoğunlukta (agresif kilitlerine tabi).
    assert is_aggressive("exploit") is True
    assert is_aggressive(ScanMode.exploit) is True


def test_does_exploitation() -> None:
    """SR-1: gerçek sömürü YALNIZ ``exploit`` modunda; agresif/güvenli sömürmez."""
    assert does_exploitation("exploit") is True
    assert does_exploitation(ScanMode.exploit) is True
    assert does_exploitation("aggressive") is False  # agresif CVE artık sömürmez
    assert does_exploitation("safe") is False
    assert does_exploitation(None) is False


def test_parse_mode_exploit() -> None:
    assert parse_mode("exploit") == ScanMode.exploit
    assert parse_mode(ScanMode.exploit) == ScanMode.exploit


def test_exploit_mode_uses_aggressive_nmap() -> None:
    """SR-1: Sömürme modu agresif yoğunlukta tarar (aynı nmap seçenekleri)."""
    assert nmap_options_for(ScanMode.exploit) == AGGRESSIVE_NMAP_OPTIONS


def test_exploit_mode_gated_like_aggressive() -> None:
    """SR-1: Sömürme modu da ALLOW_AGGRESSIVE kapalıyken reddedilir; açıkken serbest."""
    with pytest.raises(AggressiveScanNotAllowed):
        ensure_mode_allowed(ScanMode.exploit, allow_aggressive=False)
    ensure_mode_allowed(ScanMode.exploit, allow_aggressive=True)


def test_wizard_modes_split() -> None:
    """SR-1: agresif CVE exploit=False; ayrı 'exploit' (Sömürme) modu exploit=True (kapılı)."""
    aggr = WIZARD_MODES["cve_aggressive"]
    assert aggr.nmap_mode == ScanMode.aggressive
    assert aggr.exploit is False  # sömürmez
    assert aggr.needs_ack and aggr.admin_only

    # Sömürme (exploit) modu WIZARD_MODES'ta — UI'da YALNIZ eklenti+lisans varken görünür
    # (exploit_unlocked, template-gated); backend ScanMode.exploit ile gerçek sömürü yapar.
    assert "exploit" in WIZARD_MODES
    exp = resolve_wizard_mode("exploit")
    assert exp.nmap_mode == ScanMode.exploit
    assert exp.exploit and exp.admin_only and exp.needs_ack


def test_nmap_options_mapping() -> None:
    assert nmap_options_for(ScanMode.safe) == SAFE_NMAP_OPTIONS
    assert nmap_options_for(ScanMode.aggressive) == AGGRESSIVE_NMAP_OPTIONS
    # Güvenli mod default (bilgi toplayıcı) NSE scriptlerini çalıştırır (-sC) ama
    # müdahaleci vuln/exploit --script seçicisini KULLANMAZ.
    assert "-sC" in SAFE_NMAP_OPTIONS
    assert "--script" not in SAFE_NMAP_OPTIONS
    # Agresif mod vuln + exploit + keşif (discovery) scriptlerini çalıştırır.
    assert "vuln" in AGGRESSIVE_NMAP_OPTIONS
    assert "discovery" in AGGRESSIVE_NMAP_OPTIONS
    # DoS (hedefi düşürür) ve brute (hesap kilitler) agresif modda dahi bilerek hariç tutulur.
    assert "not dos" in AGGRESSIVE_NMAP_OPTIONS
    assert "not brute" in AGGRESSIVE_NMAP_OPTIONS


def test_scan_speed_options() -> None:
    """SCAN-SPEED: hız ayarı → nmap zamanlama/paralellik bayrakları."""
    # normal = ek bayrak yok (saf -T4, en doğru).
    assert scan_speed_options("normal") == ""
    # fast = paralellik zorla (boştaki kaynağı kullan), ama --min-rate YOK (düşük risk).
    fast = scan_speed_options("fast")
    assert "--min-hostgroup" in fast and "--min-parallelism" in fast
    assert "--min-rate" not in fast
    # insane = en agresif: --min-rate dahil.
    assert "--min-rate" in scan_speed_options("insane")
    # normal/fast/insane -T şablonunu içermez (mod dizesindeki -T4 ile çakışmasın).
    assert all("-T" not in scan_speed_options(s) for s in ("normal", "fast", "insane"))
    # slow (Uzak/VPN) = paralellik YOK + nazik -T2 (base -T4'ü ezer) + retry + host-timeout.
    slow = scan_speed_options("slow")
    assert "-T2" in slow and "--max-retries" in slow and "--host-timeout" in slow
    assert "--min-parallelism" not in slow and "--min-rate" not in slow  # şişirme yok
    # Bilinmeyen/boş → güvenli "fast"a düşer (geçersiz değer komuta sızmaz).
    assert scan_speed_options("bogus") == fast
    assert scan_speed_options(None) == fast
    assert scan_speed_options("") == fast


def test_normalize_scan_speed() -> None:
    """Serbest metin geçerli hız anahtarına; geçersiz → fast."""
    assert normalize_scan_speed("INSANE") == "insane"
    assert normalize_scan_speed("  fast ") == "fast"
    assert normalize_scan_speed("normal") == "normal"
    assert normalize_scan_speed("bogus") == "fast"
    assert normalize_scan_speed(None) == "fast"


def test_target_needs_chunking() -> None:
    """SCAN-NET: yalnız BÜYÜK CIDR (>64 adres) parçalı keşfi tetikler."""
    assert target_needs_chunking("192.168.1.0/24") is True  # 256 adres
    assert target_needs_chunking("10.0.0.0/25") is True  # 128 adres
    assert target_needs_chunking("10.0.0.0/26") is False  # 64 adres (eşik dahil değil)
    assert target_needs_chunking("172.28.0.24") is False  # tek host
    assert target_needs_chunking("example.com") is False  # hostname
    assert target_needs_chunking("192.168.1.0/24 10.0.0.5") is True  # karışık → büyük var


def test_partition_scan_targets() -> None:
    """SCAN-NET: büyük CIDR → /27 keşif blokları; tek host/küçük CIDR/hostname → explicit."""
    # /24 → 8 × /27 keşif bloğu, explicit boş.
    explicit, blocks = partition_scan_targets("192.168.1.0/24")
    assert explicit == []
    assert len(blocks) == 8
    assert blocks[0] == "192.168.1.0/27"
    assert blocks[-1] == "192.168.1.224/27"
    assert all(b.endswith("/27") for b in blocks)
    # Karışık: büyük CIDR bloklaşır; tek host + hostname explicit kalır (kaçırılmaz).
    explicit, blocks = partition_scan_targets("192.168.1.0/24 10.0.0.5 host.local")
    assert "10.0.0.5/32" in explicit
    assert "host.local" in explicit
    assert len(blocks) == 8
    # Küçük CIDR (≤ eşik) bloklaşmaz → explicit (doğrudan taranır).
    explicit, blocks = partition_scan_targets("10.0.0.0/26")
    assert explicit == ["10.0.0.0/26"]
    assert blocks == []
    # Patlama koruması: /16 ağ başına ≤128 blok (/23'e kabalaşır), /27'ye değil.
    _, big = partition_scan_targets("10.0.0.0/16")
    assert len(big) == 128
    assert all(b.endswith("/23") for b in big)


def test_safe_mode_always_allowed() -> None:
    # Güvenli mod global ayardan bağımsız her zaman serbest.
    ensure_mode_allowed(ScanMode.safe, allow_aggressive=False)
    ensure_mode_allowed("safe", allow_aggressive=False)


def test_aggressive_blocked_when_disabled() -> None:
    with pytest.raises(AggressiveScanNotAllowed):
        ensure_mode_allowed(ScanMode.aggressive, allow_aggressive=False)


def test_aggressive_allowed_when_enabled() -> None:
    # Global ayar açıksa istisna fırlatmamalı.
    ensure_mode_allowed(ScanMode.aggressive, allow_aggressive=True)


def test_sanitize_ports() -> None:
    # Genel/boş → None (nmap varsayılan top-1000).
    assert sanitize_ports(None) is None
    assert sanitize_ports("") is None
    assert sanitize_ports("top") is None
    # Tüm portlar.
    assert sanitize_ports("all") == "all"
    assert sanitize_ports("-p-") == "all"
    # Elle liste: boşluk/temizlik + geçersiz karakter atılır.
    assert sanitize_ports("80,443, 8080") == "80,443,8080"
    assert sanitize_ports("22-25, 80") == "22-25,80"
    # Harf/kabuk metakarakteri atılır → enjeksiyon yok (yalnızca rakam/virgül/tire kalır).
    assert sanitize_ports("80,rm -rf,443") == "80,-,443"


def test_nmap_port_options() -> None:
    assert nmap_port_options(None) == ""  # genel → nmap varsayılanı
    assert nmap_port_options("all") == "-p-"
    assert nmap_port_options("80,443") == "-p 80,443"


def test_nmap_options_with_ports() -> None:
    # Port seçimi mod seçeneklerine eklenir.
    assert nmap_options_for(ScanMode.safe, "all") == f"{SAFE_NMAP_OPTIONS} -p-"
    assert nmap_options_for(ScanMode.safe, "80,443") == f"{SAFE_NMAP_OPTIONS} -p 80,443"
    # Genel portlar → ek argüman yok.
    assert nmap_options_for(ScanMode.safe, None) == SAFE_NMAP_OPTIONS


def test_nmap_options_with_udp() -> None:
    """#143: include_udp → -sU + birleşik T:/U: port sözdizimi."""
    from cybersectool.core.scan_policy import UDP_TOP_PORTS

    # Açık port verilmemiş → yaygın TCP seti + hedeflenmiş UDP.
    opt = nmap_options_for(ScanMode.safe, None, include_udp=True)
    assert "-sU" in opt
    # KRİTİK regresyon: -sU yanında AÇIK TCP tarama tipi (-sS) olmalı; yoksa nmap T: portlarını
    # atlar ve tüm TCP servisleri/CVE'leri kaybolur ("port taranmadı" bug'ı).
    assert "-sS" in opt
    assert f"U:{UDP_TOP_PORTS}" in opt
    assert "-pT:1-1024" in opt  # yaygın TCP seti
    # Açık port verilince TCP tarafı onu kullanır.
    opt2 = nmap_options_for(ScanMode.safe, "80,443", include_udp=True)
    assert f"-pT:80,443,U:{UDP_TOP_PORTS}" in opt2
    # "all" → tüm TCP + UDP set.
    opt3 = nmap_options_for(ScanMode.aggressive, "all", include_udp=True)
    assert "-pT:1-65535,U:" in opt3
    # include_udp=False → değişiklik yok (geriye uyumlu).
    assert nmap_options_for(ScanMode.safe, "80") == f"{SAFE_NMAP_OPTIONS} -p 80"


def test_examined_port_scope() -> None:
    """STALE-PRUNE kapsamı: incelenen protokol→port kümesi (budama bunu kullanır)."""
    from cybersectool.core.scan_policy import _UDP_COMBINED_TCP_PORTS, UDP_TOP_PORTS, _ports_to_set

    # Varsayılan (top-1000) → TCP için tam yetkili (None), UDP sözlükte yok (incelenmedi).
    default = examined_port_scope(None)
    assert default == {"tcp": None}
    # "all" (-p-) → yine TCP tam yetkili.
    assert examined_port_scope("all") == {"tcp": None}
    # Hedefli portlar → yalnız o portlar; aralık genişler.
    scoped = examined_port_scope("80,443,8000-8002")
    assert scoped == {"tcp": {80, 443, 8000, 8001, 8002}}
    # UDP açık + port verilmemiş → TCP yaygın seti + UDP top portları (her ikisi de incelenmiş).
    udp = examined_port_scope(None, include_udp=True)
    assert udp["tcp"] == _ports_to_set(_UDP_COMBINED_TCP_PORTS)
    assert udp["udp"] == _ports_to_set(UDP_TOP_PORTS)
    # UDP açık + "all" → TCP tam yetkili (None), UDP yine hedefli set.
    udp_all = examined_port_scope("all", include_udp=True)
    assert udp_all["tcp"] is None
    assert udp_all["udp"] == _ports_to_set(UDP_TOP_PORTS)


def test_should_port_fanout() -> None:
    """PORT-FANOUT: port-sayısı ≥ worker-sayısı ise böl (tüm taramalar); UDP/az-portta kapalı."""
    # Büyük port → True (hızdan bağımsız; scan_fanout ayarı kontrol eder).
    assert should_port_fanout("all", include_udp=False, workers=8) is True
    assert should_port_fanout("1-10000", include_udp=False, workers=8) is True
    # VARSAYILAN top-1000 (1000 port) ARTIK bölünür (1000 ≥ 8) — patron: tüm taramalar worker.
    assert should_port_fanout(None, include_udp=False, workers=8) is True
    # UDP birleşik T:/U: port sözdizimi temiz bölünemez → kapalı (korunan tek teknik kısıt).
    assert should_port_fanout("all", include_udp=True, workers=8) is False
    # Worker'dan AZ portlu küçük tarama → bölme overhead'i faydadan çok → tek worker.
    assert should_port_fanout("80,443", include_udp=False, workers=8) is False  # 2 < 8
    # Ama worker sayısı düşükse (≤ port) bölünür: 2 port, 2 worker.
    assert should_port_fanout("80,443", include_udp=False, workers=2) is True


def test_split_port_specs() -> None:
    """ROUND-ROBIN dağıtım: ardışık portlar farklı worker'a → açık portlar bloklara yayılır."""
    from cybersectool.core.scan_policy import _collapse_ports, _ports_to_set

    # 'all' (-p-) → 8 parça, birleşimi TÜM 1-65535 (port kaybı yok).
    specs = split_port_specs("all", 8)
    assert len(specs) == 8
    covered: set[int] = set()
    for s in specs:
        covered |= _ports_to_set(s)
    assert covered == set(range(1, 65536))
    # STRIDED: worker 0 = indeks 0,8,16,... → portlar {1,9,17,...} (ardışık değil, 8'er atlamalı).
    w0 = sorted(_ports_to_set(specs[0]))
    assert w0[:3] == [1, 9, 17]
    # Ardışık portlar AYRI worker'larda: 1→w0, 2→w1, 3→w2 (açık portlar tek blokta toplanmaz).
    w1 = sorted(_ports_to_set(specs[1]))
    assert w1[:2] == [2, 10]
    # n > port sayısı → her port ayrı parça (round-robin: her worker'a 1 port).
    assert set(split_port_specs("80,443,8080", 8)) == {"80", "443", "8080"}
    # _collapse_ports bitişik koşuları aralığa indirir, tekilleri korur.
    assert _collapse_ports([1, 2, 3, 5, 10, 11]) == "1-3,5,10-11"
    assert _collapse_ports([]) == ""


def test_port_queue_batch_count() -> None:
    """PORT-QUEUE: M >> N küçük parti; ağır mod daha çok parti; üst sınır + port-sayısı kısıtı."""
    from cybersectool.core.scan_policy import (
        PORT_QUEUE_MAX_BATCHES,
        port_queue_batch_count,
    )

    # Hafif mod (safe/-sV): oversubscribe 3 → 8 worker × 3 = 24 parti (M >> N=8).
    assert port_queue_batch_count(None, 8, heavy=False) == 24
    # Ağır mod (exploit/NSE): oversubscribe 8 → 8 × 8 = 64 parti (asıl denge kazancı burada).
    assert port_queue_batch_count(None, 8, heavy=True) == 64
    # İkisi de N=8'den BÜYÜK (dinamik kuyruk için M >> N şart).
    assert port_queue_batch_count(None, 8, heavy=False) > 8
    # Üst sınır: 32 worker × 8 = 256 ama PORT_QUEUE_MAX_BATCHES'e kısılır (nmap açılış patlaması).
    assert port_queue_batch_count("all", 32, heavy=True) == PORT_QUEUE_MAX_BATCHES
    # Port sayısı partiden azsa M = port sayısı (3 port → en çok 3 parti, 8/24 değil).
    assert port_queue_batch_count("80,443,8080", 8, heavy=False) == 3
    assert port_queue_batch_count("80,443", 2, heavy=True) == 2


def test_split_port_queue() -> None:
    """PORT-QUEUE bölmesi: M>>N strided parti; TÜM portları kapsar (kayıp yok); ağır>hafif parti."""
    from cybersectool.core.scan_policy import _ports_to_set, split_port_queue

    # Ağır mod 'all' → 64 parti, birleşimi TÜM 1-65535 (port kaybı yok).
    heavy = split_port_queue("all", 8, heavy=True)
    assert len(heavy) == 64
    covered: set[int] = set()
    for s in heavy:
        covered |= _ports_to_set(s)
    assert covered == set(range(1, 65536))
    # Ağır mod hafif moddan DAHA ÇOK parti üretir (daha ince granül = daha iyi denge).
    light = split_port_queue("all", 8, heavy=False)
    assert len(heavy) > len(light)
    # Az port → parti sayısı port sayısına düşer (her port ayrı parti).
    assert set(split_port_queue("22,80,443", 8, heavy=True)) == {"22", "80", "443"}


def test_normalize_fanout_workers() -> None:
    """Worker bölme sayısı 1-32 aralığına kısılır; geçersiz/None → varsayılan (8)."""
    from cybersectool.core.scan_policy import PORT_FANOUT_MAX_CHILDREN

    assert normalize_fanout_workers(4) == 4
    assert normalize_fanout_workers(1) == 1  # 1 = bölme yok
    assert normalize_fanout_workers(0) == 1  # alt sınıra kısılır
    assert normalize_fanout_workers(-5) == 1
    assert normalize_fanout_workers(999) == 32  # üst sınıra kısılır
    assert normalize_fanout_workers(None) == PORT_FANOUT_MAX_CHILDREN  # varsayılan (8)


def test_host_batch_count() -> None:
    """HOST-QUEUE (Birleşik Dispatcher): M = N×oversubscribe; host-sayısı + üst sınır kısıtı."""
    from cybersectool.core.scan_policy import PORT_QUEUE_MAX_BATCHES, host_batch_count

    # Bol host (1000) → hafif mod 8×3=24, ağır mod 8×8=64 parti (M >> N=8, dinamik kuyruk).
    assert host_batch_count(1000, 8, heavy=False) == 24
    assert host_batch_count(1000, 8, heavy=True) == 64
    # Host sayısı partiden azsa M = host sayısı (5 host → en çok 5 parti, 24/64 değil).
    assert host_batch_count(5, 8, heavy=False) == 5
    assert host_batch_count(1, 8, heavy=True) == 1  # tek host → tek parti (tek geçiş)
    # Üst sınır: 32 worker × 8 ağır = 256 ama PORT_QUEUE_MAX_BATCHES'e kısılır.
    assert host_batch_count(10_000, 32, heavy=True) == PORT_QUEUE_MAX_BATCHES
    assert host_batch_count(0, 8, heavy=False) == 1  # boş → en az 1 (bölme-sıfır koruması)


def test_split_host_queue() -> None:
    """HOST-QUEUE bölmesi: host'lar M strided partiye yayılır; TÜM host'lar kapsanır (kayıp yok)."""
    from cybersectool.core.scan_policy import split_host_queue

    hosts = [f"10.0.0.{i}" for i in range(1, 41)]  # 40 host
    # Ağır mod: 8×8=64 ama host=40 → 40 parti (her host ayrı), hafif: 8×3=24 parti.
    heavy = split_host_queue(hosts, 8, heavy=True)
    light = split_host_queue(hosts, 8, heavy=False)
    assert len(heavy) == 40  # host sayısıyla kısıtlı
    assert len(light) == 24  # 8×3
    assert len(heavy) > len(light)  # ağır = daha ince granül
    # Host kaybı yok + tekrar yok (her host TAM bir partide — overlap yok → prune güvenli).
    for batches in (heavy, light):
        flat = [h for b in batches for h in b]
        assert sorted(flat) == sorted(hosts)
        assert len(flat) == len(set(flat))
        assert all(b for b in batches)  # boş parti yok
    # Tek host → tek parti (tek geçiş, fan-out overhead'i yok).
    assert split_host_queue(["10.0.0.9"], 8, heavy=True) == [["10.0.0.9"]]
    assert split_host_queue([], 8, heavy=False) == []
