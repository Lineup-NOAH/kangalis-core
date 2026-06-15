"""İnteraktif kelime listesi üreticileri — kullanıcı adı + parola.

Saf/deterministik fonksiyonlar; Kelime Listeleri sayfasındaki "Üretici" kutularından VE
yerleşik liste üretiminden (``wordlist_defaults``) çağrılır. Üretim tarama YAPMAZ — yalnız
kelime listesi üretir; üretilen liste mevcut GATED brute/spray kapısından geçer.

* Kullanıcı adı: operatör GERÇEK ad-soyad listesini girer → kurumsal kullanıcı-adı
  kalıpları (``generate_usernames``). TR karakter ASCII'ye indirgenir (AD/LDAP genelde
  ASCII): ``İ/ı→i, ş→s, ğ→g, ü→u, ö→o, ç→c`` (``normalize_tr``).
* Parola: operatör taban kelimeler + örnek parolalar girer, parola politikası sorularını
  yanıtlar (min uzunluk, gerekli karakter sınıfları, sonek, yıl, leet) → politikaya uyan
  aday parola listesi (``generate_passwords`` + ``PasswordSpec``).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

# Türkçe karakter → ASCII (kullanıcı adı normalizasyonu). Büyük harfler de eklendi.
_TR_MAP = str.maketrans(
    {
        "ı": "i",
        "İ": "i",
        "ş": "s",
        "Ş": "s",
        "ğ": "g",
        "Ğ": "g",
        "ü": "u",
        "Ü": "u",
        "ö": "o",
        "Ö": "o",
        "ç": "c",
        "Ç": "c",
    }
)

# Desteklenen kullanıcı-adı kalıpları (sıra = üretim/önizleme sırası). UI checkbox'ları
# bu anahtarları gönderir; bilinmeyen anahtarlar sessizce atılır.
USERNAME_PATTERN_KEYS: tuple[str, ...] = (
    "flast",  # ayilmaz       (ad-baş + soyad)
    "first.last",  # ahmet.yilmaz
    "f.last",  # a.yilmaz
    "firstlast",  # ahmetyilmaz
    "first_last",  # ahmet_yilmaz
    "first",  # ahmet
    "firstl",  # ahmety        (ad + soyad-baş)
)

# Kalıpsız (soyadı olmadan) da üretilebilen kalıplar — tek kelimelik girişlerde geçerli.
_NO_LAST_OK = frozenset({"firstlast", "first", "firstl"})


def normalize_tr(text: str) -> str:
    """Türkçe karakterleri ASCII'ye indirir + küçük harfe çevirir + uçları kırpar."""
    return text.translate(_TR_MAP).strip().lower()


def parse_name_pairs(text: str) -> list[tuple[str, str]]:
    """Serbest metinden (satır veya virgül ayrık) ad-soyad çiftleri çıkarır.

    Her kayıt 'Ad Soyad' (boşlukla ayrık). Tek kelime → ``(ad, "")``. İkiden çok kelime →
    ilk=ad, son=soyad (ortadaki ikinci adlar yok sayılır). Boş satırlar atlanır.
    """
    pairs: list[tuple[str, str]] = []
    for raw_line in text.replace(",", "\n").splitlines():
        parts = raw_line.split()
        if not parts:
            continue
        first = parts[0]
        last = parts[-1] if len(parts) > 1 else ""
        pairs.append((first, last))
    return pairs


def _apply_username_pattern(key: str, first: str, last: str) -> str | None:
    """Tek kalıbı uygular; üretilemiyorsa (örn. soyad yok) ``None`` döner."""
    fi = first[:1]
    li = last[:1]
    if key == "flast":
        return f"{fi}{last}" if last else None
    if key == "first.last":
        return f"{first}.{last}" if last else None
    if key == "f.last":
        return f"{fi}.{last}" if last else None
    if key == "firstlast":
        return f"{first}{last}"
    if key == "first_last":
        return f"{first}_{last}" if last else None
    if key == "first":
        return first
    if key == "firstl":
        return f"{first}{li}" if last else first
    return None


def apply_custom_pattern(template: str, first: str, last: str) -> str | None:
    """Operatörün özel kalıbını uygular: token ikamesi ``{first}/{last}/{f}/{l}``.

    ``{f}``=ad baş harfi, ``{l}``=soyad baş harfi. Şablon soyad gerektiren bir token
    (``{last}`` veya ``{l}``) içeriyor ama soyad yoksa → ``None`` (atla). Boş sonuç → None.
    Token'lar zaten normalize edilmiş ``first``/``last`` ile doldurulur.
    """
    needs_last = "{last}" in template or "{l}" in template
    if needs_last and not last:
        return None
    result = (
        template.replace("{first}", first)
        .replace("{last}", last)
        .replace("{f}", first[:1])
        .replace("{l}", last[:1])
    )
    return result or None


def generate_usernames(
    pairs: Iterable[tuple[str, str]],
    patterns: Iterable[str] | None = None,
    *,
    normalize: bool = True,
    custom_patterns: Iterable[str] | None = None,
) -> list[str]:
    """Ad-soyad çiftlerinden seçili kalıplarla kullanıcı adı üretir (deterministik, dedup).

    ``patterns`` None → tüm preset kalıplar (``USERNAME_PATTERN_KEYS`` sırasında).
    ``custom_patterns`` verilirse her preset'ten SONRA operatörün ``{first}/{last}/{f}/{l}``
    token'lı şablonları uygulanır. ``normalize`` True → Türkçe karakter ASCII + küçük harf.
    Sıra korunur; tekrar edenler elenir. (kurumsal üretici davranışıyla aynı.)
    """
    if patterns is None:
        keys: tuple[str, ...] = USERNAME_PATTERN_KEYS
    else:
        wanted = set(patterns)
        # Kanonik sırayı koru, yalnız istenen + bilinen kalıpları al.
        keys = tuple(k for k in USERNAME_PATTERN_KEYS if k in wanted)

    customs = [c.strip() for c in (custom_patterns or []) if c.strip()]

    seen: set[str] = set()
    out: list[str] = []

    def _add(username: str | None) -> None:
        if username and username not in seen:
            seen.add(username)
            out.append(username)

    for first_raw, last_raw in pairs:
        first = normalize_tr(first_raw) if normalize else first_raw.strip()
        last = normalize_tr(last_raw) if normalize else last_raw.strip()
        if not first:
            continue
        for key in keys:
            if not last and key not in _NO_LAST_OK:
                continue
            _add(_apply_username_pattern(key, first, last))
        for template in customs:
            _add(apply_custom_pattern(template, first, last))
    return out


# ===========================================================================
# Parola üretici — taban kelime + örnek parola + politika → uyumlu aday liste
# ===========================================================================

# Leet (1337) eşlemesi — kurumsal spray'de yaygın karakter ikameleri.
_LEET_MAP = str.maketrans(
    {
        "a": "@",
        "A": "@",
        "o": "0",
        "O": "0",
        "i": "1",
        "I": "1",
        "s": "$",
        "S": "$",
        "e": "3",
        "E": "3",
    }
)

# Üst sınır — aşırı kombinasyonda kelime listesini sertçe sınırla (kilit/sel riski).
MAX_GENERATED_PASSWORDS = 5000


@dataclass
class PasswordSpec:
    """Parola üretim + politika filtre parametreleri (UI'daki sorulardan beslenir).

    Üretim: her taban kelimeden kökler (olduğu gibi / Baş-harf-büyük / leet) türetilir;
    her köke sayı eki (``digits`` + ``years``) ve sonra son-ek (``suffixes``) eklenir.
    Sonra YALNIZ politikaya (``min_len`` + gerekli karakter sınıfları) uyanlar tutulur.
    """

    min_len: int = 8
    require_upper: bool = True
    require_lower: bool = True
    require_digit: bool = True
    require_special: bool = False
    capitalize: bool = True  # 'sirket' → 'Sirket' kökü de eklenir
    leet: bool = False  # 'Sirket' → 'S1rk3t' kökü de eklenir
    digits: tuple[str, ...] = ("1", "12", "123", "1234", "123456")
    years: tuple[int, ...] = ()  # ör. (2023, 2024, 2025, 2026)
    suffixes: tuple[str, ...] = ("", "!", ".")
    max_results: int = MAX_GENERATED_PASSWORDS


def password_passes_policy(password: str, spec: PasswordSpec) -> bool:
    """Parola, ``spec`` politikasını (uzunluk + gerekli karakter sınıfları) sağlıyor mu?"""
    if len(password) < spec.min_len:
        return False
    if spec.require_upper and not any(c.isupper() for c in password):
        return False
    if spec.require_lower and not any(c.islower() for c in password):
        return False
    if spec.require_digit and not any(c.isdigit() for c in password):
        return False
    # Özel karakter gerekiyorsa en az bir alfanümerik-olmayan karakter bulunmalı.
    return not spec.require_special or any(not c.isalnum() for c in password)


def _password_roots(base: str, spec: PasswordSpec) -> list[str]:
    """Tek taban kelimeden kökler: olduğu gibi + (ops.) baş-harf-büyük + (ops.) leet."""
    roots: list[str] = [base]
    if spec.capitalize and base[:1].islower():
        roots.append(base[:1].upper() + base[1:])
    if spec.leet:
        for root in list(roots):
            leeted = root.translate(_LEET_MAP)
            if leeted != root:
                roots.append(leeted)
    return roots


def generate_passwords(
    bases: Iterable[str],
    spec: PasswordSpec | None = None,
    *,
    examples: Iterable[str] | None = None,
) -> list[str]:
    """Taban kelimelerden politika-uyumlu aday parolalar üretir (deterministik, dedup).

    ``examples`` verilirse (operatörün girdiği örnek parolalar): politikaya uyanlar
    DOĞRUDAN listeye eklenir (önce), ayrıca taban kelime gibi mutasyona da girer.
    Sıra korunur, tekrar elenir, ``spec.max_results`` sert üst sınırdır.
    """
    spec = spec or PasswordSpec()
    seen: set[str] = set()
    out: list[str] = []

    def _add(password: str) -> bool:
        """Ekler; üst sınıra ulaşıldıysa False döner (üretimi durdur)."""
        if password and password not in seen and password_passes_policy(password, spec):
            seen.add(password)
            out.append(password)
        return len(out) < spec.max_results

    # Sayı ekleri: sabit rakamlar + yıllar (sıra korunur, tekilleştirilir).
    number_tokens: list[str] = [""]
    for token in (*spec.digits, *(str(y) for y in spec.years)):
        if token not in number_tokens:
            number_tokens.append(token)

    # 1) Örnek parolalar: politikaya uyanları DOĞRUDAN ekle (operatörün verdiği gerçek kalıp).
    example_list = [e.strip() for e in (examples or []) if e.strip()]
    for example in example_list:
        if not _add(example):
            return out

    # 2) Taban kelimeler + örnekler → mutasyon (kök × sayı × sonek).
    for base_raw in (*bases, *example_list):
        base = base_raw.strip()
        if not base:
            continue
        for root in _password_roots(base, spec):
            for number in number_tokens:
                for suffix in spec.suffixes:
                    if not _add(f"{root}{number}{suffix}"):
                        return out
    return out
