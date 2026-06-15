"""Risk önceliklendirme skoru: CVSS + EPSS + KEV + exploit birleşimi (0-10).

- Taban: CVSS skoru (0-10)
- EPSS (sömürülme olasılığı) skoru en fazla +2 artırır
- KEV (aktif sömürü) +3 artırır
- Exploit sinyali: silahlandırılmış/Metasploit modülü +1.5, yalnızca herkese açık PoC +0.5
- 10 ile sınırlandırılır

Not (VI-1): Önceden elimizdeki ~69k exploit DB SADECE UI'da çip olarak gösteriliyordu;
risk skoruna hiç girmiyordu. Artık gerçek önceliklendirme motorunu besler.
"""

from __future__ import annotations

# "Acil" EPSS eşiği: bu olasılığın üstü hemen müdahale kovasına girer.
URGENT_EPSS_THRESHOLD = 0.5

# CVSS yokken (NVD "Awaiting Analysis" / yalnız önem etiketi) kullanılan taban skor (#136).
_SEVERITY_BASE = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "info": 1.0}
# KEV (aktif sömürülüyor) bir CVE en az "yüksek" sayılmalı — CVSS yoksa bile hafife alınmasın.
_KEV_FLOOR = 7.0


def compute_priority(
    cvss: float | None,
    epss: float | None,
    kev: bool,
    *,
    exploit_level: int = 0,
    severity: str | None = None,
) -> float:
    """Birleşik risk skoru (0-10).

    Taban: CVSS skoru; CVSS YOKSA ``severity`` etiketinden türetilir (#136 — yalnız CVSS v4
    yayımlanan ya da henüz skorlanmamış CVE'ler taban 0 ile hafife alınmasın). ``exploit_level``:
    0=yok, 1=herkese açık PoC (+0.5), 2=silahlandırılmış/Metasploit (+1.5). KEV (aktif sömürü)
    +3 VE skor en az ``_KEV_FLOOR`` (7.0) olur — CVSS yoksa bile aktif tehdit yüksek kalır.
    """
    score = cvss if cvss is not None else _SEVERITY_BASE.get((severity or "").lower(), 0.0)
    if epss is not None:
        score += epss * 2.0
    if kev:
        score += 3.0
    if exploit_level >= 2:
        score += 1.5
    elif exploit_level == 1:
        score += 0.5
    if kev:
        score = max(score, _KEV_FLOOR)
    return round(min(score, 10.0), 2)


def exploit_level_from_hit(count: int, weaponized: bool) -> int:
    """Exploit özetinden seviye türet: silahlandırılmış=2, sadece PoC=1, yok=0."""
    if count <= 0:
        return 0
    return 2 if weaponized else 1


def is_urgent(kev: bool, epss: float | None, weaponized: bool) -> bool:
    """'Acil' kovası: KEV (aktif sömürü) VEYA EPSS≥0.5 VEYA silahlandırılmış (Metasploit).

    Patron tanımı (VI-1): hemen müdahale gerektiren en yüksek öncelikli zafiyetler.
    """
    if kev or weaponized:
        return True
    return epss is not None and epss >= URGENT_EPSS_THRESHOLD
