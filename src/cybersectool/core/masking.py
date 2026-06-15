"""Kimlik bilgisi maskeleme yardımcıları (bulgu metinlerinde düz parola gösterilmez).

``mask_password`` zayıf/varsayılan-kimlik (VI-12) bulgularında bulunan parolayı maskeler;
saf bir yardımcıdır, hiçbir tarama/sömürü mantığına bağlı değildir (açık-kaynak çekirdek).
"""

from __future__ import annotations


def mask_password(password: str) -> str:
    """Parolayı bulgu metni için maskeler — ilk/son karakter görünür, ortası gizli."""
    n = len(password)
    if n == 0:
        return "(boş)"
    if n <= 2:
        return "*" * n + f" ({n} hane)"
    return f"{password[0]}{'*' * (n - 2)}{password[-1]} ({n} hane)"
