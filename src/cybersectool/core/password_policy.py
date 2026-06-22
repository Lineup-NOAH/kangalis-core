"""Parola politikası doğrulaması — boşluk + uzunluk + (opsiyonel) karmaşıklık.

``app_settings``'teki ``password_min_length`` ve ``password_require_complexity``
değerlerine göre uygulanır. Yeni kullanıcı oluşturma / parola belirleme noktalarında
çağrılır. Uymuyorsa kullanıcıya gösterilecek hata mesajı (TR), uyuyorsa ``None`` döner.
"""

from __future__ import annotations


def validate_password(password: str, *, min_length: int, require_complexity: bool) -> str | None:
    """Politikaya uymayan parola için hata mesajı, uyan parola için None döndürür."""
    if not password.strip():
        return "Parola yalnızca boşluktan oluşamaz."
    if password != password.strip():
        return "Parola baştaki veya sondaki boşluk içeremez."
    if len(password) < min_length:
        return f"Parola en az {min_length} karakter olmalı."
    if require_complexity:
        has_alpha = any(c.isalpha() for c in password)
        has_digit = any(c.isdigit() for c in password)
        if not (has_alpha and has_digit):
            return "Parola en az bir harf ve bir rakam içermeli."
    return None
