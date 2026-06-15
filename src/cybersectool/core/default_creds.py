"""Varsayılan/zayıf kimlik denetimi için küratörlü liste + servis eşleme (VI-12).

KASITLI OLARAK ÇOK KÜÇÜK liste — bu bir TAM brute-force DEĞİL; yalnızca en bilinen
varsayılan kimlikleri (admin/admin gibi) kontrol eder (Nessus default-cred / OpenVAS
"Default Accounts" dengi). Hesap kilidini tetiklememek için servis başına en fazla
``MAX_DEFAULT_CRED_ATTEMPTS`` deneme yapılır. Yalnız agresif + ack arkasında çalışır.
"""

from __future__ import annotations

# Servis başına en fazla deneme (lockout-farkında: tipik eşik 5; biz <=3 deniyoruz).
MAX_DEFAULT_CRED_ATTEMPTS = 3

# En yaygın varsayılan SSH kimlikleri (küçük, küratörlü — brute-force DEĞİL).
DEFAULT_SSH_CREDS: tuple[tuple[str, str], ...] = (
    ("root", "root"),
    ("root", "toor"),
    ("admin", "admin"),
)

# Gelecekte genişletme için servis→kimlik haritası (şimdilik yalnız SSH uygulanıyor).
_SSH_SERVICE_NAMES = {"ssh", "openssh"}


def creds_for_service(service_name: str | None, port: int) -> tuple[tuple[str, str], ...]:
    """Keşfedilen bir servise denenecek varsayılan kimlikleri döndürür (saf).

    Yalnızca SSH (servis adı ssh/openssh ya da port 22) için liste döner; aksi halde
    boş (diğer protokoller henüz uygulanmadı — çerçeve genişletilebilir).
    """
    name = (service_name or "").strip().lower()
    if name in _SSH_SERVICE_NAMES or port == 22:
        return DEFAULT_SSH_CREDS[:MAX_DEFAULT_CRED_ATTEMPTS]
    return ()
