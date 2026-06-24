"""Sorumluluk reddi (DISCLAIMER.md) kapısı — ortak etkinlik anahtarı.

Kapı iki yerde zorlanır: (1) girişte kabul edilmemişse ``/disclaimer`` ekranına yönlendirme
(``web/routes.py``), (2) ``/scans*`` isteklerinde middleware engeli (``api/app.py``). İkisi de
bu tek fonksiyonu çağırır.

Üretimde **her zaman True** — sorumluluk reddi kabul edilmeden tarama yapılamaz. Bu fonksiyon
yalnızca bir **test dikişi** olarak ayrı durur: kapı kesişen (cross-cutting) bir kısıt olduğundan,
onu sınamayan testler ``conftest`` içinden tek noktadan kapatır; kapının kendisi kendi özel
testinde (``@pytest.mark.disclaimer_gate``) gerçek haliyle doğrulanır. Çağıranlar bunu modül
üzerinden (``disclaimer.disclaimer_enforced()``) çağırır ki monkeypatch çalışsın.
"""

from __future__ import annotations


def disclaimer_enforced() -> bool:
    """Sorumluluk reddi kapısı etkin mi? Üretimde daima True (yukarıdaki nota bakın)."""
    return True
