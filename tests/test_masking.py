"""Kimlik-bilgisi maskeleme testleri — bulgu metninde düz parola gösterilmez (çekirdek).

``mask_password`` saf bir yardımcıdır (tarama/sömürü mantığına bağlı değil); zayıf/varsayılan
kimlik bulgularında parolayı ilk/son karakter görünür, ortası gizli olacak şekilde maskeler.
"""

from __future__ import annotations

from cybersectool.core.masking import mask_password


def test_mask_password() -> None:
    assert mask_password("") == "(boş)"
    assert mask_password("ab") == "** (2 hane)"
    assert mask_password("password") == "p******d (8 hane)"
