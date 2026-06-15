"""Gerçek yetki yükseltme DENEMESİ (VIII-3b) — sahte SSH conn ile (SSH gerekmez).

_run_privesc_attempts: zaten-root atlama + vektörle root doğrulama → KRİTİK validated bulgu.
"""

from __future__ import annotations

from cybersectool.core.models import Severity
from cybersectool.scanners.credentialed import _run_privesc_attempts


class _FakeResult:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout


class _FakeConn:
    """Komuta göre kanıtlı çıktı döndüren sahte SSH bağlantısı."""

    def __init__(self, whoami: str, attempt_outputs: dict[str, str]) -> None:
        self._whoami = whoami
        self._attempts = attempt_outputs

    async def run(self, command: str, check: bool = False) -> _FakeResult:
        if command.startswith("id "):  # whoami probu
            return _FakeResult(self._whoami)
        for key, out in self._attempts.items():
            if key in command:
                return _FakeResult(out)
        return _FakeResult("")


async def test_privesc_attempt_confirms_sudo_root() -> None:
    """Parolasız sudo root verirse KRİTİK + doğrulanmış 'DOĞRULANDI' bulgusu üretilir."""
    conn = _FakeConn(
        whoami="uid=1000(msfadmin) gid=1000(msfadmin)",
        attempt_outputs={"sudo -n": "uid=0(root) gid=0(root) groups=0(root)"},
    )
    findings = await _run_privesc_attempts(conn)  # type: ignore[arg-type]
    confirmed = [f for f in findings if f.title.startswith("Yetki yükseltme DOĞRULANDI")]
    assert len(confirmed) == 1
    assert "parolasız sudo" in confirmed[0].title
    assert confirmed[0].severity == Severity.critical
    assert confirmed[0].validated is True
    assert "uid=0" in confirmed[0].detail


async def test_privesc_attempt_no_vector_no_finding() -> None:
    """Hiçbir vektör root vermezse doğrulanmış bulgu OLUŞMAZ (yanlış-pozitif yok)."""
    conn = _FakeConn(
        whoami="uid=1000(msfadmin) gid=1000(msfadmin)",
        attempt_outputs={},  # tüm denemeler boş döner
    )
    findings = await _run_privesc_attempts(conn)  # type: ignore[arg-type]
    assert not any(f.title.startswith("Yetki yükseltme DOĞRULANDI") for f in findings)


async def test_privesc_attempt_already_root_skips() -> None:
    """Oturum zaten root ise deneme yapılmaz (info bulgusu)."""
    conn = _FakeConn(
        whoami="uid=0(root) gid=0(root)",
        attempt_outputs={"sudo -n": "uid=0(root)"},  # çağrılmamalı
    )
    findings = await _run_privesc_attempts(conn)  # type: ignore[arg-type]
    assert len(findings) == 1
    assert "zaten root" in findings[0].title
    assert findings[0].severity == Severity.info
