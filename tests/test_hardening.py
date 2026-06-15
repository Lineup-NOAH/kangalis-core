"""Host sıkılaştırma denetim değerlendirme (saf) testleri."""

from __future__ import annotations

from cybersectool.core.models import Severity
from cybersectool.scanners.hardening import (
    eval_empty_password,
    eval_empty_pw_ssh,
    eval_max_auth_tries,
    eval_root_login,
    eval_tmp_sticky,
)


def test_eval_root_login() -> None:
    verdict = eval_root_login("PermitRootLogin yes")
    assert verdict is not None and verdict[0] == Severity.high
    assert eval_root_login("PermitRootLogin no") is None
    assert eval_root_login("none") is None


def test_eval_empty_password() -> None:
    verdict = eval_empty_password("baduser\n")
    assert verdict is not None and verdict[0] == Severity.critical
    assert eval_empty_password("") is None


def test_eval_tmp_sticky() -> None:
    assert eval_tmp_sticky("drwxrwxrwt 2 root root 4096 /tmp") is None
    verdict = eval_tmp_sticky("drwxrwxrwx 2 root root 4096 /tmp")
    assert verdict is not None and verdict[0] == Severity.medium


def test_eval_empty_pw_ssh() -> None:
    """VII-1b: PermitEmptyPasswords yes → high; no/none → temiz."""
    verdict = eval_empty_pw_ssh("PermitEmptyPasswords yes")
    assert verdict is not None and verdict[0] == Severity.high
    assert eval_empty_pw_ssh("PermitEmptyPasswords no") is None
    assert eval_empty_pw_ssh("none") is None


def test_eval_max_auth_tries() -> None:
    """VII-1b: MaxAuthTries >4 ya da ayarsız → bulgu; <=4 → temiz."""
    assert eval_max_auth_tries("MaxAuthTries 4") is None
    assert eval_max_auth_tries("MaxAuthTries 3") is None
    over = eval_max_auth_tries("MaxAuthTries 6")
    assert over is not None and over[0] == Severity.low
    unset = eval_max_auth_tries("none")
    assert unset is not None and unset[0] == Severity.low
