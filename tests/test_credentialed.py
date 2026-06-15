"""Credentialed (authenticated) tarama saf fonksiyon testleri (SSH gerektirmez)."""

from __future__ import annotations

from cybersectool.core.models import Severity
from cybersectool.scanners.credentialed import (
    count_packages,
    eval_pending_updates,
    eval_sudo_nopasswd,
    eval_world_writable,
    parse_os_release,
)

OS_RELEASE = """\
NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
PRETTY_NAME="Ubuntu 22.04.3 LTS"
ID=ubuntu
"""


def test_parse_os_release() -> None:
    assert parse_os_release(OS_RELEASE) == "Ubuntu 22.04.3 LTS"
    assert parse_os_release("") is None
    assert parse_os_release("ID=alpine\n") is None


def test_count_packages() -> None:
    assert count_packages(".\n.\n.\n") == 3
    assert count_packages("") == 0
    assert count_packages("\n\n") == 0


def test_eval_pending_updates() -> None:
    none_pending = "Reading package lists...\n"
    assert eval_pending_updates(none_pending) is None

    few = "Inst libc6 [2.35] (2.36 Ubuntu:22.04)\nInst openssl [3.0.2] (3.0.3 ...)\n"
    verdict = eval_pending_updates(few)
    assert verdict is not None
    assert verdict[0] == Severity.medium
    assert "2 paket" in verdict[1]

    many = "\n".join(f"Inst pkg{i} [1.0] (1.1 ...)" for i in range(25))
    verdict_many = eval_pending_updates(many)
    assert verdict_many is not None
    assert verdict_many[0] == Severity.high


def test_eval_sudo_nopasswd() -> None:
    assert eval_sudo_nopasswd("%admin ALL=(ALL) ALL\n") is None
    # Yorum satırı sayılmamalı.
    assert eval_sudo_nopasswd("# deploy ALL=(ALL) NOPASSWD: ALL\n") is None
    verdict = eval_sudo_nopasswd("deploy ALL=(ALL) NOPASSWD: ALL\n")
    assert verdict is not None
    assert verdict[0] == Severity.high
    assert "NOPASSWD" in verdict[1]


def test_eval_world_writable() -> None:
    assert eval_world_writable("") is None
    verdict = eval_world_writable("/etc/passwd\n/etc/shadow\n")
    assert verdict is not None
    assert verdict[0] == Severity.medium
    assert "/etc/passwd" in verdict[1]
