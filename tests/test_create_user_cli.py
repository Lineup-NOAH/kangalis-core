"""create_user CLI parola-çözümleme testleri (env / stdin / argv önceliği).

Parola argv'de taşınmasın diye kurulum sihirbazları ortam değişkenini ya da stdin'i
kullanır; bu testler _resolve_password önceliğini ve newline kırpmayı doğrular.
"""

from __future__ import annotations

import argparse
import io

import pytest

from cybersectool.scripts import create_user as cu


def _ns(**kwargs: object) -> argparse.Namespace:
    base: dict[str, object] = {"password_stdin": False, "password": None}
    base.update(kwargs)
    return argparse.Namespace(**base)


def test_password_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KANGALIS_ADMIN_PASSWORD", "env-secret")
    assert cu._resolve_password(_ns()) == "env-secret"


def test_arg_beats_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KANGALIS_ADMIN_PASSWORD", "env-secret")
    assert cu._resolve_password(_ns(password="arg-secret")) == "arg-secret"


def test_stdin_strips_trailing_newline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("stdin-secret\r\n"))
    assert cu._resolve_password(_ns(password_stdin=True)) == "stdin-secret"


def test_stdin_without_newline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("stdin-secret"))
    assert cu._resolve_password(_ns(password_stdin=True)) == "stdin-secret"


def test_stdin_beats_arg_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KANGALIS_ADMIN_PASSWORD", "env-secret")
    monkeypatch.setattr("sys.stdin", io.StringIO("stdin-secret\n"))
    got = cu._resolve_password(_ns(password_stdin=True, password="arg-secret"))
    assert got == "stdin-secret"


def test_no_source_raises_systemexit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KANGALIS_ADMIN_PASSWORD", raising=False)
    with pytest.raises(SystemExit):
        cu._resolve_password(_ns())


def test_empty_env_falls_through_to_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # Boş ortam değişkeni "verilmedi" sayılır (truthy değil) -> hata.
    monkeypatch.setenv("KANGALIS_ADMIN_PASSWORD", "")
    with pytest.raises(SystemExit):
        cu._resolve_password(_ns())
