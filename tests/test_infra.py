"""Aracın kendi altyapı IP tespiti (own_infra_ips) testleri."""

from __future__ import annotations

import pytest

from cybersectool.core.infra import own_infra_ips


def test_own_infra_ips_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """EXCLUDE_SCAN_IPS env'i (virgül/; ile) dışlama kümesine eklenir."""
    monkeypatch.setenv("EXCLUDE_SCAN_IPS", "10.1.1.1, 10.1.1.2 ;10.1.1.3")
    ips = own_infra_ips()
    assert {"10.1.1.1", "10.1.1.2", "10.1.1.3"} <= ips


def test_own_infra_ips_empty_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Env yok + Docker DNS yok (test ortamı) → patlamaz, küme döner."""
    monkeypatch.delenv("EXCLUDE_SCAN_IPS", raising=False)
    ips = own_infra_ips()
    assert isinstance(ips, set)
