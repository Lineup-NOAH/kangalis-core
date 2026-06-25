"""Iskelet duman testi: paket ve alt paketler import edilebiliyor mu?"""

from __future__ import annotations

import importlib
import re

import cybersectool

SUBPACKAGES = ("core", "scanners", "intel", "api", "web", "tasks", "mcp")


def test_version() -> None:
    # Semver string; the exact value bumps each release, so assert the shape, not a literal.
    assert re.fullmatch(r"\d+\.\d+\.\d+", cybersectool.__version__)


def test_subpackages_importable() -> None:
    for name in SUBPACKAGES:
        importlib.import_module(f"cybersectool.{name}")
