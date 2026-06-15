"""Iskelet duman testi: paket ve alt paketler import edilebiliyor mu?"""

from __future__ import annotations

import importlib

import cybersectool

SUBPACKAGES = ("core", "scanners", "intel", "api", "web", "tasks", "mcp")


def test_version() -> None:
    assert cybersectool.__version__ == "0.1.0"


def test_subpackages_importable() -> None:
    for name in SUBPACKAGES:
        importlib.import_module(f"cybersectool.{name}")
