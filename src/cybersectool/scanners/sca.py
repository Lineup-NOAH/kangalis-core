"""SCA — bağımlılık manifesti (requirements.txt / package.json) ayrıştırma.

Saf ayrıştırma fonksiyonları (birim testi edilebilir). OSV sorgusu `intel/osv.py`'de.
"""

from __future__ import annotations

import json
import re

_PINNED = re.compile(r"^([A-Za-z0-9_.\-]+)\s*==\s*([0-9][\w.\-]*)")


def parse_requirements(content: str) -> list[tuple[str, str]]:
    """`requirements.txt` içeriğinden sabitlenmiş (==) bağımlılıkları çıkarır."""
    deps: list[tuple[str, str]] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split(";")[0].strip()  # ortam işaretçilerini at
        match = _PINNED.match(line)
        if match:
            deps.append((match.group(1), match.group(2)))
    return deps


def parse_package_json(content: str) -> list[tuple[str, str]]:
    """`package.json` içeriğinden bağımlılıkları çıkarır (^~ önekleri temizlenir)."""
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return []
    deps: list[tuple[str, str]] = []
    for key in ("dependencies", "devDependencies"):
        section = data.get(key)
        if not isinstance(section, dict):
            continue
        for name, spec in section.items():
            version = str(spec).lstrip("^~>=< ").strip()
            if version and version[0].isdigit():
                deps.append((str(name), version))
    return deps
