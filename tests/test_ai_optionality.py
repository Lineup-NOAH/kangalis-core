"""AI-OPSİYONEL SÖZLEŞMESİ testleri (Faz 0) — uygulama AI'a BEL BAĞLAMADAN tam çalışır.

``core/ai/__init__.AI_OPTIONAL_CONTRACT`` kurallarını CI'da zorlar. Yeni HER AI özelliği eklenmeden
ÖNCE bu testler yeşil olmalı: (1) çekirdek motor AI'ı İTHAL ETMEZ, (2) AI modülleri sözdizimsel
sağlam, (3) ai_enabled=False iken config kullanılamaz, (4) AI route'ları kapalıyken graceful (200),
(5) çekirdek sayfalar AI kapalıyken bozulmadan render olur.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import cybersectool
from cybersectool.core.ai import AIConfig
from cybersectool.core.models import Role
from cybersectool.core.users import create_user

_PKG = Path(cybersectool.__file__).parent

# AI'a ASLA sert-bağımlı olmaması gereken çekirdek motor modülleri (tarama/exploit/bulgu/çözüm).
# AI yalnız web/settings katmanından (routes.py top-level + app_settings.py lazy) bağlanır.
_ENGINE_MODULES = (
    "core/remediation.py",
    "core/findings.py",
    "core/vuln.py",
    "core/scans.py",
    "core/exploits.py",
    "core/exploit_attempts.py",
    "core/notify.py",  # bildirim: AI özetini AIExplanation önbelleğinden SALT-OKUR (import etmez)
    "tasks/network_scan.py",
    "tasks/web_scan.py",
    "tasks/sca_scan.py",
    "scanners/network.py",
)


def _ai_imports(py_path: Path) -> list[str]:
    """Dosyadaki ``cybersectool.core.ai`` import'larını döndürür (ast ile, çalıştırmadan)."""
    tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
            "cybersectool.core.ai"
        ):
            hits.append(f"from {node.module}")
        elif isinstance(node, ast.Import):
            hits.extend(
                f"import {a.name}" for a in node.names if a.name.startswith("cybersectool.core.ai")
            )
    return hits


def test_core_engine_does_not_import_ai() -> None:
    """SÖZLEŞME: çekirdek motor modülleri ``cybersectool.core.ai``'dan İTHAL ETMEZ."""
    offenders = {rel: hits for rel in _ENGINE_MODULES if (hits := _ai_imports(_PKG / rel))}
    assert not offenders, f"Çekirdek motor AI'a sert-bağımlı (opsiyonellik ihlali): {offenders}"


def test_all_ai_modules_parse() -> None:
    """AI paketindeki her modül sözdizimsel sağlam (bozuk AI kodu uygulamayı çökertmesin)."""
    for p in sorted((_PKG / "core" / "ai").glob("*.py")):
        ast.parse(p.read_text(encoding="utf-8"), filename=str(p))


def test_aiconfig_disabled_ignores_endpoint() -> None:
    """ai_enabled=False iken endpoint+model dolu olsa BİLE config kullanılamaz (tek anahtar)."""
    row = SimpleNamespace(
        ai_enabled=False,
        ai_endpoint_url="http://x:1234/v1",
        ai_model_name="qwen3:8b",
        ai_timeout_sec=60,
    )
    assert AIConfig.from_app_settings(row).available is False


async def _login(
    client: AsyncClient,
    factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role = Role.admin,
) -> None:
    async with factory() as session:
        await create_user(session, username, "pass1234", role=role)
    await client.post("/auth/login", json={"username": username, "password": "pass1234"})


async def test_ai_routes_graceful_when_disabled(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """AI VARSAYILAN KAPALI: /ai/explain + /ai/summary + /ai/priorities HTTP 200 (asla 500)."""
    await _login(client, session_factory, "aiopt", Role.admin)
    r1 = await client.post("/ai/explain", data={"cve_id": "CVE-2021-41773"})
    assert r1.status_code == 200
    r2 = await client.post("/ai/summary", data={"scope": "all"})
    assert r2.status_code == 200
    r3 = await client.post("/ai/priorities", data={"scope": "all"})
    assert r3.status_code == 200
    r5 = await client.post("/ai/remediation-script", data={"finding_id": 1})
    assert r5.status_code == 200
    r6 = await client.post("/ai/asset-story", data={"asset_id": 1, "scope": "all"})
    assert r6.status_code == 200


async def test_key_pages_render_with_ai_disabled(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """AI kapalıyken çekirdek sayfalar bozulmadan render olur (sıfır regresyon)."""
    await _login(client, session_factory, "aiopt2", Role.admin)
    for path in ("/", "/vulnerabilities", "/settings", "/scans"):
        resp = await client.get(path)
        assert resp.status_code == 200, f"{path} → {resp.status_code} (AI kapalıyken sayfa bozuldu)"
