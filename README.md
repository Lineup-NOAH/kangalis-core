# Kangalis

> **The guardian of your internal network** — a Python-based vulnerability management platform with a web dashboard, focused primarily on **internal network/system scanning**.

[![CI](https://github.com/Lineup-NOAH/kangalis-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Lineup-NOAH/kangalis-core/actions/workflows/ci.yml)
[![version](https://img.shields.io/badge/version-1.0.1-blue)]()
[![python](https://img.shields.io/badge/python-3.12%2B-blue)]()
[![license](https://img.shields.io/badge/license-MIT-green)]()

A lightweight OpenVAS/Nessus alternative: it discovers hosts and services on your internal
network, matches them against known vulnerabilities (CVEs), and enriches them with
**exploitability signals** (Exploit-DB, CISA KEV, EPSS) to deliver **risk prioritization**.
It can also talk to Claude over **MCP**.

> ⚠️ **Legal notice:** This tool must be used only within an **authorized scope** (networks you
> own or are permitted to test). Unauthorized scanning is illegal. The software is provided
> **"as is", without warranty**; using it means you accept the [Disclaimer](DISCLAIMER.md).

## 📦 Open-source core

This repository is the **open-source core** (MIT): network/host discovery, port & service/version
detection, CVE matching, exploitability **signals** (Exploit-DB/CISA KEV/EPSS — *informational
only*), compliance checks (CIS/KVKK/ISO/PCI), reporting, and local (on-prem) defensive AI. It
**does *not* run exploits.** Real exploitation/intrusion (Metasploit orchestration, sandboxed PoC
execution, credential brute-force) is kept in a separate, optional **exploitation plugin** and is
**not** part of this repository. The core is fully functional without the plugin.

> **nmap required:** The scan engine invokes the `nmap` binary; scanning **does not work** without
> it. You don't need to install it manually — it is added to the image **automatically** during
> `docker compose up --build` (`ARG INSTALL_NMAP=true`, on by default). nmap is distributed under
> the **NPSL** (Nmap Public Source License); Kangalis does not redistribute the binary — your build
> pulls it from the Debian repository.
> Details: [`docs/KURULUM.md`](docs/KURULUM.md) and [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).

## Features

- 🔍 **Network & host scanning** — host discovery, port scanning, service/version detection (nmap)
- 🛡️ **CVE matching + risk score** — NVD/OSV + Exploit-DB + CISA KEV + EPSS
- 🌐 **Web scanning** — security headers, TLS/SSL checks, directory discovery
- 📦 **SCA** — dependency (requirements.txt, package.json) vulnerability scanning
- ✅ **Compliance checks** — CIS/KVKK/ISO/PCI controls and reporting
- 🤖 **MCP server** — Claude starts scans and queries results
- 🧠 **Local (on-prem) defensive AI** — finding summaries and compliance narratives
- 📊 **Web dashboard** — HTMX + Tailwind

Architecture/design: [`docs/PROJE_PLANI.md`](docs/PROJE_PLANI.md)

## Installation (quick start)

**Only prerequisite: Docker + Docker Compose.** Runs entirely **on-prem**: scanning, data, and AI
all stay on your own machine — no data ever leaves it.

### Option 1 — Setup wizard (easiest; builds from source)

One command: build + start → migrate runs **automatically** → prompts for an admin user → prompts
for the authorized scan scope/CIDR. Everything including `nmap` lands in the image automatically
(no manual install).

```bash
# Linux / macOS
bash setup.sh          # or:  make setup

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File setup.ps1
```

### Option 2 — With the published image (no build; faster)

Pull the prebuilt images straight from the registry (ghcr.io) and run — no local build required:

```bash
git clone https://github.com/Lineup-NOAH/kangalis-core.git && cd kangalis-core
cp .env.example .env              # fill in the secret keys (or run the Option 1 wizard)

docker compose pull              # pulls the published core image (NO build)
docker compose up -d             # starts; migrate sets up the schema automatically

# Admin user + authorized scan scope (REQUIRED):
docker compose exec app python -m cybersectool.scripts.create_user \
    --username <name> --password <password> --role admin
# Define the scope from the panel (Settings → Authorized Scope) or via docs/KURULUM.md §3.3.
```

> To pin a version, set `KANGALIS_IMAGE=ghcr.io/lineup-noah/kangalis-core:vX.Y.Z` in `.env`.

Then open the panel: **http://localhost:8000/login**

> ⚠️ Scanning will not run until an authorized **scope** (CIDR) is defined. Enter only networks
> you are **authorized** to scan.

### Reset / clean reinstall

If the install breaks or you want to change the DB user/password, the **old database volume
conflicts with the new `.env`** (`migrate` → `password authentication failed for user ...`).
PostgreSQL bakes the user/password only on first launch; deleting the folder/Docker **does not
remove the volume**. One command for a clean reset:

```bash
# Windows
powershell -ExecutionPolicy Bypass -File reset.ps1

# Linux / macOS
bash reset.sh
```

> ⚠️ This **deletes** all scan data (`docker compose down -v` + every `kangalis*` volume).
> Then reinstall with `setup.ps1`/`setup.sh` or `docker compose up -d --build`.
> It keeps your `.env` (secret keys); for a from-scratch wipe add `-IncludeEnv` / `--include-env`.
> Manually: `docker compose down -v` → run `docker volume rm <name>` until
> `docker volume ls | grep kangalis` is empty.

### Local AI (optional, on-prem, zero egress)

The AI is fully local (runs on CPU); it only produces suggestions/drafts, and a human always
triggers the action. **Recommended path — Ollama** (official `ollama/ollama` image; the model is
pulled at runtime):

```bash
docker compose --profile ai up -d ollama          # Ollama engine (Docker Hub, public)
docker compose exec ollama ollama pull qwen3:8b   # download the model (~5 GB, one-time)
```

Then in the panel under **Plugins → AI**: endpoint `http://ollama:11434/v1`, model `qwen3:8b`,
click "Test connection" → green.

> **Air-gap / zero runtime download (optional):** you can use the `kangalis-ai` image that ships the
> model **baked in** (`-f docker-compose.ai-baked.yml`). To pull the published image, the ghcr
> package must be **public** — otherwise you'll get `unauthorized`. Alternative: build it locally on
> an internet-connected machine (`bash build-ai-image.sh` / `powershell -File build-ai-image.ps1`).
> Details: [`docs/EKLENTILER.md`](docs/EKLENTILER.md).

- 📘 Detailed install / manual steps / production deployment: [`docs/KURULUM.md`](docs/KURULUM.md)
- 🧩 Optional features (local AI, MCP, plugins): [`docs/EKLENTILER.md`](docs/EKLENTILER.md)

## Tech stack

| Layer | Choice |
|---|---|
| Language / packaging | Python 3.12+ · uv |
| Backend | FastAPI |
| Database | PostgreSQL + SQLAlchemy + Alembic |
| Task queue | Celery + Redis |
| Frontend | Jinja2 + HTMX + Tailwind |
| Scanning | nmap, httpx |
| Deployment | Docker + docker-compose |

## Development environment

Requirement: [uv](https://docs.astral.sh/uv/) (uv downloads Python itself).

```bash
# Install dependencies (including Python 3.12)
uv sync

# Run the tests
uv run pytest

# Lint & type checks
uv run ruff check .
uv run mypy

# (Optional) install the pre-commit hooks
uv run pre-commit install
```

## Project structure

```
src/cybersectool/
├── core/        # shared business logic (service layer) + scope guard
├── scanners/    # scan modules (network, web, sca, hardening)
├── intel/       # vulnerability/exploit data sources (NVD, OSV, EDB, KEV, EPSS)
├── api/         # FastAPI routers
├── web/         # dashboard (Jinja2 + HTMX)
├── tasks/       # Celery tasks
└── mcp/         # MCP server
```

## Contributing / workflow

Fork + PR to **main**. Conventional Commits. Every PR must pass `ruff` + `mypy` + `pytest`.
Details: [CONTRIBUTING.md](CONTRIBUTING.md)

## License

[MIT](LICENSE) © 2026 Lineup-NOAH

- Third-party dependency licenses: [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)
- Security & responsible/authorized use: [SECURITY.md](SECURITY.md)
- **Disclaimer & terms of use:** [DISCLAIMER.md](DISCLAIMER.md)
