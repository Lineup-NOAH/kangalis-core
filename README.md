# Kangalis

> **The guardian of your internal network** — a Python-based vulnerability management platform with a web dashboard, focused primarily on **internal network/system scanning**.

[![CI](https://github.com/Lineup-NOAH/kangalis-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Lineup-NOAH/kangalis-core/actions/workflows/ci.yml)
[![version](https://img.shields.io/badge/version-1.0.1-blue)]()
[![python](https://img.shields.io/badge/python-3.12%2B-blue)]()
[![license](https://img.shields.io/badge/license-MIT-green)]()

A lightweight, fully self-hosted internal-network vulnerability scanner: it discovers hosts and
services on your internal network, matches them against known vulnerabilities (CVEs), and enriches
them with
**exploitability signals** (Exploit-DB, CISA KEV, EPSS) to deliver **risk prioritization**.
It can also talk to Claude over **MCP**.

<p align="center">
  <img src="docs/architecture.svg" alt="Kangalis architecture — detect, match, prioritize; runs 100% on-prem; exploitation is a separate optional plugin" width="900">
</p>

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
> Details: [`docs/INSTALL.md`](docs/INSTALL.md) and [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).

## Features

- 🔍 **Network & host scanning** — host discovery, port scanning, service/version detection (nmap)
- 🛡️ **CVE matching + risk score** — NVD/OSV + Exploit-DB + CISA KEV + EPSS
- 🌐 **Web scanning** — security headers, TLS/SSL checks, directory discovery
- 📦 **SCA** — dependency (requirements.txt, package.json) vulnerability scanning
- ✅ **Compliance checks** — CIS/KVKK/ISO/PCI controls and reporting
- 🤖 **MCP server** — Claude starts scans and queries results
- 🧠 **Local (on-prem) defensive AI** — finding summaries and compliance narratives
- 📊 **Web dashboard** — HTMX + Tailwind

Architecture/design: [`docs/PROJECT_PLAN.md`](docs/PROJECT_PLAN.md)

## How it works

Most scanners hand you a wall of ten-thousand CVEs and walk away. Kangalis is built around one
question: **what here can actually hurt me — and what do I fix first?** It runs a tight
**detect → match → prioritize** pipeline, end to end, **on your own infrastructure** (see the
diagram above).

**Why each step matters**

- **1 · Discovery (nmap).** Battle-tested fingerprinting maps every live host, open port, and
  service version on your internal network — the ground truth everything else builds on.
- **2 · CVE matching — offline, on your box.** nmap tells us *what's running*; Kangalis matches that
  version against its **own local CVE/CPE database** (mirrored from NVD by a background sync).
  **No per-scan internet call — nothing about your network ever leaves your machine.** It runs fully
  **air-gapped**, a hard requirement for banks, OT/ICS, and other regulated environments that cloud
  scanners structurally can't meet.
- **3 · Risk prioritization, not a CVE dump.** Every match is enriched with real-world
  **exploitability signals** — Exploit-DB (a public exploit exists), **CISA KEV** (actively exploited
  in the wild), and **EPSS** (statistical exploit probability). The ~2% attackers actually use float
  to the top; the theoretical noise sinks.

**What makes Kangalis different**

- 🔒 **100% on-prem · zero egress.** Scanning, data, the vulnerability database, and the AI all stay
  on your hardware. Air-gap ready by design.
- 🎯 **Exploit-aware prioritization.** KEV + EPSS + Exploit-DB turn *"10,000 CVEs"* into *"these 12,
  today."*
- ✅ **Honest confidence.** Findings are labeled **NSE-confirmed** (actively verified) vs
  **version-inferred** (probable) — no false-positive theater.
- 🛡️ **Safe by default.** The default mode is non-intrusive; aggressive probing is **opt-in and
  gated**, so a scan won't knock over production.
- 🧠 **On-prem defensive AI.** A local model (Ollama) explains findings and drafts remediation — a
  human always pulls the trigger, and no data leaves the box.
- 🤖 **Claude-native (MCP).** Launch scans and query results straight from Claude.
- 📋 **Compliance built in.** CIS · KVKK · ISO 27001 · PCI-DSS controls and audit-ready reports.

**Scan modes**

| Mode | What it does |
|---|---|
| **Ping** | fast host discovery |
| **Network** | ports · services · versions (+ version-inferred CVEs) |
| **Safe CVE** | local CVE-DB matching, non-intrusive — **default** |
| **Aggressive CVE** | + live NVD + active NSE confirmation — *still never exploits*; opt-in / gated |
| **Web CVE** | web-stack CVEs (security headers · TLS · app) |
| **Credentialed** | authenticated audits (SSH/Windows/DB/SNMP/SMB/LDAP) + compliance |

(plus **SCA** for dependency manifests)

### 🧩 Exploitation — a separate, premium plugin (not in this repo)

The open-source core **finds and flags** exploitable CVEs but **never runs an exploit** — a clean,
defensive tool you can deploy anywhere with zero liability. To go from *"probably exploitable"* to
*proof*, the optional, license-gated **exploitation plugin** plugs in (Metasploit orchestration,
sandboxed Exploit-DB/searchsploit PoC runner, credential brute-force). The core ships only the
Exploit-DB **metadata signal** (*an exploit exists* — id ↔ CVE ↔ URL, informational); fetching and
**running** PoCs is the plugin's job.

## System requirements

Everything runs in Docker containers, so the host's **only** hard prerequisite is **Docker + Docker
Compose** — `nmap`, Python, PostgreSQL, Redis and (optionally) the local AI model are all provisioned
inside the images. Nothing to install by hand.

| Resource | Core (scanning + dashboard) | + Local AI (optional) |
|---|---|---|
| **CPU** | 2 cores (4 recommended) | 4 cores (8+ recommended — CPU inference) |
| **RAM** | 4 GB min · **8 GB recommended** | **+8 GB** → **16 GB** total recommended |
| **Disk** | ~5 GB (10 GB recommended) | **+6 GB** → ~15–20 GB |
| **GPU** | — | not required (CPU-only); a GPU only makes the AI faster |

**Operating system** — anything that runs Docker:
- **Linux** — native Docker Engine (recommended for production / air-gapped sites).
- **Windows 10/11** — Docker Desktop (WSL2 backend).
- **macOS 12+** — Docker Desktop (Apple Silicon or Intel).

**Software & connectivity**
- **Docker Engine 24+** and **Docker Compose v2** — the single hard requirement.
- Internet is needed only for the **first** build/pull and the CVE-database seed (~42 MB). After
  that the scanner — and the local AI — run **fully offline / air-gapped**.
- Optional: a free **NVD API key** for faster vulnerability-database sync.

**Where the footprint goes** (measured on a live install)
- Images: core ~0.9 GB · PostgreSQL ~0.6 GB · Redis ~0.15 GB.
- Vulnerability database: **~0.5 GB**, pre-seeded with ≈220 K CVEs + 1.3 M CPE rules at install.
- Local AI model `qwen3:8b`: **~5 GB** (one-time, stored in a Docker volume).

> **🧠 Local-AI memory (Docker Desktop on Windows/macOS).** The AI container needs ~8 GB to hold the
> model (`mem_limit`, env `AI_MEM_LIMIT`, default `8g`). Docker Desktop only allocates a *slice* of
> physical RAM (≈half by default), so on a **16 GB** laptop the AI may not fit. Give Docker ≥12 GB
> (Windows: `%UserProfile%\.wslconfig` → `memory=…`; or Docker Desktop → Settings → Resources), or
> lower `AI_MEM_LIMIT`. **The scanning core runs fine on 4–8 GB — the AI is entirely optional.**

> **⚙️ Local-AI CPU usage.** The model runs on CPU and uses the cores **only while generating** a
> reply (a few seconds per summary) — it idles at ~0 % the rest of the time. It scales with cores:
> **4 cores are enough** (slower replies), 8+ just answer faster. The scanning core itself needs only
> ~2. On a low-core host you can cap it with `OLLAMA_NUM_THREAD=N` (or a Compose `cpus:` limit) so an
> AI reply doesn't briefly take the whole box.

> **🌐 Network reachability.** Scans run from the worker container, so the host must have layer-3
> connectivity to the networks you scan (same subnet/VLAN, or a route to them).

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

> **Note:** the prebuilt image must be published and public for this to work. If `docker compose pull`
> reports `unauthorized` or `not found`, the image isn't available yet — use **Option 1** (build from
> source), which always works.

```bash
git clone https://github.com/Lineup-NOAH/kangalis-core.git && cd kangalis-core
cp .env.example .env              # fill in the secret keys (or run the Option 1 wizard)

docker compose pull              # pulls the published core image (NO build)
docker compose up -d             # starts; migrate sets up the schema automatically

# Admin user + authorized scan scope (REQUIRED):
docker compose exec app python -m cybersectool.scripts.create_user \
    --username <name> --password <password> --role admin
# Define the scope from the panel (Settings → Authorized Scope) or via docs/INSTALL.md §3.3.
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
> Details: [`docs/PLUGINS.md`](docs/PLUGINS.md).

- 📘 Detailed install / manual steps / production deployment: [`docs/INSTALL.md`](docs/INSTALL.md)
- 🧩 Optional features (local AI, MCP, plugins): [`docs/PLUGINS.md`](docs/PLUGINS.md)

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
