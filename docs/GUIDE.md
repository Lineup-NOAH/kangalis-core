# Kangalis — Getting Started & User Guide

> The guardian of your internal network. This guide walks you through standing
> up Kangalis from scratch, creating your first user, accepting the Disclaimer,
> launching your first scan, and setting up the optional MCP integration.

---

## 1. 🚀 Running it (from scratch)

**The only prerequisite is Docker and Docker Compose.** You don't need to install
anything else by hand — every tool, including `nmap`, is pulled into the image
**automatically** during `docker compose up --build` (scanning won't work without
nmap; see the note below and `docs/INSTALL.md` for details).
Clone the repository and change into its directory.

### A) Single command — setup wizard (recommended)

The wizard does the following: **build + start → schema migration (automatic) → prompts
for the admin user → prompts for the authorized scan scope (CIDR).**

```powershell
# <repo-dir> = the root of the repository you cloned
cd <repo-dir>

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File setup.ps1

# Linux / macOS:  bash setup.sh        (or:  make setup)
```

### B) Manual steps (alternative)

```powershell
# <repo-dir> = the root of the repository you cloned
cd <repo-dir>

# 1) Start all services (app, db, redis, worker, beat, mcp)
#    Schema migration is AUTOMATIC (the migrate service applies the schema; you do NOT need to run 'alembic upgrade head' by hand).
docker compose up -d --build

# 2) Create the first user — set your own strong password
docker compose exec app python -m cybersectool.scripts.create_user --username <username> --password "<choose-a-strong-password>" --role admin

# 3) ⚠️ REQUIRED: authorized scan scope (no scan runs without it)
docker compose exec app python -m cybersectool.scripts.set_scope --name internal-net --allow 192.168.1.0/24 --allow 10.0.0.0/8

# Stop:  docker compose down        (data is preserved)
# Reset: docker compose down -v      (data is DELETED)
```

> **nmap (scan engine):** Not installed by hand; it is pulled into the image
> automatically during `docker compose up --build` (`ARG INSTALL_NMAP=true`, on by
> default). The tool **cannot** scan without nmap. nmap is distributed under the
> **NPSL**; Kangalis does not redistribute the binary — your build pulls it from
> the Debian repository. Details: `docs/INSTALL.md` and `THIRD-PARTY-NOTICES.md`.

> 📘 Detailed installation / moving to production: `docs/INSTALL.md` ·
> 🧩 optional features (local AI, MCP, plugins): `docs/PLUGINS.md`.

**Access addresses:**
| Service | Address |
|---|---|
| Web panel | http://localhost:8000/login |
| API docs (Swagger) | http://localhost:8000/docs |
| Remote MCP (token-based) | http://localhost:8001/mcp |
| PostgreSQL | localhost:5432 |
| Redis | localhost:6379 |

> Connection details (DATABASE_URL, REDIS_URL, SECRET_KEY, the PostgreSQL password,
> etc.) are configured through the Compose file and environment variables. For
> production use, see §5 — be sure to replace the default/development values with
> your own strong ones.

---

## 2. 🖥️ Using the Web Panel

Log in at `http://localhost:8000/login` with the username and password you created
in step 1.

> **First-login prerequisite — Disclaimer acceptance:** Before any scan or audit can
> start, the operator must read and accept the Disclaimer (`DISCLAIMER.md`). Scanning
> stays blocked until it is accepted, and each acceptance is recorded as an
> audit-logged event (`disclaimer_accepted`).

| Page | URL | What it does |
|---|---|---|
| Dashboard | `/` | Summary counters + severity breakdown |
| Scans | `/scans` | New scan (target + type: Network/Web) + Zone scan (safe/aggressive/credentialed) |
| Zones | `/zones` | Group IP/CIDR blocks into zones (management) |
| Assets | `/assets` | Inventory of discovered hosts/services |
| Vulnerabilities | `/findings` | CVEs — ranked by risk, with CVSS/Risk/KEV/EPSS |
| Exploit DB | `/exploits` | Local exploit-metadata repository (Exploit-DB + Metasploit), searchable by title/CVE/ID |
| Report | `/report` | Printable/PDF security report |
| Credentials | `/credentials` | Credential vault: SSH/WinRM/RDP credentials + credential zones (admin only) |
| Audit | `/audit` | Who did what (admin only) |

**Credential vault (`/credentials`, admin):** Create credentials for Windows/Linux/other
connections (name + type SSH/WinRM/RDP + user + password + domain/port). Passwords are
stored **encrypted with Fernet** and are never shown again in the panel. Group credentials
into **credential zones** (the credential counterpart of an IP zone).
API: `POST/GET/DELETE /api/credentials`, `POST/GET/DELETE /api/credential-zones`.
Encryption key: `CREDENTIAL_ENCRYPTION_KEY` (if empty, it is derived from SECRET_KEY; supply a separate one in production).

**IP zone × credential zone scan:** Scans → IP Zone scan → scan type
**"🔑 With credential zone"** → pick a credential zone. Each host's open ports are probed
(OS hint: 22→Linux/SSH, 3389/5985/5986→Windows) and credentials are tried **in OS-priority order**.
SSH credentialed auditing works fully (inventory + audit from inside); if a Windows port is open,
reachability is reported (a full WinRM/RDP auth backend is the next step). Credentials are resolved
from the vault and used on the fly.

**Starting a scan:** Scans → enter a target (`192.168.1.0/24` or `https://site`) → choose a type → "Start Scan".

**Vulnerability & exploit metadata database (`/exploits`):** A local repository. Imported from three
sources: **NVD** (CVEs from the last 120 days, with CVSS scores), **Exploit-DB** (~47k), and
**Metasploit** (~6.6k). Searchable by title, CVE, or ID. **Classification:** every record is automatically
sorted by **criticality** (Critical/High/Medium/Low) and by **usage category**
(Windows / Linux / macOS / Web / Database / Network / IoT / Cloud / Mobile) — newly synced records are
classified automatically too. The panel offers criticality + category + source filters and counted category chips.
Updating: in the panel via **"🔄 Update Database"** (admin → confirmation popup → background task) or
`docker compose exec app python -m cybersectool.scripts.sync_exploits`.
To reclassify old records: `... python -m cybersectool.scripts.reclassify_exploits [--all]`.
API: `GET /api/exploits?q=&source=&category=windows&severity=critical`, `POST /api/exploits/sync`.
Bulk NVD fetching is faster with an `NVD_API_KEY`. Typical size: ~70k records ≈ 20–25 MB.

> ℹ️ This page is **metadata only** — it correlates Exploit-DB / Metasploit identifiers with CVEs and links
> (id ↔ CVE ↔ URL) for situational awareness. The open-source core only *flags* exploitable CVEs; it never
> runs an exploit. Actually launching exploits (Metasploit orchestration, searchsploit / Exploit-DB PoC runner,
> credential brute-force) lives in the separate, optional **exploitation plugin** (license-gated), not in this core.

**Zone (scan zone):** `/zones` → enter a name + IP/CIDR blocks (one per line) → "Create Zone".
Zones are **only managed** here (create/delete). **Scanning is done from the Scans page**:
`/scans` → "🗺️ Zone scan" → pick a zone + choose a scan type (**Safe / Aggressive / Credentialed**) → "Scan Zone".
**All blocks** in the zone are scanned (blocks outside scope are skipped automatically, with an info message shown).
For Credentialed, you enter an SSH user/password (not stored; the same credential is tried against each host).
API (network mode): `POST /api/zones`, `GET /api/zones`, `POST /api/zones/{id}/scan` (mode), `DELETE /api/zones/{id}`.

---

## 3. 🔧 Scan Types

| Type | How | Finds |
|---|---|---|
| **Network** | Panel form (target = IP/CIDR) | Open ports, service/version → CVE matching (NVD) + KEV/EPSS + risk |
| **Web** | Panel form (target = URL) | Missing security headers, TLS, sensitive paths (.git/.env, etc.) |
| **SCA** | `POST /sca` (API) | requirements.txt / package.json → OSV.dev vulnerabilities |
| **Host** | `POST /hardening` (API) | CIS-style audit over SSH (credentials are not stored) |
| **Credentialed** | Panel (🔐 admin) / `POST /scans/credentialed` | Audit **from inside the server** over SSH: OS/kernel inventory, pending updates, NOPASSWD sudo, world-writable files + CIS. Does not modify the target. Credentials are **not stored** |

### 🛡️ vs ⚠️ Scan intensity (mode) — for network scans

Network scans run at two intensities (the "Intensity" selector in the panel):

| Mode | What it does | nmap |
|---|---|---|
| 🛡️ **Safe** (default) | Detection — port/service/version → CVE inference + nmap **default** (information-gathering) NSE scripts (`-sC`: banner/header/TLS/SMB OS discovery). Does **not** run intrusive scripts. | `-sV -sC -T4` |
| ⚠️ **Aggressive** | NSE `vuln`/`exploit`/`discovery` scripts + OS fingerprinting — **actively verifies** vulnerabilities by attempting them. **Excludes** DoS and brute-force. Risk of service disruption / leaving traces. | `-sV -T4 -A --script "(vuln or exploit or discovery) and not dos and not brute"` |

**Aggressive mode is double-locked** (to prevent accidental service disruption):
1. The **global setting** `ALLOW_AGGRESSIVE_SCANS=true` must be enabled (default is **off** → the option is disabled in the UI).
2. Only the **`admin`** role can start it.

If either lock is not satisfied, the request is rejected with **403**. An aggressive scan is written to the
**audit log** as `aggressive_scan_start` (who/when). Scheduled scans and MCP are **always in safe** mode.

---

## 4. 🤖 MCP (Claude integration) — 2 modes

### A) Local (stdio) — your own Claude Desktop

`claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "cybersectool": {
      "command": "uv",
      "args": ["run", "--directory", "<repo-dir>", "cybersectool-mcp"],
      "env": { "DATABASE_URL": "postgresql+asyncpg://<user>:<password>@localhost:5432/cybersectool" }
    }
  }
}
```

> Fill in `<repo-dir>` and `DATABASE_URL` to match your own installation.

### B) Remote (HTTP + token) — anyone on the network
1. Generate a token: `docker compose exec app python -m cybersectool.scripts.create_token --username <username> --name claude-remote`
2. Client connection:
   ```
   URL:    http://<server-ip>:8001/mcp
   Header: Authorization: Bearer cst_...
   ```
If the token is missing/invalid → **401**. Details: `docs/MCP.md`.

**MCP tools:** `list_assets`, `list_vulnerabilities(severity?)`, `lookup_cve(cve_id)`, `scan_status(scan_id)`, `start_scan(target)`.

---

## 5. 🔐 Moving to Production (change the default passwords)

1. Create a **`.env`** file at the project root (template: `.env.example`); it is NOT committed to git.
2. Provide strong values:
   ```
   SECRET_KEY=<long-random-string>
   DATABASE_URL=postgresql+asyncpg://<user>:<strong-password>@db:5432/cybersectool
   NOTIFY_WEBHOOK_URL=<Slack/webhook, if you want one>
   ALLOW_AGGRESSIVE_SCANS=false   # aggressive/intrusive scanning; enable only deliberately
   ```
3. Also update `POSTGRES_PASSWORD` and the app's `SECRET_KEY` in `docker-compose.yml` (or read them from `.env`).
4. Add a password to Redis, don't expose the ports (5432/6379) externally; internal network only.
5. **For internal-network scanning:** Windows Docker Desktop has limited access to the real LAN → in production, run on a **Linux server** (with host networking).

---

## 6. 👥 Roles (RBAC)

| Role | Permissions |
|---|---|
| `admin` | Everything: scanning, scope, users, audit, scheduling, hosts |
| `analyst` | Starts scans, views results |
| `viewer` | View only |

> **Authorized scope** can be configured from the **web UI (Settings → Authorized Scope)** as well as via the
> `set_scope` CLI. Either way, only targets you have explicitly added are scanned (default-deny).

---

## 7. ⚙️ Architecture (overview)

**6 Docker services** (single machine, Docker Compose — not Kubernetes):

| Service | Image | Job |
|---|---|---|
| `db` | postgres:16 | Database |
| `redis` | redis:7 | Job queue |
| `app` | cybersectool (own) | Web + API (8000) |
| `worker` | cybersectool (own) | Runs scans in the background |
| `beat` | cybersectool (own) | Triggers scheduled scans |
| `mcp` | cybersectool (own) | Remote MCP (8001, token-based) |

> `app/worker/beat/mcp` are different roles of the **same image** (same code, different command).

**Scan flow:** `app` enqueues a job → `redis` queue → `worker` (nmap/CVE/risk) → `db` → the panel reads it.

**Code layout (`src/cybersectool/`):** `core/` (shared business logic + scope + risk), `scanners/` (network/web/sca/hardening), `intel/` (nvd/osv/kev/epss), `tasks/` (Celery), `api/` (FastAPI), `web/` (HTML), `mcp/` (Claude). **The Web UI, MCP, and API all call the same `core` layer.**

---

## 8. 📋 Command Cheat-Sheet

```powershell
# Note: if 'docker' is not on your shell's PATH, prepend this:
#   $env:PATH = "C:\Program Files\Docker\Docker\resources\bin;" + $env:PATH

bash setup.sh                                # single-command setup wizard (Linux/macOS; Win: setup.ps1)
docker compose up -d --build                 # start (schema migration is AUTOMATIC; no manual alembic needed)
docker compose ps                            # service status
docker compose logs worker --tail 20         # worker logs
docker compose logs migrate --tail 20        # migration logs (runs automatically)

# user / token / scope
docker compose exec app python -m cybersectool.scripts.create_user --username X --password "Y" --role admin
docker compose exec app python -m cybersectool.scripts.create_token --username X --name mcp
docker compose exec app python -m cybersectool.scripts.set_scope --name internal --allow 10.0.0.0/8

# development (when code changes)
uv run pytest                  # tests
uv run ruff check .            # lint
uv run mypy                    # type checking
docker compose down            # stop
```

---

## 9. ⚠️ Important Notes

- **Scope is mandatory:** No target you haven't defined will be scanned (default-deny, a legal safeguard).
- **Windows + internal network:** Docker Desktop is limited at scanning the real office LAN; for production, prefer a Linux server.
- **Data persists:** `docker compose down` preserves data (the pgdata volume). Add `-v` to delete it.
- **MCP over HTTP requires a token (or Basic auth)**; tools are RBAC-gated by the token owner's role (viewer/analyst/admin) — e.g. starting a scan requires analyst+, and an unauthorized call returns 403.
- **Aggressive scanning is dangerous:** it can disrupt the target service / leave traces. Off by default; **back up the target** before enabling it. Use with care on production/fragile systems.

---

*Detailed plan: `docs/PROJECT_PLAN.md` · MCP details: `docs/MCP.md`*
