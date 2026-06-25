# Kangalis — Installation Guide

> The guardian of your internal network. This guide walks you, step by step,
> through everything you need to bring Kangalis up from scratch.

Kangalis is a web-based internal-network vulnerability scanning platform that runs four
application services (API, worker, scheduler, MCP) from a single Docker image. **The only
prerequisite is Docker** — the database, cache, scan engine (nmap), Python, and all
dependencies ship inside the containers or are installed automatically during the build.
You do not need to install Python, nmap, or PostgreSQL by hand.

> ⚠️ **Legal notice:** Kangalis must be used only within an **authorized scope** — that is,
> on networks you own or for which you have obtained **written permission** to scan.
> Unauthorized network scanning, credential attempts, and vulnerability verification are
> **illegal** in many jurisdictions, and all responsibility rests with the operator. For
> details, see [SECURITY.md](../SECURITY.md).

> ⚠️ **Disclaimer acceptance (new in 1.0.1):** On first login, every operator must accept
> the in-app Disclaimer ([DISCLAIMER.md](../DISCLAIMER.md)) before any scan or audit can be
> started. No scan runs until the Disclaimer is accepted, and each acceptance is recorded as
> an audit-logged event (`disclaimer_accepted`).

---

## 1. Prerequisites

The machine you install on needs only **Docker** and **Docker Compose**. Nothing else is
installed by hand.

| Platform | Required | Notes |
|---|---|---|
| **Windows** | [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Docker Compose is bundled. The WSL2 backend is recommended. |
| **macOS** | [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Docker Compose is bundled. |
| **Linux** | Docker Engine + Compose plugin | `docker` package + `docker-compose-plugin` (command: `docker compose`, not the hyphenated `docker-compose`). |

### Hardware (recommended minimum)

| Scenario | RAM | Disk | Description |
|---|---|---|---|
| Core (without AI) | ~4 GB | ~3 GB | All scan/report/MCP functionality works. |
| With local AI | **+8 GB** (~12 GB total) | **+~6 GB** (model) | The AI engine runs on CPU and is capped via `mem_limit 8g`. A GPU is **not required**. |

### Pre-installation check

Confirm that Docker is installed and running:

```bash
docker --version
docker compose version
docker info        # is the daemon running?
```

> **Network-conflict warning:** By default, Kangalis containers use the `172.28.0.0/16`
> bridge network. If the client LAN you will scan overlaps this range, read the
> **[Section 7 — `DOCKER_SUBNET`](#7-configuration-env)** setting before you begin the
> installation.

---

## 2. Quick install (single command — recommended)

From the repository root, run the **single command** for your platform:

```bash
# Linux / macOS
bash setup.sh
# or:
make setup
```

```powershell
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File setup.ps1
```

### What does the wizard do?

`setup.sh` / `setup.ps1` is an interactive setup wizard that performs the following 5 steps
for you:

1. **Credentials & security keys** — prompts for the PostgreSQL user/password/database name
   and the Redis password; **the default for each field is shown in square brackets** and can
   be accepted with an empty **Enter** (e.g. `Username [cyber]:`). It **automatically generates
   a strong, random** `SECRET_KEY` and credential-vault (Fernet) key, and also prompts for the
   optional NVD API key and notification webhook. It writes everything to `.env` (with access
   restricted to you alone — `chmod 600` / ACL). Input validation: user/password may contain
   only letters, digits, and `. _ -`; the NVD key letters/digits/`-`; the webhook must start
   with `http(s)://` — otherwise the wizard prompts again. **If credentials already exist in
   `.env`, this step is skipped** (safe to re-run; for this reason, do not copy `.env.example`
   first if you plan to run the wizard).
2. **Build + start** — `docker compose up -d --build`. The image is built (including nmap; the
   first build may take a few minutes) and all services are started in the background.
3. **Schema migration + health wait** — the `migrate` service installs the database schema
   **automatically** (you do not need to run `alembic` by hand). The wizard waits until the
   application's `/health` endpoint responds.
4. **Administrator (admin) user** — prompts for a username and password and creates the first
   account with an `admin` role.
5. **Authorized scan scope (REQUIRED)** — prompts for the networks you are **authorized** to
   scan in CIDR form (e.g. `192.168.1.0/24,10.0.0.0/8`) and saves the scope policy.

When the wizard finishes, the web panel, API/Swagger, and the (optional) AI start command are
printed to the screen. You can jump straight to [Section 6 — Access addresses](#6-access-addresses).

> **Note:** The wizard automates everything but **asks you for the scan scope** — no scan runs
> until a scope is defined (see below).

> **Note (changing the password):** The PostgreSQL password is baked into the database disk
> (`pgdata`) **on first startup**. If you want to change the Postgres user/password/db after the
> initial installation, edit `.env` and reset `pgdata` with `docker compose down -v` (otherwise
> you get a credential mismatch).

---

## 3. Manual installation (step by step instead of the wizard)

If you prefer not to use the wizard, you can achieve the same result with a few commands.

> **Credentials:** The steps below use the **default** credentials (DB `cyber:cyber`, Redis
> without a password, `SECRET_KEY=dev-secret`). To customize them, edit `.env` **before `up`**
> (Section 7) — in production especially, set a strong `SECRET_KEY` + `CREDENTIAL_ENCRYPTION_KEY`
> and DB/Redis passwords.

### 3.1 — Build + start (migrate is automatic)

```bash
docker compose up -d --build
```

This command builds the image (including nmap), starts the services, and the `migrate` service
automatically installs the schema with `alembic upgrade head` **before the application starts**.
The migration is **idempotent**; it re-runs safely on every `up` call. **You do not need to run
alembic by hand.**

Verify that the services have come up:

```bash
docker compose ps
```

### 3.1-B — Install from the published image (pull-and-run, NO build)

Instead of building locally, you can pull and run the **published prebuilt image** (Deployment B).
The `migrate/app/worker/beat/mcp` services all use a single image.

```bash
# 1) Pull the image (no build). To pin a version, set KANGALIS_IMAGE in .env,
#    e.g. KANGALIS_IMAGE=ghcr.io/lineup-noah/kangalis-core:v1.0.1  (default: :latest)
docker compose pull

# 2) Start (migrate installs the schema automatically)
docker compose up -d
```

The subsequent **REQUIRED** steps are the same as the build-based installation: the administrator
user (**§3.2**) and the scan scope (**§3.3** — no scan runs until a scope is defined). For `.env`
customization, see **§7**. These commands (`docker compose exec app …`) run identically from the
pulled image.

> Note: this pull path requires that the published ghcr image actually **exists and is public**.
> If the image is local, `docker compose up` uses it; if not, it **tries to pull from ghcr first**
> (Compose's default `pull_policy=missing`), and only if the pull fails (private package + not
> logged in, or offline) does it **fall back to a local build**, since a `build:` is defined. So
> with a public package + internet, `up` alone will also pull; nonetheless, for clarity it is
> recommended to run **`docker compose pull`** explicitly. No login is required for a public ghcr
> package; for a private one, run `docker login ghcr.io` first. For the local AI image, see
> [§8](#8-local-ai-optional-on-prem-zero-egress).

### 3.2 — Create the administrator (admin) user

```bash
docker compose exec app python -m cybersectool.scripts.create_user \
    --username <name> --password <password> --role admin
```

### 3.3 — Define the authorized scan scope (REQUIRED)

```bash
docker compose exec app python -m cybersectool.scripts.set_scope \
    --name ic-ag --allow <CIDR> [--allow <CIDR2> ...] [--deny <CIDR>]
```

Example:

```bash
docker compose exec app python -m cybersectool.scripts.set_scope \
    --name ic-ag --allow 192.168.1.0/24 --allow 10.0.0.0/8 --deny 10.0.0.1/32
```

> 🛑 **REQUIRED SCOPE — cannot be skipped.** All of Kangalis's scan surfaces are protected by a
> **scope guard**. If at least one allowed CIDR is not defined via `set_scope`, **no scan runs** —
> requests are rejected as out-of-scope. This is a deliberate safety design that prevents you from
> scanning accidentally or without authorization. **Enter only the networks you are authorized to
> scan.** A new `set_scope` call deactivates the previous policy and activates the new one.
>
> You can also manage the authorized scope from the **web UI (Settings → Authorized Scope)** — it
> is not limited to the `set_scope` CLI.

---

## 4. What gets installed? (images and services)

**The user installs only Docker by hand.** Everything below is pulled or built automatically by
Docker; you do not download images or install dependencies one by one.

| Image / service | Type | Description |
|---|---|---|
| `postgres:16` | **Auto-pulled** | Database (`db` service). |
| `redis:7` | **Auto-pulled** | Celery broker / cache (`redis` service). |
| `python:3.12-slim` | **Auto-pulled** (build time) | Base layer of the application image. |
| `ghcr.io/astral-sh/uv` | **Auto-pulled** (build time) | Python dependency manager (used during the build). |
| **`app`** | **Built** (`Dockerfile`) | FastAPI API + web panel (port 8000). |
| **`worker`** | **Built** (same image) | Celery scan worker. |
| **`beat`** | **Built** (same image) | Celery scheduler (periodic tasks). |
| **`mcp`** | **Built** (same image) | MCP server — Claude integration (port 8001). |
| `migrate` | **Built** (same image) | One-shot schema migration; exits when done. |
| `ollama/ollama` | **Optional** | Local AI engine (Ollama) — runs **only** with `--profile ai` (the model is pulled after first startup with `ollama pull qwen3:8b`). |
| `ghcr.io/lineup-noah/kangalis-ai` | **Optional** (air-gap) | Prebuilt AI image with the model **baked in** — zero downloads at runtime (see §8). |

> **One image, four services:** `app`, `worker`, `beat`, and `mcp` share a **single image** built
> from the same `Dockerfile`; only the command they run differs. This keeps build time and disk
> usage low.

---

## 5. nmap and licensing

### Default: nmap is installed automatically during the build

The scan engine calls the **nmap** binary; **scanning is not possible without nmap**. For this
reason, nmap is **enabled by default** in the `Dockerfile`:

```dockerfile
ARG INSTALL_NMAP=true
```

During `docker compose up --build`, nmap is installed **automatically** from the Debian
repository — **the user does not install nmap by hand**.

### Disabling nmap

If you do not want to include nmap in the image:

```bash
docker compose build --build-arg INSTALL_NMAP=false
```

> ⚠️ If you build without nmap, **scanning will not work** — there is no alternative scan engine
> in the core yet.

### Licensing (NPSL)

nmap is distributed under the **NPSL** (Nmap Public Source License — a GPLv2 derivative). The key
point from a licensing standpoint:

- **Kangalis does not redistribute the nmap binary.** The repository distributes only the
  **source** (the `Dockerfile` line).
- The step that fetches nmap from the Debian repository happens during **your `docker build`** —
  this is **your installation**, not a binary distribution by Kangalis.
- For details, see [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md).

---

## 6. Access addresses

When installation is complete, the following endpoints become reachable on your local machine:

| Service | Address | Description |
|---|---|---|
| **Web panel** | http://localhost:8000/login | Main interface — log in here. |
| **API / Swagger** | http://localhost:8000/docs | Interactive API documentation. |
| **MCP server** | http://localhost:8001/mcp | Claude integration (token required). |
| **PostgreSQL** | `localhost:5432` | Database. User/password are set via `.env` `POSTGRES_USER`/`POSTGRES_PASSWORD` (dev default: `cyber`/`cyber`). |
| **Redis** | `localhost:6379` | Broker / cache (password required if `REDIS_PASSWORD` is set). |

For MCP, you need to generate an access token:

```bash
docker compose exec app python -m cybersectool.scripts.create_token
```

For details, see [docs/MCP.md](MCP.md).

---

## 7. Configuration (.env)

Configuration is managed via environment variables (or the `.env` file in the root directory). To
get started, copy the `.env.example` file:

```bash
cp .env.example .env
```

Important variables:

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `dev-secret` (dev) | Session signing + vault key derivation. **In production, set a strong, random value.** |
| `CREDENTIAL_ENCRYPTION_KEY` | empty (derived from SECRET_KEY in dev) | Fernet key for the credential vault (SSH/DB/AD passwords). **In production, set a separate, secret value.** |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | `cyber` / `cyber` / `cybersectool` | PostgreSQL credentials (the wizard prompts for these). In Docker, compose builds `DATABASE_URL` from them (`@db`). **The password is baked into `pgdata` on first startup** — to change it, use `docker compose down -v`. |
| `REDIS_PASSWORD` | empty (auth off) | Redis password. If set, auth is enabled with `redis-server --requirepass` and embedded in `REDIS_URL`. |
| `DATABASE_URL` | `...@db:5432/cybersectool` (compose builds it) | Read only when running **outside Docker** (uv run); in Docker it is derived from `POSTGRES_*`. |
| `REDIS_URL` | `redis://redis:6379/0` | Redis / Celery broker. If a password is set, `redis://:PASSWORD@redis:6379/0` (the wizard writes it). |
| `DOCKER_SUBNET` | `172.28.0.0/16` | Container bridge network. **Change it if it overlaps with the client LAN** (e.g. `10.89.0.0/16`). |
| `EXCLUDE_SCAN_IPS` | empty | Additional IPs to exclude from scanning/inventory (comma-separated). The tool's own container IPs are already excluded automatically. |
| `ALLOW_AGGRESSIVE_SCANS` | dev=`true`, code default=`false` | Kill-switch for aggressive (intrusive) scanning. **Leave `false` in production.** |
| `AI_ENDPOINT` | `http://ollama:11434/v1` | Local AI engine OpenAI-compatible endpoint. For an engine on the host, `http://host.docker.internal:<port>/v1`. |
| `AI_MODEL` | `qwen3:8b` | AI model tag. |
| `AI_TIMEOUT` | `300` | AI request timeout (sec). CPU inference is slow; kept generous. |

> **Generating strong secrets:** The setup wizard (`setup.sh`/`setup.ps1`) already **generates**
> `SECRET_KEY` and `CREDENTIAL_ENCRYPTION_KEY` **automatically**. If you want to generate them by
> hand (wizard-less installation or a production override):
> ```bash
> # SECRET_KEY
> python -c "import secrets; print(secrets.token_urlsafe(48))"
> # CREDENTIAL_ENCRYPTION_KEY (Fernet)
> python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
> ```

---

## 8. Local AI (optional, on-prem, zero egress)

Kangalis's local AI assistant (vulnerability explanations + report summaries) is **off by default**
and starts only with the `ai` profile:

```bash
docker compose --profile ai up -d ollama
# or:
make ai
```

This command starts the Ollama server; it pulls the model (Qwen3-8B Q4, ~5–6 GB) **one time** after
first startup with `docker compose exec ollama ollama pull qwen3:8b` and runs it **on CPU** (no GPU
required). The port is **not published** to the host — meaning client data does not leave the client
network (**zero egress**; only the model download is one-time). RAM is capped via `mem_limit 8g`.

### Prebuilt (air-gap) image — model baked in, zero downloads at runtime

The default path above pulls the model after first startup with `ollama pull` (requires internet +
a ~5 GB download). For isolated/air-gapped networks, use our prebuilt image, which carries the model
(Qwen3-8B Q4) **baked in** — so there are **no external downloads** at runtime:

```bash
# (first) pull the image or build it locally
docker pull ghcr.io/lineup-noah/kangalis-ai:qwen3-8b
#   or build locally:  bash build-ai-image.sh   /   powershell -File build-ai-image.ps1

# (then) start with the baked-image override
docker compose -f docker-compose.yml -f docker-compose.ai-baked.yml --profile ai up -d ollama
#   or:  make ai-baked
```

> The image is large (~5–6 GB, model baked in). You can pull it once and move it into an air-gapped
> environment (`docker save`/`docker load`). This image is a **separate** artifact from the
> MIT-licensed core; it bundles Ollama (MIT) + Qwen3 (Apache-2.0) — see `THIRD-PARTY-NOTICES.md`.

### Other options and notes

- **Alternative (host engine):** you can run LM Studio / Ollama on the host and set
  `AI_ENDPOINT=http://host.docker.internal:<port>/v1`.
- AI is enabled from the **Plugins > AI** card in the web panel. When it is off, everything degrades
  gracefully (static content is shown, the application still comes up).
- The first grounded generation is slow on CPU (~a few minutes).

For details and zero-egress verification, see [docs/AI-ZERO-EGRESS.md](AI-ZERO-EGRESS.md).

---

## 9. Production notes

The development defaults (`SECRET_KEY=dev-secret`, DB user/password `cyber:cyber`) are **for
development only**. In production:

1. **Set `APP_ENV=production`.** This mode strictly validates the configuration at application
   startup and **rejects weak values** (stops startup with a `ValueError`):
   - A weak/default `SECRET_KEY` (`dev-secret`, `change-me`, `secret`, empty, etc.) →
     **rejected**.
   - An empty `CREDENTIAL_ENCRYPTION_KEY` → **rejected** (the vault key cannot be derived from
     SECRET_KEY; a leak would open the entire vault).
2. **Set a strong `SECRET_KEY`** and a **separate, strong `CREDENTIAL_ENCRYPTION_KEY`** (for the
   production commands, see Section 7).
3. **Leave `ALLOW_AGGRESSIVE_SCANS=false`.** Aggressive mode runs nmap NSE vuln/exploit scripts; it
   interferes with the target (risk of service disruption / leaving traces). Enable it only
   deliberately, on authorized systems that have been backed up.
4. **Change the default DB credentials** and do not expose the database/Redis ports to the outside
   world.

---

## 10. Troubleshooting

| Symptom | Possible cause | Solution |
|---|---|---|
| **Scan does not run / "out of scope" error** | Scope is not defined **or** nmap is not installed | Define at least one `--allow <CIDR>` with `set_scope` (Section 3.3). If you disabled nmap with `INSTALL_NMAP=false`, scanning will not work — rebuild with the default (Section 5). |
| **Migrate error / application does not start** | The database is not healthy yet, or the migration failed | Check with `docker compose logs migrate db`. Is the `db` service `healthy` (`docker compose ps`)? If needed, retry with `docker compose up -d --build`. |
| **`password authentication failed for user "..."`** (in migrate/app logs) | The old `pgdata` volume does not match the **new DB password** in `.env`. Postgres bakes in the user/password **only on first startup** (empty data directory); on a reinstall, the **volume persists** even if you delete the folder and retains the old password. | Reset the old database: **`docker compose down -v`** → then `docker compose up -d --build` (or `setup.ps1`). ⚠️ `-v` **deletes** existing scan data; use it only for a deliberate credential change / clean install. Verify the effective creds with `POSTGRES_*` in the output of `docker compose config`. If you want to keep the data, instead align the password in `.env` with the **old (initial install) value**. |
| **AI does not connect** | The profile is not enabled, the endpoint is wrong, or (Linux) the host-gateway is missing | Enable the engine with `docker compose --profile ai up -d ollama`. If you use a host engine, is `AI_ENDPOINT` correct? **On Linux**, a `host.docker.internal:host-gateway` mapping is required to reach the host engine (defined in compose; verify it in a custom setup). The application still runs when AI is off. |
| **Container network overlaps with the client LAN** | `DOCKER_SUBNET` overlaps with the client range | Set `DOCKER_SUBNET` to an unusual range (e.g. `10.89.0.0/16`) in `.env` and restart. |
| **No exploitation / exploit execution** | By core design | The open-source core does **not** run exploits; it only shows an "is there an exploit?" signal. Actual exploitation lives in a separate `kangalis-exploit` plugin — see the link below. |

To watch the logs live: `docker compose logs -f` (or `make logs`).

---

## Related documents

- **[docs/PLUGINS.md](PLUGINS.md)** — optional/commercial plugins (e.g. the exploitation/pentest
  plugin `kangalis-exploit`). The core does not run exploits; actual exploitation lives in a
  separate plugin.
- **[docs/GUIDE.md](GUIDE.md)** — getting-started and day-to-day usage guide (scan, finding, and
  report workflows).
- **[SECURITY.md](../SECURITY.md)** — security policy, acceptable use, and responsible disclosure.

---

> ⚠️ **Reminder:** Use Kangalis only within the **scope you are authorized to scan**. Unauthorized
> scanning is illegal, and all responsibility rests with the operator.
