# Kangalis — Optional Features and Plugins

> This guide walks through the **optional** capabilities and plugins in the Kangalis
> open-source core one by one: what each one **does**, **how to enable it** (command/setting),
> what its **requirement/cost** is, and **what happens when it is off**.
>
> **Core guarantee:** **None** of these sections are mandatory. Even with all of them disabled,
> the core works fully — network/host discovery, port & service/version detection, CVE matching,
> exploitability **signals** (Exploit-DB/CISA KEV/EPSS), risk prioritization, reporting, and the
> web panel all work completely. Each feature below is added **on top** of this core, optionally.
>
> Prerequisite (common to all): the user only installs **Docker + Docker Compose**; nothing else
> is installed by hand. For the base installation, see `docs/GUIDE.md`.

---

## Contents

1. [Local (on-prem) AI](#1-local-on-prem-ai)
2. [Exploitation / pentest plugin](#2-exploitation--pentest-plugin)
3. [nmap scan engine](#3-nmap-scan-engine)
4. [MCP (Claude integration)](#4-mcp-claude-integration)
5. [Aggressive (intrusive) scanning](#5-aggressive-intrusive-scanning)
6. [Credentialed scanning](#6-credentialed-scanning)
7. [Compliance reporting](#7-compliance-reporting)
8. [LDAP / Active Directory integration](#8-ldap--active-directory-integration)

---

## 1. Local (on-prem) AI

**What it does.** Explains vulnerability findings in plain language, and generates report summaries
and compliance narratives. It runs entirely **on-prem**: analyzed data never **leaves** the
deployment network (zero-egress). No cloud API, no API key. (For detailed zero-egress evidence, see
`docs/AI-ZERO-EGRESS.md`.)

**How to enable it.** There are three paths (A is easiest; B is for air-gapped/isolated networks;
C uses your own host engine):

- **A) Embedded engine (easiest) — Ollama profile:**
  ```bash
  docker compose --profile ai up -d ollama
  ```
  This starts an OpenAI-compatible local inference server; after the first launch you pull the
  model (default `qwen3:8b`, ~5GB) **one time** with `docker compose exec ollama ollama pull qwen3:8b`,
  and it runs on the CPU (a pre-packaged image for air-gap already exists, see B).
  In Compose, `app`/`worker` already point to `AI_ENDPOINT=http://ollama:11434/v1`.
  To change the model, set `AI_MODEL=...` in `.env`.

- **B) Pre-packaged (air-gap) image — model EMBEDDED, zero download:**
  Path (A) pulls the model with `ollama pull` after the first launch (~5 GB download + internet
  required). Instead, you can use our pre-packaged image that ships the model (Qwen3-8B Q4)
  **embedded** — so there is **no external download at all** at runtime (suitable for air-gapped/
  isolated networks; the LLM data stays on the customer network):
  ```bash
  # (first) pull the image or build it locally:
  docker pull ghcr.io/lineup-noah/kangalis-ai:qwen3-8b
  #   or:  bash build-ai-image.sh   /   powershell -File build-ai-image.ps1
  # (then) start it with the embedded-image override:
  docker compose -f docker-compose.yml -f docker-compose.ai-baked.yml --profile ai up -d ollama
  #   or:  make ai-baked
  ```
  > This image is a **separate** artifact from the MIT-licensed core; it embeds Ollama (MIT) +
  > Qwen3 weights (Apache-2.0) — both licenses permit embedding/redistribution.
  > Recipe: `Dockerfile.ai`. Details: `THIRD-PARTY-NOTICES.md`.
  >
  > Note: the pre-packaged `ghcr.io/lineup-noah/kangalis-ai` image must be published and public for
  > the `docker pull` path to work; if it is not yet available, build it locally with the script
  > above (`build-ai-image.sh` / `build-ai-image.ps1`).

- **C) Host-native engine (LM Studio / Ollama / LocalAI):**
  Run your own engine on the host machine and point the endpoint at it in `.env`:
  ```env
  AI_ENDPOINT=http://host.docker.internal:<port>/v1
  AI_MODEL=<model-name>
  ```
  > On Linux, the host-native path requires the Compose `extra_hosts: host.docker.internal:host-gateway`
  > mapping (already defined in the Compose file). Without this mapping, the app silently fails to
  > connect to the host engine.

Whichever path you choose, the final step is the same: **enable** the AI from the **Plugins > AI**
card (`ai_enabled`), verify the endpoint/model/timeout, and probe the engine with "Test connection."
AI surfaces are not visible until it is enabled. When enabled, the interface brand becomes "Kangalis AI."

**Requirement / cost.**
- Disk: one-time ~5GB model download (Qwen3-8B Q4).
- RAM: the AI container is capped at `mem_limit: 8g` → in practice ~8GB RAM is needed.
- CPU: a GPU is **not required**; it runs on the CPU.
- Egress: only a **one-time model download**. Zero external traffic at runtime. In an air-gapped
  deployment, if the model is pre-embedded in the image, even that download does not occur.
- Performance: the first grounded generation is slow on the CPU (summary/script ~3–5 min with a
  warm model). For this reason the `AI_TIMEOUT` default is generous (300 s). The port is **not**
  published to the host (internal network only).

**What happens when it is off.** Everything is **graceful**: AI buttons/surfaces are not shown, and
the relevant pages display static (pre-prepared) content. Scanning, CVE matching, reporting, the
panel — all work fully without AI. AI is an entirely optional layer.

---

## 2. Exploitation / pentest plugin

**Honest framing — let's draw the boundary first.** Real exploitation/intrusion capability does
**NOT exist** in this **open-source core**. The core never **runs** any exploit. This is a
deliberate design decision: the core is a defensive vulnerability management platform.

**What it does (what the core does).** The core shows whether **"an exploit EXISTS"** for a CVE —
that is, it presents the Exploit-DB / Metasploit metadata **signal** (whether an exploit/PoC or
Metasploit module is available, and how many) as a badge on the panel. This is purely for
**information/risk prioritization**; no code is **executed** against a target.

**How to enable it.** You do not need to enable anything extra in the core — exploit **signals** are
already visible by default (the Vulnerabilities `/findings` and Exploit DB `/exploits` pages). To
update the local exploit/CVE database:
```bash
docker compose exec app python -m cybersectool.scripts.sync_exploits
```
or from the panel, **"🔄 Update Database"** (admin → confirm → background task).

**For real exploitation.** Intrusive capabilities such as Metasploit orchestration, isolated PoC
execution, credential brute-force, and AI exploit preparation are kept in a separate, **commercial
`kangalis-exploit`** plugin and are **not** included in this repository.
- **Roadmap (remote target):** the core is planned to talk to a remote **"Kangalis Exploit Agent"**
  running on the customer's own Metasploit box; actual exploit execution always stays **outside** the
  core, in a separate/isolated component.

**Plugin contract (seam).** The core calls the plugin only **if it is installed**, via a late import
(`try/except ImportError`); the contract is documented in
[`core/exploit_seam.py`](../src/cybersectool/core/exploit_seam.py). The plugin (the
`cybersectool.exploit` namespace package) must provide: `msf_client.msf_configured()` (whether
msfrpcd is ready), `runner.run_exploitation_for_scan(session, scan_id, *, user_id=None)` (the actual
MSF exploitation), and `exploitdb_stage.stage_exploitdb_attempts(...)` (Exploit-DB PoC staging). The
*Exploitation* card on the **Plugins** page shows the status (Installed/Inactive) plus the
installation steps and an **authorized-use-only** warning. An authorization/EULA gate (scope ack +
authorization statement) will be added in a separate phase and made mandatory before any exploitation
is fired.

**Requirement / cost.** No extra cost for the signals (the local database has ~70k records ≈
20–25 MB; bulk NVD fetching is faster with `NVD_API_KEY`). Because the real exploitation plugin is a
separate/commercial product, it does not change the core's prerequisites.

**What happens when it is off.** The exploitation plugin is already **absent** from this core; the
core works **fully** without it. The "does an exploit exist" information (the signal) continues to be
shown, but no exploit is run — this is the expected and safe default.

---

## 3. nmap scan engine

**What it does.** This is Kangalis's core scan engine: host discovery, port scanning,
service/version detection, and (in aggressive mode) NSE script audits are all done via nmap. The
tool **cannot scan without nmap**.

**How to enable it.** **On by default.** The Dockerfile defines `ARG INSTALL_NMAP=true`; during
`docker compose up -d --build`, nmap is installed **automatically** from the Debian repository. The
user does **not** install nmap by hand.

To disable it (rarely needed):
```bash
docker compose build --build-arg INSTALL_NMAP=false
```
> If disabled, **no scan will run** — there is currently no alternative scan engine.

**Requirement / cost.** No extra cost; nmap is installed when the image is built. The download is small.

**License note (NPSL).** nmap is distributed under the **NPSL** (Nmap Public Source License, a GPLv2
derivative). Kangalis does **not** redistribute the nmap binary: it distributes only the source (the
Dockerfile line); **your** `docker build` pulls nmap from the Debian repository = this is **your**
installation, not our binary distribution. Details: `THIRD-PARTY-NOTICES.md`.

**What happens when it is off.** If nmap is disabled, the scanning capability is turned off (the
application still comes up, the panel opens, but scans cannot be started). In practice, do not disable
nmap; this is only for special/license scenarios.

---

## 4. MCP (Claude integration)

**What it does.** Lets Claude (Desktop / Code) use Kangalis directly: start scans, query
inventory/vulnerabilities, search CVEs. MCP tools call the **same core/service layer** as the web
interface (same scope guard, same RBAC).

**How to enable it.** There are two modes:

- **A) Local (stdio)** — your own Claude Desktop. Add the `cybersectool-mcp` command to
  `claude_desktop_config.json` (example: `docs/MCP.md`). The Docker stack must be running.

- **B) Remote (HTTP + token)** — everyone on the network connects to a single, central MCP. The
  `mcp` service is ready in Compose and runs at **http://localhost:8001/mcp**:
  1. Generate a token:
     ```bash
     docker compose exec app python -m cybersectool.scripts.create_token --username <username> --name claude-remote
     ```
  2. Connect from Claude Desktop (or any client that supports streamable-http):
     ```
     URL:    http://<server-ip>:8001/mcp
     Header: Authorization: Bearer cst_...
        or   Authorization: Basic <base64(user:password)>   # local or LDAP user
     ```
  Invalid/missing credentials → **401**. For detailed configuration and the tool list, see **`docs/MCP.md`**.

**Requirement / cost.** No extra download; the `mcp` service is a different role of the same
application image. The stack must be running for DB/Redis access.

**Security.** `start_scan` passes through the scope guard. In HTTP mode, authentication is
**mandatory** (Bearer token or Basic). RBAC is enforced at the tool level (viewer < analyst < admin).
In production, TLS (a reverse proxy) is recommended.

**What happens when it is off.** MCP is just an integration surface. If you never use it (or do not
start the `mcp` service), the web panel, the API, and all scanning capabilities work as they are.

---

## 5. Aggressive (intrusive) scanning

**What it does.** Upgrades the network scan from "detection only" to "validate by attempting": it
**actively** validates vulnerabilities using the nmap NSE `vuln`/`exploit`/`discovery` scripts + OS
fingerprinting. DoS and brute-force are **excluded**.

**How to enable it.** For safety there is a **double lock** (to prevent accidental service disruption) and
a confirmation gate:
1. The **global setting** `ALLOW_AGGRESSIVE_SCANS=true` must be set (`.env` or Compose env). The code
   default is `false` (production-safe). When off, the option is disabled in the UI.
2. Only the **`admin`** role can start the operation.
3. On the panel, **⚠️ Aggressive** is selected as the scan intensity and the **"I accept"**
   confirmation is given.

If one of the locks is not satisfied, the request is rejected with **403**. Every aggressive scan is
written to the **audit log** as `aggressive_scan_start` (who/when). Scheduled scans and MCP are
**always** in safe mode.

**What it enables (difference vs. safe mode).**
- 🛡️ Safe (default): `-sV -sC -T4` — port/service/version + information-gathering NSE; no intrusion.
- ⚠️ Aggressive: `-sV -T4 -A --script "(vuln or exploit or discovery) and not dos and not brute"`.

**Requirement / cost.** No extra software (the same nmap). The cost is **risk**: aggressive mode
**interacts** with the target → possible service disruption / leaving traces. Enable it consciously,
only on authorized and **backed-up** systems.

**What happens when it is off.** All scans run in safe (detection) mode — this is sufficient for most
deployments and is the recommended default. The core works fully; only active validation is not
performed.

---

## 6. Credentialed scanning

**What it does.** Performs an **internal**, credentialed audit of the target system: via SSH, it
collects the OS/kernel inventory, pending security updates, NOPASSWD sudo, world-writable files, and
**CIS** checks. It does **not** modify the target (read-only audit). It provides internal inventory +
hardening visibility.

**How to enable it.**
1. **Credential vault** (`/credentials`, admin only): create SSH / WinRM / RDP / LDAP credentials
   (name + type + user + password + domain/port). Passwords are stored **encrypted with Fernet** and
   are never shown again on the panel. You can group credentials into **credential zones** (the
   credential counterpart of an IP zone).
2. Start a scan:
   - Single host / IP zone: Scans → IP Zone scan → type **"🔑 With credential zone"** → select a
     credential zone. Each host's open port is probed (OS hint: 22→Linux/SSH, 3389/5985/5986→Windows)
     and credentials are tried with **OS priority**.
   - API: `POST /scans/credentialed` (the 🔐 admin flow in the panel).

> Credentials are resolved from the vault **on demand**; the SSH path works fully (internal inventory
> + CIS audit). If a Windows port is open, reachability is reported (a full WinRM/RDP auth backend is
> the next step).

**Requirement / cost.** No extra software. Encryption key: `CREDENTIAL_ENCRYPTION_KEY` (if empty, it
is derived from `SECRET_KEY` — dev only; **in production, provide a separate secret key**). To
generate one:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**What happens when it is off.** If you do not define credentials, credentialed scanning is not used;
the core performs only **uncredentialed (external)** network/web scanning — which also works fully.
Credentialed auditing is an optional layer that deepens visibility.

---

## 7. Compliance reporting

**What it does.** Maps hardening/credentialed-audit findings to well-known **CIS** controls (CIS
Linux — SSH, CIS Windows — WinRM) and produces formatted compliance reports for the **KVKK / ISO
27001 / PCI** frameworks. It also correlates CVE findings with the relevant compliance frameworks
(compliance badges on the panel).

**How to enable it.** **Built in** — there is no separate plugin to enable. Compliance results are
derived automatically as the relevant audits run:
- Run a host/credentialed audit (see §6) → findings are mapped to CIS controls (stored as
  `ComplianceCheck`).
- View the compliance summary on the panel; get a printable/PDF report from the **Report**
  (`/report`) page (with KVKK/ISO/PCI framework badges).

**Requirement / cost.** No extra software. PDF generation is done with WeasyPrint embedded in the
image (DejaVu fonts are included for non-ASCII/Unicode characters). For the richest compliance
visibility, credentialed scanning (§6) is recommended, because most CIS controls require an internal
audit.

**What happens when it is off.** The compliance engine is always available; if you simply do not run
the relevant (credentialed/host) audits, there are no findings to map. In that case the rest of the
core (network/web scanning, CVE, reporting) continues to work fully.

---

## 8. LDAP / Active Directory integration

**What it does.** Lets you manage users from a central directory (LDAP / Active Directory): search
for and import users from the directory, log in with LDAP credentials (instead of a local user), and
an optional **periodic sync**. You can also run a read-only security audit (IX-7b) against the
LDAP/AD server.

**How to enable it.** From **Settings**, admin only:
1. Fill out and save the **Settings > LDAP connection** form (`POST /settings/ldap`):
   - `server_uri` (e.g. `ldap://dc.example.local` or `ldaps://...`), `base_dn`, `bind_dn` +
     `bind_password` (service account; stored **encrypted with Fernet**; if left empty, anonymous
     bind), `user_filter`, attribute mappings (`attr_username`/`attr_email`/`attr_display_name`),
     `default_role`, and `use_ssl`.
   - Verify with **"Test connection"**; you can list users/groups/OUs.
2. Enable the integration (`ldap_enabled`); when enabled, the LDAP option appears on the login screen
   and an LDAP user is created automatically on first login.
3. (Optional) **Periodic sync**: choose an `hourly`/`daily`/`weekly` schedule and time from
   **Settings > LDAP sync** (`POST /settings/ldap-sync`).

> LDAPS certificate verification is managed via Settings > hardening (`ldaps_verify_cert` + an
> optional CA PEM). LDAP users can also connect to MCP with Basic auth (see §4).

**Requirement / cost.** No extra software (the `ldap3` LDAP client is included in the image). You need
a reachable LDAP/AD server and (unless you use anonymous bind) a service/bind account. In production,
**LDAPS** (with certificate verification) is recommended.

**What happens when it is off.** When LDAP `ldap_enabled` is off, login is done entirely with **local
users** (such as the admin you created in the setup wizard). Without directory integration,
authentication, RBAC, and all core features work completely.

---

## Summary — all optional

| Feature | Default | How to enable | When off |
|---|---|---|---|
| Local AI | Off | `--profile ai` + Plugins>AI | Static content (graceful) |
| Exploitation plugin | Not in core | Separate/commercial `kangalis-exploit` | Signal shown, not executed |
| nmap | **On** | Automatic at build | No scan runs (do not disable) |
| MCP | Ready (use optional) | Generate token + connect | Panel/API work fully |
| Aggressive scanning | Off (default) | `ALLOW_AGGRESSIVE_SCANS` + admin + confirm | Safe (detection) mode |
| Credentialed scanning | Off | Credential vault + 🔑 scan | Uncredentialed (external) scan |
| Compliance reporting | Built in | Run credentialed/host audit | No findings to map |
| LDAP/AD | Off | Settings>LDAP | Local users |

**In all cases:** even with all of the above disabled, the **core works fully**.

---

*Related docs: `docs/GUIDE.md` (getting started/usage) · `docs/MCP.md` (MCP details) ·
`docs/AI-ZERO-EGRESS.md` (AI zero-egress evidence) · `THIRD-PARTY-NOTICES.md` (licenses).*
