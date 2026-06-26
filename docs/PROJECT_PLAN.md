# Kangalis — Architecture and Design

---

## 1. Overview / Vision

**Kangalis** is a **Python-based vulnerability management platform with a web panel, focused primarily on internal-network/system scanning**. Think of it as a lightweight, self-hosted internal-network vulnerability scanner with its own dashboard and the ability to **talk to Claude over MCP**.

The platform discovers hosts and services on the internal network, matches them against known vulnerabilities (CVE), and enriches them with **exploitability signals** (is there a public exploit, is it being exploited in the wild, what is the probability of exploitation) to perform **risk prioritization**; it also covers web application and dependency scanning.

### What it is NOT (out-of-scope principles)
- It is not an attack/exploitation tool. It does *not* run exploits; it only uses the information that an exploit *exists* for defensive prioritization.
- It only scans within the **authorized scope**; it does not scan unauthorized targets.

> **Note on exploitation (1.0.1):** Active exploitation — Metasploit orchestration, a searchsploit / Exploit-DB PoC runner, and credential brute-force — is **not** part of this open-source core. It lives in a separate, optional, license-gated **exploitation plugin** (commercial). The open-source core only *flags* exploitable CVEs and never runs an exploit. The core does, however, retain the Exploit-DB **metadata signal** (id ↔ CVE ↔ URL) as informational risk context.

---

## 2. Target Users and Use Cases

- **Primary user:** In-house security/infrastructure team.
- **Scenarios:**
  - "Scan the internal subnet `10.0.0.0/24`, list open ports and service versions."
  - "List the critical CVEs on the discovered services, putting the ones with a public exploit at the top."
  - "Audit the security headers and TLS configuration of this web application."
  - "Are there any known vulnerabilities in this project's dependencies?"
  - **With Claude:** "Scan this subnet, and when it's done summarize the critical findings and mark the ones on the KEV list." (via MCP tools)

---

## 3. Scope

| Priority | Module | Description |
|---|---|---|
| 🥇 | **Network & Host Scanning** | Host discovery, port scanning, service/version detection (internal-network focused) |
| 🥈 | **CVE Matching + Exploitability** | Service version → CVE; Exploit-DB/KEV/EPSS enrichment |
| 🥉 | **MCP Server** | Tool layer that lets Claude use the platform |
| 4 | **Web Application Scanning** | Security headers, TLS/SSL, directory discovery |
| 5 | **SCA / Dependency Scanning** | requirements.txt, package.json, etc. → known vulnerabilities |
| 6 | **Host Hardening** | Credentialed (SSH/WinRM) CIS-style configuration audit |

---

## 4. Technology Stack

| Layer | Choice | Why |
|---|---|---|
| Language | **Python 3.12+** | Richest security ecosystem |
| Package management | **uv** | Very fast, modern |
| Backend | **FastAPI** | Async, automatic OpenAPI, fast |
| DB | **PostgreSQL + SQLAlchemy 2.0 (async) + Alembic** | Robust, with migrations |
| Task queue | **Celery + Redis** | Scans are long-running and need to run in the background |
| Frontend | **Jinja2 + HTMX + Tailwind + Alpine.js** | Python-centric, no separate JS build |
| Network scanning | **nmap** (python-libnmap wrapper) | The most powerful/fastest path (assumes nmap is installed on the system) |
| Web checks | **httpx**, **cryptography/ssl** | Header + TLS auditing |
| Vulnerability data | **NVD API 2.0** + **OSV.dev** | CVE + CVSS |
| Exploitability | **Exploit-DB** + **CISA KEV** + **EPSS** (+ Metasploit, via the optional exploitation plugin) | Risk prioritization |
| MCP | **FastMCP** (stdio → later HTTP/SSE) | Claude integration |
| Reporting | **WeasyPrint** (PDF) | Shareable reports |
| Deployment | **Docker + docker-compose** | Comes up with a single command |
| CI/CD | **GitHub Actions** | Test + lint + build |
| Test/Lint | **pytest, ruff, mypy, pre-commit** | Quality |

---

## 5. System Architecture

```
   ┌──────────────┐          ┌──────────────────┐
   │ Web Dashboard│          │ Claude (Desktop/ │
   │  (HTMX)      │          │ Code) = MCP client│
   └──────┬───────┘          └────────┬─────────┘
          │ HTTP                      │ MCP (stdio/SSE)
   ┌──────▼───────┐          ┌────────▼──────────┐
   │FastAPI routes│          │ MCP Server (tools)│
   └──────┬───────┘          └────────┬──────────┘
          └────────────┬──────────────┘
                ┌───────▼─────────┐
                │  CORE / SERVICE │   ← shared business logic (single source)
                │  - asset svc    │
                │  - scan svc     │
                │  - vuln svc     │
                │  - scope guard  │
                └───────┬─────────┘
       ┌────────────────┼─────────────────────┐
 ┌─────▼─────┐   ┌──────▼───────┐      ┌───────▼────────┐
 │PostgreSQL │   │ Celery+Redis │      │ Vuln/Exploit   │
 │(asset,    │   │ (scan        │      │ data sources   │
 │ vuln,     │   │  tasks)      │      │ NVD/OSV/EDB/KEV│
 │ CVE, log) │   └──────┬───────┘      └────────────────┘
 └───────────┘          │
              ┌─────────┼──────────┬───────────────┐
        ┌─────▼─────┐ ┌──▼──────┐ ┌─▼────────┐ ┌────▼─────┐
        │ Network/  │ │ Web     │ │ SCA      │ │ Host     │
        │ Port scan │ │ scanner │ │ scanner  │ │ hardening│
        └───────────┘ └─────────┘ └──────────┘ └──────────┘
```

**Architectural principle:** The web panel and the MCP server **never** duplicate business logic; both call the same **core/service** layer. The scope (authorized scope) check is enforced in a single place, in the core.

---

## 6. Scan Modules (Summary)

1. **Network & Host Scanning:** host discovery via ping/ARP sweep → port scanning → service/version via `nmap -sV` → OS fingerprinting (optional). Output: asset inventory.
2. **CVE Matching:** `service + version` (CPE) → NVD/OSV → CVE list + CVSS.
3. **Exploitability Enrichment:** for each CVE, Exploit-DB (public PoC?), CISA KEV (actively exploited?), EPSS (probability %).
4. **Web Application Scanning:** security headers, TLS/SSL configuration, directory/file discovery, common misconfigurations.
5. **SCA / Dependency:** parse manifest files → match against known vulnerabilities via OSV.dev.
6. **Host Hardening:** credentialed CIS-benchmark-style checks via SSH/WinRM.

---

## 7. Vulnerability & Exploitability Data Sources

| Source | What it provides | Access | Cost |
|---|---|---|---|
| **NVD API 2.0** | CVE detail, CVSS, CPE matching | REST API (rate-limited, optional API key) | Free |
| **OSV.dev** | Open-source/package vulnerabilities | REST API | Free |
| **Exploit-DB** | Is there a public exploit/PoC? | `files_exploits.csv` mirror (`codes` column = CVE) | Free |
| **CISA KEV** | CVEs actively exploited in the wild | Single JSON feed | Free |
| **EPSS (FIRST.org)** | Probability of exploitation (%) | REST API | Free |
| **Metasploit** (exploitation plugin) | Is there a ready MSF module? | `modules_metadata_base.json` | Free |

> In the open-source core, all of the above are used for **read-only enrichment / risk context**. The Exploit-DB and Metasploit signals are consumed as *metadata only* (does an exploit/module exist?), not as an execution capability. Actually running a Metasploit module or a PoC is part of the separate, optional **exploitation plugin** (license-gated).

**Risk score (draft formula):**
`risk = CVSS_base × weight(EPSS) × (KEV ? +bonus) × (public_exploit ? +bonus)`
→ The list is sorted so that items that are `Critical CVSS + public exploit + KEV` appear at the top.

---

## 8. MCP Server

A tool layer that lets Claude (and other MCP clients) use the platform.

**Tools:**
- `list_assets(filter?)` — discovered hosts/services
- `start_scan(target, scan_type)` — start a scan *(goes through the scope check)*
- `get_scan_status(scan_id)`
- `get_vulnerabilities(asset_id?, severity?)`
- `lookup_cve(cve_id)` — CVE detail + exploit/KEV/EPSS status
- `get_exploits_for_cve(cve_id)` — Exploit-DB matches
- `generate_report(scan_id, format)`

**Resources:** asset list, latest scan summary, critical vulnerabilities.

**Transport:** first **stdio** (local Claude Desktop/Code), later **HTTP/SSE** for the team.

**Security:** MCP tools go through the same **auth + scope guard**; an LLM cannot scan an unauthorized target.

---

## 9. Authentication Architecture

**Golden rule:** *Authentication (who you are)* is separate from *authorization (what you can do)*.
There may be multiple login methods; they all resolve to a **single `User` identity** and pass through a **single authorization layer** (RBAC + scope guard, in `core`).

### Login channels and credential types

| Channel | Credential | Verification source |
|---|---|---|
| Web dashboard (browser) | username/password → **session cookie** | local hash **or** LDAP |
| API (programmatic) | **API token** (`Authorization: Bearer`) | our `ApiToken` table |
| MCP (Claude) | **API token** (stored in config) | our `ApiToken` table |

> MCP is **not** a separate auth mechanism — it is a client that uses an API token. So in reality there are **2 kinds of credentials**: session + API token.

```
   LOGIN METHOD                  CREDENTIAL
Web browser   → username/password → session cookie ┐
API client    → API token (Bearer) ───────────────┤→ [get_current_user] → User
MCP (Claude)  → API token (Bearer) ───────────────┘         │
                                                            ▼
                                       core: RBAC role + scope guard
                                       (single place — channel-independent)
```

### Single verification dependency
`get_current_user` accepts both a `Bearer` token and a session cookie, resolving both to a single `User`. On top of that, RBAC is enforced via a dependency such as `require_role("admin", "analyst")`. The rule for starting a scan lives in one place; whether the request comes from the browser, the API, or Claude, it passes through the same authorization + scope check.

### API tokens
- Generation: `secrets.token_urlsafe` + a `cst_` prefix; only the **hash** is written to the DB (shown to the user **once** — like a password).
- Revocable (`revoked`), time-limited (`expires_at`), and **inherits the owner's role**.
- **Independent of LDAP:** we generate and verify the tokens ourselves → the directory is not consulted on every API/MCP request (LDAP only comes into play on interactive login).

### LDAP / Active Directory (optional identity backend)
Integration with a corporate directory. It only changes the **login step**; session/token/MCP/RBAC stay the same.
- Verifies the password by **binding** to the directory instead of a local hash (look up with a service account → re-bind with the user's own password).
- `User.auth_source` = `local | ldap`; LDAP users' passwords are **not stored** (`password_hash = NULL`).
- **Just-in-time provisioning:** on the first successful LDAP login, a local `User` row is created (tokens, audit log, and scan ownership attach to this persistent identity).
- **Group → role mapping:** AD groups (`memberOf`) → `admin` / `analyst` / `viewer`.
- Library: **`ldap3`** (pure Python, Docker-friendly).
- **Security:** always use **LDAPS/StartTLS**; keep the service account in secrets; maintain a **break-glass** local `admin` in case LDAP goes down; reject disabled/locked accounts in AD.

### Flow summary
```
login(username/password) → backend selector ──► local: verify password_hash
                                            └──► ldap: bind to directory + JIT provision
        │ (success → User)
        ▼
   session cookie  →  from here on, the same across ALL channels: RBAC + scope guard
```

## 10. Data Model (Draft)

- **User** (id, username, email, password_hash[nullable], role, **auth_source**[local|ldap], is_active) — RBAC: `admin`, `analyst`, `viewer`
- **ApiToken** (id, user_id, name, token_hash, expires_at, revoked, last_used_at) — API + MCP access
- **Session** (id → user_id, last_used) — kept in Redis, the web session
- **ScopePolicy** (id, allowed_cidrs, denied_cidrs, owner) — authorized scope
- **Asset** (id, ip, hostname, os, first_seen, last_seen)
- **Service** (id, asset_id, port, protocol, service_name, version, cpe)
- **Scan** (id, type, target, status, start, end, started_by_user)
- **Finding** (id, scan_id, asset_id, service_id, cve_id, severity, risk_score, status)
- **CVE** (id, description, cvss, epss, kev_flag, exploit_count, references)
- **Exploit** (id, edb_id, cve_id, title, platform, verified, source_url)
- **Report** (id, scan_id, format, path, created_at)
- **AuditLog** (id, user_id, action, target, timestamp) — who scanned what

---

## 11. Repository Directory Structure (target)

```
cybersectool/
├── docs/
├── src/cybersectool/
│   ├── core/                     # shared business logic (service layer)
│   │   ├── services/             # asset, scan, vuln, report services
│   │   ├── scope.py              # authorized-scope check
│   │   └── models.py             # SQLAlchemy models
│   ├── scanners/                 # scan modules (plugin-style)
│   │   ├── base.py
│   │   ├── network.py
│   │   ├── web.py
│   │   ├── sca.py
│   │   └── hardening.py
│   ├── intel/                    # vulnerability/exploit data sources
│   │   ├── nvd.py  osv.py  exploitdb.py  kev.py  epss.py
│   ├── api/                      # FastAPI routers
│   ├── web/                      # Jinja2 + HTMX templates, statics
│   ├── tasks/                    # Celery tasks
│   ├── mcp/                      # MCP server (FastMCP)
│   └── config.py
├── alembic/                      # migrations
├── tests/
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
├── .env.example
└── README.md
```

---

## 12. Security, Legal, and Ethical Principles

1. **Authorized scope is mandatory:** Scans only run within the allowed ranges defined in `ScopePolicy`. An out-of-scope target returns an error. (The authorized scope is configurable from the web UI under **Settings → Authorized Scope**, not only via the `set_scope` CLI.)
2. **Audit log:** Every scan is recorded as "who, when, what."
3. **Credential security:** SSH/WinRM credentials are stored encrypted (e.g., a secrets manager / encrypted field).
4. **Exploits are not run:** Only asset/metadata information is kept.
5. **Rate limiting & politeness:** Respectful requests to external APIs (NVD, etc.); scan-rate settings that do not harm the target.
6. **Secrets are not kept in the repo:** `.env` is not committed to git; `.env.example` serves as the example.

> **Disclaimer acceptance gate (new in 1.0.1):** Before any scan or audit can start, the operator must accept the in-app Disclaimer (see `DISCLAIMER.md`). Each acceptance is recorded as an audit-logged event (`disclaimer_accepted`).

---

## 13. Risks and Open Questions

- **nmap dependency:** nmap must be installed in the deployment environment (it will be added to the Docker image). A pure-Python alternative remains limited.
- **NVD rate limit:** the API limit under heavy scanning; a local CVE mirror may be needed in the future.
- **CPE matching accuracy:** generating a CPE from a service version sometimes mismatches; it requires fine-tuning.
- **Host hardening scope:** which OSes (Linux/Windows) take priority should be clarified.
- **MCP HTTP/SSE security:** once remote access is enabled, the authentication/authorization model must be hardened.

---

## 14. Glossary

- **CVE:** A record of a known security vulnerability.
- **CVSS:** The severity score of a vulnerability (0–10).
- **EPSS:** The probability that a vulnerability will be exploited within 30 days (%).
- **KEV:** CISA's list of vulnerabilities "actively exploited in the wild."
- **CPE:** A product/version identification standard (used in CVE matching).
- **SCA:** Software Composition Analysis — dependency security scanning.
- **MCP:** Model Context Protocol — the protocol by which LLMs connect to tools/data sources.
- **Scope:** The authorized (allowed) target scope for scanning.
