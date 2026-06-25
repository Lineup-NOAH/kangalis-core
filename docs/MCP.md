# Kangalis MCP Server

An MCP server that lets Claude (Desktop / Code) use Kangalis directly.
The tools call the **same core/service layer** as the web UI.

## Tools

| Tool | Description |
|---|---|
| `list_assets()` | Lists discovered hosts and services (inventory) |
| `list_vulnerabilities(severity?, limit?)` | Lists findings by risk order (severity: critical/high/medium/low/info) |
| `lookup_cve(cve_id)` | CVE detail: CVSS, severity, EPSS probability, KEV (known exploited) |
| `scan_status(scan_id)` | Scan status (pending/running/completed/failed) |
| `start_scan(target)` | Starts a network scan within the authorized scope (passes through the scope guard) |
| `search_exploits(query?, category?, severity?, limit?)` | Searches the local Exploit-DB/CVE metadata repository (category: windows/web/database/...; severity) |
| `exploits_for_cve(cve_id)` | Number of Exploit-DB entries for a CVE + whether a Metasploit module exists |
| `exploit_db_stats()` | Exploit-DB counts (distribution by source/severity/category) |
| `list_ip_zones()` | Defined IP zones and CIDR blocks |

## Running

```bash
# stdio transport
cybersectool-mcp
# or
python -m cybersectool.mcp.server
```

The server connects to the database via `DATABASE_URL` (default `localhost:5432`).
`start_scan` also dispatches a job to the Celery worker (Redis required).

## Claude Desktop configuration

`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cybersectool": {
      "command": "uv",
      "args": ["run", "--directory", "<repo-dir>", "cybersectool-mcp"],
      "env": {
        "DATABASE_URL": "postgresql+asyncpg://cyber:cyber@localhost:5432/cybersectool",
        "REDIS_URL": "redis://localhost:6379/0"
      }
    }
  }
}
```

> The Docker stack must be running (`docker compose up -d`) so that the DB/Redis are reachable.

## Example usage (to Claude)

> "Scan this subnet: 10.0.0.0/24, and when it's done summarize the critical vulnerabilities."

Claude calls `start_scan` → `scan_status` → `list_vulnerabilities(severity="critical")`
in sequence.

## Remote access (HTTP)

Instead of stdio, you can run a central MCP server over **HTTP transport**; everyone on the
network connects with their own identity. **Two authentication methods** are supported:

1. **API token** — `Authorization: Bearer cst_...` (for programmatic/automated use)
2. **Username + password** — `Authorization: Basic base64(user:password)`
   (HTTP Basic). Both **local** users and **LDAP/AD** users are valid
   (an LDAP user is created automatically on first connection). Most MCP/HTTP clients
   support this directly via their "Basic auth: user/password" fields.

Run the server in HTTP mode (the `mcp` service in docker-compose does this):

```bash
MCP_TRANSPORT=http python -m cybersectool.mcp.server   # http://0.0.0.0:8001/mcp
```

Invalid/missing credentials → 401. Generating an API token (for Bearer):

```bash
docker compose exec app python -m cybersectool.scripts.create_token --username <username> --name claude-remote
```

Client connection (one that supports streamable-http):

```
URL:    http://<sunucu-ip>:8001/mcp
Header: Authorization: Bearer cst_...           # with a token
   or   Authorization: Basic <base64(user:pass)>  # username/password (local or LDAP)
```

> Users on the same LAN connect to a single central MCP; every access is tied to the user
> (and therefore to the audit log and to the **role** — see RBAC below).

## Security

- `start_scan` passes through the **scope guard**; targets outside the authorized scope are rejected.
- MCP scans run in **safe mode** only: `start_scan` performs non-intrusive discovery/assessment and never
  runs an exploit. Exploitation (Metasploit orchestration, PoC runners, credential brute-force) is not part
  of the open-source core; it ships in a separate, optional, license-gated exploitation plugin.
- **stdio**: local/trusted process (launched by Claude Desktop).
- **HTTP**: authentication is mandatory (`TokenAuthASGIMiddleware`) — a Bearer token or Basic
  (user/password, local + LDAP); missing/invalid is rejected. Basic auth only base64-encodes the
  password in transit → **TLS is recommended in production (reverse proxy / ldaps)**.
- **RBAC**: tools are authorized by role (viewer < analyst < admin). Read-only
  tools are open to viewer; `start_scan` requires analyst+. Unauthorized call → 403 + audit.
