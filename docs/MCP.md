# Kangalis MCP Sunucusu

Claude'un (Desktop / Code) Kangalis'i doğrudan kullanabilmesi için MCP sunucusu.
Araçlar, web arayüzüyle **aynı core/service katmanını** çağırır.

## Araçlar

| Araç | Açıklama |
|---|---|
| `list_assets()` | Keşfedilen host ve servisleri (envanter) listeler |
| `list_vulnerabilities(severity?, limit?)` | Bulguları risk sırasına göre listeler (severity: critical/high/medium/low/info) |
| `lookup_cve(cve_id)` | CVE detayı: CVSS, severity, EPSS olasılığı, KEV (aktif sömürü) |
| `scan_status(scan_id)` | Tarama durumu (pending/running/completed/failed) |
| `start_scan(target)` | Yetkili kapsamda ağ taraması başlatır (scope guard'dan geçer) |
| `search_exploits(query?, category?, severity?, limit?)` | Yerel exploit/CVE deposunda arar (kategori: windows/web/database/...; severity) |
| `exploits_for_cve(cve_id)` | Bir CVE için exploit sayısı + Metasploit modülü var mı |
| `exploit_db_stats()` | Exploit DB sayıları (kaynak/kritiklik/kategori dağılımı) |
| `list_ip_zones()` | Tanımlı IP zone'ları ve CIDR blokları |

## Çalıştırma

```bash
# stdio transport
cybersectool-mcp
# veya
python -m cybersectool.mcp.server
```

Sunucu veritabanına `DATABASE_URL` ile bağlanır (varsayılan `localhost:5432`).
`start_scan` ayrıca Celery worker'a iş gönderir (Redis gerekir).

## Claude Desktop yapılandırması

`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cybersectool": {
      "command": "uv",
      "args": ["run", "--directory", "<repo-dizini>", "cybersectool-mcp"],
      "env": {
        "DATABASE_URL": "postgresql+asyncpg://cyber:cyber@localhost:5432/cybersectool",
        "REDIS_URL": "redis://localhost:6379/0"
      }
    }
  }
}
```

> Docker stack'i ayakta olmalı (`docker compose up -d`) ki DB/Redis erişilebilsin.

## Örnek kullanım (Claude'a)

> "Şu subnet'i tara: 10.0.0.0/24, bittiğinde kritik zafiyetleri özetle."

Claude sırayla `start_scan` → `scan_status` → `list_vulnerabilities(severity="critical")`
araçlarını çağırır.

## Uzaktan erişim (HTTP)

stdio yerine **HTTP transport** ile merkezi bir MCP sunucusu çalıştırılabilir; ağdaki
herkes kendi kimliğiyle bağlanır. **İki kimlik yöntemi** desteklenir:

1. **API token** — `Authorization: Bearer cst_...` (programatik/otomasyon için)
2. **Kullanıcı adı + parola** — `Authorization: Basic base64(kullanıcı:parola)`
   (HTTP Basic). Hem **yerel** kullanıcılar hem de **LDAP/AD** kullanıcıları geçerlidir
   (LDAP kullanıcısı ilk bağlantıda otomatik oluşturulur). Çoğu MCP/HTTP istemcisi
   "Basic auth: kullanıcı/parola" alanlarıyla bunu doğrudan destekler.

Sunucuyu HTTP modunda çalıştır (docker-compose'daki `mcp` servisi bunu yapar):

```bash
MCP_TRANSPORT=http python -m cybersectool.mcp.server   # http://0.0.0.0:8001/mcp
```

Geçersiz/eksik kimlik → 401. API token üretimi (Bearer için):

```bash
docker compose exec app python -m cybersectool.scripts.create_token --username <kullanıcı-adı> --name claude-uzak
```

İstemci (streamable-http destekleyen) bağlantısı:

```
URL:    http://<sunucu-ip>:8001/mcp
Header: Authorization: Bearer cst_...           # token ile
   ya da Authorization: Basic <base64(user:pass)>  # kullanıcı/parola (yerel veya LDAP)
```

> Aynı LAN'daki kullanıcılar tek merkezi MCP'ye bağlanır; her erişim kullanıcıya
> (dolayısıyla denetim günlüğüne ve **role** — bkz. aşağıdaki RBAC) bağlanır.

## Güvenlik

- `start_scan` **scope guard**'dan geçer; yetkili kapsam dışı hedef reddedilir.
- **stdio**: yerel/güvenilir süreç (Claude Desktop başlatır).
- **HTTP**: kimlik zorunlu (`TokenAuthASGIMiddleware`) — Bearer token ya da Basic
  (kullanıcı/parola, yerel+LDAP); eksik/geçersiz reddedilir. Basic auth parolayı
  yalnızca base64 ile taşır → **üretimde TLS (reverse proxy / ldaps) önerilir**.
- **RBAC**: araçlar role göre yetkilendirilir (viewer < analyst < admin). Salt-okunur
  araçlar viewer'a açık; `start_scan` analyst+ ister. Yetkisiz çağrı → 403 + audit.
