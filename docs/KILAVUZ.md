# CyberSecTool — Kullanım Kılavuzu & Referans

> Bu dosya: **bilmen gereken her şey** tek yerde — giriş bilgileri, komutlar, mimari, kullanım.
> Proje: `C:\Users\Omer\Desktop\cybersectool` · GitHub: `Lineup-NOAH/CyberSecTool` (branch `dev`)
> Durum: **27 PR merged, tüm yol haritası tamam + uzaktan MCP.** 69 test geçiyor, CI yeşil.

---

## 1. 🔑 GİRİŞ BİLGİLERİ (Credentials)

> ⚠️ Aşağıdaki `cyber`, `dev-secret`, `Admin123!` değerleri **geliştirme varsayılanlarıdır** —
> local test için güvenli, **gerçek/üretim kullanımında MUTLAKA değiştir** (bkz. §6).

| Bileşen | Kullanıcı | Şifre / Değer | Nerede tanımlı | Not |
|---|---|---|---|---|
| **Web paneli (admin)** | `admin` | `Admin123!` | DB'de (testte oluşturuldu) | Hemen giriş için |
| **PostgreSQL** | `cyber` | `cyber` | `docker-compose.yml` | DB adı: `cybersectool` |
| **Oturum imzası** | — | `dev-secret` (SECRET_KEY) | `docker-compose.yml` (app) | Cookie imzalama |
| **Redis** | — | (şifresiz) | — | Port 6379 |
| **API token (Claude/MCP/API)** | — | `cst_...` | `create_token` ile üretilir | Bir kez gösterilir |

**Bağlantı dizesi (varsayılan):**
```
DATABASE_URL = postgresql+asyncpg://cyber:cyber@localhost:5432/cybersectool
REDIS_URL    = redis://localhost:6379/0
```

---

## 2. 🚀 ÇALIŞTIRMA (sıfırdan)

```powershell
cd C:\Users\Omer\Desktop\cybersectool

# 1) Tüm servisleri başlat (app, db, redis, worker, beat, mcp)
docker compose up -d --build

# 2) Veritabanı tablolarını oluştur/güncelle
docker compose exec app alembic upgrade head

# 3) Admin kullanıcı (yoksa). Mevcut: admin/Admin123!
docker compose exec app python -m cybersectool.scripts.create_user --username admin --password "GucluParola!" --role admin

# 4) ⚠️ ZORUNLU: yetkili tarama kapsamı (yoksa hiçbir tarama çalışmaz)
docker compose exec app python -m cybersectool.scripts.set_scope --name ic-ag --allow 192.168.1.0/24 --allow 10.0.0.0/8

# Durdurma:  docker compose down        (veri kalır)
# Sıfırlama: docker compose down -v      (veri SİLİNİR)
```

**Erişim adresleri:**
| Servis | Adres |
|---|---|
| Web paneli | http://localhost:8000/login |
| API dokümanı (Swagger) | http://localhost:8000/docs |
| Uzak MCP (token'lı) | http://localhost:8001/mcp |
| PostgreSQL | localhost:5432 |
| Redis | localhost:6379 |

---

## 3. 🖥️ WEB PANELİ KULLANIMI

`http://localhost:8000/login` → `admin` / `Admin123!`

| Sayfa | URL | Ne yapar |
|---|---|---|
| Panel | `/` | Özet sayaçlar + önem dağılımı |
| Taramalar | `/scans` | Yeni tarama (hedef + tür: Ağ/Web) + Zone taraması (güvenli/agresif/kimlikli) |
| Zone'lar | `/zones` | IP/CIDR bloklarını bölgelere grupla (yönetim) |
| Varlıklar | `/assets` | Keşfedilen host/servis envanteri |
| Zafiyetler | `/findings` | CVE'ler — risk sıralı, CVSS/Risk/KEV/EPSS |
| Exploit DB | `/exploits` | Yerel exploit deposu (Exploit-DB + Metasploit), başlık/CVE/ID ile ara |
| Rapor | `/report` | Yazdırılabilir/PDF güvenlik raporu |
| Kimlikler | `/credentials` | Kimlik kasası: SSH/WinRM/RDP kimlikleri + kimlik bölgeleri (sadece admin) |
| Denetim | `/audit` | Kim ne yaptı (sadece admin) |

**Kimlik kasası (`/credentials`, admin):** Windows/Linux/farklı bağlantılar için kimlik oluştur
(ad + tip SSH/WinRM/RDP + kullanıcı + parola + domain/port). Parolalar **Fernet ile şifreli** saklanır,
panelde bir daha gösterilmez. Kimlikleri **kimlik bölgelerinde** grupla (IP zone'unun kimlik karşılığı).
API: `POST/GET/DELETE /api/credentials`, `POST/GET/DELETE /api/credential-zones`.
Şifreleme anahtarı: `CREDENTIAL_ENCRYPTION_KEY` (boşsa SECRET_KEY'den türetilir; üretimde ayrı ver).

**IP zone × kimlik bölgesi taraması:** Taramalar → IP Zone taraması → tarama tipi
**"🔑 Kimlik bölgesiyle"** → bir kimlik bölgesi seç. Her host'un açık portu yoklanır (OS ipucu:
22→Linux/SSH, 3389/5985/5986→Windows) ve kimlikler **OS önceliğiyle** denenir. SSH kimlikli
denetimi tam çalışır (içeriden envanter+denetim); Windows portu açıksa erişilebilirlik raporlanır
(tam WinRM/RDP auth backend'i sonraki adım). Kimlikler kasadan çözülür, anlık kullanılır.

**Tarama başlatma:** Taramalar → hedef gir (`192.168.1.0/24` veya `https://site`) → tür seç → "Tarama Başlat".

**Zafiyet & Exploit veritabanı (`/exploits`):** Yerel depo. Üç kaynaktan içe aktarılır:
**NVD** (son 120 günün CVE'leri, CVSS skorlu), **Exploit-DB** (~47k), **Metasploit** (~6.6k).
Başlık, CVE veya ID ile aranır. **Sınıflandırma:** her kayıt **kritikliğe** (Kritik/Yüksek/Orta/Düşük)
ve **kullanım kategorisine** (Windows / Linux / macOS / Web / Database / Ağ / IoT / Cloud / Mobil)
otomatik ayrılır — sync'te yeni gelenler de otomatik sınıflanır. Panelde kritiklik + kategori + kaynak
filtreleri ve sayılı kategori çipleri var. Güncelleme: panelde **"🔄 Veritabanını Güncelle"**
(admin → onay popup'ı → arka plan görevi) ya da `docker compose exec app python -m cybersectool.scripts.sync_exploits`.
Eski kayıtları yeniden sınıflandırmak: `... python -m cybersectool.scripts.reclassify_exploits [--all]`.
API: `GET /api/exploits?q=&source=&category=windows&severity=critical`, `POST /api/exploits/sync`.
NVD toplu çekme `NVD_API_KEY` ile hızlanır. Tipik boyut: ~70k kayıt ≈ 20-25 MB.
> Taramayla otomatik eşleştirme (bir CVE bulununca ilgili exploit'leri gösterme) sonraki adımda.

**Zone (tarama bölgesi):** `/zones` → ad + IP/CIDR blokları gir (her satıra bir tane) → "Zone Oluştur".
Zone'lar **yalnızca yönetilir** burada (oluştur/sil). **Tarama Taramalar sayfasından** yapılır:
`/scans` → "🗺️ Zone taraması" → zone seç + tarama tipi seç (**Güvenli / Agresif / Credentialed**) → "Zone'u Tara".
Bölgedeki **tüm bloklar** taranır (kapsam dışı bloklar otomatik atlanır, bilgi mesajı gösterilir).
Credentialed'da SSH kullanıcı/parola girilir (saklanmaz, her host'a aynı kimlikle denenir).
API (ağ modu): `POST /api/zones`, `GET /api/zones`, `POST /api/zones/{id}/scan` (mode), `DELETE /api/zones/{id}`.

---

## 4. 🔧 TARAMA TÜRLERİ

| Tür | Nasıl | Bulur |
|---|---|---|
| **Ağ** | Panel formu (hedef=IP/CIDR) | Açık port, servis/versiyon → CVE eşleştirme (NVD) + KEV/EPSS + risk |
| **Web** | Panel formu (hedef=URL) | Eksik güvenlik başlıkları, TLS, hassas yollar (.git/.env vb) |
| **SCA** | `POST /sca` (API) | requirements.txt / package.json → OSV.dev açıkları |
| **Host** | `POST /hardening` (API) | SSH ile CIS-tarzı denetim (kimlik bilgisi saklanmaz) |
| **Kimlikli (credentialed)** | Panel (🔐 admin) / `POST /scans/credentialed` | SSH ile **sunucu içinden** denetim: OS/kernel envanteri, bekleyen güncellemeler, NOPASSWD sudo, dünya-yazılabilir dosyalar + CIS. Hedefi değiştirmez. Kimlik bilgisi **saklanmaz** |

### 🛡️ vs ⚠️ Tarama yoğunluğu (mod) — ağ taraması için

Ağ taraması iki yoğunlukta çalışır (panelde "Yoğunluk" seçici):

| Mod | Ne yapar | nmap |
|---|---|---|
| 🛡️ **Güvenli** (varsayılan) | Tespit — port/servis/versiyon → CVE çıkarımı + nmap **default** (bilgi toplayıcı) NSE scriptleri (`-sC`: banner/başlık/TLS/SMB OS keşfi). Müdahaleci script **çalıştırmaz**. | `-sV -sC -T4` |
| ⚠️ **Agresif** | NSE `vuln`/`exploit`/`discovery` scriptleri + OS parmak izi — zafiyeti **deneyerek doğrular**. DoS ve brute **hariç**. Servis kesintisi / iz bırakma riski. | `-sV -T4 -A --script "(vuln or exploit or discovery) and not dos and not brute"` |

**Agresif mod çift kilitlidir** (OpenVAS-tarzı kazaları önlemek için):
1. **Global ayar** `ALLOW_AGGRESSIVE_SCANS=true` olmalı (varsayılan **kapalı** → UI'da seçenek pasif).
2. Yalnızca **`admin`** rolü başlatabilir.

Kilitlerden biri sağlanmazsa istek **403** ile reddedilir. Agresif tarama `aggressive_scan_start`
olarak **denetim günlüğüne** (kim/ne zaman) yazılır. Zamanlanmış taramalar ve MCP **her zaman güvenli** moddadır.

---

## 5. 🤖 MCP (Claude entegrasyonu) — 2 mod

### A) Local (stdio) — kendi Claude Desktop'ın
`claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "cybersectool": {
      "command": "uv",
      "args": ["run", "--directory", "C:/Users/Omer/Desktop/cybersectool", "cybersectool-mcp"],
      "env": { "DATABASE_URL": "postgresql+asyncpg://cyber:cyber@localhost:5432/cybersectool" }
    }
  }
}
```

### B) Uzak (HTTP + token) — ağdaki herkes
1. Token üret: `docker compose exec app python -m cybersectool.scripts.create_token --username omer --name claude-uzak`
2. İstemci bağlantısı:
   ```
   URL:    http://<sunucu-ip>:8001/mcp
   Header: Authorization: Bearer cst_...
   ```
Token yoksa/geçersizse → **401**. Detay: `docs/MCP.md`.

**MCP araçları:** `list_assets`, `list_vulnerabilities(severity?)`, `lookup_cve(cve_id)`, `scan_status(scan_id)`, `start_scan(target)`.

---

## 6. 🔐 ÜRETİME GEÇİŞ (varsayılan şifreleri değiştir)

1. Proje köküne **`.env`** oluştur (örnek: `.env.example`), git'e GİRMEZ.
2. Güçlü değerler ver:
   ```
   SECRET_KEY=<uzun-rastgele-dize>
   DATABASE_URL=postgresql+asyncpg://cyber:<GUCLU_PAROLA>@db:5432/cybersectool
   NOTIFY_WEBHOOK_URL=<istersen Slack/webhook>
   ALLOW_AGGRESSIVE_SCANS=false   # agresif/müdahaleci tarama; yalnızca bilinçli aç
   ```
3. `docker-compose.yml`'de `POSTGRES_PASSWORD` ve app `SECRET_KEY` değerlerini de güncelle (ya da `.env`'den oku).
4. Redis'e şifre ekle, portları (5432/6379) dışarı açma; sadece iç ağ.
5. **İç ağ taraması için:** Windows Docker Desktop gerçek LAN'a sınırlı erişir → üretimde **Linux sunucuda** (host networking ile) çalıştır.

---

## 7. 👥 ROLLER (RBAC)

| Rol | Yetki |
|---|---|
| `admin` | Her şey: tarama, scope, kullanıcı, denetim, zamanlama, host |
| `analyst` | Tarama başlatır, sonuçları görür |
| `viewer` | Sadece görüntüler |

---

## 8. ⚙️ MİMARİ (özet)

**6 Docker servisi** (tek makine, Docker Compose — Kubernetes değil):

| Servis | İmaj | Görev |
|---|---|---|
| `db` | postgres:16 | Veritabanı |
| `redis` | redis:7 | İş kuyruğu |
| `app` | cybersectool (kendi) | Web + API (8000) |
| `worker` | cybersectool (kendi) | Taramaları arka planda yapar |
| `beat` | cybersectool (kendi) | Zamanlanmış taramaları tetikler |
| `mcp` | cybersectool (kendi) | Uzak MCP (8001, token'lı) |

> `app/worker/beat/mcp` **aynı imajın** farklı rolleridir (aynı kod, farklı komut).

**Tarama akışı:** `app` işi → `redis` kuyruğu → `worker` (nmap/CVE/risk) → `db` → panel okur.

**Kod yapısı (`src/cybersectool/`):** `core/` (ortak iş mantığı + scope + risk), `scanners/` (network/web/sca/hardening), `intel/` (nvd/osv/kev/epss), `tasks/` (Celery), `api/` (FastAPI), `web/` (HTML), `mcp/` (Claude). **Web UI, MCP, API → hepsi aynı `core` katmanını çağırır.**

---

## 9. 📋 KOMUT CHEAT-SHEET

```powershell
# Not: shell'inde 'docker' PATH'te yoksa başına şunu ekle:
#   $env:PATH = "C:\Program Files\Docker\Docker\resources\bin;" + $env:PATH

docker compose up -d --build                 # başlat
docker compose ps                            # servis durumu
docker compose logs worker --tail 20         # worker logları
docker compose exec app alembic upgrade head # migration

# kullanıcı / token / scope
docker compose exec app python -m cybersectool.scripts.create_user --username X --password "Y" --role admin
docker compose exec app python -m cybersectool.scripts.create_token --username X --name mcp
docker compose exec app python -m cybersectool.scripts.set_scope --name ic --allow 10.0.0.0/8

# geliştirme (kod değişince)
uv run pytest                  # testler (69)
uv run ruff check .            # lint
uv run mypy                    # tip kontrolü
docker compose down            # durdur
```

---

## 10. ⚠️ ÖNEMLİ NOTLAR

- **Scope zorunlu:** Tanımlamadığın hiçbir hedef taranmaz (default-deny, yasal güvence).
- **Windows + iç ağ:** Docker Desktop gerçek ofis LAN'ını taramada sınırlı; üretim için Linux sunucu öner.
- **Veri kalıcı:** `docker compose down` veriyi korur (pgdata volume). `-v` eklersen siler.
- **Migration zinciri başı→son:** baseline → users → api_tokens → assets/scans/findings → scope_policies → cves → cve exploitability → scheduled_scans (`af93c05a857c` = güncel head).
- **Git/PR akışı:** `feature/*` → `dev` PR → squash merge. CI (GitHub Actions) her PR'da ruff+mypy+pytest çalıştırır.
- **MCP HTTP'de token = kimlik doğrulama**; araç-içi per-user RBAC henüz yok (geçerli token'lı herkes tüm araçları kullanır).
- **Agresif tarama tehlikelidir:** hedef servisi kesintiye uğratabilir / iz bırakabilir. Varsayılan kapalı; açmadan önce hedefin **yedeğini al**. Üretim/kırılgan sistemlerde dikkatli kullan.

---

## 11. ✅ YAPILANLAR (27 PR) & SONRAKİ ADAY İŞLER

**Tamamlandı:** Temel (Docker/FastAPI/Postgres/Alembic/auth/RBAC/token) · MVP (nmap ağ tarama + envanter + panel) · CVE zekâsı (NVD + KEV + EPSS + risk skoru) · MCP (local + uzak) · Web/SCA/Host tarayıcılar · Zamanlanmış taramalar · Bildirimler · Rapor · Denetim · CI/CD.

**Sonraki aday işler (plan dışı, istersen):**
- MCP araçlarına **per-user RBAC** (token → kullanıcı rolü)
- **Ürün-içi /chat** (Claude API tool-use **veya** local Ollama modeli)
- SSH credential **şifreli saklama**
- Gerçek **PDF** rapor (WeasyPrint), NVD **yerel mirror**

---

*Detaylı plan: `docs/PROJE_PLANI.md` · MCP detay: `docs/MCP.md`*
