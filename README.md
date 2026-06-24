# Kangalis

> **İç ağınızın bekçisi** — Kangalis ekibinin Python tabanlı, web panelli, ağırlıklı **iç ağ/sistem taramasına** odaklı zafiyet yönetim platformu.

[![CI](https://github.com/Lineup-NOAH/kangalis-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Lineup-NOAH/kangalis-core/actions/workflows/ci.yml)
[![sürüm](https://img.shields.io/badge/sürüm-1.0.0-blue)]()
[![python](https://img.shields.io/badge/python-3.12%2B-blue)]()
[![lisans](https://img.shields.io/badge/lisans-MIT-green)]()

Hafif bir OpenVAS/Nessus alternatifi; iç ağdaki host ve servisleri keşfeder, bilinen
zafiyetlerle (CVE) eşleştirir ve bunları **sömürülebilirlik sinyalleriyle** (Exploit-DB,
CISA KEV, EPSS) zenginleştirerek **risk önceliklendirmesi** yapar. Ayrıca **MCP** üzerinden
Claude ile konuşabilir.

> ⚠️ **Yasal uyarı:** Bu araç yalnızca **yetkili kapsam** içinde (sahip olduğunuz ya da
> izin verilen ağlar) kullanılmalıdır. İzinsiz tarama yasa dışıdır.

## 📦 Açık-kaynak çekirdek

Bu depo **açık-kaynak çekirdektir** (MIT): ağ/host keşfi, port & servis/sürüm tespiti, CVE
eşleştirme, sömürülebilirlik **sinyalleri** (Exploit-DB/CISA KEV/EPSS — yalnız *bilgi*), uyum
denetimleri (CIS/KVKK/ISO/PCI), raporlama ve yerel (on-prem) savunmacı AI. **Exploit
*çalıştırmaz*.** Gerçek sömürü/sızma (Metasploit orkestrasyonu, izole PoC çalıştırma,
kimlik brute-force) ayrı, opsiyonel bir **sömürü eklentisinde** tutulur ve bu depoya dahil
**değildir**. Çekirdek, eklenti olmadan tam çalışır.

> **nmap gerekir:** Tarama motoru `nmap` ikilisini çağırır; tarama bunsuz **çalışmaz**.
> Elle kurmanız gerekmez — `docker compose up --build` sırasında imaja **otomatik** gelir
> (`ARG INSTALL_NMAP=true`, varsayılan açık). nmap **NPSL** (Nmap Public Source License) ile
> dağıtılır; Kangalis ikiliyi yeniden dağıtmaz, sizin build'iniz Debian deposundan çeker.
> Ayrıntı: [`docs/KURULUM.md`](docs/KURULUM.md) ve [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).

## Özellikler

- 🔍 **Ağ & Host tarama** — host keşfi, port tarama, servis/versiyon tespiti (nmap)
- 🛡️ **CVE eşleştirme + risk skoru** — NVD/OSV + Exploit-DB + CISA KEV + EPSS
- 🌐 **Web tarama** — güvenlik başlıkları, TLS/SSL denetimi, dizin keşfi
- 📦 **SCA** — bağımlılık (requirements.txt, package.json) zafiyet taraması
- ✅ **Uyum denetimleri** — CIS/KVKK/ISO/PCI kontrolleri ve raporlama
- 🤖 **MCP sunucusu** — Claude tarama başlatıp sonuçları sorgular
- 🧠 **Yerel (on-prem) savunmacı AI** — bulgu özetleme ve uyum anlatısı
- 📊 **Web dashboard** — HTMX + Tailwind

Mimari/tasarım: [`docs/PROJE_PLANI.md`](docs/PROJE_PLANI.md)

## Kurulum (hızlı başlangıç)

**Tek önkoşul: Docker + Docker Compose.** Tamamen **on-prem** çalışır: tarama, veri ve AI
hepsi kendi makinenizde kalır — hiçbir veri dışarı çıkmaz.

### Seçenek 1 — Kurulum sihirbazı (en kolay; kaynaktan derler)

Tek komut: derle + başlat → migrate **otomatik** → admin kullanıcı sor → yetkili tarama
kapsamı/CIDR sor. `nmap` dahil her şey imaja otomatik gelir (elle kurulum yok).

```bash
# Linux / macOS
bash setup.sh          # veya:  make setup

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File setup.ps1
```

### Seçenek 2 — Yayınlanmış imajla (derleme yok; daha hızlı)

Hazır imajları doğrudan kayıt defterinden (ghcr.io) çekip çalıştırın — yerel derleme gerekmez:

```bash
git clone https://github.com/Lineup-NOAH/kangalis-core.git && cd kangalis-core
cp .env.example .env              # gizli anahtarları doldurun (ya da Seçenek 1 sihirbazını çalıştırın)

docker compose pull              # yayınlanmış çekirdek imajını çeker (derleme YOK)
docker compose up -d             # başlatır; migrate şemayı otomatik kurar

# Yönetici kullanıcı + yetkili tarama kapsamı (ZORUNLU):
docker compose exec app python -m cybersectool.scripts.create_user \
    --username <ad> --password <parola> --role admin
# Kapsamı panelden (Ayarlar → Yetkili Kapsam) ya da docs/KURULUM.md §3.3 ile tanımlayın.
```

> Sürüm sabitlemek için `.env`'de `KANGALIS_IMAGE=ghcr.io/lineup-noah/kangalis-core:vX.Y.Z`.

Ardından panel: **http://localhost:8000/login**

> ⚠️ Tarama yetkili **kapsam** (CIDR) tanımlanmadan çalışmaz. Yalnızca taramaya **yetkili
> olduğunuz** ağları girin.

### Sıfırlama / temiz yeniden kurulum

Kurulum bozulduysa ya da DB kullanıcı/parolasını değiştirmek istiyorsanız, **eski veritabanı
volume'ü yeni `.env` ile çakışır** (`migrate` → `password authentication failed for user ...`).
PostgreSQL kullanıcı/parolayı yalnız ilk açılışta gömer; klasörü/Docker'ı silmek **volume'ü
silmez**. Temiz sıfırlama tek komut:

```bash
# Windows
powershell -ExecutionPolicy Bypass -File reset.ps1

# Linux / macOS
bash reset.sh
```

> ⚠️ Tüm tarama verisini **siler** (`docker compose down -v` + tüm `kangalis*` volume'leri).
> Ardından `setup.ps1`/`setup.sh` ya da `docker compose up -d --build` ile yeniden kurun.
> `.env`'i (gizli anahtarlar) korur; sıfırdan istiyorsanız `-IncludeEnv` / `--include-env` ekleyin.
> Elle: `docker compose down -v` → `docker volume ls | grep kangalis` boşalana kadar
> `docker volume rm <ad>`.

### Yerel AI (opsiyonel, on-prem, sıfır egress)

AI tamamen yereldir (CPU'da çalışır); yalnız öneri/taslak hazırlar, eylemi her zaman insan
tetikler. **Önerilen yol — Ollama** (resmi `ollama/ollama` imajı; model çalışma anında iner):

```bash
docker compose --profile ai up -d ollama          # Ollama motoru (Docker Hub, public)
docker compose exec ollama ollama pull qwen3:8b   # modeli indir (~5 GB, tek seferlik)
```

Sonra panelde **Eklentiler → AI**: endpoint `http://ollama:11434/v1`, model `qwen3:8b`,
"Bağlantıyı test et" → yeşil.

> **Air-gap / sıfır çalışma-anı indirme (opsiyonel):** modeli **gömülü** taşıyan `kangalis-ai`
> imajını kullanabilirsiniz (`-f docker-compose.ai-baked.yml`). Yayınlanmış imajı çekmek için ghcr
> paketinin **public** olması gerekir — aksi halde `unauthorized` alırsınız. Alternatif: internetli
> bir makinede yerelde derleyin (`bash build-ai-image.sh` / `powershell -File build-ai-image.ps1`).
> Ayrıntı: [`docs/EKLENTILER.md`](docs/EKLENTILER.md).

- 📘 Ayrıntılı kurulum / manuel adımlar / üretime geçiş: [`docs/KURULUM.md`](docs/KURULUM.md)
- 🧩 Opsiyonel özellikler (yerel AI, MCP, eklentiler): [`docs/EKLENTILER.md`](docs/EKLENTILER.md)

## Teknoloji yığını

| Katman | Seçim |
|---|---|
| Dil / paket | Python 3.12+ · uv |
| Backend | FastAPI |
| Veritabanı | PostgreSQL + SQLAlchemy + Alembic |
| Görev kuyruğu | Celery + Redis |
| Frontend | Jinja2 + HTMX + Tailwind |
| Tarama | nmap, httpx |
| Dağıtım | Docker + docker-compose |

## Geliştirme ortamı

Gereksinim: [uv](https://docs.astral.sh/uv/) (Python'ı uv kendisi indirir).

```bash
# Bağımlılıkları kur (Python 3.12 dahil)
uv sync

# Testleri çalıştır
uv run pytest

# Lint & tip kontrolü
uv run ruff check .
uv run mypy

# (Opsiyonel) pre-commit kancalarını kur
uv run pre-commit install
```

## Proje yapısı

```
src/cybersectool/
├── core/        # ortak iş mantığı (service katmanı) + scope guard
├── scanners/    # tarama modülleri (ağ, web, sca, hardening)
├── intel/       # zafiyet/exploit veri kaynakları (NVD, OSV, EDB, KEV, EPSS)
├── api/         # FastAPI router'ları
├── web/         # dashboard (Jinja2 + HTMX)
├── tasks/       # Celery görevleri
└── mcp/         # MCP sunucusu
```

## Katkı / iş akışı

Fork + **main**'e PR. Conventional Commits. Her PR'da `ruff` + `mypy` + `pytest` geçmeli.
Ayrıntılar için: [CONTRIBUTING.md](CONTRIBUTING.md)

## Lisans

[MIT](LICENSE) © 2026 Lineup-NOAH

- Üçüncü taraf bağımlılık lisansları: [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)
- Güvenlik & sorumlu/yetkili kullanım: [SECURITY.md](SECURITY.md)
