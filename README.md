# Kangalis

> **İç ağınızın bekçisi** — Lineup-NOAH ekibinin Python tabanlı, web panelli, ağırlıklı **iç ağ/sistem taramasına** odaklı zafiyet yönetim platformu.

[![CI](https://github.com/Lineup-NOAH/kangalis/actions/workflows/ci.yml/badge.svg)](https://github.com/Lineup-NOAH/kangalis/actions/workflows/ci.yml)
[![durum](https://img.shields.io/badge/durum-beta-yellow)]()
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

> **nmap gerekir:** Tarama motoru `nmap` ikilisini çağırır; Docker imajına gömülü **gelmez**.
> Host'a kurun (`apt install nmap` / `brew install nmap` / `choco install nmap`) veya çalışma
> ortamında sağlayın.

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
