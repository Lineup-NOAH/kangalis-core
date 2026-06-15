# CyberSecTool — Proje Planı ve Yol Haritası

> **Durum:** Taslak v1 · **Sahip:** Lineup-NOAH ekibi · **Hedef branch:** `dev`
> Bu doküman, projenin yol haritasını **sırayla yapılacak PR'lar** halinde tanımlar.
> Her PR küçük, gözden geçirilebilir ve bir öncekinin üstüne inşa edilebilir olacak şekilde planlanmıştır.

---

## 1. Genel Bakış / Vizyon

**CyberSecTool**, Lineup-NOAH ekibinin gerçekten kullanacağı, **Python tabanlı, web panelli, ağırlıklı olarak iç ağ/sistem taramasına odaklanan** bir **zafiyet yönetim platformudur**. Hafif bir OpenVAS/Nessus alternatifi gibi düşünülebilir; farkı, kendi dashboard'umuz ve **MCP üzerinden Claude ile konuşabilmesidir**.

Platform; iç ağdaki host ve servisleri keşfeder, bilinen zafiyetlerle (CVE) eşleştirir, bunları **sömürülebilirlik sinyalleriyle** (açık exploit var mı, vahşi doğada sömürülüyor mu, sömürülme olasılığı nedir) zenginleştirerek **risk önceliklendirmesi** yapar; ayrıca web uygulaması ve bağımlılık taramalarını da kapsar.

### Ne DEĞİLDİR (kapsam dışı ilkeler)
- Saldırı/sömürü aracı değildir. Exploit *çalıştırmaz*; yalnızca bir exploit'in *var olduğu* bilgisini savunma amaçlı önceliklendirme için kullanır.
- Yalnızca **yetkili kapsam (authorized scope)** içinde tarama yapar; izinsiz hedefleri taramaz.

---

## 2. Hedef Kullanıcı ve Kullanım Senaryoları

- **Birincil kullanıcı:** Lineup-NOAH güvenlik/altyapı ekibi.
- **Senaryolar:**
  - "İç subnet `10.0.0.0/24`'ü tara, açık portları ve servis versiyonlarını çıkar."
  - "Bulunan servislerdeki kritik CVE'leri, açık exploit'i olanları en üste koyarak listele."
  - "Şu web uygulamasının güvenlik başlıklarını ve TLS yapılandırmasını denetle."
  - "Bu projenin bağımlılıklarında bilinen güvenlik açığı var mı?"
  - **Claude ile:** "Şu subnet'i tara, bittiğinde kritikleri özetle ve KEV listesinde olanları işaretle." (MCP araçları üzerinden)

---

## 3. Kapsam (Scope)

| Öncelik | Modül | Açıklama |
|---|---|---|
| 🥇 | **Ağ & Host Tarama** | Host keşfi, port tarama, servis/versiyon tespiti (iç ağ ağırlıklı) |
| 🥈 | **CVE Eşleştirme + Sömürülebilirlik** | Servis versiyonu → CVE; Exploit-DB/KEV/EPSS zenginleştirme |
| 🥉 | **MCP Sunucusu** | Claude'un platformu kullanabilmesi için araç katmanı |
| 4 | **Web Uygulama Tarama** | Güvenlik başlıkları, TLS/SSL, dizin keşfi |
| 5 | **SCA / Bağımlılık Tarama** | requirements.txt, package.json vb. → bilinen açıklar |
| 6 | **Host Sıkılaştırma** | Kimlik doğrulamalı (SSH/WinRM) CIS-tarzı yapılandırma denetimi |

---

## 4. Teknoloji Yığını (Kararlar)

| Katman | Seçim | Durum | Neden |
|---|---|---|---|
| Dil | **Python 3.12+** | ✅ Karar | Güvenlik ekosistemi en zengin |
| Paket yönetimi | **uv** | ✅ Karar | Çok hızlı, modern |
| Backend | **FastAPI** | ✅ Karar | Async, otomatik OpenAPI, hızlı |
| DB | **PostgreSQL + SQLAlchemy 2.0 (async) + Alembic** | ✅ Karar | Sağlam, migration'lı |
| Görev kuyruğu | **Celery + Redis** | ✅ Karar | Taramalar uzun sürer, arka plan gerekir |
| Frontend | **Jinja2 + HTMX + Tailwind + Alpine.js** | ✅ Karar | Python-merkezli, ayrı JS build yok (sonra React opsiyonu) |
| Ağ tarama | **nmap** (python-libnmap sarmalayıcı) | ✅ Karar | En güçlü/hızlı yol (sistemde nmap kurulu varsayımı) |
| Web kontrolleri | **httpx**, **cryptography/ssl** | ✅ Karar | Başlık + TLS denetimi |
| Zafiyet verisi | **NVD API 2.0** + **OSV.dev** | ✅ Karar | CVE + CVSS |
| Sömürülebilirlik | **Exploit-DB** + **CISA KEV** + **EPSS** (+ ops. Metasploit) | ✅ Karar | Risk önceliklendirme |
| MCP | **FastMCP** (stdio → sonra HTTP/SSE) | ✅ Karar | Claude entegrasyonu |
| Rapor | **WeasyPrint** (PDF) | ✅ Karar | Paylaşılabilir raporlar |
| Dağıtım | **Docker + docker-compose** | ✅ Karar | Tek komutla ayağa kalkar |
| CI/CD | **GitHub Actions** | ✅ Karar | Test + lint + build |
| Test/Lint | **pytest, ruff, mypy, pre-commit** | ✅ Karar | Kalite |

> Kararlar değiştirilebilir; değişiklik olursa bu tablo güncellenir.

---

## 5. Sistem Mimarisi

```
   ┌──────────────┐          ┌──────────────────┐
   │ Web Dashboard│          │  Claude (Desktop/│
   │  (HTMX)      │          │  Code) = MCP'ci  │
   └──────┬───────┘          └────────┬─────────┘
          │ HTTP                      │ MCP (stdio/SSE)
   ┌──────▼───────┐          ┌────────▼─────────┐
   │ FastAPI routes│         │ MCP Server (araç)│
   └──────┬───────┘          └────────┬─────────┘
          └────────────┬──────────────┘
                ┌───────▼────────┐
                │  CORE / SERVICE │   ← ortak iş mantığı (TEK kaynak)
                │  - asset svc    │
                │  - scan svc     │
                │  - vuln svc     │
                │  - scope guard  │
                └───────┬────────┘
       ┌────────────────┼─────────────────────┐
 ┌─────▼─────┐   ┌──────▼───────┐      ┌───────▼────────┐
 │PostgreSQL │   │ Celery+Redis │      │ Vuln/Exploit   │
 │(varlık,   │   │ (tarama      │      │ veri kaynakları│
 │ zafiyet,  │   │  görevleri)  │      │ NVD/OSV/EDB/KEV│
 │ CVE, log) │   └──────┬───────┘      └────────────────┘
 └───────────┘          │
              ┌─────────┼──────────┬───────────────┐
        ┌─────▼────┐ ┌──▼──────┐ ┌─▼────────┐ ┌────▼─────┐
        │ Ağ/Port  │ │ Web     │ │ SCA      │ │ Host     │
        │ tarayıcı │ │ tarayıcı│ │ tarayıcı │ │ harden.  │
        └──────────┘ └─────────┘ └──────────┘ └──────────┘
```

**Mimari ilke:** Web paneli ve MCP sunucusu **asla** iş mantığını tekrarlamaz; ikisi de aynı **core/service** katmanını çağırır. Scope (yetkili kapsam) kontrolü tek bir yerde, core'da uygulanır.

---

## 6. Tarama Modülleri (Özet)

1. **Ağ & Host Tarama:** ping/ARP sweep ile host keşfi → port tarama → `nmap -sV` ile servis/versiyon → OS fingerprinting (ops.). Çıktı: Asset envanteri.
2. **CVE Eşleştirme:** `servis + versiyon` (CPE) → NVD/OSV → CVE listesi + CVSS.
3. **Sömürülebilirlik Zenginleştirme:** her CVE için Exploit-DB (açık PoC?), CISA KEV (aktif sömürülüyor?), EPSS (olasılık %).
4. **Web Uygulama Tarama:** güvenlik başlıkları, TLS/SSL yapılandırması, dizin/dosya keşfi, yaygın yanlış yapılandırmalar.
5. **SCA / Bağımlılık:** manifest dosyalarını parse → OSV.dev ile bilinen açık eşleştirmesi.
6. **Host Sıkılaştırma:** SSH/WinRM ile kimlik doğrulamalı CIS-benchmark tarzı kontroller.

---

## 7. Zafiyet & Sömürülebilirlik Veri Kaynakları

| Kaynak | Ne sağlar | Erişim | Maliyet |
|---|---|---|---|
| **NVD API 2.0** | CVE detayı, CVSS, CPE eşleştirme | REST API (rate-limit, ops. API key) | Ücretsiz |
| **OSV.dev** | Açık kaynak/paket zafiyetleri | REST API | Ücretsiz |
| **Exploit-DB** | Açık exploit/PoC var mı? | `files_exploits.csv` mirror (`codes` sütunu = CVE) | Ücretsiz |
| **CISA KEV** | Vahşi doğada aktif sömürülen CVE'ler | Tek JSON feed | Ücretsiz |
| **EPSS (FIRST.org)** | Sömürülme olasılığı (%) | REST API | Ücretsiz |
| **Metasploit** (ops.) | Hazır MSF modülü var mı? | `modules_metadata_base.json` | Ücretsiz |

**Risk skoru (taslak formül):**
`risk = CVSS_taban × ağırlık(EPSS) × (KEV ? +bonus) × (açık_exploit ? +bonus)`
→ Liste, `Kritik CVSS + açık exploit + KEV` olanları en üste koyacak şekilde sıralanır.

---

## 8. MCP Sunucusu

Claude'un (ve diğer MCP istemcilerinin) platformu kullanabilmesi için araç katmanı.

**Araçlar (tools):**
- `list_assets(filter?)` — keşfedilen host/servisler
- `start_scan(target, scan_type)` — tarama başlat *(scope kontrolünden geçer)*
- `get_scan_status(scan_id)`
- `get_vulnerabilities(asset_id?, severity?)`
- `lookup_cve(cve_id)` — CVE detayı + exploit/KEV/EPSS durumu
- `get_exploits_for_cve(cve_id)` — Exploit-DB eşleşmeleri
- `generate_report(scan_id, format)`

**Resources:** asset listesi, son tarama özeti, kritik zafiyetler.

**Transport:** önce **stdio** (yerel Claude Desktop/Code), sonra ekip için **HTTP/SSE**.

**Güvenlik:** MCP araçları aynı **auth + scope guard**'dan geçer; bir LLM izinsiz hedef tarayamaz.

---

## 9. Kimlik Doğrulama Mimarisi

**Altın kural:** *Kimlik doğrulama (kim olduğun)* ile *yetkilendirme (ne yapabildiğin)* ayrıdır.
Birden çok giriş yöntemi olabilir; hepsi **tek bir `User` kimliğine** çözülür ve **tek bir yetki
katmanından** (RBAC + scope guard, `core`'da) geçer.

### Giriş kanalları ve kimlik bilgisi türleri

| Kanal | Kimlik bilgisi | Doğrulama kaynağı |
|---|---|---|
| Web dashboard (tarayıcı) | kullanıcı/şifre → **session cookie** | local hash **veya** LDAP |
| API (programatik) | **API token** (`Authorization: Bearer`) | bizim `ApiToken` tablomuz |
| MCP (Claude) | **API token** (config'de saklı) | bizim `ApiToken` tablomuz |

> MCP ayrı bir auth mekanizması **değildir** — API token'ı kullanan bir istemcidir. Yani aslında
> **2 tür kimlik bilgisi** vardır: session + API token.

```
   GİRİŞ YÖNTEMİ              KİMLİK BİLGİSİ
Web tarayıcı  → kullanıcı/şifre → session cookie ┐
API istemcisi → API token (Bearer) ─────────────┤→ [get_current_user] → User
MCP (Claude)  → API token (Bearer) ─────────────┘         │
                                                          ▼
                                        core: RBAC rol + scope guard
                                        (TEK yer — kanaldan bağımsız)
```

### Tek doğrulama bağımlılığı
`get_current_user` hem `Bearer` token'ı hem session cookie'sini kabul eder, ikisini de tek `User`'a
çözer. Üstüne `require_role("admin", "analyst")` gibi bir bağımlılık ile RBAC uygulanır. Tarama
başlatma kuralı tek yerdedir; ister tarayıcıdan, ister API'den, ister Claude'dan gelsin aynı yetki +
scope kontrolünden geçer.

### API token'ları
- Üretim: `secrets.token_urlsafe` + `cst_` ön eki; DB'ye yalnızca **hash** yazılır (kullanıcıya bir
  kez gösterilir — şifre gibi).
- İptal edilebilir (`revoked`), süreli (`expires_at`), sahibinin **rolünü miras alır**.
- **LDAP'tan bağımsız:** token'ları biz üretir, biz doğrularız → her API/MCP isteğinde dizine gidilmez
  (LDAP yalnızca interaktif login'de devreye girer).

### LDAP / Active Directory (opsiyonel kimlik backend'i)
Kurumsal dizinle entegrasyon. **Sadece login adımını** değiştirir; session/token/MCP/RBAC aynı kalır.
- Şifreyi yerel hash yerine dizine **bind** ederek doğrular (servis hesabıyla ara → kullanıcının kendi
  şifresiyle yeniden bind).
- `User.auth_source` = `local | ldap`; LDAP kullanıcılarının şifresi **saklanmaz** (`password_hash = NULL`).
- **Just-in-time provisioning:** ilk başarılı LDAP girişinde yerel `User` satırı açılır (token, audit
  log, tarama sahipliği bu kalıcı kimliğe bağlanır).
- **Grup → rol haritalama:** AD grupları (`memberOf`) → `admin` / `analyst` / `viewer`.
- Kütüphane: **`ldap3`** (saf Python, Docker dostu).
- **Güvenlik:** mutlaka **LDAPS/StartTLS**; servis hesabı secrets'ta; LDAP çökerse diye **break-glass**
  bir yerel `admin`; AD'de disabled/locked hesabı reddet.

### Akış özeti
```
login(kullanıcı/şifre) → backend seçici ──► local: password_hash doğrula
                                       └──► ldap : dizine bind + JIT provision
        │ (başarılı → User)
        ▼
   session cookie  →  bundan sonrası TÜM kanallarda aynı: RBAC + scope guard
```

## 10. Veri Modeli (Taslak)

- **User** (id, username, email, password_hash[nullable], rol, **auth_source**[local|ldap], is_active) — RBAC: `admin`, `analyst`, `viewer`
- **ApiToken** (id, user_id, name, token_hash, expires_at, revoked, last_used_at) — API + MCP erişimi
- **Session** (id → user_id, son_kullanım) — Redis'te tutulur, web oturumu
- **ScopePolicy** (id, izinli_cidr'ler, yasak_cidr'ler, sahip) — yetkili kapsam
- **Asset** (id, ip, hostname, os, ilk_görülme, son_görülme)
- **Service** (id, asset_id, port, protokol, servis_adı, versiyon, cpe)
- **Scan** (id, tür, hedef, durum, başlangıç, bitiş, başlatan_user)
- **Finding** (id, scan_id, asset_id, service_id, cve_id, severity, risk_score, durum)
- **CVE** (id, açıklama, cvss, epss, kev_flag, exploit_count, referanslar)
- **Exploit** (id, edb_id, cve_id, başlık, platform, doğrulanmış_mı, kaynak_url)
- **Report** (id, scan_id, format, yol, oluşturulma)
- **AuditLog** (id, user_id, eylem, hedef, zaman) — kim neyi taradı

---

## 11. Repo Dizin Yapısı (hedef)

```
cybersectool/
├── docs/
│   └── PROJE_PLANI.md            # bu doküman
├── src/cybersectool/
│   ├── core/                     # ortak iş mantığı (service katmanı)
│   │   ├── services/             # asset, scan, vuln, report servisleri
│   │   ├── scope.py              # yetkili kapsam kontrolü
│   │   └── models.py             # SQLAlchemy modelleri
│   ├── scanners/                 # tarama modülleri (eklenti tarzı)
│   │   ├── base.py
│   │   ├── network.py
│   │   ├── web.py
│   │   ├── sca.py
│   │   └── hardening.py
│   ├── intel/                    # zafiyet/exploit veri kaynakları
│   │   ├── nvd.py  osv.py  exploitdb.py  kev.py  epss.py
│   ├── api/                      # FastAPI router'ları
│   ├── web/                      # Jinja2 + HTMX şablonları, statikler
│   ├── tasks/                    # Celery görevleri
│   ├── mcp/                      # MCP sunucusu (FastMCP)
│   └── config.py
├── alembic/                      # migration'lar
├── tests/
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
├── .env.example
└── README.md
```

---

## 12. Güvenlik, Yasal ve Etik İlkeler

1. **Yetkili kapsam zorunlu:** Tarama yalnızca `ScopePolicy`'de tanımlı izinli aralıklarda çalışır. Kapsam dışı hedefte hata döner.
2. **Audit log:** Her tarama "kim, ne zaman, neyi" diye kaydedilir.
3. **Kimlik bilgisi güvenliği:** SSH/WinRM kimlik bilgileri şifreli saklanır (ör. secrets yöneticisi / şifreli alan).
4. **Exploit'ler çalıştırılmaz:** Yalnızca varlık/meta bilgisi tutulur.
5. **Rate-limit & nezaket:** Dış API'lere (NVD vb.) saygılı istek; tarama hızında hedefe zarar vermeyen ayarlar.
6. **Gizli veriler repoda tutulmaz:** `.env` git'e girmez; `.env.example` örnek olur.

---

## 13. Geliştirme İş Akışı (Git / PR Süreci)

- **Branch modeli:** `main` (kararlı) ← `dev` (entegrasyon) ← `feature/*` (PR dalları).
- **Akış:** her iş için `feature/<kısa-ad>` dalı aç → `dev`'e PR → review → merge. Sürüm zamanı `dev` → `main`.
- **Commit standardı:** Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`).
- **PR kuralları:** küçük ve odaklı; açıklama + ekran görüntüsü (UI ise); CI yeşil; en az 1 review.
- **CI (PR-26 ile):** ruff + mypy + pytest her PR'da çalışır.

### Genel "Definition of Done" (her PR için)
- [ ] Kod ruff + mypy'den temiz geçer
- [ ] İlgili testler yazıldı ve geçer
- [ ] Gerekliyse migration eklendi
- [ ] README/doküman güncellendi
- [ ] `.env.example` güncel (yeni ayar varsa)
- [ ] Manuel doğrulama notu PR açıklamasında

---

## 14. Yol Haritası — PR Sırası

> Her PR: **Amaç → Kapsam → Teslimatlar → Kabul Kriterleri → Bağımlılık**.
> Sıra önemlidir; PR'lar bir önceki üstüne inşa olur.

### Faz 0 — Temel / İskelet

#### PR-00 · Proje planı dokümanı *(bu PR)*
- **Amaç:** Yol haritasını belgelemek.
- **Teslimat:** `docs/PROJE_PLANI.md`.
- **Kabul:** Ekip planı onaylar.

#### PR-01 · Proje iskeleti + tooling
- **Kapsam:** `uv` ile `pyproject.toml`, dizin yapısı, `ruff`/`mypy`/`pytest`/`pre-commit`, `.gitignore`, `.env.example`, `LICENSE`, README iskeleti.
- **Teslimat:** `uv run pytest` çalışan boş bir proje.
- **Kabul:** Lint + boş test geçer; `uv sync` sorunsuz.
- **Bağımlılık:** PR-00.

#### PR-02 · Docker Compose + FastAPI + DB bağlantısı
- **Kapsam:** `Dockerfile`, `docker-compose.yml` (app + PostgreSQL + Redis), FastAPI uygulaması, `/health` endpoint, SQLAlchemy async engine, Alembic baseline.
- **Teslimat:** `docker compose up` ile API ayağa kalkar, `/health` 200 döner.
- **Kabul:** DB'ye bağlanır, ilk (boş) migration uygulanır.
- **Bağımlılık:** PR-01.

#### PR-03 · Auth + RBAC iskeleti
- **Kapsam:** `User` modeli (+`auth_source`), parola hash (argon2/bcrypt), web login → **session cookie**, rol kontrolü (`require_role`), korumalı örnek endpoint. Detay: bkz. **§9 Kimlik Doğrulama Mimarisi**.
- **Teslimat:** Giriş yapıp korumalı endpoint'e erişim.
- **Kabul:** Yetkisiz erişim 401/403; testler geçer.
- **Bağımlılık:** PR-02.

#### PR-03.5 · API token'ları (API + MCP erişimi)
- **Kapsam:** `ApiToken` modeli, token üret/iptal et (panel), `get_current_user`'ı **Bearer token + session**'ı birlikte kabul edecek şekilde genişlet.
- **Kabul:** Üretilen token ile API çağrısı yetkilenir; iptal edilen token reddedilir.
- **Bağımlılık:** PR-03.

#### PR-03.7 · LDAP / Active Directory entegrasyonu (opsiyonel)
- **Kapsam:** `ldap3` ile LDAP bind doğrulama, JIT provisioning, grup→rol haritalama; pluggable backend seçici (`local`/`ldap`). LDAPS zorunlu.
- **Kabul:** LDAP kullanıcısı giriş yapıp doğru rolü alır; break-glass yerel admin çalışır.
- **Bağımlılık:** PR-03.

#### PR-04 · Dashboard kabuğu
- **Kapsam:** Jinja2 + HTMX + Tailwind layout, login sayfası, boş dashboard, navigasyon.
- **Teslimat:** Tarayıcıdan giriş + boş panel görünür.
- **Kabul:** Login akışı uçtan uca çalışır.
- **Bağımlılık:** PR-03.

### Faz 1 — Ağ / Host Tarama MVP

#### PR-05 · Çekirdek veri modelleri + service katmanı
- **Kapsam:** `Asset`, `Service`, `Scan`, `Finding`, `AuditLog` modelleri + migration'lar; `core/services` temel CRUD servisleri.
- **Kabul:** Modeller migrate olur; servis birim testleri geçer.
- **Bağımlılık:** PR-02.

#### PR-06 · Celery + Redis entegrasyonu
- **Kapsam:** Celery app, Redis broker, örnek async görev, görev durum takibi.
- **Kabul:** Bir görev kuyruğa girip worker'da tamamlanır; durum DB'ye yazılır.
- **Bağımlılık:** PR-02.

#### PR-07 · Scope (yetkili kapsam) modülü
- **Kapsam:** `ScopePolicy` modeli, hedef doğrulama (`core/scope.py`), izin dışı hedefte hata.
- **Kabul:** İzinli CIDR'de geçer, dışında reddeder; testlerle kanıtlanır.
- **Bağımlılık:** PR-05.

#### PR-08 · Ağ tarayıcı modülü
- **Kapsam:** `scanners/network.py` — host keşfi + port tarama + `nmap -sV` servis/versiyon; Celery görevi olarak çalışır; sonuçları Asset/Service'e yazar; scope guard'dan geçer.
- **Kabul:** Bir test hedefinde (ör. yerel/laboratuvar) açık portlar ve versiyonlar doğru kaydedilir.
- **Bağımlılık:** PR-06, PR-07.

#### PR-09 · Dashboard'dan tarama başlatma + sonuç görüntüleme
- **Kapsam:** "Yeni tarama" formu, tarama listesi/durumu, asset envanteri ve servis detay sayfaları (HTMX).
- **Kabul:** Panelden tarama başlatılıp sonuçlar görülebilir. **← İlk çalışan ürün (MVP)**
- **Bağımlılık:** PR-08, PR-04.

### Faz 2 — CVE Zekâsı + Sömürülebilirlik

#### PR-10 · CVE modeli + NVD entegrasyonu
- **Kapsam:** `intel/nvd.py`, `CVE` modeli, `servis(CPE) → CVE` eşleştirme, CVSS kaydı, sonuçların `Finding` olarak üretilmesi.
- **Kabul:** Bilinen versiyonlu bir servis için doğru CVE'ler eşleşir.
- **Bağımlılık:** PR-08.

#### PR-11 · OSV entegrasyonu + severity hesaplama
- **Kapsam:** `intel/osv.py`, CVSS → severity (Kritik/Yüksek/Orta/Düşük), Finding zenginleştirme.
- **Kabul:** Bulgular severity ile etiketlenir.
- **Bağımlılık:** PR-10.

#### PR-12 · Sömürülebilirlik zenginleştirme (Exploit-DB + KEV + EPSS)
- **Kapsam:** `intel/exploitdb.py` (CSV mirror + `codes`→CVE), `intel/kev.py` (JSON feed), `intel/epss.py` (API). `Exploit` modeli, CVE'ye `kev_flag`, `epss`, `exploit_count` alanları.
- **Kabul:** Bir CVE için açık exploit/KEV/EPSS bilgisi doğru gösterilir.
- **Bağımlılık:** PR-10.

#### PR-13 · Risk önceliklendirme + zafiyet panelleri
- **Kapsam:** Risk skoru formülü, sıralı zafiyet listesi, severity dağılım grafikleri, asset bazlı drill-down.
- **Kabul:** Panel, `Kritik + açık exploit + KEV` olanları en üste koyar.
- **Bağımlılık:** PR-11, PR-12.

### Faz 2.5 — MCP Sunucusu

#### PR-14 · MCP sunucu iskeleti
- **Kapsam:** `mcp/` (FastMCP, stdio), core/service'e bağlanma, auth/token, scope guard.
- **Kabul:** Claude Desktop/Code, sunucuya bağlanıp araçları listeler.
- **Bağımlılık:** PR-09 (en az), tercihen PR-13.

#### PR-15 · MCP araçları + resources
- **Kapsam:** `list_assets`, `start_scan`, `get_scan_status`, `get_vulnerabilities`, `lookup_cve`, `get_exploits_for_cve`, `generate_report` + resource'lar.
- **Kabul:** Claude bu araçlarla tarama başlatıp sonuç sorgulayabilir.
- **Bağımlılık:** PR-14.

#### PR-16 · MCP entegrasyon dokümanı
- **Kapsam:** Kurulum (claude_desktop_config / Claude Code), örnek komutlar, güvenlik notları.
- **Kabul:** Dokümanı takip eden biri MCP'yi bağlayabilir.
- **Bağımlılık:** PR-15.

### Faz 3 — Web & SCA

#### PR-17 · Web tarayıcı (başlıklar + TLS)
- **Kapsam:** `scanners/web.py` — güvenlik başlıkları (CSP/HSTS/X-Frame-Options...), TLS/SSL denetimi (zayıf şifre, sertifika süresi).
- **Kabul:** Bir hedefte eksik başlıklar ve TLS sorunları raporlanır.
- **Bağımlılık:** PR-06, PR-07.

#### PR-18 · Dizin/dosya keşfi + yanlış yapılandırma
- **Kapsam:** Yaygın yol/dosya keşfi (wordlist), açık dizin/yedek dosya/yaygın hatalı yapılandırma kontrolleri (nezaketli hız).
- **Kabul:** Bilinen test hedefinde beklenen yollar bulunur.
- **Bağımlılık:** PR-17.

#### PR-19 · SCA / bağımlılık tarayıcı
- **Kapsam:** `scanners/sca.py` — `requirements.txt`, `package.json` vb. parse → OSV.dev eşleştirme → Finding.
- **Kabul:** Açık içeren örnek bağımlılık doğru tespit edilir.
- **Bağımlılık:** PR-11.

### Faz 4 — Host Sıkılaştırma

#### PR-20 · Kimlik doğrulamalı bağlantı + kimlik yönetimi
- **Kapsam:** SSH/WinRM bağlantısı, kimlik bilgilerinin **şifreli** saklanması, bağlantı testi.
- **Kabul:** Test host'una güvenli bağlanılır; kimlikler düz metin tutulmaz.
- **Bağımlılık:** PR-05.

#### PR-21 · CIS-tarzı yapılandırma denetimleri
- **Kapsam:** `scanners/hardening.py` — temel sıkılaştırma kontrolleri (parola politikası, açık servisler, eski paketler...).
- **Kabul:** Test host'unda kontrol sonuçları (geçti/kaldı) üretilir.
- **Bağımlılık:** PR-20.

### Faz 5 — Cilalama / Üretim

#### PR-22 · Zamanlanmış taramalar
- **Kapsam:** Celery beat / cron ile tekrarlı taramalar, zamanlama arayüzü.
- **Kabul:** Planlı tarama tanımlanıp otomatik çalışır.
- **Bağımlılık:** PR-09.

#### PR-23 · Rapor üretimi (PDF/HTML)
- **Kapsam:** WeasyPrint ile tarama/zafiyet raporu, indirilebilir çıktı.
- **Kabul:** Bir taramadan düzgün PDF üretilir.
- **Bağımlılık:** PR-13.

#### PR-24 · Bildirimler
- **Kapsam:** E-posta / Slack / webhook ile kritik bulgu bildirimi.
- **Kabul:** Kritik bulguda bildirim gider.
- **Bağımlılık:** PR-13.

#### PR-25 · RBAC ince ayar + audit log arayüzü
- **Kapsam:** Rol bazlı yetki sıkılaştırma, audit log görüntüleme ekranı.
- **Kabul:** Roller doğru kısıtlar; audit log panelde görünür.
- **Bağımlılık:** PR-03, PR-05.

#### PR-26 · CI/CD + dağıtım dokümanı
- **Kapsam:** GitHub Actions (ruff + mypy + pytest + build), dağıtım/kurulum rehberi.
- **Kabul:** PR'larda CI otomatik çalışır ve geçer.
- **Bağımlılık:** PR-01.

---

## 15. Riskler ve Açık Sorular

- **nmap bağımlılığı:** Dağıtım ortamında nmap kurulu olmalı (Docker imajına eklenecek). Saf-Python alternatifi sınırlı kalır.
- **NVD rate-limit:** Yoğun taramada API limiti; yerel CVE mirror'ı ileride gerekebilir.
- **CPE eşleştirme doğruluğu:** Servis versiyonundan CPE üretmek bazen hatalı eşleşir; ince ayar gerektirir.
- **Host sıkılaştırma kapsamı:** Hangi OS'ler (Linux/Windows) öncelikli? (Faz 4 öncesi netleşecek.)
- **MCP HTTP/SSE güvenliği:** Uzak erişim açılınca kimlik doğrulama/yetki modeli sıkılaştırılmalı.

---

## 16. Sözlük

- **CVE:** Bilinen güvenlik açığı kaydı.
- **CVSS:** Açığın önem skoru (0–10).
- **EPSS:** Açığın 30 gün içinde sömürülme olasılığı (%).
- **KEV:** CISA'nın "vahşi doğada aktif sömürülen" açıklar listesi.
- **CPE:** Ürün/versiyon tanımlama standardı (CVE eşleştirmede kullanılır).
- **SCA:** Software Composition Analysis — bağımlılık güvenlik taraması.
- **MCP:** Model Context Protocol — LLM'lerin araç/veri kaynaklarına bağlanma protokolü.
- **Scope:** Tarama için yetkili (izinli) hedef kapsamı.

---

*Bu doküman yaşayan bir belgedir; her faz/PR'da güncellenir.*
