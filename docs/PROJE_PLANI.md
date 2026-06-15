# Kangalis — Mimari ve Tasarım

---

## 1. Genel Bakış / Vizyon

**Kangalis**, **Python tabanlı, web panelli, ağırlıklı olarak iç ağ/sistem taramasına odaklanan** bir **zafiyet yönetim platformudur**. Hafif bir OpenVAS/Nessus alternatifi gibi düşünülebilir; farkı, kendi dashboard'u ve **MCP üzerinden Claude ile konuşabilmesidir**.

Platform; iç ağdaki host ve servisleri keşfeder, bilinen zafiyetlerle (CVE) eşleştirir, bunları **sömürülebilirlik sinyalleriyle** (açık exploit var mı, vahşi doğada sömürülüyor mu, sömürülme olasılığı nedir) zenginleştirerek **risk önceliklendirmesi** yapar; ayrıca web uygulaması ve bağımlılık taramalarını da kapsar.

### Ne DEĞİLDİR (kapsam dışı ilkeler)
- Saldırı/sömürü aracı değildir. Exploit *çalıştırmaz*; yalnızca bir exploit'in *var olduğu* bilgisini savunma amaçlı önceliklendirme için kullanır.
- Yalnızca **yetkili kapsam (authorized scope)** içinde tarama yapar; izinsiz hedefleri taramaz.

---

## 2. Hedef Kullanıcı ve Kullanım Senaryoları

- **Birincil kullanıcı:** Kurum içi güvenlik/altyapı ekibi.
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

## 4. Teknoloji Yığını

| Katman | Seçim | Neden |
|---|---|---|
| Dil | **Python 3.12+** | Güvenlik ekosistemi en zengin |
| Paket yönetimi | **uv** | Çok hızlı, modern |
| Backend | **FastAPI** | Async, otomatik OpenAPI, hızlı |
| DB | **PostgreSQL + SQLAlchemy 2.0 (async) + Alembic** | Sağlam, migration'lı |
| Görev kuyruğu | **Celery + Redis** | Taramalar uzun sürer, arka plan gerekir |
| Frontend | **Jinja2 + HTMX + Tailwind + Alpine.js** | Python-merkezli, ayrı JS build yok |
| Ağ tarama | **nmap** (python-libnmap sarmalayıcı) | En güçlü/hızlı yol (sistemde nmap kurulu varsayımı) |
| Web kontrolleri | **httpx**, **cryptography/ssl** | Başlık + TLS denetimi |
| Zafiyet verisi | **NVD API 2.0** + **OSV.dev** | CVE + CVSS |
| Sömürülebilirlik | **Exploit-DB** + **CISA KEV** + **EPSS** (+ ops. Metasploit) | Risk önceliklendirme |
| MCP | **FastMCP** (stdio → sonra HTTP/SSE) | Claude entegrasyonu |
| Rapor | **WeasyPrint** (PDF) | Paylaşılabilir raporlar |
| Dağıtım | **Docker + docker-compose** | Tek komutla ayağa kalkar |
| CI/CD | **GitHub Actions** | Test + lint + build |
| Test/Lint | **pytest, ruff, mypy, pre-commit** | Kalite |

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

## 13. Riskler ve Açık Sorular

- **nmap bağımlılığı:** Dağıtım ortamında nmap kurulu olmalı (Docker imajına eklenecek). Saf-Python alternatifi sınırlı kalır.
- **NVD rate-limit:** Yoğun taramada API limiti; yerel CVE mirror'ı ileride gerekebilir.
- **CPE eşleştirme doğruluğu:** Servis versiyonundan CPE üretmek bazen hatalı eşleşir; ince ayar gerektirir.
- **Host sıkılaştırma kapsamı:** Hangi OS'ler (Linux/Windows) öncelikli olduğu netleştirilmelidir.
- **MCP HTTP/SSE güvenliği:** Uzak erişim açılınca kimlik doğrulama/yetki modeli sıkılaştırılmalı.

---

## 14. Sözlük

- **CVE:** Bilinen güvenlik açığı kaydı.
- **CVSS:** Açığın önem skoru (0–10).
- **EPSS:** Açığın 30 gün içinde sömürülme olasılığı (%).
- **KEV:** CISA'nın "vahşi doğada aktif sömürülen" açıklar listesi.
- **CPE:** Ürün/versiyon tanımlama standardı (CVE eşleştirmede kullanılır).
- **SCA:** Software Composition Analysis — bağımlılık güvenlik taraması.
- **MCP:** Model Context Protocol — LLM'lerin araç/veri kaynaklarına bağlanma protokolü.
- **Scope:** Tarama için yetkili (izinli) hedef kapsamı.
