> **English** · [Türkçe](#turkce)

# Third-Party Notices

Kangalis (MIT-licensed open-source core) uses the following third-party runtime
dependencies. Each dependency is distributed under its own license; the relevant
license texts and copyrights are included in the packages' own distributions. This
list is for information only and covers runtime dependencies; development/test tooling
is not included. (Exception: the optional **prebuilt AI image** redistributes the
Ollama binary and the Qwen3 weights, so their license texts are **additionally
embedded** in the image — see the "Prebuilt AI image" section below.)

## Web and Server

- **fastapi** — MIT — web application framework (routing/schema/dependency injection).
- **starlette** — BSD-3-Clause — the ASGI framework underneath FastAPI (request/response, middleware).
- **uvicorn** — BSD-3-Clause — ASGI server (runs the application).
- **jinja2** — BSD-3-Clause — HTML template engine (UI pages).
- **itsdangerous** — BSD-3-Clause — signed session/cookie tokens.
- **python-multipart** — Apache-2.0 — multipart form (file/upload) parsing.
- **httpx** — BSD-3-Clause — async HTTP client (web scanning + AI engine calls).

## Database and Migration

- **sqlalchemy** — MIT — ORM and async database access layer.
- **alembic** — MIT — database schema migrations.
- **asyncpg** — Apache-2.0 — async PostgreSQL driver.
- **aiomysql** — MIT — async MySQL/MariaDB driver (database auditing).
- **oracledb** — Apache-2.0 / UPL-1.0 — Oracle database driver (database auditing).
- **python-tds** — MIT — Microsoft SQL Server driver (database auditing).

## Task Queue and Cache

- **celery** — BSD-3-Clause — distributed background task queue (scan workers).
- **redis** (redis-py) — MIT — Redis client (broker/result backend).

## Network, Identity, and Protocol Auditing

- **python-libnmap** — Apache-2.0 — parses/wraps nmap XML output (the external **nmap**
  binary is under **GPL-2.0** and is NOT DISTRIBUTED with the application; the customer
  installs it in their own environment).
- **asyncssh** — EPL-2.0 — async SSH client (SSH access/auditing; the EPL-2.0 arm is chosen).
- **impacket** — Apache-2.0 (modified, SecureAuth) — SMB/MSRPC/Kerberos protocol tools.
- **ldap3** — LGPL-3.0 — LDAP/Active Directory client (directory sync + auditing).
- **pysnmp** — BSD-2-Clause — SNMP client (network device auditing).
- **pywinrm** — MIT — Windows Remote Management (WinRM) client.

## Cryptography and Authentication

- **cryptography** — Apache-2.0 / BSD-3-Clause — cryptographic primitives (protection of secret data).
- **argon2-cffi** — MIT — Argon2 password hashing (user authentication).
- **pyotp** — MIT — TOTP one-time passwords (multi-factor authentication).
- **qrcode** — BSD-3-Clause — MFA enrollment QR code generation.

## Reporting

- **weasyprint** — BSD-3-Clause — PDF report generation from HTML (the transitive
  **pyphen** dependency comes with an **LGPL-2.1+ / MPL-2.0** dual-license arm).

## Configuration and Utilities

- **pydantic-settings** — MIT — typed configuration loading from environment variables.
- **tzdata** — Apache-2.0 / public domain (IANA) — time zone database.
- **mcp** — MIT — Model Context Protocol server/client (integration surface).

## Scanning / Vulnerability Data Sources (synced at runtime — NOT DISTRIBUTED)

Kangalis pulls the following **public** data sources **at runtime** (via the operator's
"Update" command) **into the user's own installation**. This repository does **not**
package/redistribute this data — it contains only the sync *code*; the data is
downloaded from the upstream source in each user's own deployment (**use ≠
distribution**). Only **metadata/facts** (CVE-ID, title, references, version) are used;
exploit/PoC **code** is not fetched or executed.

- **NVD** (NIST National Vulnerability Database) — **public domain** (US government) — CVE/CPE matching.
- **CISA KEV** (Known Exploited Vulnerabilities) — **public domain** — known-exploited flag.
- **EPSS** (FIRST.org) — exploit-probability score (FIRST terms of use; free to use).
- **Exploit-DB** (OffSec) — content is **GPL-2.0** — only the **index metadata**
  (`files_exploits.csv`: EDB-ID, CVE, title) is fetched; exploit code is not
  fetched/distributed → use of data/facts does not affect the MIT core's license (not a
  derivative work).
- **Metasploit Framework** (Rapid7) — **BSD-3-Clause** — only module **metadata**
  (`db/modules_metadata_base.json`: module name, CVE references, platform, rank) is
  fetched; module code is not fetched. *"Metasploit" is a registered trademark of
  Rapid7; it is used here only to **identify** the data source (nominative) — it does
  not imply endorsement or affiliation.*

> Dual-use note: this public exploit metadata is used only for **defensive
> detection/prioritization**. Actual exploit execution is not present in this core.

## Optional — Local AI (disabled by default)

- **Ollama** — MIT — local LLM inference engine. This open-source core repository does
  NOT distribute the Ollama binary; the default `ollama` service pulls the official
  `ollama/ollama` image. (See also the prebuilt image below.)
- **Qwen3** (model weights) — Apache-2.0 — optional local AI model. In the default flow
  the weights are pulled **once** from the Ollama model library (`ollama pull qwen3:8b`,
  onto the operator's machine); this core repository does not contain/distribute the
  weights.

### Prebuilt AI image (`kangalis-ai` — optional, SEPARATE artifact)

For air-gap/easy-install, an **optional** prebuilt image can be provided
(`Dockerfile.ai`; published at `ghcr.io/lineup-noah/kangalis-ai`). This image is a
distribution artifact **separate** from the MIT-licensed core application, and carries
the following **embedded** in it:

- **Ollama** — **MIT** — permits redistribution; MIT requires the license text +
  copyright notice to be preserved "in all copies." The MIT text is embedded in the
  image → `/licenses/ollama-LICENSE.txt` (copyright: `Copyright (c) Ollama`).
- **Qwen3-8B** model weights (from the Ollama library, `qwen3:8b`) — **Apache-2.0** —
  permits redistribution and modification; Apache-2.0 §4(a) requires the license text
  to be preserved **unconditionally**. The Apache-2.0 text (from the upstream model repo
  `Qwen/Qwen3-8B`) is embedded in the image → `/licenses/Qwen3-8B-LICENSE.txt`
  (copyright: `Copyright 2024 Alibaba Cloud`). As there is no **NOTICE** file upstream,
  Apache-2.0 §4(d) is not triggered.

So this prebuilt image **redistributes** these two components; the license of each (MIT,
Apache-2.0) explicitly permits this, and the required license texts are **embedded** in
the image under `/licenses/` (vendored in the repo under the `licenses/` folder —
air-gap/reproducible; see [`licenses/README.md`](licenses/README.md)). The image is
distributed under the licenses of its own components; it does not change the license of
the MIT-licensed Kangalis core.

> **Note (base layers + model source):** since this image is derived from the official
> `ollama/ollama` image, it also **inherits** the base operating-system layers (Ubuntu
> 24.04 + system packages; NVIDIA CUDA libraries in GPU variants). These layers are
> **not** re-vendored by Kangalis under `licenses/`; each is carried in its respective
> image layer under its own upstream license. `licenses/` covers only the two
> components Kangalis adds/pins (Ollama, Qwen3-8B). The embedded model comes from the
> Ollama library via `ollama pull qwen3:8b` (Apache-2.0 today); the tag is not immutable,
> so for each release the embedded version's license must be verified with
> `ollama show qwen3:8b --license`.

---

<a id="turkce"></a>

> [English](#) · **Türkçe**

# Üçüncü Taraf Bildirimleri

Kangalis (MIT lisanslı, açık-kaynak çekirdek), aşağıdaki üçüncü taraf çalışma-zamanı
bağımlılıklarını kullanır. Her bağımlılık kendi lisansı altında dağıtılır; ilgili lisans
metinleri ve telif hakları paketlerin kendi dağıtımlarında yer alır. Bu liste yalnızca
bilgilendirme amaçlıdır ve çalışma-zamanı (runtime) bağımlılıklarını kapsar; geliştirme/
test araçları dahil değildir. (İstisna: opsiyonel **ön-paketli AI imajı** Ollama ikilisini ve
Qwen3 ağırlıklarını yeniden dağıttığından, bunların lisans metinleri imaja **ayrıca gömülür** —
bkz. aşağıdaki "Ön-paketli AI imajı" bölümü.)

## Web ve Sunucu

- **fastapi** — MIT — web uygulama çatısı (route/şema/bağımlılık enjeksiyonu).
- **starlette** — BSD-3-Clause — FastAPI'nin altındaki ASGI çatısı (istek/yanıt, middleware).
- **uvicorn** — BSD-3-Clause — ASGI sunucusu (uygulamayı çalıştırır).
- **jinja2** — BSD-3-Clause — HTML şablon motoru (arayüz sayfaları).
- **itsdangerous** — BSD-3-Clause — imzalı oturum/çerez belirteçleri.
- **python-multipart** — Apache-2.0 — çok-parçalı form (dosya/yükleme) ayrıştırma.
- **httpx** — BSD-3-Clause — asenkron HTTP istemcisi (web tarama + AI motoru çağrıları).

## Veritabanı ve Migrasyon

- **sqlalchemy** — MIT — ORM ve asenkron veritabanı erişim katmanı.
- **alembic** — MIT — veritabanı şema migrasyonları.
- **asyncpg** — Apache-2.0 — asenkron PostgreSQL sürücüsü.
- **aiomysql** — MIT — asenkron MySQL/MariaDB sürücüsü (veritabanı denetimi).
- **oracledb** — Apache-2.0 / UPL-1.0 — Oracle veritabanı sürücüsü (veritabanı denetimi).
- **python-tds** — MIT — Microsoft SQL Server sürücüsü (veritabanı denetimi).

## Görev Kuyruğu ve Önbellek

- **celery** — BSD-3-Clause — dağıtık arka plan görev kuyruğu (tarama işçileri).
- **redis** (redis-py) — MIT — Redis istemcisi (broker/sonuç-backend).

## Ağ, Kimlik ve Protokol Denetimi

- **python-libnmap** — Apache-2.0 — nmap XML çıktısı ayrıştırma/sarmalama (harici **nmap**
  ikilisi **GPL-2.0** altındadır ve uygulamayla DAĞITILMAZ; müşteri kendi ortamına kurar).
- **asyncssh** — EPL-2.0 — asenkron SSH istemcisi (SSH erişim/denetim; EPL-2.0 kolu seçildi).
- **impacket** — Apache-2.0 (değiştirilmiş, SecureAuth) — SMB/MSRPC/Kerberos protokol araçları.
- **ldap3** — LGPL-3.0 — LDAP/Active Directory istemcisi (dizin senkron + denetim).
- **pysnmp** — BSD-2-Clause — SNMP istemcisi (ağ cihazı denetimi).
- **pywinrm** — MIT — Windows Remote Management (WinRM) istemcisi.

## Kriptografi ve Kimlik Doğrulama

- **cryptography** — Apache-2.0 / BSD-3-Clause — şifreleme ilkelleri (gizli veri koruması).
- **argon2-cffi** — MIT — Argon2 parola özetleme (kullanıcı kimlik doğrulama).
- **pyotp** — MIT — TOTP tek-kullanımlık parola (çok-faktörlü kimlik doğrulama).
- **qrcode** — BSD-3-Clause — MFA kayıt QR kodu üretimi.

## Raporlama

- **weasyprint** — BSD-3-Clause — HTML'den PDF rapor üretimi (transitif **pyphen** bağımlılığı
  **LGPL-2.1+ / MPL-2.0** çift-lisans koluyla gelir).

## Yapılandırma ve Yardımcılar

- **pydantic-settings** — MIT — ortam değişkeninden tipli yapılandırma yükleme.
- **tzdata** — Apache-2.0 / kamu malı (IANA) — zaman dilimi veritabanı.
- **mcp** — MIT — Model Context Protocol sunucu/istemci (entegrasyon yüzeyi).

## Tarama / Zafiyet Veri Kaynakları (çalışma anında senkronlanan — DAĞITILMAZ)

Kangalis aşağıdaki **public** veri kaynaklarını **çalışma anında** (operatörün "Güncelle" komutuyla)
**kullanıcının kendi kurulumuna** çeker. Bu depo bu verileri **paketlemez/yeniden dağıtmaz** —
yalnızca senkron *kodunu* içerir; veri her kullanıcının kendi dağıtımında yukarı-akış kaynaktan
indirilir (**kullanım ≠ dağıtım**). Yalnızca **metadata/olgular** (CVE-ID, başlık, referans, sürüm)
kullanılır; exploit/PoC **kodu** çekilmez/çalıştırılmaz.

- **NVD** (NIST National Vulnerability Database) — **kamu malı** (ABD hükümeti) — CVE/CPE eşleştirme.
- **CISA KEV** (Known Exploited Vulnerabilities) — **kamu malı** — bilinen-sömürülen işareti.
- **EPSS** (FIRST.org) — sömürü-olasılık skoru (FIRST kullanım şartları; serbest kullanım).
- **Exploit-DB** (OffSec) — içerik **GPL-2.0** — yalnız **index metadata** (`files_exploits.csv`:
  EDB-ID, CVE, başlık) çekilir; exploit kodu çekilmez/dağıtılmaz → veri/olgu kullanımı, MIT
  çekirdeğin lisansını etkilemez (türev iş değil).
- **Metasploit Framework** (Rapid7) — **BSD-3-Clause** — yalnız modül **metadata'sı**
  (`db/modules_metadata_base.json`: modül adı, CVE referansları, platform, rank) çekilir; modül kodu
  çekilmez. *"Metasploit", Rapid7'nin tescilli markasıdır; burada yalnızca veri kaynağını
  **belirtmek** (nominatif) için kullanılır — onay/iş birliği ima etmez.*

> Çift-kullanım notu: bu public exploit-metadata'sı yalnızca **savunmacı tespit/önceliklendirme**
> için kullanılır. Gerçek sömürü-çalıştırma bu çekirdekte yoktur.

## Opsiyonel — Yerel AI (varsayılan kapalı)

- **Ollama** — MIT — yerel LLM çıkarım motoru. Bu açık-kaynak çekirdek deposu Ollama ikilisini
  DAĞITMAZ; varsayılan `ollama` servisi resmi `ollama/ollama` imajını çeker. (Ayrıca aşağıdaki
  ön-paketli imaja bakın.)
- **Qwen3** (model ağırlıkları) — Apache-2.0 — opsiyonel yerel AI modeli. Varsayılan akışta
  ağırlıklar Ollama model kütüphanesinden (`ollama pull qwen3:8b`, operatörün makinesine) **tek
  seferlik** çekilir; bu çekirdek deposu ağırlıkları içermez/dağıtmaz.

### Ön-paketli AI imajı (`kangalis-ai` — opsiyonel, AYRI artefakt)

Air-gap/kolay-kurulum için **opsiyonel** bir ön-paketli imaj sağlanabilir (`Dockerfile.ai`;
yayın: `ghcr.io/lineup-noah/kangalis-ai`). Bu imaj, MIT-lisanslı çekirdek uygulamadan **ayrı** bir
dağıtım artefaktıdır ve içine **gömülü** olarak şunları taşır:

- **Ollama** — **MIT** — yeniden dağıtıma izin verir; MIT, lisans metni + telif bildiriminin
  "tüm kopyalarda" korunmasını zorunlu kılar. MIT metni imaja gömülür →
  `/licenses/ollama-LICENSE.txt` (telif: `Copyright (c) Ollama`).
- **Qwen3-8B** model ağırlıkları (Ollama kütüphanesinden `qwen3:8b`) — **Apache-2.0** — yeniden
  dağıtıma ve değiştirmeye izin verir; Apache-2.0 §4(a) lisans metninin **koşulsuz** korunmasını
  ister. Apache-2.0 metni (üst model deposu `Qwen/Qwen3-8B`'den) imaja gömülür →
  `/licenses/Qwen3-8B-LICENSE.txt` (telif: `Copyright 2024 Alibaba Cloud`). Upstream'de **NOTICE**
  dosyası bulunmadığından Apache-2.0 §4(d) tetiklenmez.

Yani bu ön-paketli imaj, bu iki bileşeni **yeniden dağıtır**; her ikisinin lisansı (MIT,
Apache-2.0) buna açıkça izin verir ve gerekli lisans metinleri imaja `/licenses/` altına **gömülür**
(depoda `licenses/` klasöründe vendor edilir — air-gap/yeniden-üretilebilir; bkz.
[`licenses/README.md`](licenses/README.md)). İmaj, kendi bileşenlerinin lisansları altında
dağıtılır; MIT-lisanslı Kangalis çekirdeğinin lisansını değiştirmez.

> **Not (taban katmanlar + model kaynağı):** Bu imaj `ollama/ollama` resmi imajından türediğinden
> taban işletim-sistemi katmanlarını da (Ubuntu 24.04 + sistem paketleri; GPU değişkenlerinde NVIDIA
> CUDA kütüphaneleri) **miras alır**. Bu katmanlar Kangalis tarafından `licenses/` altında yeniden
> vendor **edilmez**; her biri kendi yukarı-akış (upstream) lisansı altında ilgili imaj katmanında
> taşınır. `licenses/` yalnızca Kangalis'in eklediği/pinlediği iki bileşeni (Ollama, Qwen3-8B) kapsar.
> Gömülü model `ollama pull qwen3:8b` ile Ollama kütüphanesinden gelir (bugün Apache-2.0); etiket
> sabit (immutable) değildir, bu yüzden her yayın için gömülü sürümün lisansı
> `ollama show qwen3:8b --license` ile doğrulanmalıdır.
