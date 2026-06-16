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
> için kullanılır (Nessus/OpenVAS/Nuclei deseni). Gerçek sömürü-çalıştırma bu çekirdekte yoktur.

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
