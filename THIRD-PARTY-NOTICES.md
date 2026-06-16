# Üçüncü Taraf Bildirimleri

Kangalis (MIT lisanslı, açık-kaynak çekirdek), aşağıdaki üçüncü taraf çalışma-zamanı
bağımlılıklarını kullanır. Her bağımlılık kendi lisansı altında dağıtılır; ilgili lisans
metinleri ve telif hakları paketlerin kendi dağıtımlarında yer alır. Bu liste yalnızca
bilgilendirme amaçlıdır ve çalışma-zamanı (runtime) bağımlılıklarını kapsar; geliştirme/
test araçları dahil değildir. (İstisna: opsiyonel **ön-paketli AI imajı** llama.cpp ikilisini ve
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

## Opsiyonel — Yerel AI (varsayılan kapalı)

- **llama.cpp** — MIT — yerel LLM çıkarım motoru. Bu açık-kaynak çekirdek deposu llama.cpp
  ikilisini DAĞITMAZ; varsayılan `llamacpp` servisi resmi `ghcr.io/ggml-org/llama.cpp` imajını
  çeker. (Ayrıca aşağıdaki ön-paketli imaja bakın.)
- **Qwen3** (model ağırlıkları) — Apache-2.0 — opsiyonel yerel AI modeli. Varsayılan akışta
  ağırlıklar HuggingFace'ten (operatörün makinesine) **tek seferlik** çekilir; bu çekirdek deposu
  ağırlıkları içermez/dağıtmaz.

### Ön-paketli AI imajı (`kangalis-ai` — opsiyonel, AYRI artefakt)

Air-gap/kolay-kurulum için **opsiyonel** bir ön-paketli imaj sağlanabilir (`Dockerfile.ai`;
yayın: `ghcr.io/lineup-noah/kangalis-ai`). Bu imaj, MIT-lisanslı çekirdek uygulamadan **ayrı** bir
dağıtım artefaktıdır ve içine **gömülü** olarak şunları taşır:

- **llama.cpp** — **MIT** — yeniden dağıtıma izin verir; MIT, lisans metni + telif bildiriminin
  "tüm kopyalarda" korunmasını zorunlu kılar. **Not:** resmi taban imaj
  (`ghcr.io/ggml-org/llama.cpp:server`) llama.cpp lisans metnini **içermez** (yalnız Python'ın
  lisansı bulunur); bu yüzden MIT metni imaja **ayrıca gömülür** →
  `/licenses/llama.cpp-LICENSE.txt` (telif: `Copyright (c) 2023-2026 The ggml authors`).
- **Qwen3-8B** model ağırlıkları (varsayılan `unsloth/Qwen3-8B-GGUF`, Q4_K_M kuantizasyonu) —
  **Apache-2.0** — yeniden dağıtıma ve değiştirmeye izin verir; Apache-2.0 §4(a) lisans metninin
  **koşulsuz** korunmasını ister. **Not:** modelin dağıtıldığı `unsloth/Qwen3-8B-GGUF` deposunda
  LICENSE dosyası **yoktur**; bu yüzden Apache-2.0 metni üst (base) model deposu `Qwen/Qwen3-8B`'den
  alınıp imaja gömülür → `/licenses/Qwen3-8B-LICENSE.txt` (telif: `Copyright 2024 Alibaba Cloud`).
  Her iki upstream'de de **NOTICE** dosyası bulunmadığından Apache-2.0 §4(d) tetiklenmez.

Yani bu ön-paketli imaj, bu iki bileşeni **yeniden dağıtır**; her ikisinin lisansı (MIT,
Apache-2.0) buna açıkça izin verir ve gerekli lisans metinleri imaja `/licenses/` altına **gömülür**
(depoda `licenses/` klasöründe vendor edilir — air-gap/yeniden-üretilebilir; bkz.
[`licenses/README.md`](licenses/README.md)). İmaj, kendi bileşenlerinin lisansları altında
dağıtılır; MIT-lisanslı Kangalis çekirdeğinin lisansını değiştirmez.
