# Üçüncü Taraf Bildirimleri

CyberSecTool (MIT lisanslı, açık-kaynak çekirdek), aşağıdaki üçüncü taraf çalışma-zamanı
bağımlılıklarını kullanır. Her bağımlılık kendi lisansı altında dağıtılır; ilgili lisans
metinleri ve telif hakları paketlerin kendi dağıtımlarında yer alır. Bu liste yalnızca
bilgilendirme amaçlıdır ve çalışma-zamanı (runtime) bağımlılıklarını kapsar; geliştirme/
test araçları dahil değildir.

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

- **llama.cpp** — MIT — yerel LLM çıkarım motoru (operatör tarafından harici çalıştırılır;
  uygulamayla DAĞITILMAZ).
- **Qwen3** (model ağırlıkları) — Apache-2.0 — opsiyonel yerel AI modeli (harici sağlanır).
