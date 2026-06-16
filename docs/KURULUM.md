# Kangalis — Kurulum Rehberi

> İç ağınızın bekçisi. Bu rehber, Kangalis'i sıfırdan ayağa kaldırmak için
> ihtiyacınız olan her şeyi adım adım anlatır.

Kangalis, tek bir Docker imajından dört uygulama servisini (API, worker, zamanlayıcı,
MCP) çalıştıran, web panelli bir iç-ağ zafiyet tarama platformudur. **Tek önkoşul
Docker'dır** — veritabanı, önbellek, tarama motoru (nmap), Python ve tüm bağımlılıklar
konteynerler içinde gelir veya derleme sırasında otomatik kurulur. Elle Python, nmap ya
da PostgreSQL kurmanıza gerek yoktur.

> ⚠️ **Yasal uyarı:** Kangalis yalnızca **yetkili kapsam** içinde — yani sahibi
> olduğunuz ya da tarama için **yazılı izin** aldığınız ağlarda — kullanılmalıdır.
> İzinsiz ağ taraması, kimlik denemesi ve zafiyet doğrulaması birçok ülkede **yasa
> dışıdır** ve tüm sorumluluk operatöre aittir. Ayrıntı: [SECURITY.md](../SECURITY.md).

---

## 1. Önkoşullar

Kurulum yapacak makinede yalnızca **Docker** ve **Docker Compose** bulunmalıdır. Başka
hiçbir şey elle kurulmaz.

| Platform | Gereken | Notlar |
|---|---|---|
| **Windows** | [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Docker Compose dahili gelir. WSL2 arka ucu önerilir. |
| **macOS** | [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Docker Compose dahili gelir. |
| **Linux** | Docker Engine + Compose eklentisi | `docker` paketi + `docker-compose-plugin` (komut: `docker compose`, tireli `docker-compose` değil). |

### Donanım (önerilen asgari)

| Senaryo | RAM | Disk | Açıklama |
|---|---|---|---|
| Çekirdek (AI olmadan) | ~4 GB | ~3 GB | Tüm tarama/rapor/MCP işlevleri çalışır. |
| Yerel AI ile birlikte | **+8 GB** (toplam ~12 GB) | **+~6 GB** (model) | AI motoru CPU'da koşar; `mem_limit 8g` ile sınırlıdır. GPU **gerekmez**. |

### Kurulum öncesi doğrulama

Docker'ın kurulu ve çalışır olduğunu teyit edin:

```bash
docker --version
docker compose version
docker info        # daemon çalışıyor mu?
```

> **Ağ çakışması uyarısı:** Kangalis konteynerleri varsayılan olarak `172.28.0.0/16`
> köprü ağını kullanır. Tarayacağınız müşteri LAN'ı bu aralıkla çakışıyorsa, kuruluma
> başlamadan **[Bölüm 7 — `DOCKER_SUBNET`](#7-yapılandırma-env)** ayarını okuyun.

---

## 2. Hızlı kurulum (tek komut — önerilen)

Depo kök dizininde, platformunuza uygun **tek komutu** çalıştırın:

```bash
# Linux / macOS
bash setup.sh
# veya:
make setup
```

```powershell
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File setup.ps1
```

### Sihirbaz ne yapar?

`setup.sh` / `setup.ps1` etkileşimli bir kurulum sihirbazıdır ve şu 4 adımı sizin için
yürütür:

1. **Derle + başlat** — `docker compose up -d --build`. İmaj derlenir (nmap dahil; ilk
   derleme birkaç dakika sürebilir) ve tüm servisler arka planda başlatılır.
2. **Şema migrasyonu + sağlık beklemesi** — `migrate` servisi veritabanı şemasını
   **otomatik** kurar (elle `alembic` çalıştırmanıza gerek yoktur). Sihirbaz, uygulama
   `/health` ucu yanıt verene kadar bekler.
3. **Yönetici (admin) kullanıcı** — kullanıcı adı ve parola sorar; bir `admin` rolünde
   ilk hesap oluşturur.
4. **Yetkili tarama kapsamı (ZORUNLU)** — taramaya **yetkili** olduğunuz ağları CIDR
   biçiminde sorar (ör. `192.168.1.0/24,10.0.0.0/8`) ve kapsam politikasını kaydeder.

Sihirbaz bittiğinde web paneli, API/Swagger ve (opsiyonel) AI açma komutu ekrana
yazdırılır. Doğrudan [Bölüm 6 — Erişim adresleri](#6-erişim-adresleri)'ne geçebilirsiniz.

> **Not:** Sihirbaz her şeyi otomatik yapar ama **tarama kapsamını sizden alır** —
> kapsam tanımlanmadan hiçbir tarama çalışmaz (aşağıya bakın).

---

## 3. Manuel kurulum (sihirbaz yerine adım adım)

Sihirbazı kullanmak istemiyorsanız aynı sonucu dört komutla elde edebilirsiniz.

### 3.1 — Derle + başlat (migrate otomatik)

```bash
docker compose up -d --build
```

Bu komut imajı derler (nmap dahil), servisleri başlatır ve `migrate` servisi
**uygulama başlamadan önce** `alembic upgrade head` ile şemayı otomatik kurar. Migrasyon
**idempotent**'tir; her `up` çağrısında güvenle yeniden çalışır. **Elle alembic
çalıştırmanız gerekmez.**

Servislerin ayağa kalktığını doğrulayın:

```bash
docker compose ps
```

### 3.2 — Yönetici (admin) kullanıcı oluştur

```bash
docker compose exec app python -m cybersectool.scripts.create_user \
    --username <ad> --password <parola> --role admin
```

### 3.3 — Yetkili tarama kapsamını tanımla (ZORUNLU)

```bash
docker compose exec app python -m cybersectool.scripts.set_scope \
    --name ic-ag --allow <CIDR> [--allow <CIDR2> ...] [--deny <CIDR>]
```

Örnek:

```bash
docker compose exec app python -m cybersectool.scripts.set_scope \
    --name ic-ag --allow 192.168.1.0/24 --allow 10.0.0.0/8 --deny 10.0.0.1/32
```

> 🛑 **ZORUNLU KAPSAM — atlanmaz.** Kangalis'in tüm tarama yüzeyleri bir **kapsam
> koruyucusu (scope guard)** ile korunur. `set_scope` ile en az bir izinli CIDR
> tanımlanmazsa **hiçbir tarama çalışmaz** — istekler kapsam-dışı diye reddedilir. Bu,
> kazara/izinsiz tarama yapmanızı engelleyen bilinçli bir güvenlik tasarımıdır.
> **Yalnızca taramaya yetkili olduğunuz ağları** girin. Yeni bir `set_scope` çağrısı
> önceki politikayı pasifleştirip yenisini aktif eder.

---

## 4. Ne kuruluyor? (imajlar ve servisler)

**Kullanıcı yalnızca Docker'ı elle kurar.** Aşağıdaki her şey Docker tarafından otomatik
çekilir veya derlenir; siz tek tek imaj indirmez, bağımlılık kurmazsınız.

| İmaj / servis | Tür | Açıklama |
|---|---|---|
| `postgres:16` | **Otomatik çekilen** | Veritabanı (`db` servisi). |
| `redis:7` | **Otomatik çekilen** | Celery broker / önbellek (`redis` servisi). |
| `python:3.12-slim` | **Otomatik çekilen** (derleme anı) | Uygulama imajının taban katmanı. |
| `ghcr.io/astral-sh/uv` | **Otomatik çekilen** (derleme anı) | Python bağımlılık yöneticisi (derlemede kullanılır). |
| **`app`** | **Derlenen** (`Dockerfile`) | FastAPI API + web paneli (port 8000). |
| **`worker`** | **Derlenen** (aynı imaj) | Celery tarama işçisi. |
| **`beat`** | **Derlenen** (aynı imaj) | Celery zamanlayıcı (periyodik görevler). |
| **`mcp`** | **Derlenen** (aynı imaj) | MCP sunucusu — Claude entegrasyonu (port 8001). |
| `migrate` | **Derlenen** (aynı imaj) | Tek-seferlik şema migrasyonu; iş bitince çıkar. |
| `ghcr.io/ggml-org/llama.cpp` | **Opsiyonel** | Yerel AI motoru — **yalnız** `--profile ai` ile çalışır (model HuggingFace'ten çekilir). |
| `ghcr.io/lineup-noah/kangalis-ai` | **Opsiyonel** (air-gap) | Model **gömülü** ön-paketli AI imajı — çalışma anında sıfır indirme (bkz. §8). |

> **Tek imaj, dört servis:** `app`, `worker`, `beat` ve `mcp` aynı `Dockerfile`'dan
> derlenen **tek imajı** paylaşır; yalnız çalıştırdıkları komut farklıdır. Bu, derleme
> süresini ve disk kullanımını düşük tutar.

---

## 5. nmap ve lisans

### Varsayılan: nmap derleme sırasında otomatik kurulur

Tarama motoru **nmap** ikilisini çağırır; **nmap olmadan tarama yapılamaz**. Bu yüzden
`Dockerfile` içinde nmap **varsayılan olarak açıktır**:

```dockerfile
ARG INSTALL_NMAP=true
```

`docker compose up --build` sırasında nmap, Debian deposundan **otomatik** kurulur —
**kullanıcı nmap'i elle kurmaz**.

### nmap'i kapatma

nmap'i imaja dahil etmek istemezseniz:

```bash
docker compose build --build-arg INSTALL_NMAP=false
```

> ⚠️ nmap olmadan derlerseniz **tarama çalışmaz** — çekirdekte alternatif bir tarama
> motoru henüz yoktur.

### Lisans (NPSL)

nmap, **NPSL** (Nmap Public Source License — GPLv2 türevi) altında dağıtılır. Lisans
açısından dikkat edilmesi gereken nokta:

- **Kangalis, nmap binary'sini yeniden dağıtmaz.** Depo yalnızca **kaynağı**
  (`Dockerfile` satırını) dağıtır.
- nmap'i Debian deposundan çeken işlem **sizin `docker build`'iniz** sırasında olur — bu,
  **sizin kurulumunuzdur**, Kangalis'in binary dağıtımı değildir.
- Ayrıntı: [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md).

---

## 6. Erişim adresleri

Kurulum tamamlandığında aşağıdaki uçlar yerel makinenizde erişilebilir olur:

| Servis | Adres | Açıklama |
|---|---|---|
| **Web paneli** | http://localhost:8000/login | Ana arayüz — buradan giriş yapın. |
| **API / Swagger** | http://localhost:8000/docs | Etkileşimli API dokümantasyonu. |
| **MCP sunucusu** | http://localhost:8001/mcp | Claude entegrasyonu (token gerekir). |
| **PostgreSQL** | `localhost:5432` | Veritabanı (kullanıcı/şifre: `cyber`/`cyber` — dev). |
| **Redis** | `localhost:6379` | Broker / önbellek. |

MCP için bir erişim token'ı üretmeniz gerekir:

```bash
docker compose exec app python -m cybersectool.scripts.create_token
```

Ayrıntı: [docs/MCP.md](MCP.md).

---

## 7. Yapılandırma (.env)

Yapılandırma, ortam değişkenleriyle (veya kök dizindeki `.env` dosyasıyla) yönetilir.
Başlangıç için `.env.example` dosyasını kopyalayın:

```bash
cp .env.example .env
```

Önemli değişkenler:

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `SECRET_KEY` | `dev-secret` (dev) | Oturum imzalama + kasa anahtarı türetimi. **Üretimde güçlü, rastgele bir değer verin.** |
| `CREDENTIAL_ENCRYPTION_KEY` | boş (dev'de SECRET_KEY'den türetilir) | Kimlik kasası (SSH/DB/AD parolaları) Fernet anahtarı. **Üretimde ayrı, gizli bir değer verin.** |
| `DATABASE_URL` | `...@db:5432/cybersectool` | PostgreSQL bağlantı dizesi. |
| `REDIS_URL` | `redis://redis:6379/0` | Redis / Celery broker. |
| `DOCKER_SUBNET` | `172.28.0.0/16` | Konteyner köprü ağı. **Müşteri LAN'ı ile çakışıyorsa değiştirin** (ör. `10.89.0.0/16`). |
| `EXCLUDE_SCAN_IPS` | boş | Taramadan/envanterden dışlanacak ek IP'ler (virgülle). Aracın kendi konteyner IP'leri zaten otomatik dışlanır. |
| `ALLOW_AGGRESSIVE_SCANS` | dev=`true`, kod varsayılanı=`false` | Agresif (müdahaleci) tarama kill-switch'i. **Üretimde `false` bırakın.** |
| `AI_ENDPOINT` | `http://llamacpp:8080/v1` | Yerel AI motoru OpenAI-uyumlu uç. Host'taki motor için `http://host.docker.internal:<port>/v1`. |
| `AI_MODEL` | `qwen3:8b` | AI model etiketi. |
| `AI_TIMEOUT` | `300` | AI istek zaman aşımı (sn). CPU çıkarımı yavaştır; cömert tutuldu. |

> **Güçlü secret üretimi:**
> ```bash
> # SECRET_KEY
> python -c "import secrets; print(secrets.token_urlsafe(48))"
> # CREDENTIAL_ENCRYPTION_KEY (Fernet)
> python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
> ```

---

## 8. Yerel AI (opsiyonel, on-prem, sıfır egress)

Kangalis'in yerel AI asistanı (zafiyet açıklama + rapor özeti) **varsayılan kapalıdır** ve
yalnızca `ai` profiliyle başlar:

```bash
docker compose --profile ai up -d llamacpp
# veya:
make ai
```

Bu komut llama.cpp sunucusunu başlatır; modeli (Qwen3-8B-GGUF Q4, ~5–6 GB)
HuggingFace'ten **tek seferlik** çeker ve **CPU'da** koşar (GPU gerekmez). Port host'a
**publish edilmez** — yani istemci verisi müşteri ağından çıkmaz (**sıfır egress**;
yalnızca model indirme tek seferliktir). RAM `mem_limit 8g` ile sınırlıdır.

### Ön-paketli (air-gap) imaj — model gömülü, çalışma anında sıfır indirme

Yukarıdaki varsayılan yol, modeli ilk açılışta **HuggingFace'ten** çeker (internet + ~5 GB
indirme gerekir). İzole/air-gap ağlar için, modeli (Qwen3-8B Q4) **gömülü** taşıyan ön-paketli
imajımızı kullanın — böylece çalışma anında **hiç dış indirme olmaz**:

```bash
# (önce) imajı çekin ya da yerelde derleyin
docker pull ghcr.io/lineup-noah/kangalis-ai:qwen3-8b-q4km
#   veya yerel derleme:  bash build-ai-image.sh   /   powershell -File build-ai-image.ps1

# (sonra) gömülü-imaj override'ı ile başlatın
docker compose -f docker-compose.yml -f docker-compose.ai-baked.yml --profile ai up -d llamacpp
#   veya:  make ai-baked
```

> İmaj büyüktür (~5–6 GB, model gömülü). Bir kez çekip air-gap ortama taşıyabilirsiniz
> (`docker save`/`docker load`). Bu imaj MIT-lisanslı çekirdekten **ayrı** bir artefakttır;
> llama.cpp (MIT) + Qwen3 (Apache-2.0) gömülüdür — bkz. `THIRD-PARTY-NOTICES.md`.

### Diğer seçenekler ve notlar

- **Alternatif (host motoru):** host'ta LM Studio / Ollama çalıştırıp
  `AI_ENDPOINT=http://host.docker.internal:<port>/v1` verebilirsiniz.
- AI, web panelinde **Ayarlar > AI** kartından açılır. Kapalıyken her şey graceful'dur
  (statik içerik gösterilir, uygulama yine ayağa kalkar).
- İlk grounded üretim CPU'da yavaştır (~birkaç dakika).

Ayrıntı ve sıfır-egress doğrulaması: [docs/AI-SIFIR-EGRESS.md](AI-SIFIR-EGRESS.md).

---

## 9. Üretim notları

Geliştirme varsayılanları (`SECRET_KEY=dev-secret`, DB kullanıcı/şifre `cyber:cyber`)
**yalnızca geliştirme içindir**. Üretimde:

1. **`APP_ENV=production` ayarlayın.** Bu mod, uygulama başlarken yapılandırmayı sıkı
   denetler ve **zayıf değerleri reddeder** (`ValueError` ile başlamayı durdurur):
   - Zayıf/varsayılan `SECRET_KEY` (`dev-secret`, `change-me`, `secret`, boş, vb.) →
     **reddedilir**.
   - Boş `CREDENTIAL_ENCRYPTION_KEY` → **reddedilir** (kasa anahtarı SECRET_KEY'den
     türetilemez; sızıntıda tüm kasayı açar).
2. **Güçlü `SECRET_KEY`** ve **ayrı, güçlü `CREDENTIAL_ENCRYPTION_KEY`** verin (üretim
   komutları için Bölüm 7).
3. **`ALLOW_AGGRESSIVE_SCANS=false`** bırakın. Agresif mod nmap NSE vuln/exploit
   scriptlerini çalıştırır; hedefe müdahale eder (servis kesintisi / iz bırakma riski).
   Yalnızca yetkili, yedeği alınmış sistemlerde, bilinçli olarak açın.
4. **Varsayılan DB kimlik bilgilerini değiştirin** ve veritabanı/Redis portlarını dış
   dünyaya açmayın.

---

## 10. Sorun giderme

| Belirti | Olası neden | Çözüm |
|---|---|---|
| **Tarama çalışmıyor / "kapsam dışı" hatası** | Kapsam tanımlı değil **ya da** nmap kurulu değil | `set_scope` ile en az bir `--allow <CIDR>` tanımlayın (Bölüm 3.3). nmap'i `INSTALL_NMAP=false` ile kapattıysanız tarama çalışmaz — varsayılanla yeniden derleyin (Bölüm 5). |
| **Migrate hatası / uygulama başlamıyor** | Veritabanı henüz sağlıklı değil ya da migrasyon başarısız | `docker compose logs migrate db` ile bakın. `db` servisi `healthy` mi (`docker compose ps`)? Gerekirse `docker compose up -d --build` ile yeniden deneyin. |
| **AI bağlanmıyor** | Profil açık değil, endpoint yanlış ya da (Linux) host-gateway eksik | `docker compose --profile ai up -d llamacpp` ile motoru açın. Host motoru kullanıyorsanız `AI_ENDPOINT` doğru mu? **Linux'ta** host motoruna ulaşmak için `host.docker.internal:host-gateway` eşlemesi şarttır (compose'da tanımlıdır; özel kurulumda doğrulayın). AI kapalıyken uygulama yine çalışır. |
| **Konteyner ağı müşteri LAN'ıyla çakışıyor** | `DOCKER_SUBNET` müşteri aralığıyla örtüşüyor | `.env` içinde `DOCKER_SUBNET`'i alışılmadık bir aralığa çekin (ör. `10.89.0.0/16`) ve yeniden başlatın. |
| **Sömürü/exploit çalıştırma yok** | Çekirdek tasarımı gereği | Açık-kaynak çekirdek exploit **çalıştırmaz**; yalnız "exploit var mı" sinyalini gösterir. Gerçek sömürü ayrı `kangalis-exploit` eklentisindedir — bkz. aşağıdaki link. |

Loglara canlı bakmak için: `docker compose logs -f` (veya `make logs`).

---

## İlgili belgeler

- **[docs/EKLENTILER.md](EKLENTILER.md)** — opsiyonel/ticari eklentiler (örn. sömürü/pentest
  eklentisi `kangalis-exploit`). Çekirdek exploit çalıştırmaz; gerçek sömürü ayrı eklentidedir.
- **[docs/KILAVUZ.md](KILAVUZ.md)** — başlangıç ve günlük kullanım rehberi (tarama, bulgu,
  rapor akışları).
- **[SECURITY.md](../SECURITY.md)** — güvenlik politikası, kabul edilebilir kullanım ve
  sorumlu açıklama.

---

> ⚠️ **Hatırlatma:** Kangalis'i yalnızca **taramaya yetkili olduğunuz kapsam** içinde
> kullanın. İzinsiz tarama yasa dışıdır ve tüm sorumluluk operatöre aittir.
