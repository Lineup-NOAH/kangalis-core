# Kangalis — Opsiyonel Özellikler ve Eklentiler

> Bu rehber, Kangalis açık-kaynak çekirdeğindeki **opsiyonel** yetenekleri ve eklentileri
> tek tek anlatır: her biri **ne işe yarar**, **nasıl açılır** (komut/ayar), **gereksinimi/maliyeti**
> nedir ve **kapalıyken ne olur**.
>
> **Temel güvence:** Bu bölümlerin **hiçbiri zorunlu değildir**. Hepsi kapalıyken bile çekirdek
> tam çalışır — ağ/host keşfi, port & servis/sürüm tespiti, CVE eşleştirme, sömürülebilirlik
> **sinyalleri** (Exploit-DB/CISA KEV/EPSS), risk önceliklendirme, raporlama ve web paneli
> eksiksiz işler. Aşağıdaki her özellik bu çekirdeğin **üstüne** isteğe bağlı eklenir.
>
> Önkoşul (hepsi için ortak): kullanıcı yalnızca **Docker + Docker Compose** kurar; başka hiçbir
> şey elle kurulmaz. Temel kurulum için bkz. `docs/KILAVUZ.md`.

---

## İçindekiler

1. [Yerel (on-prem) AI](#1-yerel-on-prem-ai)
2. [Sömürü / Pentest eklentisi](#2-sömürü--pentest-eklentisi)
3. [nmap tarama motoru](#3-nmap-tarama-motoru)
4. [MCP (Claude entegrasyonu)](#4-mcp-claude-entegrasyonu)
5. [Agresif (müdahaleci) tarama](#5-agresif-müdahaleci-tarama)
6. [Kimlikli (credentialed) tarama](#6-kimlikli-credentialed-tarama)
7. [Uyum (compliance) raporlama](#7-uyum-compliance-raporlama)
8. [LDAP / Active Directory entegrasyonu](#8-ldap--active-directory-entegrasyonu)

---

## 1. Yerel (on-prem) AI

**Ne işe yarar.** Zafiyet bulgularını sade Türkçe ile açıklar, rapor özetleri ve uyum anlatıları
üretir. Tamamen **on-prem** çalışır: analiz edilen veri dağıtım ağının dışına **çıkmaz**
(sıfır-egress). Bulut API'si yok, API anahtarı yok. (Detaylı sıfır-egress kanıtı:
`docs/AI-SIFIR-EGRESS.md`.)

**Nasıl açılır.** Üç yol var (A en kolay; B air-gap/izole ağ için; C kendi host motorunuz):

- **A) Gömülü motor (en kolay) — Ollama profili:**
  ```bash
  docker compose --profile ai up -d ollama
  ```
  Bu, OpenAI-uyumlu yerel bir çıkarım sunucusu başlatır; modeli (varsayılan `qwen3:8b`, ~5GB)
  ilk açılıştan sonra `docker compose exec ollama ollama pull qwen3:8b` ile **tek seferlik**
  çeker ve CPU'da koşar (air-gap için ön-paketli imaj zaten var, bkz. B).
  Compose'da `app`/`worker` zaten `AI_ENDPOINT=http://ollama:11434/v1`'e işaret eder.
  Modeli değiştirmek için `.env` içinde `AI_MODEL=...` ayarlayın.

- **B) Ön-paketli (air-gap) imaj — model GÖMÜLÜ, sıfır indirme:**
  Yol (A) modeli ilk açılıştan sonra `ollama pull` ile çeker (~5 GB indirme + internet gerekir).
  Bunun yerine, modeli (Qwen3-8B Q4) **gömülü** taşıyan ön-paketli imajımızı kullanabilirsiniz —
  böylece çalışma anında **hiç dış indirme olmaz** (air-gap/izole ağlar için uygundur; LLM verisi
  müşteri ağında kalır):
  ```bash
  # (önce) imajı çekin ya da yerelde derleyin:
  docker pull ghcr.io/lineup-noah/kangalis-ai:qwen3-8b
  #   veya:  bash build-ai-image.sh   /   powershell -File build-ai-image.ps1
  # (sonra) gömülü-imaj override'ı ile başlatın:
  docker compose -f docker-compose.yml -f docker-compose.ai-baked.yml --profile ai up -d ollama
  #   veya:  make ai-baked
  ```
  > Bu imaj, MIT-lisanslı çekirdekten **ayrı** bir artefakttır; içine Ollama (MIT) + Qwen3
  > ağırlıkları (Apache-2.0) gömülüdür — her ikisinin lisansı gömmeye/yeniden dağıtıma izin verir.
  > Recipe: `Dockerfile.ai`. Ayrıntı: `THIRD-PARTY-NOTICES.md`.

- **C) Host-native motor (LM Studio / Ollama / LocalAI):**
  Host makinede kendi motorunuzu çalıştırın ve `.env` içinde endpoint'i ona yöneltin:
  ```env
  AI_ENDPOINT=http://host.docker.internal:<port>/v1
  AI_MODEL=<model-adı>
  ```
  > Linux'ta host-native yolu için Compose `extra_hosts: host.docker.internal:host-gateway`
  > eşlemesi gerekir (Compose dosyasında zaten tanımlı). Bu eşleme yoksa app, host motoruna
  > sessizce bağlanamaz.

Hangi yolu seçerseniz seçin, son adım aynıdır: **Eklentiler > AI** kartından AI'yı **etkinleştirin**
(`ai_enabled`), endpoint/model/zaman aşımını doğrulayın ve "Bağlantıyı test et" ile motoru
yoklayın. Etkinleştirilmeden AI yüzeyleri görünmez. Etkinken arayüz markası "Kangalis AI" olur.

**Gereksinim / maliyet.**
- Disk: model tek seferlik ~5GB indirme (Qwen3-8B Q4).
- RAM: AI konteyneri `mem_limit: 8g` ile sınırlıdır → pratikte ~8GB RAM gerekir.
- CPU: GPU **gerekmez**; CPU'da koşar.
- Egress: yalnızca **tek seferlik model indirme**. Çalışma anında sıfır dış trafik. Air-gap
  dağıtımında model imaja önceden gömülürse o indirme de olmaz.
- Performans: İlk grounded üretim CPU'da yavaştır (özet/script ~3-5 dk sıcak modelle). Bu yüzden
  `AI_TIMEOUT` varsayılanı cömerttir (300 sn). Port host'a publish **edilmez** (yalnız iç ağ).

**Kapalıyken ne olur.** Her şey **graceful**: AI butonları/yüzeyleri görünmez, ilgili sayfalarda
statik (önceden hazırlanmış) içerik gösterilir. Tarama, CVE eşleştirme, raporlama, panel — hepsi
AI'sız tam çalışır. AI tamamen opsiyonel bir katmandır.

---

## 2. Sömürü / Pentest eklentisi

**Dürüst çerçeve — önce sınırı çizelim.** Gerçek sömürü/sızma yeteneği bu **açık-kaynak
çekirdekte YOKTUR**. Çekirdek hiçbir exploit **çalıştırmaz**. Bu kasıtlı bir tasarım kararıdır:
çekirdek savunmacı bir zafiyet yönetim platformudur.

**Ne işe yarar (çekirdeğin yaptığı).** Çekirdek, bir CVE için **"exploit VAR MI"** bilgisini
gösterir — yani Exploit-DB / Metasploit metadata **sinyalini** (bir exploit/PoC veya Metasploit
modülü mevcut mu, kaç tane) panelde rozet olarak sunar. Bu yalnızca **bilgilendirme/risk
önceliklendirme** içindir; hiçbir kod hedefe karşı **çalıştırılmaz**.

**Nasıl açılır.** Çekirdekte ek bir şey açmanıza gerek yok — exploit **sinyalleri** zaten
varsayılan olarak görünür (Zafiyetler `/findings`, Exploit DB `/exploits` sayfaları). Yerel
exploit/CVE deposunu güncellemek için:
```bash
docker compose exec app python -m cybersectool.scripts.sync_exploits
```
veya panelde **"🔄 Veritabanını Güncelle"** (admin → onay → arka plan görevi).

**Gerçek sömürü için.** Metasploit orkestrasyonu, izole PoC çalıştırma, kimlik brute-force ve
AI exploit-hazırlama gibi **müdahaleci** yetenekler ayrı, **ticari `kangalis-exploit`**
eklentisinde tutulur ve bu depoya dahil **değildir**.
- **Yol haritası (uzak hedef):** Çekirdeğin, müşterinin kendi Metasploit kutusunda koşan uzak
  **"Kangalis Exploit Agent"** ile konuşması planlanır; gerçek exploit yürütme her zaman
  çekirdeğin **dışında**, ayrı/izole bir bileşende kalır.

**Eklenti kontratı (seam).** Çekirdek, eklentiyi yalnız **kuruluysa** geç-import (`try/except
ImportError`) ile çağırır; kontrat [`core/exploit_seam.py`](../src/cybersectool/core/exploit_seam.py)
içinde belgelidir. Eklenti (`cybersectool.exploit` namespace paketi) şunları sağlamalı:
`msf_client.msf_configured()` (msfrpcd hazır mı), `runner.run_exploitation_for_scan(session,
scan_id, *, user_id=None)` (gerçek MSF exploitation), `exploitdb_stage.stage_exploitdb_attempts(...)`
(Exploit-DB PoC staging). **Eklentiler** sayfasındaki *Sömürü* kartı durumu (Kurulu/Pasif) +
kurulum adımlarını + **yalnız yetkili kullanım** uyarısını gösterir. Yetkilendirme/EULA kapısı
(scope ack + yetki beyanı) ayrı bir fazda eklenip sömürü ateşlenmeden önce zorunlu olacaktır.

**Gereksinim / maliyet.** Sinyaller için ek maliyet yok (yerel depo ~70k kayıt ≈ 20-25 MB; NVD
toplu çekme `NVD_API_KEY` ile hızlanır). Gerçek sömürü eklentisi ayrı/ticari bir ürün olduğundan
çekirdeğin önkoşullarını değiştirmez.

**Kapalıyken ne olur.** Sömürü eklentisi bu çekirdekte zaten **yoktur**; çekirdek onsuz **tam
çalışır**. Exploit "var mı" bilgisi (sinyal) görünmeye devam eder, ama hiçbir exploit
çalıştırılmaz — bu beklenen ve güvenli varsayılandır.

---

## 3. nmap tarama motoru

**Ne işe yarar.** Kangalis'in çekirdek tarama motorudur: host keşfi, port tarama,
servis/sürüm tespiti ve (agresif modda) NSE script denetimleri nmap üzerinden yapılır. Araç
**nmap olmadan tarama yapamaz**.

**Nasıl açılır.** **Varsayılan AÇIK.** Dockerfile'da `ARG INSTALL_NMAP=true` tanımlıdır;
`docker compose up -d --build` sırasında nmap **otomatik** olarak Debian deposundan kurulur.
Kullanıcı nmap'i **elle kurmaz**.

Kapatmak için (nadiren gerekir):
```bash
docker compose build --build-arg INSTALL_NMAP=false
```
> Kapatılırsa **hiçbir tarama çalışmaz** — şu an alternatif bir tarama motoru yoktur.

**Gereksinim / maliyet.** Ek maliyet yok; nmap imaj derlenirken kurulur. İndirme küçüktür.

**Lisans notu (NPSL).** nmap, **NPSL** (Nmap Public Source License, GPLv2 türevi) ile dağıtılır.
Kangalis nmap ikilisini **yeniden dağıtmaz**: yalnızca kaynağı (Dockerfile satırını) dağıtır;
**sizin** `docker build`'iniz nmap'i Debian deposundan çeker = bu **sizin kurulumunuzdur**, bizim
binary dağıtımımız değil. Ayrıntı: `THIRD-PARTY-NOTICES.md`.

**Kapalıyken ne olur.** nmap kapatılırsa tarama yeteneği devre dışı kalır (uygulama yine ayağa
kalkar, panel açılır, ama tarama başlatılamaz). Pratikte nmap'i kapatmayın; bu yalnızca özel/lisans
senaryoları içindir.

---

## 4. MCP (Claude entegrasyonu)

**Ne işe yarar.** Claude'un (Desktop / Code) Kangalis'i doğrudan kullanmasını sağlar: tarama
başlatma, envanter/zafiyet sorgulama, CVE arama. MCP araçları web arayüzüyle **aynı core/service
katmanını** çağırır (aynı scope guard, aynı RBAC).

**Nasıl açılır.** İki mod var:

- **A) Yerel (stdio)** — kendi Claude Desktop'ınız. `claude_desktop_config.json`'a
  `cybersectool-mcp` komutunu ekleyin (örnek: `docs/MCP.md`). Docker stack ayakta olmalı.

- **B) Uzak (HTTP + token)** — ağdaki herkes tek merkezi MCP'ye bağlanır. `mcp` servisi
  Compose'da hazırdır ve **http://localhost:8001/mcp** adresinde çalışır:
  1. Token üretin:
     ```bash
     docker compose exec app python -m cybersectool.scripts.create_token --username <kullanıcı-adı> --name claude-uzak
     ```
  2. Claude Desktop'a (ya da streamable-http destekleyen istemciye) bağlanın:
     ```
     URL:    http://<sunucu-ip>:8001/mcp
     Header: Authorization: Bearer cst_...
        ya da Authorization: Basic <base64(kullanıcı:parola)>   # yerel veya LDAP kullanıcısı
     ```
  Geçersiz/eksik kimlik → **401**. Ayrıntılı yapılandırma ve araç listesi: **`docs/MCP.md`**.

**Gereksinim / maliyet.** Ek bir indirme yok; `mcp` servisi aynı uygulama imajının farklı bir
rolüdür. DB/Redis erişimi için stack ayakta olmalı.

**Güvenlik.** `start_scan` scope guard'dan geçer. HTTP modunda kimlik **zorunludur** (Bearer
token veya Basic). RBAC araç düzeyinde uygulanır (viewer < analyst < admin). Üretimde TLS
(reverse proxy) önerilir.

**Kapalıyken ne olur.** MCP yalnızca bir entegrasyon yüzeyidir. Hiç kullanmazsanız (veya `mcp`
servisini başlatmazsanız) web paneli, API ve tüm tarama yetenekleri olduğu gibi çalışır.

---

## 5. Agresif (müdahaleci) tarama

**Ne işe yarar.** Ağ taramasını "yalnızca tespit"ten "deneyerek doğrula"ya yükseltir: nmap NSE
`vuln`/`exploit`/`discovery` scriptleri + OS parmak izi ile zafiyetleri **aktif olarak**
doğrular. DoS ve brute **hariç** tutulur.

**Nasıl açılır.** Güvenlik için **çift kilit** (OpenVAS-tarzı kazaları önlemek için) ve bir
onay kapısı vardır:
1. **Global ayar** `ALLOW_AGGRESSIVE_SCANS=true` olmalı (`.env` veya Compose env). Kod
   varsayılanı: üretim güvenli (`false`); dev'de `true`. Kapalıyken UI'da seçenek pasiftir.
2. İşlemi yalnızca **`admin`** rolü başlatabilir.
3. Panelde tarama yoğunluğu olarak **⚠️ Agresif** seçilir ve **"kabul ediyorum"** onayı verilir.

Kilitlerden biri sağlanmazsa istek **403** ile reddedilir. Her agresif tarama
`aggressive_scan_start` olarak **denetim günlüğüne** (kim/ne zaman) yazılır. Zamanlanmış
taramalar ve MCP **her zaman güvenli** moddadır.

**Ne açar (güvenli moda göre fark).**
- 🛡️ Güvenli (varsayılan): `-sV -sC -T4` — port/servis/sürüm + bilgi toplayıcı NSE; müdahale yok.
- ⚠️ Agresif: `-sV -T4 -A --script "(vuln or exploit or discovery) and not dos and not brute"`.

**Gereksinim / maliyet.** Ek yazılım gerekmez (aynı nmap). Maliyet **risktir**: agresif mod
hedefe **müdahale eder** → servis kesintisi / iz bırakma olasılığı. Yalnızca yetkili ve **yedeği
alınmış** sistemlerde, bilinçli açın.

**Kapalıyken ne olur.** Tüm taramalar güvenli (tespit) modda yürür — bu çoğu kurulum için
yeterli ve önerilen varsayılandır. Çekirdek tam çalışır; yalnızca aktif doğrulama yapılmaz.

---

## 6. Kimlikli (credentialed) tarama

**Ne işe yarar.** Hedef sisteme **içeriden** kimlikli denetim yapar: SSH ile OS/kernel envanteri,
bekleyen güvenlik güncellemeleri, NOPASSWD sudo, dünya-yazılabilir dosyalar ve **CIS** kontrolleri.
Hedefi **değiştirmez** (salt-okunur denetim). İç envanter + sertleştirme görünürlüğü sağlar.

**Nasıl açılır.**
1. **Kimlik kasası** (`/credentials`, yalnız admin): SSH / WinRM / RDP / LDAP kimlikleri oluşturun
   (ad + tip + kullanıcı + parola + domain/port). Parolalar **Fernet ile şifreli** saklanır,
   panelde bir daha gösterilmez. Kimlikleri **kimlik bölgelerinde** gruplayabilirsiniz (IP
   zone'un kimlik karşılığı).
2. Tarama başlatın:
   - Tekil/IP-zone: Taramalar → IP Zone taraması → tip **"🔑 Kimlik bölgesiyle"** → bir kimlik
     bölgesi seçin. Her host'un açık portu yoklanır (OS ipucu: 22→Linux/SSH, 3389/5985/5986→
     Windows) ve kimlikler **OS önceliğiyle** denenir.
   - API: `POST /scans/credentialed` (panelde 🔐 admin akışı).

> Kimlikler kasadan **anlık** çözülür; SSH yolu tam çalışır (içeriden envanter + CIS denetimi).
> Windows portu açıksa erişilebilirlik raporlanır (tam WinRM/RDP auth backend'i sonraki adım).

**Gereksinim / maliyet.** Ek yazılım gerekmez. Şifreleme anahtarı: `CREDENTIAL_ENCRYPTION_KEY`
(boşsa `SECRET_KEY`'den türetilir — yalnız dev; **üretimde ayrı bir gizli anahtar verin**).
Üretmek için:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**Kapalıyken ne olur.** Kimlik tanımlamazsanız kimlikli tarama kullanılmaz; çekirdek yalnızca
**kimliksiz (dışarıdan)** ağ/web taraması yapar — bu da tam çalışır. Kimlikli denetim, görünürlüğü
derinleştiren opsiyonel bir katmandır.

---

## 7. Uyum (compliance) raporlama

**Ne işe yarar.** Sertleştirme/kimlikli denetim bulgularını tanınmış **CIS** kontrollerine eşler
(CIS Linux — SSH, CIS Windows — WinRM) ve **KVKK / ISO 27001 / PCI** çerçeveleri için biçimli uyum
raporları üretir. Ayrıca CVE bulguları ilgili uyum çerçeveleriyle ilişkilendirilir (panelde uyum
rozetleri).

**Nasıl açılır.** **Yerleşik** — ayrı bir eklenti açmaya gerek yoktur. Uyum sonuçları, ilgili
denetimler çalıştıkça otomatik türetilir:
- Host/kimlikli denetim çalıştırın (bkz. §6) → bulgular CIS kontrollerine eşlenir
  (`ComplianceCheck` olarak saklanır).
- Panelde uyum özetini görüntüleyin; **Rapor** (`/report`) sayfasından yazdırılabilir/PDF rapor
  alın (KVKK/ISO/PCI çerçeve rozetleriyle).

**Gereksinim / maliyet.** Ek yazılım gerekmez. PDF üretimi imaja gömülü WeasyPrint ile yapılır
(Türkçe karakterler için DejaVu fontları dahildir). En zengin uyum görünürlüğü için kimlikli
tarama (§6) önerilir, çünkü CIS kontrollerinin çoğu içeriden denetim gerektirir.

**Kapalıyken ne olur.** Uyum motoru her zaman mevcuttur; yalnızca ilgili denetimleri (kimlikli/
host) çalıştırmazsanız eşlenecek bulgu olmaz. Bu durumda çekirdeğin geri kalanı (ağ/web tarama,
CVE, raporlama) tam çalışmaya devam eder.

---

## 8. LDAP / Active Directory entegrasyonu

**Ne işe yarar.** Kullanıcıları merkezi dizinden (LDAP / Active Directory) yönetmenizi sağlar:
dizinden kullanıcı arama ve içe aktarma, LDAP kimlik bilgileriyle giriş (yerel kullanıcı yerine),
ve opsiyonel **periyodik senkron**. Ayrıca LDAP/AD sunucusuna salt-okunur güvenlik denetimi
(IX-7b) yapılabilir.

**Nasıl açılır.** **Ayarlar**'dan, yalnızca admin:
1. **Ayarlar > LDAP bağlantısı** formunu doldurun ve kaydedin (`POST /settings/ldap`):
   - `server_uri` (örn. `ldap://dc.ornek.local` ya da `ldaps://...`), `base_dn`, `bind_dn` +
     `bind_password` (servis hesabı; **Fernet ile şifreli** saklanır; boş bırakılırsa anonim
     bind), `user_filter`, öznitelik eşlemeleri (`attr_username`/`attr_email`/`attr_display_name`),
     `default_role` ve `use_ssl`.
   - **"Bağlantıyı test et"** ile doğrulayın; kullanıcı/grup/OU listeleyebilirsiniz.
2. Entegrasyonu etkinleştirin (`ldap_enabled`); etkinken giriş ekranında LDAP seçeneği belirir ve
   LDAP kullanıcısı ilk girişte otomatik oluşturulur.
3. (Opsiyonel) **Periyodik senkron**: **Ayarlar > LDAP senkron** (`POST /settings/ldap-sync`) ile
   `hourly`/`daily`/`weekly` zamanlama ve saat seçin.

> LDAPS sertifika doğrulaması Ayarlar > sertleştirme (`ldaps_verify_cert` + opsiyonel CA PEM)
> üzerinden yönetilir. LDAP kullanıcıları MCP'ye de Basic auth ile bağlanabilir (bkz. §4).

**Gereksinim / maliyet.** Ek yazılım gerekmez (LDAP istemcisi `ldap3` imaja dahildir). Erişilebilir
bir LDAP/AD sunucusu ve (anonim bind kullanmıyorsanız) bir servis/bind hesabı gerekir. Üretimde
**LDAPS** (sertifika doğrulamalı) önerilir.

**Kapalıyken ne olur.** LDAP `ldap_enabled` kapalıyken giriş tamamen **yerel kullanıcılarla**
yapılır (setup sihirbazında oluşturduğunuz admin gibi). Dizin entegrasyonu olmadan kimlik
doğrulama, RBAC ve tüm çekirdek özellikleri eksiksiz çalışır.

---

## Özet — hepsi opsiyonel

| Özellik | Varsayılan | Nasıl açılır | Kapalıyken |
|---|---|---|---|
| Yerel AI | Kapalı | `--profile ai` + Eklentiler>AI | Statik içerik (graceful) |
| Sömürü eklentisi | Çekirdekte yok | Ayrı/ticari `kangalis-exploit` | Sinyal gösterilir, çalıştırılmaz |
| nmap | **Açık** | Build'de otomatik | Tarama çalışmaz (kapatmayın) |
| MCP | Hazır (kullanmak ops.) | Token üret + bağlan | Panel/API tam çalışır |
| Agresif tarama | Kapalı (prod) | `ALLOW_AGGRESSIVE_SCANS` + admin + onay | Güvenli (tespit) mod |
| Kimlikli tarama | Kapalı | Kimlik kasası + 🔑 tarama | Kimliksiz (dış) tarama |
| Uyum raporlama | Yerleşik | Kimlikli/host denetimi çalıştır | Eşlenecek bulgu olmaz |
| LDAP/AD | Kapalı | Ayarlar>LDAP | Yerel kullanıcılar |

**Her durumda:** yukarıdakilerin hepsi kapalıyken bile **çekirdek tam çalışır**.

---

*İlgili belgeler: `docs/KILAVUZ.md` (başlangıç/kullanım) · `docs/MCP.md` (MCP detayı) ·
`docs/AI-SIFIR-EGRESS.md` (AI sıfır-egress kanıtı) · `THIRD-PARTY-NOTICES.md` (lisanslar).*
