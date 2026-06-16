# Kangalis Yerel AI — Sıfır-Egress (Veri Dışarı Çıkmaz) Doğrulama Runbook'u

> **Amaç:** Kangalis'in yerel AI asistanının, analiz ettiği zafiyet/bulgu verilerini
> **dağıtım ağının dışına çıkarmadığını** bağımsız olarak kanıtlamak. Bu belge hem iç ekip
> hem de operatörün güvenlik/uyum (KVKK, ISO 27001) ekibi için tekrar uygulanabilir bir
> denetim prosedürüdür.

## 1. Mimari — neden veri çıkamaz

AI üç katmandan oluşur ve **üçü de operatörün kendi sunucusunda** çalışır:

| Katman | Görev | Konum |
|--------|-------|-------|
| **Kangalis AI çatısı** (`core/ai/`) | İstek hazırlar, prompt kurar, yanıtı gösterir | Dağıtım sunucusu (uygulama konteyneri) |
| **Yerel çıkarım motoru** (Ollama; LM Studio/LocalAI gibi yerel motorlar da olur) | Modeli yükler, OpenAI-uyumlu API sunar | Dağıtım sunucusu (AI konteyneri) |
| **Model** (örn. qwen3:8b) | Metni üreten yapay zekâ | Dağıtım sunucusu (yerel diskte) |

Bulut API'si **yoktur**. AI çağrısı yalnızca **iç ağ adresine** (`http://kangalis-ai:11434/v1`)
gider — bu bir Docker iç-DNS adıdır, internet IP'si değildir; host makineden fiziksel olarak
çıkamaz. Model "düşünürken" yalnızca yerel CPU + diski kullanır, hiçbir dış bağlantı açmaz.

## 2. Üç bağımsız kanıt yöntemi

### Kanıt A — Kod denetimi (tek çıkış noktası)

`core/ai/` paketindeki **tek** dış-ağ çağrısı `client.py`'dir. Doğrula:

```bash
# Paketteki tüm HTTP istemci kullanımları — yalnız client.py çıkmalı:
grep -rn "httpx\|requests\.\|urllib\|aiohttp" src/cybersectool/core/ai/

# Bulut sağlayıcı / API anahtarı izi — SONUÇ BOŞ olmalı:
grep -rni "openai.com\|anthropic\|api_key\|sk-\|bearer" src/cybersectool/core/ai/
```

`client.py` yalnızca **ayarlardaki endpoint'e** (`AppSettings.ai_endpoint_url`) gider; başka
hiçbir hedef gömülü değildir. Çıkış noktası tek ve denetlenebilirdir.

### Kanıt B — Yapılandırılmış endpoint iç ağda

```bash
docker compose exec -T app python -c "
import asyncio
from cybersectool.core.db import SessionLocal
from cybersectool.core.app_settings import get_settings
async def m():
    async with SessionLocal() as s:
        r = await get_settings(s)
        print('endpoint =', r.ai_endpoint_url)
asyncio.run(m())"
# Beklenen: endpoint = http://kangalis-ai:11434/v1   (iç Docker-DNS adı, internet değil)
```

### Kanıt C — Çalışırken sıfır internet bağlantısı

Gerçek bir AI üretimi yaparken AI konteynerinin aktif bağlantılarını oku. Genel-internet
IP'sine **tek bir bağlantı bile** olmamalı:

```bash
# Arka planda bir üretim başlat:
docker compose exec -T app python -c "
import asyncio
from cybersectool.core.ai.service import AIConfig, generate
c = AIConfig(True,'http://kangalis-ai:11434/v1','qwen3:8b',180.0)
asyncio.run(generate(c,'Apache CVE-2021-41773 nedir?',system='Sen analistsin.'))" &

# Üretim sürerken AI konteynerinin KURULU bağlantılarını çözümle:
docker exec kangalis-ai cat /proc/net/tcp /proc/net/tcp6 | awk '$4=="01"{print $3}'
# (Hex IP:PORT — yalnız 127.x / 172.x / 10.x / 192.168.x = iç ağ görülmeli)
```

**Bu repoda canlı sonuç:** üretim sırasında tek kurulu bağlantı `127.0.0.1` (modelin kendi içi)
idi; genel-internet bağlantısı **SIFIR**. ✅

## 3. Kesin kanıt — Air-Gap (internet-kes) testi

En güçlü kanıt: AI konteynerinin internetini **tamamen kes**, AI **yine de çalışmalı**.
Phone-home yapsaydı bozulurdu — yapmıyor.

> ⚠️ Bu test AI servisini birkaç dakikalığına etkiler; bakım penceresinde, operatör onayıyla
> çalıştırın. Tüm adımlar geri alınabilir; en kötü durumda `docker compose up -d` +
> `docker restart kangalis-ai` ağı tamamen onarır.

> **Not (güvenlik artısı):** AI konteyneri varsayılan olarak `NET_ADMIN` yetkisi olmadan
> çalışır → kendi ağ rotalarını bile değiştiremez (`ip route del` → *Operation not permitted*).
> Bu yüzden internet, konteynerin İÇİNDEN değil, **Docker ağ katmanından** kesilir:

```bash
# 1) İnternetsiz bir iç ağ kur; app erişimini koru, AI'ı internetli ağdan KOPAR:
docker network create --internal kg-airgap
docker network connect    kg-airgap          kangalis-core-app-1   # app erişimi korunur
docker network connect    kg-airgap          kangalis-ai
docker network disconnect kangalis-core_default kangalis-ai        # ← internet gider

# 2) İnternetin gerçekten kesildiğini DOĞRULA (BLOCKED beklenir):
docker exec kangalis-ai sh -c "curl -m6 -sS https://www.google.com >/dev/null 2>&1 && echo REACHABLE || echo BLOCKED"

# 3) AI üretimini DENE — internet yokken bile ÇALIŞMALI:
docker compose exec -T app python -c "
import asyncio
from cybersectool.core.ai.service import AIConfig, generate
c = AIConfig(True,'http://kangalis-ai:11434/v1','qwen3:8b',180.0)
print(asyncio.run(generate(c,'Kısa bir test cümlesi yaz.',system='Sen analistsin.')))"
# Beklenen: model normal Türkçe yanıt üretir → veri dışarı GEREKMİYOR.

# 4) GERİ AL (AI'ı internetli ağa geri bağla + test ağını temizle):
docker network connect    kangalis-core_default kangalis-ai
docker network disconnect kg-airgap kangalis-ai
docker network disconnect kg-airgap kangalis-core-app-1
docker network rm         kg-airgap
```

**Bu repoda canlı çalıştırıldı (2026-06-13):** 1. adımdan sonra `curl` → **BLOCKED**; 3. adımda
model internet yokken normal Türkçe yanıt üretti (*"Redis kimlik doğrulaması ... yetkisiz erişimi
önlemek ... kritik öneme sahiptir."*). Geri-alma sonrası internet REACHABLE, AI endpoint OK,
konteynerler sağlıklı. ✅ **AI'ın internete ihtiyacı YOK; veri dışarı çıkmıyor.**

> Üretimde kalıcı yöntem: AI konteynerini sürekli Docker `--internal` ağında tut ya da host
> firewall'ında (iptables/Windows Defender Firewall) konteyner egress'ini DROP'la. Bu durumda
> internet hiç açılmaz; model, önceden indirilmiş ağırlıklarla (imaja gömülü) gelir.

## 4. Bağımsız ağ izleme (operatör denetçisi için)

Host üzerinden paket düzeyinde doğrulama (Wireshark/tcpdump):

```bash
# AI konteynerinin köprü arayüzünü bul, üretim sırasında dışa giden paketleri izle:
sudo tcpdump -ni any "host kangalis-ai and not (net 172.16.0.0/12 or net 10.0.0.0/8 or net 192.168.0.0/16)"
# Bir AI üretimi tetikle → bu komutun çıktısı BOŞ kalmalı (genel-internet'e paket yok).
```

## 5. Tek dürüst istisna — model indirme (veri DEĞİL)

Veri hiçbir zaman çıkmaz; ancak **ilk kurulumda** yerel çıkarım motoru, modeli (qwen3 *ağırlık
dosyaları*) genel bir model deposundan indirir. Bu:

- **Operatör/dağıtım verisi değildir** — yalnızca genel, açık-kaynak model ağırlıklarıdır (tek yön: indirme).
- **Tek seferliktir** — model diske indikten sonra bir daha gerekmez.
- **Air-gap dağıtımında hiç olmaz** — model, ürün imajına önceden gömülü gelir (`docker load`), sıfır
  kurulum-egress.

## 6. Özet

| Soru | Cevap |
|------|-------|
| Veri buluta gider mi? | **Hayır** — bulut API'si yok, anahtar yok (Kanıt A). |
| AI nereye bağlanır? | Yalnız iç-ağ `kangalis-ai:11434` (Kanıt B). |
| Çalışırken internete bağlanır mı? | **Hayır** — 0 genel-internet bağlantısı (Kanıt C). |
| İnternetsiz çalışır mı? | **Evet** — air-gap testi geçer (Bölüm 3). |
| Hiç dış trafik var mı? | Yalnız tek-seferlik model indirme; air-gap'te o da yok (Bölüm 5). |

**Sonuç:** Kangalis yerel AI, operatör verisini ağ dışına çıkarmaz; bu, kod denetimi, çalışma-anı
ağ analizi ve air-gap testiyle bağımsız olarak doğrulanabilir.
