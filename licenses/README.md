# Üçüncü taraf lisans metinleri (ön-paketli AI imajı için)

Bu klasör, **ön-paketli AI imajına** (`Dockerfile.ai` → `ghcr.io/lineup-noah/kangalis-ai`)
**gömülen** üçüncü taraf bileşenlerin **lisans metinlerini** barındırır. İmaj bu bileşenleri
**yeniden dağıttığı** için lisansları korumak zorunludur; metinler imaja `/licenses/` altına
kopyalanır (`COPY licenses/ /licenses/`). Air-gap/yeniden-üretilebilir derleme için bu metinler
build sırasında ağdan çekilmek yerine depoda **vendor** edilmiştir.

| Dosya | Bileşen | Lisans | Telif |
|---|---|---|---|
| `ollama-LICENSE.txt` | Ollama (çıkarım sunucusu) | MIT | Copyright (c) Ollama |
| `Qwen3-8B-LICENSE.txt` | Qwen3-8B model ağırlıkları | Apache-2.0 | Copyright 2024 Alibaba Cloud |

Notlar:
- **Ollama**: Resmi `ollama/ollama` imajı MIT lisanslıdır; metni uyum/atıf için buraya da gömülür.
- **Qwen3**: Model `ollama pull qwen3:8b` ile Ollama kütüphanesinden gelir; ağırlıklar **Qwen3-8B**
  (Apache-2.0). Lisans metni üst (base) model deposu `Qwen/Qwen3-8B`'den alınmıştır. Upstream'de bir
  **NOTICE** dosyası bulunmadığından Apache-2.0 §4(d) tetiklenmez.
- **Taban katmanlar**: İmaj `ollama/ollama` tabanından gelen Ubuntu 24.04 + sistem paketlerini (ve
  GPU değişkeninde NVIDIA CUDA kütüphanelerini) miras alır; bunlar burada vendor **edilmez**, kendi
  upstream lisansları altında imaj katmanlarında taşınır. Bu klasör yalnızca Kangalis'in pinlediği
  iki bileşeni kapsar.
- Bu metinler yalnızca **bilgilendirme/uyum** amaçlıdır; her bileşen kendi lisansı altında dağıtılır
  ve MIT-lisanslı Kangalis çekirdeğinin lisansını değiştirmez. (Hukuki tavsiye değildir.)

Genel üçüncü taraf bildirimi: [`../THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md).
