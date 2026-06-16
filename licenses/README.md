# Üçüncü taraf lisans metinleri (ön-paketli AI imajı için)

Bu klasör, **ön-paketli AI imajına** (`Dockerfile.ai` → `ghcr.io/lineup-noah/kangalis-ai`)
**gömülen** üçüncü taraf bileşenlerin **lisans metinlerini** barındırır. İmaj bu bileşenleri
**yeniden dağıttığı** için lisansları korumak zorunludur; metinler imaja `/licenses/` altına
kopyalanır (`COPY licenses/ /licenses/`). Air-gap/yeniden-üretilebilir derleme için bu metinler
build sırasında ağdan çekilmek yerine depoda **vendor** edilmiştir.

| Dosya | Bileşen | Lisans | Telif |
|---|---|---|---|
| `llama.cpp-LICENSE.txt` | llama.cpp (çıkarım motoru ikilisi) | MIT | Copyright (c) 2023-2026 The ggml authors |
| `Qwen3-8B-LICENSE.txt` | Qwen3-8B model ağırlıkları (GGUF) | Apache-2.0 | Copyright 2024 Alibaba Cloud |

Notlar:
- **llama.cpp**: Resmi taban imaj (`ghcr.io/ggml-org/llama.cpp:server`) MIT lisans metnini
  **içermez** (yalnızca Python'ın lisansı bulunur); bu yüzden MIT metni buradan gömülür.
- **Qwen3**: Modelin dağıtıldığı `unsloth/Qwen3-8B-GGUF` deposunda LICENSE dosyası **yoktur**;
  Apache-2.0 metni, üst (base) model deposu `Qwen/Qwen3-8B`'den alınmıştır. Her iki upstream'de de
  bir **NOTICE** dosyası bulunmadığından Apache-2.0 §4(d) tetiklenmez.
- Bu metinler yalnızca **bilgilendirme/uyum** amaçlıdır; her bileşen kendi lisansı altında dağıtılır
  ve MIT-lisanslı Kangalis çekirdeğinin lisansını değiştirmez. (Hukuki tavsiye değildir.)

Genel üçüncü taraf bildirimi: [`../THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md).
