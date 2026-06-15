# Güvenlik Politikası

CyberSecTool, Lineup-NOAH tarafından geliştirilen bir iç-ağ zafiyet tarama
platformudur. Aktif tarama, kimlik-doğrulama denetimi ve ağ keşfi gerçekleştirir;
bu nedenle hem **sorumlu açıklama** hem de **yetkili kullanım** kurallarına tabidir.

## Kabul Edilebilir Kullanım

Bu araç YALNIZCA, üzerinde tarama yapma yetkisine açıkça sahip olduğunuz sistemlerde
kullanılmalıdır:

- Tarama yalnızca **sahibi olduğunuz** veya **yazılı izin** aldığınız varlıklara (IP,
  ağ blokları, alan adları, servisler) yöneltilmelidir.
- Üçüncü taraflara ait sistemlere izinsiz tarama, kimlik denemesi veya zafiyet
  doğrulaması birçok ülkede **yasa dışıdır**; sorumluluk tümüyle operatöre aittir.
- Agresif modlar (kimlik deneme/brute-force ve benzeri yüksek-etkili işlemler)
  varsayılan olarak **kapalıdır** ve yalnızca açık operatör onayı + yetki kapsamı
  (scope) doğrulaması ile çalışır.
- Bulgular gizli bilgi içerebilir; raporları yalnızca yetkili paydaşlarla paylaşın.

Bu kuralların ihlalinden kaynaklanan hiçbir zarardan Lineup-NOAH ve katkıda
bulunanlar sorumlu tutulamaz.

## Zafiyet Bildirimi (Sorumlu Açıklama)

CyberSecTool'un **kendisinde** bir güvenlik açığı bulursanız, lütfen sorumlu açıklama
ilkesine uyun:

- Açığı **kamuya açık** GitHub issue/PR olarak **yayınlamayın**.
- Bulguyu özel olarak Lineup-NOAH güvenlik ekibine bildirin:
  **security@lineup-noah.com** (PGP talep edebilirsiniz).
- Bildiriminize şunları ekleyin: etkilenen sürüm/commit, yeniden üretim adımları,
  etki değerlendirmesi ve varsa kavram-kanıtı (PoC).
- Sorununuzu doğrulayıp düzeltene kadar ayrıntıları gizli tutmanızı rica ederiz.

### Yanıt Süreci

- **3 iş günü** içinde alındı teyidi.
- **10 iş günü** içinde ilk değerlendirme ve önem derecesi.
- Düzeltme yayımlandıktan sonra, izniniz dahilinde katkınız sürüm notlarında
  anılır.

## Desteklenen Sürümler

Güvenlik düzeltmeleri `main` dalına ve en son yayımlanan sürüme uygulanır. Eski
sürümler için lütfen güncel sürüme yükseltin.
