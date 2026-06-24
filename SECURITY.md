# Güvenlik Politikası

Kangalis, Lineup-NOAH tarafından geliştirilen bir iç-ağ zafiyet tarama
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

Uygulama bunu **teknik olarak da zorlar**: her operatör ilk girişte uygulama-içi bir onay
ekranında (yalnız yetkili sistemleri taradığını + Sorumluluk Reddi'ni) **kabul etmeden tarama
başlatamaz**; kabul, kullanıcı-bazlı ve **zaman-damgalı denetim kaydı** olarak saklanır
(`disclaimer_accepted`). Bu yalnızca tarayıcı oturumu içindir; API token (Bearer) istemcileri
ayrı yetkilendirilir.

Bu kuralların ihlalinden kaynaklanan hiçbir zarardan Lineup-NOAH ve katkıda
bulunanlar sorumlu tutulamaz. Tam **sorumluluk reddi ve kullanım koşulları**:
[DISCLAIMER.md](DISCLAIMER.md).

## Zafiyet Bildirimi (Sorumlu Açıklama)

Kangalis'in **kendisinde** bir güvenlik açığı bulursanız, lütfen sorumlu açıklama
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

## Uygulama Güvenliği / Sertleştirme

Panelin kendi güvenliği için uygulanan başlıca önlemler (operatörlerin bilmesi gereken
davranışlar dahil):

- **Kimlik & oturum:** parolalar argon2 ile saklanır; oturum çerezi `HttpOnly` +
  `SameSite=lax` (+ üretimde `Secure`); isteğe bağlı MFA (TOTP/e-posta) ve giriş
  kilitleme.
- **CSRF:** durum-değiştiren istekler (`POST/PUT/PATCH/DELETE`) için `Origin`/`Referer`
  **aynı-köken** kontrolü yapılır; uyuşmazlık `403` döner. `Bearer` API-token istekleri
  muaftır (çerez yok = CSRF yok). Asıl katman `SameSite=lax` çerezdir; bu kontrol
  derinlemesine-savunmadır. **Not:** Paneli, `Host`/`Origin` başlığını değiştiren bir ters
  vekil (reverse proxy) arkasına alırsanız beklenmedik `403`'ler görebilirsiniz — vekili
  gerçek `Host`'u koruyacak şekilde yapılandırın.
- **Güvenlik başlıkları:** `Content-Security-Policy` (çerçeveleme/enjeksiyon daraltma),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy` ve üretimde
  HSTS.
- **SSRF/kapsam:** web taraması doğrulanan IP'ye pinlenir ve **yönlendirme takip etmez**;
  nmap XML'i `defusedxml` ile (XXE-güvenli) ayrıştırılır.
- **Dış erişim (egress):** Panel tamamen yereldir. İnternete çıkan tek admin-ayarlı uç,
  **sürüm denetimi** (`update_check_url`, varsayılan GitHub Releases) ve **yerel AI motoru**
  (`ai_endpoint_url`, ör. `http://ollama:11434/v1`) adresleridir. Diğer veri kaynakları
  (NVD/OSV/CISA KEV/EPSS/Exploit-DB) sabit, bilinen genel adreslerdir. Bu iki admin-ayarlı uç,
  link-local/bulut-metadata (ör. `169.254.169.254`) adreslerine — her sayısal kodlamada —
  gitmeye karşı süzülür; şirket-içi ayna/motor (özel-ağ/hostname) çalışmaya devam eder.
  Hava-boşluklu (air-gap) kurulumda sürüm denetimi `update_check_enabled` ile kapatılabilir.

## Desteklenen Sürümler

Güvenlik düzeltmeleri `main` dalına ve en son yayımlanan sürüme uygulanır. Eski
sürümler için lütfen güncel sürüme yükseltin.
