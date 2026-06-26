> **English** · [Türkçe](#turkce)

# Security Policy

Kangalis is an internal-network vulnerability scanning platform developed by
Lineup-NOAH. It performs active scanning, authentication auditing, and network
discovery; it is therefore subject to both **responsible disclosure** and
**authorized use** rules.

## Acceptable Use

This tool must be used ONLY on systems you are explicitly authorized to scan:

- Scanning must be directed only at assets (IPs, network blocks, domain names,
  services) you **own** or have **written permission** for.
- Unauthorized scanning, credential testing, or vulnerability verification of
  third-party systems is **illegal** in many countries; responsibility lies
  entirely with the operator.
- Aggressive modes (credential testing/brute-force and similar high-impact
  operations) are **disabled by default** and run only with explicit operator
  confirmation + authorized-scope verification.
- Findings may contain confidential information; share reports only with
  authorized stakeholders.

The application also **enforces this technically**: on first login, every operator
must **accept** — in an in-app screen — that they only scan authorized systems and
that they accept the Disclaimer, before any scan can start; acceptance is stored
per-user as a **time-stamped audit record** (`disclaimer_accepted`). This applies to
the browser session; API token (Bearer) clients are authorized separately.

Lineup-NOAH and contributors cannot be held liable for any damage resulting from a
violation of these rules. Full **disclaimer and terms of use**:
[DISCLAIMER.md](DISCLAIMER.md).

## Reporting a Vulnerability (Responsible Disclosure)

If you find a security vulnerability **in Kangalis itself**, please follow
responsible disclosure:

- **Do not publish** the issue as a **public** GitHub issue/PR.
- Report it privately via **GitHub Private Vulnerability Reporting** — open the repo's
  [**Security** tab → **Report a vulnerability**](https://github.com/Lineup-NOAH/kangalis-core/security/advisories/new).
- Include in your report: affected version/commit, reproduction steps, impact
  assessment, and a proof-of-concept (PoC) if available.
- We ask that you keep the details confidential until we have verified and fixed
  the issue.

### Response Process

- Acknowledgement of receipt within **3 business days**.
- Initial assessment and severity within **10 business days**.
- After a fix is released, your contribution is credited in the release notes,
  with your permission.

## Application Security / Hardening

The main measures applied for the panel's own security (including behaviors
operators should be aware of):

- **Identity & session:** passwords are stored with argon2; the session cookie is
  `HttpOnly` + `SameSite=lax` (+ `Secure` in production); optional MFA (TOTP/email)
  and login lockout.
- **CSRF:** state-changing requests (`POST/PUT/PATCH/DELETE`) are checked for
  **same-origin** `Origin`/`Referer`; a mismatch returns `403`. `Bearer` API-token
  requests are exempt (no cookie = no CSRF). The primary layer is the `SameSite=lax`
  cookie; this check is defense-in-depth. **Note:** if you place the panel behind a
  reverse proxy that rewrites the `Host`/`Origin` header, you may see unexpected
  `403`s — configure the proxy to preserve the real `Host`.
- **Security headers:** `Content-Security-Policy` (framing/injection hardening),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, and
  HSTS in production.
- **SSRF/scope:** web scanning is pinned to the validated IP and **does not follow
  redirects**; nmap XML is parsed with `defusedxml` (XXE-safe).
- **Egress:** the panel is fully local. The only admin-configurable endpoints that
  reach the internet are the **update check** (`update_check_url`, default GitHub
  Releases) and the **local AI engine** (`ai_endpoint_url`, e.g.
  `http://ollama:11434/v1`). Other data sources (NVD/OSV/CISA KEV/EPSS/Exploit-DB)
  are fixed, well-known public addresses. These two admin-configurable endpoints are
  filtered against reaching link-local/cloud-metadata (e.g. `169.254.169.254`)
  addresses — in any numeric encoding; an in-house mirror/engine (private
  network/hostname) keeps working. In an air-gapped install, the update check can be
  disabled with `update_check_enabled`.

## Supported Versions

Security fixes are applied to the `main` branch and the latest released version. For
older versions, please upgrade to the current release.

---

<a id="turkce"></a>

> [English](#) · **Türkçe**

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
- Bulguyu **GitHub Private Vulnerability Reporting** ile özel olarak bildirin — deponun
  [**Security** sekmesi → **Report a vulnerability**](https://github.com/Lineup-NOAH/kangalis-core/security/advisories/new).
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
