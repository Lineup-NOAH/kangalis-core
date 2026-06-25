# CVE seed (önceden indirilmiş zafiyet veritabanı)

Bu dizin, **önceden indirilmiş NVD CVE/CPE veritabanını** taşır; müşteri kurarken NVD'den
indirme beklemesin diye uygulama imajına gömülür ve ilk açılışta otomatik yüklenir.

## Dosyalar (git'e konmaz — büyük; `.gitignore`'da)
- `cves.csv.gz` — `cves` tablosu (asyncpg COPY, CSV, gzip)
- `cpe_matches.csv.gz` — `cpe_matches` tablosu (sürüm-eşleşme ölçütleri)

## Nasıl çalışır
1. **Üretim (maintainer, tek sefer):**
   ```
   python -m cybersectool.scripts.build_cve_seed 2000     # NVD'den tüm geçmişi çek (API anahtarı önerilir)
   python -m cybersectool.scripts.export_cve_seed seed/   # bu dizine .csv.gz olarak aktar
   ```
2. **Gömme:** `Dockerfile`'daki `COPY . .` `seed/`'i imaja `/app/seed` olarak basar.
3. **Kurulum (otomatik):** `migrate` servisi `alembic upgrade head` sonrası
   `import_cve_seed` çalıştırır → `cves` tablosu BOŞSA tohumu toplu yükler (saniyeler).
   Dolu DB'de ya da tohum yoksa atlar (idempotent). Sonra günlük senkron tazeler.

## Elle yükleme / yeniden yükleme
```
python -m cybersectool.scripts.import_cve_seed seed/            # boşsa yükle
python -m cybersectool.scripts.import_cve_seed seed/ --force    # mevcudu boşaltıp yeniden yükle (uygulama DURMUŞKEN; TRUNCATE eder)
```
