# Katkı Rehberi

Kangalis'e katkıda bulunmak istediğiniz için teşekkürler. Bu belge, katkı sürecini
ve kalite beklentilerini özetler. Lütfen bir PR açmadan önce gözden geçirin.

> Tüm katkılarda [Davranış Kuralları](CODE_OF_CONDUCT.md) geçerlidir.

## Güvenlik açıkları

**Güvenlik açıklarını lütfen kamuya açık issue veya PR olarak bildirmeyin.** Bunun
yerine [SECURITY.md](SECURITY.md) belgesindeki sorumlu açıklama sürecini izleyin
(özel bildirim: `security@lineup-noah.com`). Detaylar düzeltilene kadar gizli tutulur.

## Katkı akışı

1. Depoyu **fork**'layın.
2. Fork'unuzda açıklayıcı bir dal oluşturun (ör. `feature/web-tls-denetimi`).
3. Değişikliğinizi yapın ve aşağıdaki **kalite kapısını** yerelde geçirin.
4. `Lineup-NOAH/kangalis` deposunun **`main`** dalına bir **Pull Request** açın.
5. PR'ınızda CI'nin **yeşil** olması gerekir; değilse birleştirilemez.

## Geliştirme kurulumu

Tek gereksinim [uv](https://docs.astral.sh/uv/)'dur (Python'ı uv kendisi indirir):

```bash
# Bağımlılıkları kur (Python 3.12 dahil)
uv sync

# (Opsiyonel) pre-commit kancalarını kur
uv run pre-commit install
```

> **Not:** Tarama motoru `nmap` ikilisini çağırır; sistemde kurulu olmalıdır
> (`apt install nmap` / `brew install nmap` / `choco install nmap`).

## Kalite kapısı

Bir PR açmadan önce aşağıdaki komutların tümünün **yerelde geçtiğinden** emin olun.
Bunlar CI'de de çalışır:

```bash
uv run ruff format        # kod biçimlendirme
uv run ruff check .       # lint
uv run mypy src           # tip kontrolü (strict)
uv run pytest             # testler
```

- Yeni davranış ekliyorsanız **test** ekleyin.
- Kullanıcıya görünen bir değişiklik yaptıysanız ilgili **dokümanı güncelleyin**.

## Commit mesajları

[Conventional Commits](https://www.conventionalcommits.org/) kullanın. Örnekler:

```
feat(scanners): TLS sürüm denetimi ekle
fix(api): boş scope'ta 500 hatasını düzelt
docs: katkı rehberini güncelle
```

Tipler: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, `perf`.

## Pull Request beklentileri

- PR şablonunu doldurun; ne, neden ve nasıl test edildiğini açıklayın.
- Tek bir PR mümkün olduğunca **odaklı** olsun.
- CI yeşil; `ruff` + `mypy` + `pytest` geçmiş olmalı.
- İnceleme geri bildirimlerine açık olun; tartışmayı yapıcı tutun.

Sorularınız için bir issue açabilir veya tartışma başlatabilirsiniz. Katkınız için
şimdiden teşekkürler.
