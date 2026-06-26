> **English** · [Türkçe](#turkce)

# Contributing Guide

Thanks for your interest in contributing to Kangalis. This document outlines the
contribution process and quality expectations. Please review it before opening a PR.

> The [Code of Conduct](CODE_OF_CONDUCT.md) applies to all contributions.

## Security vulnerabilities

**Please do not report security vulnerabilities as public issues or PRs.** Instead,
follow the responsible-disclosure process in [SECURITY.md](SECURITY.md) — report privately via
GitHub's [**Security** tab → **Report a vulnerability**](https://github.com/Lineup-NOAH/kangalis-core/security/advisories/new).
Details are kept confidential until fixed.

## Contribution workflow

1. **Fork** the repository.
2. Create a descriptive branch on your fork (e.g. `feature/web-tls-check`).
3. Make your change and pass the **quality gate** below locally.
4. Open a **Pull Request** against the **`main`** branch of `Lineup-NOAH/kangalis-core`.
5. CI must be **green** on your PR; otherwise it cannot be merged.

## Development setup

The only requirement is [uv](https://docs.astral.sh/uv/) (uv downloads Python itself):

```bash
# Install dependencies (including Python 3.12)
uv sync

# (Optional) install the pre-commit hooks
uv run pre-commit install
```

> **Note:** the scan engine invokes the `nmap` binary; it must be installed on the
> system (`apt install nmap` / `brew install nmap` / `choco install nmap`).

## Quality gate

Before opening a PR, make sure all of the following **pass locally**. They also run
in CI:

```bash
uv run ruff format        # code formatting
uv run ruff check .       # lint
uv run mypy src           # type checks (strict)
uv run pytest             # tests
```

- If you add new behavior, add **tests**.
- If you make a user-visible change, update the relevant **documentation**.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/). Examples:

```
feat(scanners): add TLS version check
fix(api): fix 500 error on empty scope
docs: update the contributing guide
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, `perf`.

## Pull Request expectations

- Fill in the PR template; explain what, why, and how it was tested.
- Keep a single PR as **focused** as possible.
- CI green; `ruff` + `mypy` + `pytest` must pass.
- Be open to review feedback; keep the discussion constructive.

For questions, open an issue or start a discussion. Thanks in advance for your
contribution.

---

<a id="turkce"></a>

> [English](#) · **Türkçe**

# Katkı Rehberi

Kangalis'e katkıda bulunmak istediğiniz için teşekkürler. Bu belge, katkı sürecini
ve kalite beklentilerini özetler. Lütfen bir PR açmadan önce gözden geçirin.

> Tüm katkılarda [Davranış Kuralları](CODE_OF_CONDUCT.md) geçerlidir.

## Güvenlik açıkları

**Güvenlik açıklarını lütfen kamuya açık issue veya PR olarak bildirmeyin.** Bunun
yerine [SECURITY.md](SECURITY.md) belgesindeki sorumlu açıklama sürecini izleyin — GitHub'ın
[**Security** sekmesi → **Report a vulnerability**](https://github.com/Lineup-NOAH/kangalis-core/security/advisories/new)
ile özel olarak bildirin. Detaylar düzeltilene kadar gizli tutulur.

## Katkı akışı

1. Depoyu **fork**'layın.
2. Fork'unuzda açıklayıcı bir dal oluşturun (ör. `feature/web-tls-denetimi`).
3. Değişikliğinizi yapın ve aşağıdaki **kalite kapısını** yerelde geçirin.
4. `Lineup-NOAH/kangalis-core` deposunun **`main`** dalına bir **Pull Request** açın.
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
