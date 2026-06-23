"""Uygulama yapilandirmasi: ortam degiskenlerinden ayarlar (pydantic-settings)."""

from __future__ import annotations

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from cybersectool import __version__

APP_NAME: str = "Kangalis"
VERSION: str = __version__

# Üretimde kullanılması yasak zayıf/varsayılan SECRET_KEY değerleri.
# (SECRET_KEY hem oturum imzalama hem kimlik kasası Fernet anahtarı türetimi için kullanılır;
#  zayıfsa oturum sahteciliği + kasadaki tüm parolaların çözülmesi mümkün olur.)
_WEAK_SECRETS: frozenset[str] = frozenset(
    {"", "change-me", "changeme", "dev-secret", "secret", "test", "password"}
)


class Settings(BaseSettings):
    """Ortam degiskenlerinden (ya da .env) okunan uygulama ayarlari."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: str = "development"
    secret_key: str = "change-me"
    database_url: str = "postgresql+asyncpg://cyber:cyber@localhost:5432/cybersectool"
    redis_url: str = "redis://localhost:6379/0"
    notify_webhook_url: str = ""  # kritik bulgu bildirimi (Slack/webhook); boşsa kapalı
    # GÜVENLİK KİLİDİ: agresif (müdahaleci) tarama yalnızca bu açıkken yapılabilir.
    # Varsayılan KAPALI — açmadan hiçbir agresif/exploit taraması çalışmaz.
    allow_aggressive_scans: bool = False
    # Tarama fan-out (SCAN-NET Faz 2b): büyük CIDR taramalarının bloklarını Celery chord ile
    # worker'lara DAĞIT (map-reduce) → tek tarama worker sayısıyla ~doğrusal hızlanır. Kapalıyken
    # büyük taramalar tek worker'da blok-blok (Faz 1) koşar — kill-switch/fallback.
    scan_fanout: bool = True
    # Kimlik kasası şifreleme anahtarı (Fernet, url-safe base64 32 bayt). Boşsa
    # SECRET_KEY'den türetilir (dev). ÜRETİMDE mutlaka kendi anahtarını ver.
    credential_encryption_key: str = ""
    # NVD API anahtarı (opsiyonel) — rate-limit'i ciddi yükseltir (toplu CVE çekme için).
    nvd_api_key: str = ""
    # NVD senkron penceresi (gün). Günlük oto-senkron bu kadar GÜN geriye gidip yeni/değişen
    # CVE'leri tazeler — küçük tutuldu (varsayılan 1 hafta) ki her gün koşması ucuz olsun
    # (120 gün ≈ 16.000 CVE'yi her gün baştan çekmek worker/DB'yi gereksiz yorardı). Geçmiş
    # CVE'leri TEK SEFER yüklemek için Ayarlar'daki "geçmiş yükleme" (nvd_backfill) kullanılır.
    # NVD API tek istekte en çok 120 gün kabul eder; daha büyük değer ardışık pencerelere bölünür.
    nvd_sync_days: int = 7
    # LDAP / Active Directory ile giriş (opsiyonel). Kapalıyken yalnızca yerel giriş.
    ldap_enabled: bool = False
    ldap_server_uri: str = ""  # örn. ldap://dc.corp.local:389 ya da ldaps://...:636
    ldap_use_ssl: bool = False
    # Bind DN şablonu; {username} yerine kullanıcı adı konur. Örnekler:
    #   AD UPN: "{username}@corp.local"   ·   AD: "CORP\\{username}"
    #   OpenLDAP: "uid={username},ou=people,dc=corp,dc=local"
    ldap_bind_dn_template: str = "{username}"
    # LDAP ile ilk girişte otomatik oluşturulan kullanıcının rolü.
    ldap_default_role: str = "viewer"
    # YEREL AI (OpenAI-uyumlu motor, on-prem) — ürünün diferansiyatörü: müşteri ağından
    # ÇIKMAYAN, CPU'da koşan zafiyet-açıklama + rapor-özeti asistanı. Bulut API YOK
    # (gizlilik/egress). İstemci OpenAI ``/v1/chat/completions`` konuşur → Ollama / LM
    # Studio / LocalAI gibi YEREL motorlarla çalışır (tek runtime'a bağlı değil). Bu env
    # değerleri yalnız VARSAYILANDIR; çalışma anı Ayarlar > AI kartından (AppSettings) override
    # edilir. ai_enabled DB'de (admin UI); endpoint boşsa AI devre dışı (graceful: butonlar
    # gizli, statik Remediation sürer). Compose 'ai' profili Ollama servisini açar; host'taki
    # native motor için endpoint host.docker.internal olur.
    ai_endpoint: str = "http://ollama:11434/v1"  # OpenAI taban URL; internal ağ; sıfır egress
    ai_model: str = "qwen3:8b"  # Haziran-2026 sub-8B lider (çok-dilli+akıl+kod); Q4 ~6GB CPU
    # CPU çıkarımı yavaş: grounded RAPOR üretimi (özet/script/asset-story) qwen3:8b'de sıcak
    # modelle bile ~3-5 dk sürebilir (#273 ölçümü). Soğuk yükleme +~70sn. Bu yüzden cömert
    # varsayılan; ayrıca Ollama motorunu OLLAMA_KEEP_ALIVE=-1 ile sıcak tut (soğuk yüklemeyi siler).
    ai_timeout: int = 300
    # YEREL AI hız sınırı (DoS koruması): /ai/* üretim uçları login'li HER kullanıcıya açıktır ve
    # CPU-pahalı yerel LLM üretimini tetikler. Düşük-yetkili biri parametreyi değiştirip önbelleği
    # atlayarak üretimi sınırsız tetikleyip AI'yı tüm kullanıcılara kapatabilir. Üretim kullanıcı
    # başına sabit pencerede sınırlanır (önbellek isabetleri SAYILMAZ). Varsayılan AÇIK + cömert
    # (60/dk) → tek-kullanıcılı kullanım etkilenmez; betikli kötüye-kullanım ucuz reddedilir.
    # Çok-kullanıcılı sertleştirmede düşür; AI_RATELIMIT_ENABLED=false ile kapat (Redis kesintisinde
    # zaten fail-open → AI açık kalır).
    ai_ratelimit_enabled: bool = True
    ai_ratelimit_max: int = 60  # pencere başına kullanıcı başına en çok üretim
    ai_ratelimit_window_sec: int = 60  # sayaç penceresi (saniye)

    @model_validator(mode="after")
    def _enforce_production_secrets(self) -> Settings:
        """Üretimde (APP_ENV=production) zayıf/varsayılan SECRET_KEY ile başlamayı engeller.

        Geliştirmede (varsayılan) serbesttir; üretimde güçlü bir anahtar zorunludur —
        aksi halde oturum çerezleri taklit edilebilir ve kimlik kasası açılabilir.
        """
        if self.app_env.strip().lower() != "production":
            return self
        if self.secret_key.strip().lower() in _WEAK_SECRETS:
            raise ValueError(
                "Üretimde zayıf/varsayılan SECRET_KEY kullanılamaz. Güçlü, rastgele bir "
                "SECRET_KEY ayarlayın (ve kimlik kasası için ayrı bir CREDENTIAL_ENCRYPTION_KEY). "
                'Üret: python -c "import secrets; print(secrets.token_urlsafe(48))"'
            )
        # Kimlik kasası anahtarı SECRET_KEY'den TÜRETİLMEMELİ (#141): aksi halde SECRET_KEY
        # sızarsa müşterinin tüm SSH/DB/AD parolaları açılır. Üretimde ayrı bir anahtar ZORUNLU.
        if not self.credential_encryption_key.strip():
            raise ValueError(
                "Üretimde CREDENTIAL_ENCRYPTION_KEY zorunludur (kimlik kasası anahtarı "
                "SECRET_KEY'den türetilmemeli — sızıntıda tüm kasayı açar). "
                'Üret: python -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"'
            )
        return self


settings = Settings()
