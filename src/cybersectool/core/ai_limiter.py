"""Yerel AI üretim rotaları için kullanıcı-bazlı hız sınırı (rate-limit) — Redis sayaçlı.

``/ai/*`` üretim uçları (açıkla/sor/özet/öncelik/sömürü-zinciri/trend/uyum/script/hikâye)
login'li HER kullanıcıya açıktır ve CPU-pahalı yerel LLM üretimini tetikler. Giriş yapmış
düşük-yetkili biri, soruyu/parametreyi her seferinde değiştirip önbelleği atlayarak üretimi
sınırsız tetikleyip AI worker'ı + host CPU'sunu doyurabilir → tüm kullanıcılar için AI DoS
(#B AI Q&A incelemesinde MEDIUM/yüksek-güven bulgu). Bu modül üretimi kullanıcı başına sabit
pencerede sınırlar.

Tasarım (``login_guard`` ile aynı desen: Redis sayaç + fail-open):
- **Kullanıcı bazlı sayaç**: anahtar ``kg:ai:req:<user_id>``; pencere ilk istekte
  ``AI_RATELIMIT_WINDOW_SEC`` ile TTL'lenir, dolunca sayaç kendiliğinden sıfırlanır.
- **Self-heal**: login_guard ayrı bir ``lock_key``'i hep açık TTL ile kurar; burada tek anahtar
  hem sayar hem TTL taşır. ``incr`` başarılı olup ardından ``expire`` patlarsa (bölük Redis hatası)
  anahtar TTL'siz kalabilir → sayaç kalıcı büyür. Bunu önlemek için sınır aşıldığında TTL eksikse
  pencere yeniden kurulur (kullanıcı kalıcı kilitlenmez; Redis düzelince bir pencerede iyileşir).
- **Fail-open**: Redis erişilemezse sınır UYGULANMAZ (üretime izin) — bir Redis kesintisi AI'yı
  tüm kullanıcılara kapatmamalı (kullanılabilirlik > katılık), login_guard ile aynı ilke.
- **Yalnız gerçek üretim sayılır**: çağıran rota bu kontrolü önbellek-ıskası doğrulandıktan VE
  diğer erken-dönüşler (veri yok vb.) geçildikten SONRA, ``generate()`` çağrısından hemen önce
  yapar → önbellek isabetleri ve boş-veri istekleri kotaya SAYILMAZ.
"""

from __future__ import annotations

import contextlib

import redis.asyncio as aioredis

from cybersectool.config import settings as app_config

_REQ_PREFIX = "kg:ai:req:"

_client: aioredis.Redis | None = None


def _redis() -> aioredis.Redis:
    """Süreç-ömrü boyunca tek async Redis istemcisi (lazy)."""
    global _client
    if _client is None:
        # redis.asyncio.from_url tip-işaretsiz (no-untyped-call); dönüş yine de Redis tipli.
        _client = aioredis.from_url(  # type: ignore[no-untyped-call]
            app_config.redis_url, decode_responses=True
        )
    return _client


async def ai_rate_limited(user_id: int) -> int:
    """Kullanıcının AI üretim kotası dolduysa kalan pencere saniyesini, değilse 0 döner.

    ``AI_RATELIMIT_ENABLED`` kapalıysa ya da Redis erişilemezse 0 (fail-open: üretime izin).
    Çağıran rota, 0 olmayan dönüşte ``generate()``'i atlayıp kullanıcıya 'biraz sonra dene'
    parçası döndürmelidir.
    """
    if not app_config.ai_ratelimit_enabled:
        return 0
    window = app_config.ai_ratelimit_window_sec
    key = f"{_REQ_PREFIX}{user_id}"
    with contextlib.suppress(Exception):
        client = _redis()
        count = await client.incr(key)
        if count == 1:
            await client.expire(key, window)
        if count > app_config.ai_ratelimit_max:
            ttl = await client.ttl(key)
            if ttl is None or ttl < 0:
                # TTL eksik (incr başarılı ama expire patlamış olabilir) → pencereyi yeniden kur
                # ki anahtar kalıcı kalmasın ve kullanıcı sonsuza dek kilitlenmesin (self-heal).
                await client.expire(key, window)
                ttl = window
            return int(ttl) if ttl > 0 else window
    return 0
