#!/usr/bin/env bash
# Kangalis — tek-komut ilk kurulum (Linux / macOS).
# Önkoşul: Docker + Docker Compose. Çalıştır:  bash setup.sh
set -euo pipefail
cd "$(dirname "$0")"

ENV_FILE=".env"

# --- Yardımcılar ---------------------------------------------------------------
# read_default ETIKET VARSAYILAN -> stdout=değer (boş Enter = varsayılan; read zaten trim'ler)
read_default() {
  local label="$1" def="$2" shown v
  shown="${def:-yok}"
  read -rp "  ${label} [${shown}]: " v
  printf '%s' "${v:-$def}"
}

# read_safe ETIKET VARSAYILAN REGEX IPUCU -> stdout=değer (regex'e uyana kadar tekrar sorar)
read_safe() {
  local label="$1" def="$2" re="$3" hint="$4" v
  while true; do
    v="$(read_default "$label" "$def")"
    if [[ "$v" =~ $re ]]; then printf '%s' "$v"; return; fi
    echo "    ! $hint" >&2
  done
}

# rand_key BAYT -> url-safe base64 (kriptografik /dev/urandom; .env/URL'de güvenli)
rand_key() {
  head -c "$1" /dev/urandom | base64 | tr '+/' '-_' | tr -d '\n'
}

# --- 1/5 Kimlik bilgileri & güvenlik anahtarları -------------------------------
if [ -f "$ENV_FILE" ] && grep -qE '^[[:space:]]*POSTGRES_PASSWORD[[:space:]]*=' "$ENV_FILE"; then
  echo "==> 1/5 Kimlik bilgileri .env'de zaten var - atlanıyor."
  echo "    (Değiştirmek için .env'i düzenleyin; Postgres parolası için ayrıca 'docker compose down -v' ile pgdata'yı sıfırlayın.)"
else
  echo "==> 1/5 Kimlik bilgileri & güvenlik anahtarları"
  echo "    Boş Enter = köşeli parantezdeki varsayılan. Kullanıcı/parola: yalnız harf, rakam, . _ -"
  # pgdata zaten varsa: kullanıcı/parola/db DEĞİŞTİRMEK bağlantıyı kırar (parola ilk açılışta gömülür).
  if docker volume ls --format '{{.Name}}' 2>/dev/null | grep -q 'pgdata'; then
    echo "    UYARI: Veritabanı (pgdata) zaten mevcut. Postgres kullanıcı/parola/db'yi DEĞİŞTİRİRSENİZ" >&2
    echo "           bağlantı kırılır -> ya Enter'la varsayılanları koruyun ya da önce 'docker compose down -v' yapın." >&2
  fi
  echo ""
  echo "  [PostgreSQL]"
  PG_USER="$(read_safe 'Kullanıcı adı' 'cyber' '^[A-Za-z0-9._-]+$' 'Yalnız harf/rakam/. _ - kullanın.')"
  PG_PASS="$(read_safe 'Parola' 'cyber' '^[A-Za-z0-9._-]+$' 'Yalnız harf/rakam/. _ - kullanın.')"
  PG_DB="$(read_safe 'Veritabanı adı' 'cybersectool' '^[A-Za-z0-9._-]+$' 'Yalnız harf/rakam/. _ - kullanın.')"
  echo ""
  echo "  [Redis]  (Redis'te kullanıcı adı yoktur; yalnız parola. Boş = auth kapalı)"
  RD_PASS="$(read_safe 'Parola' '' '^[A-Za-z0-9._-]*$' 'Yalnız harf/rakam/. _ - kullanın (ya da boş).')"
  echo ""
  echo "  [Opsiyonel]  (Enter ile geçebilirsiniz)"
  NVD_KEY="$(read_safe 'NVD API anahtarı' '' '^[A-Za-z0-9-]*$' 'NVD anahtarı yalnız harf/rakam/- içerir.')"
  WEBHOOK="$(read_safe 'Bildirim webhook URL' '' '^(https?://[^[:space:]]+)?$' 'http(s):// ile başlamalı; boşluk içermemeli.')"

  # Güçlü anahtarlar OTO-üretilir (varsayılan dev anahtarları zayıf; _WEAK_SECRETS'e takılır).
  SECRET_KEY="$(rand_key 48)"   # oturum imzalama
  FERNET_KEY="$(rand_key 32)"   # kimlik kasası (Fernet, 32 bayt)
  echo ""
  echo "  [Oto-üretildi]  SECRET_KEY + kimlik kasası (Fernet) anahtarı (güçlü, rastgele)."

  # REDIS_URL'i doğru biçimde kur: parola varsa göm, yoksa auth'suz (iki farklı URL şekli).
  if [ -z "$RD_PASS" ]; then REDIS_URL="redis://redis:6379/0"; else REDIS_URL="redis://:${RD_PASS}@redis:6379/0"; fi

  cat >> "$ENV_FILE" <<EOF

# Kurulum sihirbazi tarafindan yazildi (duzenlenebilir)
POSTGRES_USER=$PG_USER
POSTGRES_PASSWORD=$PG_PASS
POSTGRES_DB=$PG_DB
REDIS_PASSWORD=$RD_PASS
REDIS_URL=$REDIS_URL
SECRET_KEY=$SECRET_KEY
CREDENTIAL_ENCRYPTION_KEY=$FERNET_KEY
NVD_API_KEY=$NVD_KEY
NOTIFY_WEBHOOK_URL=$WEBHOOK
EOF
  chmod 600 "$ENV_FILE" 2>/dev/null || true   # secret'ler (Fernet/SECRET_KEY/parolalar) yalnız sahibe okunur/yazılır
  echo "    [OK] .env güncellendi (chmod 600)."
fi

# --- 2/5 Derle + başlat --------------------------------------------------------
echo ""
echo "==> 2/5 Kangalis derleniyor + başlatılıyor (nmap dahil; ilk derleme birkaç dk sürebilir)..."
docker compose up -d --build

# --- 3/5 Migrasyon + sağlık ----------------------------------------------------
echo ""
echo "==> 3/5 Şema migrasyonu (otomatik) + uygulama sağlığı bekleniyor..."
ok=0
for _ in $(seq 1 80); do
  if docker compose exec -T app python -c \
      "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" >/dev/null 2>&1; then
    ok=1; break
  fi
  sleep 3
done
if [ "$ok" -ne 1 ]; then
  echo "!! Uygulama sağlıklı yanıt vermedi. 'docker compose logs app migrate' ile kontrol edin." >&2
  exit 1
fi

# --- 4/5 Admin -----------------------------------------------------------------
echo ""
echo "==> 4/5 İlk YÖNETİCİ (admin) kullanıcısı"
read -rp "  Kullanıcı adı: " KUSER
read -rsp "  Parola (güçlü bir parola seçin): " KPASS; echo
docker compose exec -T app python -m cybersectool.scripts.create_user \
  --username "$KUSER" --password "$KPASS" --role admin

# --- 5/5 Kapsam ----------------------------------------------------------------
echo ""
echo "==> 5/5 YETKİLİ TARAMA KAPSAMI (ZORUNLU — yoksa hiçbir tarama çalışmaz)"
echo "    Yalnızca taramaya YETKİLİ olduğunuz ağları girin. Örn: 192.168.1.0/24,10.0.0.0/8"
read -rp "  İzinli CIDR (virgülle birden çok): " KCIDR
SCOPE_ARGS=()
IFS=',' read -ra CIDRS <<< "$KCIDR"
# Boş-dizi açılımı bash 3.2'de (macOS stok) set -u altında "unbound variable" verir -> "${arr[@]+...}" idiomu.
for c in "${CIDRS[@]+"${CIDRS[@]}"}"; do
  c="${c#"${c%%[![:space:]]*}"}"   # baştaki boşlukları kırp (saf bash; xargs tırnak/backslash bozar)
  c="${c%"${c##*[![:space:]]}"}"   # sondaki boşlukları kırp
  [ -n "$c" ] && SCOPE_ARGS+=(--allow "$c")
done
docker compose exec -T app python -m cybersectool.scripts.set_scope --name ic-ag "${SCOPE_ARGS[@]+"${SCOPE_ARGS[@]}"}"

echo ""
echo "✅ Kurulum tamam!"
echo "   Web paneli : http://localhost:8000/login   (kullanıcı: $KUSER)"
echo "   API/Swagger: http://localhost:8000/docs"
echo "   Yerel AI'yı açmak (opsiyonel): docker compose --profile ai up -d ollama"
echo "   Ayrıntı: docs/KURULUM.md + docs/EKLENTILER.md"
