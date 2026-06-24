#!/usr/bin/env bash
# Kangalis - Temiz sifirlama (reset).
#
# Konteynerleri durdurup siler + veritabani (pgdata) ile diger 'kangalis' Docker
# volume'lerini kaldirir. Bozuk kurulum, "password authentication failed for user ..."
# (eski pgdata volume'u yeni .env parolasiyla cakisiyor) ya da temiz yeniden-kurulum icin.
#
# DIKKAT: Tum veritabani verisi (taramalar, kullanicilar, ayarlar) SILINIR, geri alinamaz.
#         .env varsayilan olarak KORUNUR; --include-env ile silinir.
#
# Kullanim:
#   bash reset.sh                # onay sorar
#   bash reset.sh --force        # onaysiz
#   bash reset.sh --include-env  # .env'i de sil (creds/secret sifirdan)
set -euo pipefail
cd "$(dirname "$0")"

FORCE=0
INCLUDE_ENV=0
for a in "$@"; do
  case "$a" in
    --force) FORCE=1 ;;
    --include-env) INCLUDE_ENV=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "Bilinmeyen secenek: $a" >&2; exit 2 ;;
  esac
done

if ! docker info >/dev/null 2>&1; then
  echo "HATA: Docker daemon yanit vermiyor. Docker'i baslatip tekrar deneyin." >&2
  exit 1
fi

echo "==> Kangalis temiz sifirlama (reset)"
echo "    Bu islem konteynerleri ve VERITABANI volume'unu (tum tarama verisi) SILER."
[ "$INCLUDE_ENV" = 1 ] && echo "    + .env de silinecek (creds/secret bir sonraki setup.sh'te yeniden uretilir)."
if [ "$FORCE" != 1 ]; then
  read -rp "    Devam edilsin mi? Geri ALINAMAZ [e/H]: " ans
  case "$ans" in [eEyY]*) ;; *) echo "Iptal edildi."; exit 0 ;; esac
fi

echo "--> docker compose down -v"
docker compose down -v || true

# Kalan 'kangalis' volume'lerini acikca sil (proje/klasor adi degismis olabilir)
for v in $(docker volume ls --format '{{.Name}}' 2>/dev/null | grep -i kangalis || true); do
  echo "--> docker volume rm $v"
  docker volume rm "$v" || true
done

if [ "$INCLUDE_ENV" = 1 ] && [ -f .env ]; then
  rm -f .env
  echo "--> .env silindi (setup.sh yeniden uretir)."
fi

left="$(docker volume ls --format '{{.Name}}' 2>/dev/null | grep -i kangalis || true)"
echo ""
if [ -z "$left" ]; then
  echo "[OK] Temiz. Kalan kangalis volume yok."
else
  echo "[!] Hala volume var: $left  -> elle silin: docker volume rm <ad>"
fi
echo ""
echo "Yeniden kurulum:  bash setup.sh   (ya da .env duruyorsa: docker compose up -d --build)"
