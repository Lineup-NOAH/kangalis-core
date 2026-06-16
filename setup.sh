#!/usr/bin/env bash
# Kangalis — tek-komut ilk kurulum (Linux / macOS).
# Önkoşul: Docker + Docker Compose. Çalıştır:  bash setup.sh
set -euo pipefail
cd "$(dirname "$0")"

echo "==> 1/4 Kangalis derleniyor + başlatılıyor (nmap dahil; ilk derleme birkaç dk sürebilir)..."
docker compose up -d --build

echo "==> 2/4 Şema migrasyonu (otomatik) + uygulama sağlığı bekleniyor..."
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

echo ""
echo "==> 3/4 İlk YÖNETİCİ (admin) kullanıcısı"
read -rp "  Kullanıcı adı: " KUSER
read -rsp "  Parola (güçlü bir parola seçin): " KPASS; echo
docker compose exec -T app python -m cybersectool.scripts.create_user \
  --username "$KUSER" --password "$KPASS" --role admin

echo ""
echo "==> 4/4 YETKİLİ TARAMA KAPSAMI (ZORUNLU — yoksa hiçbir tarama çalışmaz)"
echo "    Yalnızca taramaya YETKİLİ olduğunuz ağları girin. Örn: 192.168.1.0/24,10.0.0.0/8"
read -rp "  İzinli CIDR (virgülle birden çok): " KCIDR
SCOPE_ARGS=()
IFS=',' read -ra CIDRS <<< "$KCIDR"
for c in "${CIDRS[@]}"; do
  c="$(echo "$c" | xargs)"   # trim
  [ -n "$c" ] && SCOPE_ARGS+=(--allow "$c")
done
docker compose exec -T app python -m cybersectool.scripts.set_scope --name ic-ag "${SCOPE_ARGS[@]}"

echo ""
echo "✅ Kurulum tamam!"
echo "   Web paneli : http://localhost:8000/login   (kullanıcı: $KUSER)"
echo "   API/Swagger: http://localhost:8000/docs"
echo "   Yerel AI'yı açmak (opsiyonel): docker compose --profile ai up -d ollama"
echo "   Ayrıntı: docs/KURULUM.md + docs/EKLENTILER.md"
