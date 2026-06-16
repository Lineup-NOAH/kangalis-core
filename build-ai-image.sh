#!/usr/bin/env bash
# Kangalis — ön-paketli AI imajını (Qwen3-8B modeli gömülü, Ollama) YEREL derle (+ opsiyonel ghcr push).
# Model (~5 GB) build sırasında indirilip imaja gömülür → biten imaj internetsiz çalışır.
#
# Kullanım:
#   bash build-ai-image.sh                 # yalnız derle
#   PUSH=1 bash build-ai-image.sh          # derle + push (önce: docker login ghcr.io)
#   IMAGE=ghcr.io/lineup-noah/kangalis-ai TAG=qwen3-8b bash build-ai-image.sh
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="${IMAGE:-ghcr.io/lineup-noah/kangalis-ai}"
TAG="${TAG:-qwen3-8b}"
PUSH="${PUSH:-0}"
REF="${IMAGE}:${TAG}"

echo "==> Derleniyor: ${REF}"
echo "    (model ~5 GB build'de 'ollama pull' ile indirilip imaja gömülür; dakikalar sürebilir)"
docker build -f Dockerfile.ai -t "${REF}" .

if [ "${PUSH}" = "1" ]; then
  echo "==> Push: ${REF}  (önce 'docker login ghcr.io' yapmış olmalısınız)"
  docker push "${REF}"
fi

echo "[OK] ${REF} hazir."
echo "    Kullanim: docker compose -f docker-compose.yml -f docker-compose.ai-baked.yml --profile ai up -d ollama"
