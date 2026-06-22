# Kangalis — ön-paketli AI imajını (Qwen3-8B modeli gömülü, Ollama) YEREL derle (+ opsiyonel ghcr push).
# Model (~5 GB) build sırasında indirilip imaja gömülür → biten imaj internetsiz çalışır.
#
# Kullanım:
#   powershell -ExecutionPolicy Bypass -File build-ai-image.ps1
#   powershell -ExecutionPolicy Bypass -File build-ai-image.ps1 -Push   # önce: docker login ghcr.io
param(
    [string]$Image = "ghcr.io/lineup-noah/kangalis-ai",
    [string]$Tag   = "qwen3-8b",
    [switch]$Push
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$ref = "${Image}:${Tag}"
Write-Host "==> Derleniyor: $ref"
Write-Host "    (model ~5 GB build'de 'ollama pull' ile indirilip imaja gömülür; dakikalar sürebilir)"
docker build -f Dockerfile.ai -t $ref .
if ($LASTEXITCODE -ne 0) { throw "docker build başarısız (çıkış kodu $LASTEXITCODE)" }

if ($Push) {
    Write-Host "==> Push: $ref  (önce 'docker login ghcr.io' yapmış olmalısınız)"
    docker push $ref
    if ($LASTEXITCODE -ne 0) { throw "docker push başarısız (çıkış kodu $LASTEXITCODE)" }
}

Write-Host "[OK] $ref hazir."
Write-Host "    Kullanim: docker compose -f docker-compose.yml -f docker-compose.ai-baked.yml --profile ai up -d ollama"
