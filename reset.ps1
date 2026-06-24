#Requires -Version 5.1
<#
  Kangalis - Temiz sifirlama (reset).

  Konteynerleri durdurup SILER ve veritabani (pgdata) + diger 'kangalis' Docker
  volume'lerini KALDIRIR. Bozuk kurulum, "password authentication failed for user ..."
  (eski pgdata volume'u yeni .env parolasiyla cakisiyor) ya da temiz yeniden-kurulum icin.

  DIKKAT: Tum veritabani verisi (taramalar, kullanicilar, ayarlar) SILINIR ve geri alinamaz.
          .env (gizli anahtarlar/parolalar) varsayilan olarak KORUNUR; -IncludeEnv ile silinir.

  Kullanim:
    powershell -ExecutionPolicy Bypass -File reset.ps1              # onay sorar
    powershell -ExecutionPolicy Bypass -File reset.ps1 -Force       # onaysiz
    powershell -ExecutionPolicy Bypass -File reset.ps1 -IncludeEnv  # .env'i de sil (creds sifirdan)
#>
[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$IncludeEnv
)
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

Write-Host "==> Kangalis temiz sifirlama (reset)" -ForegroundColor Cyan

# Docker daemon yanit veriyor mu?
$dockerOk = $true
try { docker info *> $null; if ($LASTEXITCODE -ne 0) { $dockerOk = $false } } catch { $dockerOk = $false }
if (-not $dockerOk) {
    Write-Host "HATA: Docker daemon yanit vermiyor. Docker Desktop'i baslatip tekrar deneyin." -ForegroundColor Red
    exit 1
}

Write-Host "    Bu islem konteynerleri ve VERITABANI volume'unu (tum tarama verisi) SILER." -ForegroundColor Yellow
if ($IncludeEnv) { Write-Host "    + .env de silinecek (creds/secret'ler bir sonraki setup.ps1'de sifirdan uretilir)." -ForegroundColor Yellow }
if (-not $Force) {
    $ans = Read-Host "    Devam edilsin mi? Geri ALINAMAZ [e/H]"
    if ($ans -notmatch '^[eEyY]') { Write-Host "Iptal edildi."; exit 0 }
}

# 1) Bu projenin konteyner + named volume'lerini kaldir
Write-Host "`n--> docker compose down -v"
docker compose down -v 2>&1 | Out-Host

# 2) Kalan 'kangalis' volume'lerini acikca sil (proje/klasor adi degismis olabilir)
$vols = @(docker volume ls --format "{{.Name}}" 2>$null | Where-Object { $_ -match "kangalis" })
foreach ($v in $vols) {
    Write-Host "--> docker volume rm $v"
    docker volume rm $v 2>&1 | Out-Host
}

# 3) Opsiyonel: .env'i sil
if ($IncludeEnv -and (Test-Path ".env")) {
    Remove-Item ".env" -Force
    Write-Host "--> .env silindi (setup.ps1 yeniden uretir)."
}

# 4) Dogrulama
$left = @(docker volume ls --format "{{.Name}}" 2>$null | Where-Object { $_ -match "kangalis" })
Write-Host ""
if ($left.Count -eq 0) {
    Write-Host "[OK] Temiz. Kalan kangalis volume yok." -ForegroundColor Green
}
else {
    Write-Host "[!] Hala volume var: $($left -join ', ')  -> elle silin: docker volume rm <ad>" -ForegroundColor Yellow
}
Write-Host "`nYeniden kurulum:"
Write-Host "  powershell -ExecutionPolicy Bypass -File setup.ps1"
Write-Host "  (ya da .env duruyorsa)  docker compose up -d --build"
