# Kangalis — tek-komut ilk kurulum (Windows / PowerShell).
# Önkoşul: Docker Desktop. Çalıştır:  powershell -ExecutionPolicy Bypass -File setup.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "==> 1/4 Kangalis derleniyor + başlatılıyor (nmap dahil; ilk derleme birkaç dk sürebilir)..."
docker compose up -d --build

Write-Host "==> 2/4 Şema migrasyonu (otomatik) + uygulama sağlığı bekleniyor..."
$ok = $false
for ($i = 0; $i -lt 80; $i++) {
    # try/catch + tüm akışları gizle: app henüz açılırken native stderr,
    # $ErrorActionPreference="Stop" altında script'i sonlandırmasın (yalnız $LASTEXITCODE'a bak).
    try {
        docker compose exec -T app python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $ok = $true; break }
    } catch { }
    Start-Sleep -Seconds 3
}
if (-not $ok) {
    Write-Error "Uygulama saglikli yanit vermedi. 'docker compose logs app migrate' ile kontrol edin."
    exit 1
}

Write-Host "`n==> 3/4 İlk YÖNETİCİ (admin) kullanıcısı"
$kuser = Read-Host "  Kullanıcı adı"
$ksec  = Read-Host "  Parola (güçlü bir parola seçin)" -AsSecureString
$kpass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ksec))
docker compose exec -T app python -m cybersectool.scripts.create_user --username $kuser --password $kpass --role admin

Write-Host "`n==> 4/4 YETKİLİ TARAMA KAPSAMI (ZORUNLU — yoksa hiçbir tarama çalışmaz)"
Write-Host "    Yalnızca taramaya YETKİLİ olduğunuz ağları girin. Örn: 192.168.1.0/24,10.0.0.0/8"
$kcidr = Read-Host "  İzinli CIDR (virgülle birden çok)"
$scopeArgs = @("--name", "ic-ag")
foreach ($c in $kcidr.Split(",")) {
    $t = $c.Trim()
    if ($t) { $scopeArgs += "--allow"; $scopeArgs += $t }
}
docker compose exec -T app python -m cybersectool.scripts.set_scope @scopeArgs

Write-Host "`n[OK] Kurulum tamam!"
Write-Host "   Web paneli : http://localhost:8000/login   (kullanici: $kuser)"
Write-Host "   API/Swagger: http://localhost:8000/docs"
Write-Host "   Yerel AI'yi acmak (opsiyonel): docker compose --profile ai up -d ollama"
Write-Host "   Ayrinti: docs/KURULUM.md + docs/EKLENTILER.md"
