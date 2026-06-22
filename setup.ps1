# Kangalis — tek-komut ilk kurulum (Windows / PowerShell).
# Önkoşul: Docker Desktop. Çalıştır:  powershell -ExecutionPolicy Bypass -File setup.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$envPath = Join-Path $PSScriptRoot ".env"

# --- Yardımcılar ---------------------------------------------------------------
function Read-Default([string]$Label, [string]$Default) {
    # Varsayılanı köşeli parantezde gösterir; boş Enter = varsayılan. Değer trim'lenir.
    $shown = if ([string]::IsNullOrEmpty($Default)) { "yok" } else { $Default }
    $v = Read-Host "  $Label [$shown]"
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return $v.Trim()
}

function Read-Safe([string]$Label, [string]$Default, [string]$Pattern, [string]$Hint) {
    # Pattern'e uyana kadar tekrar sorar (URL/.env güvenliği için kısıtlı karakter seti).
    while ($true) {
        $v = Read-Default $Label $Default
        if ($v -match $Pattern) { return $v }
        Write-Host "    ! $Hint" -ForegroundColor Yellow
    }
}

function New-RandomKey([int]$Bytes) {
    # Kriptografik güçlü rastgele bayt -> url-safe base64 (.env/URL'de güvenli karakterler).
    $buf = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buf) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($buf).Replace('+', '-').Replace('/', '_')
}

# --- 1/5 Kimlik bilgileri & güvenlik anahtarları -------------------------------
$hasCreds = (Test-Path $envPath) -and ((Get-Content $envPath -Raw) -match '(?m)^\s*POSTGRES_PASSWORD\s*=')
if ($hasCreds) {
    Write-Host "==> 1/5 Kimlik bilgileri .env'de zaten var - atlaniyor."
    Write-Host "    (Degistirmek icin .env'i duzenleyin; Postgres parolasi icin ayrica 'docker compose down -v' ile pgdata'yi sifirlayin.)"
}
else {
    Write-Host "==> 1/5 Kimlik bilgileri & güvenlik anahtarları"
    Write-Host "    Boş Enter = köşeli parantezdeki varsayılan. Kullanıcı/parola: yalnız harf, rakam, . _ -"
    # pgdata zaten varsa: kullanıcı/parola/db DEĞİŞTİRMEK bağlantıyı kırar (parola ilk açılışta gömülür).
    $pgVolExists = $false
    try { $pgVolExists = [bool]((docker volume ls --format "{{.Name}}" 2>$null) -match "pgdata") } catch { }
    if ($pgVolExists) {
        Write-Host "    UYARI: Veritabani (pgdata) zaten mevcut. Postgres kullanici/parola/db'yi DEGISTIRIRSENIZ" -ForegroundColor Yellow
        Write-Host "           baglanti kirilir -> ya Enter'la varsayilanlari koruyun ya da once 'docker compose down -v' yapin." -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  [PostgreSQL]"
    $pgUser = Read-Safe "Kullanıcı adı"  "cyber"        '\A[A-Za-z0-9._-]+\z' "Yalnız harf/rakam/. _ - kullanın."
    $pgPass = Read-Safe "Parola"         "cyber"        '\A[A-Za-z0-9._-]+\z' "Yalnız harf/rakam/. _ - kullanın."
    $pgDb = Read-Safe "Veritabanı adı"   "cybersectool" '\A[A-Za-z0-9._-]+\z' "Yalnız harf/rakam/. _ - kullanın."
    Write-Host ""
    Write-Host "  [Redis]  (Redis'te kullanıcı adı yoktur; yalnız parola. Boş = auth kapalı)"
    $rdPass = Read-Safe "Parola" "" '\A[A-Za-z0-9._-]*\z' "Yalnız harf/rakam/. _ - kullanın (ya da boş)."
    Write-Host ""
    Write-Host "  [Opsiyonel]  (Enter ile geçebilirsiniz)"
    $nvdKey = Read-Safe "NVD API anahtarı" "" '\A[A-Za-z0-9-]*\z' "NVD anahtarı yalnız harf/rakam/- içerir."
    $webhook = Read-Safe "Bildirim webhook URL" "" '\A(https?://[^\s]+)?\z' "http(s):// ile başlamalı; boşluk içermemeli."

    # Güçlü anahtarlar OTO-üretilir (varsayılan dev anahtarları zayıf; _WEAK_SECRETS'e takılır).
    $secretKey = New-RandomKey 48   # oturum imzalama
    $fernetKey = New-RandomKey 32   # kimlik kasası (Fernet, 32 bayt)
    Write-Host ""
    Write-Host "  [Oto-üretildi]  SECRET_KEY + kimlik kasası (Fernet) anahtarı (güçlü, rastgele)."

    # REDIS_URL'i doğru biçimde kur: parola varsa göm, yoksa auth'suz (iki farklı URL şekli).
    if ([string]::IsNullOrEmpty($rdPass)) { $redisUrl = "redis://redis:6379/0" }
    else { $redisUrl = "redis://:$rdPass@redis:6379/0" }

    $block = @"

# Kurulum sihirbazi tarafindan yazildi (duzenlenebilir)
POSTGRES_USER=$pgUser
POSTGRES_PASSWORD=$pgPass
POSTGRES_DB=$pgDb
REDIS_PASSWORD=$rdPass
REDIS_URL=$redisUrl
SECRET_KEY=$secretKey
CREDENTIAL_ENCRYPTION_KEY=$fernetKey
NVD_API_KEY=$nvdKey
NOTIFY_WEBHOOK_URL=$webhook
"@
    [System.IO.File]::AppendAllText($envPath, $block, (New-Object System.Text.UTF8Encoding($false)))
    # .env artık Fernet kasa anahtarı + SECRET_KEY + parolalar içeriyor -> erişimi yalnız bu kullanıcıya kısıtla.
    try { icacls $envPath /inheritance:r /grant:r "$($env:USERNAME):(F)" 2>$null | Out-Null } catch { }
    Write-Host "    [OK] .env güncellendi (erişim bu kullanıcıya kısıtlandı)."
}

# --- 2/5 Derle + başlat --------------------------------------------------------
Write-Host "`n==> 2/5 Kangalis derleniyor + başlatılıyor (nmap dahil; ilk derleme birkaç dk sürebilir)..."
docker compose up -d --build

# --- 3/5 Migrasyon + sağlık ----------------------------------------------------
Write-Host "`n==> 3/5 Şema migrasyonu (otomatik) + uygulama sağlığı bekleniyor..."
$ok = $false
for ($i = 0; $i -lt 80; $i++) {
    # try/catch + tüm akışları gizle: app henüz açılırken native stderr,
    # $ErrorActionPreference="Stop" altında script'i sonlandırmasın (yalnız $LASTEXITCODE'a bak).
    try {
        docker compose exec -T app python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $ok = $true; break }
    }
    catch { }
    Start-Sleep -Seconds 3
}
if (-not $ok) {
    Write-Error "Uygulama saglikli yanit vermedi. 'docker compose logs app migrate' ile kontrol edin."
    exit 1
}

# --- 4/5 Admin -----------------------------------------------------------------
Write-Host "`n==> 4/5 İlk YÖNETİCİ (admin) kullanıcısı"
$kuser = Read-Host "  Kullanıcı adı"
$ksec = Read-Host "  Parola (güçlü bir parola seçin)" -AsSecureString
$kpass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ksec))
# Parolayı argv'de göstermeden ortam değişkeniyle geçir (host cmdline sızdırmasın; -e VARNAME =
# isim-only geçiş -> değer PowerShell ortamından gelir, docker komut satırına yazılmaz). Sonra temizle.
$env:KANGALIS_ADMIN_PASSWORD = $kpass
try {
    docker compose exec -T -e KANGALIS_ADMIN_PASSWORD app python -m cybersectool.scripts.create_user --username $kuser --role admin
}
finally {
    Remove-Item Env:\KANGALIS_ADMIN_PASSWORD -ErrorAction SilentlyContinue
}

# --- 5/5 Kapsam ----------------------------------------------------------------
Write-Host "`n==> 5/5 YETKİLİ TARAMA KAPSAMI (ZORUNLU — yoksa hiçbir tarama çalışmaz)"
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
