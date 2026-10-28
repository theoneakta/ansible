# Sentry Lens collector - Windows installer, served by Sentry Lens at /collector/install.ps1.
#
#   In PowerShell as administrator:
#   & ([scriptblock]::Create((irm __SENTRY_URL__/collector/install.ps1))) -Key slc_...
#
# Downloads the collector from Sentry Lens, checks it against SHA256SUMS,
# installs it in Program Files and runs it as the "Sentry Lens collector"
# service under LocalService (no administrator rights: Windows' own ARP and
# ping calls need none, no Npcap). Its key goes in
# ProgramData\SentryLens\collector.conf, readable by SYSTEM, administrators
# and the service only. Running it again updates the collector in place.
#
# Options: -Key slc_...   the collector's key (Sentry Lens > Assets > Collectors)
#          -Url URL       Sentry Lens's address (default: where this script came from)
#          -Insecure      don't check Sentry Lens's TLS certificate
#          -Uninstall     stop and remove the collector
param(
    [string]$Key = "",
    [string]$Url = "__SENTRY_URL__",
    [switch]$Insecure,
    [switch]$Uninstall
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"  # Invoke-WebRequest is much faster without its progress bar

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Run PowerShell as administrator." }
$Url = $Url.TrimEnd("/")
$dir = Join-Path $env:ProgramFiles "SentryLens"
$data = Join-Path $env:ProgramData "SentryLens"
$exe = Join-Path $dir "sentry-collector.exe"
$conf = Join-Path $data "collector.conf"

if ($Uninstall) {
    if (Test-Path $exe) { & $exe uninstall }
    Remove-Item -Recurse -Force $dir, $data -ErrorAction SilentlyContinue
    Write-Host "Sentry Lens collector removed."
    return
}
if (-not $Key.StartsWith("slc_")) { throw "-Key slc_... is needed (Sentry Lens > Assets > Collectors)." }
if (-not [Environment]::Is64BitOperatingSystem) { throw "64-bit Windows only." }

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$web = @{ UseBasicParsing = $true }
if ($Insecure) {
    if ($PSVersionTable.PSVersion.Major -ge 6) { $web.SkipCertificateCheck = $true }
    else { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
}

$file = "sentry-collector-windows-amd64.exe"
$tmp = Join-Path $env:TEMP $file
Write-Host "Downloading $file from $Url ..."
Invoke-WebRequest @web -Uri "$Url/collector/download/$file" -OutFile $tmp
$sums = [Text.Encoding]::ASCII.GetString((Invoke-WebRequest @web -Uri "$Url/collector/download/SHA256SUMS").RawContentStream.ToArray())
$want = ($sums -split "`n" | Where-Object { $_ -match [regex]::Escape($file) + "\s*$" } | Select-Object -First 1) -split "\s+" | Select-Object -First 1
$got = (Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower()
if (-not $want -or $want.ToLower() -ne $got) { Remove-Item $tmp -Force; throw "The download doesn't match its checksum - not installed." }

# The key must be one Sentry Lens accepts, or the service would run and be
# turned away every minute. The key the collector would really use: a key it
# was rotated to, kept (next to its config) for this same install key, else this one.
$useKey = $Key
$state = Join-Path (Split-Path $conf) "key.json"
if (Test-Path $state) {
    $s = Get-Content $state -Raw | ConvertFrom-Json
    $sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Key))).Replace("-", "").ToLower()
    if ($s.config_key_sha256 -eq $sha -and $s.key -like "slc_*") { $useKey = $s.key }
}
$version = try { ((& $tmp version) -split " ")[1] } catch { "" }
try {
    Invoke-WebRequest @web -Uri "$Url/api/collector/config?version=$version" -Headers @{ Authorization = "Bearer $useKey" } | Out-Null
    Write-Host "Sentry Lens accepts the key."
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 401) {
        Remove-Item $tmp -Force
        throw "Sentry Lens doesn't accept this key: it was replaced, or its collector deleted. Get the current install line from Assets > Collectors (Replace key) - not installed."
    }
    Write-Warning "Couldn't check the key with Sentry Lens ($($_.Exception.Message)) - installing anyway."
}

New-Item -ItemType Directory -Force -Path $dir, $data | Out-Null
if (Test-Path $exe) { & $exe uninstall 2>$null | Out-Null }
Move-Item -Force $tmp $exe
$verify = if ($Insecure) { "0" } else { "1" }
Set-Content -Path $conf -Encoding ASCII -Value "SENTRY_URL=$Url`r`nSENTRY_KEY=$Key`r`nSENTRY_TLS_VERIFY=$verify"
# Only SYSTEM, administrators and the service (LocalService: it also writes its log there).
icacls $data /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-19:(OI)(CI)M" | Out-Null

& $exe install --config $conf
Start-Sleep -Seconds 3
$svc = Get-Service SentryLensCollector -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "Sentry Lens collector $((& $exe version) -replace 'sentry-collector ', '') is running - its first sweep shows in Sentry Lens within a few minutes."
    Write-Host "Its log: $data\collector.log"
} else {
    throw "It didn't start - see $data\collector.log"
}
