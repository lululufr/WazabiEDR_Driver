#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ServiceName = "WazabiEDR_Driver"
$PackageDir  = Join-Path $PSScriptRoot "target\debug\WazabiEDR_Driver_package"
$InfName     = "WazabiEDR_Driver.inf"

function Write-Step([string]$msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }

# ── Test signing ──────────────────────────────────────────────────────────────
$tsEnabled = (bcdedit /enum "{current}") -match "testsigning\s+Yes"
if (-not $tsEnabled) {
    Write-Warn "Test signing désactivé. Activation..."
    bcdedit /set testsigning on | Out-Null
    Write-Warn "Redémarrez la machine puis relancez ce script."
    exit 0
}

# ── 1. Build ──────────────────────────────────────────────────────────────────
Write-Step "Build (cargo make)..."
Push-Location $PSScriptRoot
try {
    cargo make
    if ($LASTEXITCODE -ne 0) { throw "cargo make a échoué (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}
Write-Ok "Build terminé."

# ── 2. Nettoyage de l'ancienne installation ───────────────────────────────────
Write-Step "Nettoyage de l'ancienne installation..."

# Arrêt du service si actif
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne "Stopped") {
    Write-Step "Arrêt du service '$ServiceName'..."
    Stop-Service -Name $ServiceName -Force
    Start-Sleep -Seconds 2
}

# Suppression du device PnP
$device = Get-PnpDevice -ErrorAction SilentlyContinue |
    Where-Object { $_.InstanceId -like "Root\$ServiceName*" } |
    Select-Object -First 1
if ($device) {
    Write-Step "Suppression du device PnP : $($device.InstanceId)"
    pnputil /remove-device $device.InstanceId | Out-Null
    Start-Sleep -Seconds 1
}

# Suppression du driver du Driver Store (tous les oem*.inf correspondants)
$pnpBlocks = ((pnputil /enum-drivers) -join "`n") -split "(?=Published Name:)"
$oldOemNames = $pnpBlocks |
    Where-Object { $_ -match "Original Name:\s+$InfName" } |
    ForEach-Object { if ($_ -match "Published Name:\s+(oem\d+\.inf)") { $Matches[1] } }

foreach ($oem in $oldOemNames) {
    Write-Step "Suppression driver store : $oem"
    pnputil /delete-driver $oem /uninstall | Out-Null
}

Write-Ok "Nettoyage terminé."

# ── 3. Certificat de test ─────────────────────────────────────────────────────
$certFile = Get-ChildItem $PackageDir -Filter "*.cer" -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($certFile) {
    Write-Step "Installation du certificat : $($certFile.Name)"
    certutil -addstore -f "Root"             $certFile.FullName | Out-Null
    certutil -addstore -f "TrustedPublisher" $certFile.FullName | Out-Null
    Write-Ok "Certificat installé."
}

# ── 4. Installation du nouveau driver ─────────────────────────────────────────
$infPath = Join-Path $PackageDir $InfName
Write-Step "Installation du driver : $infPath"
pnputil /add-driver $infPath /install
if ($LASTEXITCODE -ne 0) { throw "pnputil /add-driver a échoué (exit $LASTEXITCODE)" }

# Scan PnP pour instancier le device racine
Write-Step "Enumération PnP..."
pnputil /scan-devices | Out-Null
Start-Sleep -Seconds 3

# ── 5. Démarrage du service ───────────────────────────────────────────────────
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Warn "Service '$ServiceName' non détecté après installation. Le device root n'a peut-être pas été énuméré."
    exit 1
}

if ($svc.Status -ne "Running") {
    Write-Step "Démarrage du service '$ServiceName'..."
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 2
    $svc.Refresh()
}

Write-Ok "WazabiEDR Driver opérationnel. Etat : $($svc.Status)"
