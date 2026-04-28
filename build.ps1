#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installe le driver WazabiEDR sur la VM cible.
    Désinstalle proprement toute version précédente, puis charge et démarre la nouvelle.

.PARAMETER PackageDir
    Dossier contenant WazabiEDR_Driver.inf, .sys, .cat et .cer.
    Défaut: .\target\debug\WazabiEDR_Driver_package (relatif au script).

.EXAMPLE
    .\build.ps1
    .\build.ps1 -PackageDir C:\Temp\WazabiEDR_Driver_package
#>
[CmdletBinding()]
param(
    [string]$PackageDir = (Join-Path $PSScriptRoot "target\debug\WazabiEDR_Driver_package")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ServiceName = "WazabiEDR_Driver"
$InfName     = "WazabiEDR_Driver.inf"

function Write-Step([string]$msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok  ([string]$msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail([string]$msg) { Write-Host "[-] $msg" -ForegroundColor Red; exit 1 }

# ── 1. Validation du package ──────────────────────────────────────────────────
if (-not (Test-Path $PackageDir)) {
    Write-Fail "Dossier package introuvable: $PackageDir"
}
$infPath = Join-Path $PackageDir $InfName
if (-not (Test-Path $infPath)) {
    Write-Fail "Fichier $InfName introuvable dans $PackageDir"
}
$sysPath = Join-Path $PackageDir "$ServiceName.sys"
if (-not (Test-Path $sysPath)) {
    Write-Fail "Fichier $ServiceName.sys introuvable dans $PackageDir"
}
Write-Ok "Package validé: $PackageDir"

# ── 2. Test signing ───────────────────────────────────────────────────────────
$tsEnabled = (bcdedit /enum "{current}") -match "testsigning\s+Yes"
if (-not $tsEnabled) {
    Write-Warn "Test signing désactivé. Activation..."
    bcdedit /set testsigning on | Out-Null
    Write-Warn "Redémarrez la VM puis relancez ce script."
    exit 0
}
Write-Ok "Test signing actif."

# ── 3. Détection et suppression d'une installation précédente ────────────────
Write-Step "Recherche d'une installation précédente..."

$hadOldInstall = $false

# 3a. Arrêt du service si présent
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    $hadOldInstall = $true
    if ($svc.Status -ne "Stopped") {
        Write-Step "Arrêt du service '$ServiceName' (état: $($svc.Status))..."
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
        } catch {
            Write-Warn "Impossible d'arrêter le service proprement: $_"
        }
    } else {
        Write-Step "Service '$ServiceName' déjà arrêté."
    }
}

# 3b. Suppression du device PnP s'il existe
$device = Get-PnpDevice -ErrorAction SilentlyContinue |
    Where-Object { $_.InstanceId -like "Root\$ServiceName*" } |
    Select-Object -First 1
if ($device) {
    $hadOldInstall = $true
    Write-Step "Suppression du device PnP: $($device.InstanceId)"
    pnputil /remove-device $device.InstanceId | Out-Null
    Start-Sleep -Seconds 1
}

# 3c. Suppression de toutes les entrées correspondantes dans le Driver Store
$pnpBlocks = ((pnputil /enum-drivers) -join "`n") -split "(?=Published Name:)"
$oldOemNames = $pnpBlocks |
    Where-Object { $_ -match "Original Name:\s+$InfName" } |
    ForEach-Object { if ($_ -match "Published Name:\s+(oem\d+\.inf)") { $Matches[1] } }

foreach ($oem in $oldOemNames) {
    $hadOldInstall = $true
    Write-Step "Suppression du Driver Store: $oem"
    pnputil /delete-driver $oem /uninstall /force | Out-Null
}

if ($hadOldInstall) {
    Write-Ok "Ancienne installation supprimée."
} else {
    Write-Ok "Aucune installation précédente détectée."
}

# ── 4. Installation du certificat de test ────────────────────────────────────
$certFile = Get-ChildItem $PackageDir -Filter "*.cer" -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($certFile) {
    Write-Step "Installation du certificat: $($certFile.Name)"
    certutil -addstore -f "Root"             $certFile.FullName | Out-Null
    certutil -addstore -f "TrustedPublisher" $certFile.FullName | Out-Null
    Write-Ok "Certificat installé (Root + TrustedPublisher)."
} else {
    Write-Warn "Aucun .cer trouvé dans $PackageDir — l'installation peut échouer."
}

# ── 5. Installation du nouveau driver ────────────────────────────────────────
Write-Step "Installation du driver: $infPath"
pnputil /add-driver $infPath /install
if ($LASTEXITCODE -ne 0) {
    Write-Fail "pnputil /add-driver a échoué (exit $LASTEXITCODE)"
}

Write-Step "Énumération PnP (instanciation du device racine)..."
pnputil /scan-devices | Out-Null
Start-Sleep -Seconds 3

# ── 6. Démarrage du service ──────────────────────────────────────────────────
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Warn "Service '$ServiceName' non détecté après installation."
    Write-Host "  Le device root n'a pas été énuméré. Essayez:" -ForegroundColor Yellow
    Write-Host "    pnputil /scan-devices" -ForegroundColor White
    Write-Host "  ou redémarrez la VM." -ForegroundColor Yellow
    exit 1
}

if ($svc.Status -ne "Running") {
    Write-Step "Démarrage du service '$ServiceName'..."
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 2
    $svc.Refresh()
}

Write-Ok "WazabiEDR Driver opérationnel. État: $($svc.Status)"
