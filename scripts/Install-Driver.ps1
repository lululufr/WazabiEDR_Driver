<#
.SYNOPSIS
    Installe WazabiEDR Agent depuis la dernière release GitHub.

.PARAMETER Repo
    Dépôt GitHub au format "owner/repo"

.PARAMETER Token
    Personal Access Token GitHub.
    Requis pour les repos privés. Peut aussi être passé via $env:GITHUB_TOKEN.

.PARAMETER Tag
    Tag de release à installer. Défaut : "latest".

.EXAMPLE
    .\Install-Driver.ps1 -Repo "MonOrg/WazabiEDR_Driver" -Token "ghp_..."
    .\Install-Driver.ps1 -Repo "MonOrg/WazabiEDR_Driver" -Tag "v1.2.0"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Repo,

    [string]$Token = $env:GITHUB_TOKEN,

    [string]$Tag = "latest"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Fonctions utilitaires
# ---------------------------------------------------------------------------

function Write-Step([string]$msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail([string]$msg) { Write-Host "[-] $msg" -ForegroundColor Red; exit 1 }

# ---------------------------------------------------------------------------
# Vérification : droits admin
# ---------------------------------------------------------------------------

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Fail "Ce script doit être exécuté en tant qu'Administrateur (clic droit → Exécuter en tant qu'administrateur)."
}

# ---------------------------------------------------------------------------
# Téléchargement de la release GitHub
# ---------------------------------------------------------------------------

Write-Step "Récupération de la release '$Tag' depuis github.com/$Repo ..."

$headers = @{ Accept = "application/vnd.github+json"; "X-GitHub-Api-Version" = "2022-11-28" }
if ($Token) { $headers["Authorization"] = "Bearer $Token" }

# /releases/latest ignore les prereleases → utiliser /releases/tags/latest
# pour récupérer le rolling build master (marqué prerelease dans le workflow).
$apiUrl = "https://api.github.com/repos/$Repo/releases/tags/$Tag"

try {
    $release = Invoke-RestMethod -Uri $apiUrl -Headers $headers
} catch {
    Write-Fail "Impossible d'atteindre l'API GitHub : $_`nVérifiez le nom du repo et le token."
}

$asset = $release.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1
if (-not $asset) {
    Write-Fail "Aucun fichier .zip trouvé dans la release '$($release.tag_name)'."
}

Write-Ok "Release trouvée : $($release.tag_name) — asset : $($asset.name)"

# Dossier temporaire d'installation
$tmpDir = Join-Path $env:TEMP "WazabiEDR_$([System.IO.Path]::GetRandomFileName().Replace('.',''))"
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
$zipPath = Join-Path $tmpDir "package.zip"

Write-Step "Téléchargement ($([math]::Round($asset.size / 1MB, 2)) MB) ..."
$dlHeaders = $headers.Clone()
$dlHeaders["Accept"] = "application/octet-stream"
Invoke-WebRequest -Uri $asset.browser_download_url -Headers $dlHeaders -OutFile $zipPath

Write-Step "Extraction dans $tmpDir ..."
Expand-Archive -Path $zipPath -DestinationPath $tmpDir -Force

# ---------------------------------------------------------------------------
# Installation du certificat de test
# ---------------------------------------------------------------------------

$certFile = Get-ChildItem $tmpDir -Filter "*.cer" | Select-Object -First 1
if ($certFile) {
    Write-Step "Installation du certificat de test : $($certFile.Name)"
    certutil -addstore -f "Root"            $certFile.FullName | Out-Null
    certutil -addstore -f "TrustedPublisher" $certFile.FullName | Out-Null
    Write-Ok "Certificat installé dans Root + TrustedPublisher."
} else {
    Write-Warn "Aucun certificat .cer trouvé dans le package."
}

# ---------------------------------------------------------------------------
# Test signing (obligatoire pour les drivers signés avec un cert de test)
# ---------------------------------------------------------------------------

$bcdedit   = bcdedit /enum "{current}"
$tsSetting = ($bcdedit | Select-String "testsigning") -replace '\s+', ' '
$tsEnabled = $tsSetting -match "Yes"

if (-not $tsEnabled) {
    Write-Warn "Test signing désactivé. Activation..."
    bcdedit /set testsigning on | Out-Null
    Write-Warn "REDÉMARRAGE REQUIS."
    Write-Host ""
    Write-Host "  Après le redémarrage, relancez ce script pour finaliser l'installation." -ForegroundColor Yellow
    $choice = Read-Host "Redémarrer maintenant ? (o/N)"
    if ($choice -match "^[oOyY]") {
        shutdown /r /t 10 /c "Activation testsigning pour WazabiEDR Driver"
    }
    exit 0
}

Write-Ok "Test signing actif."

# ---------------------------------------------------------------------------
# Installation du driver via pnputil
# ---------------------------------------------------------------------------

$infFile = Get-ChildItem $tmpDir -Filter "*.inf" | Select-Object -First 1
if (-not $infFile) {
    Write-Fail "Fichier .inf introuvable dans le package."
}

# Si le driver est déjà chargé, l'arrêter proprement avant mise à jour
$svcName = "WazabiEDR_Driver"
$existingSvc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($existingSvc -and $existingSvc.Status -eq "Running") {
    Write-Step "Arrêt du service existant '$svcName' ..."
    Stop-Service -Name $svcName -Force
    Start-Sleep -Seconds 2
}

Write-Step "Ajout du driver au Driver Store Windows..."
$pnpResult = pnputil /add-driver $infFile.FullName /install 2>&1
Write-Host $pnpResult

# Déclencher l'énumération des devices racine pour instancier le device PnP
Write-Step "Scan des devices PnP (instanciation du device racine)..."
pnputil /scan-devices 2>&1 | Out-Null

# Vérification
Start-Sleep -Seconds 3
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Ok "Service '$svcName' détecté : état = $($svc.Status)"
    if ($svc.Status -ne "Running") {
        Write-Step "Démarrage du service..."
        Start-Service -Name $svcName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $svc.Refresh()
        Write-Ok "État final : $($svc.Status)"
    }
} else {
    Write-Warn "Service '$svcName' non détecté automatiquement."
    Write-Host ""
    Write-Host "  Si devcon.exe est disponible (installé avec le WDK), exécutez :" -ForegroundColor Yellow
    Write-Host "  devcon.exe install `"$($infFile.FullName)`" Root\WazabiEDR_Driver" -ForegroundColor White
}

# ---------------------------------------------------------------------------
# Nettoyage
# ---------------------------------------------------------------------------

Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Ok "Installation terminée."
