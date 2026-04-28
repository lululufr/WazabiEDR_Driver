Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# cargo-make 0.37+ resout "extend" avant "load_script" donc le fichier
# doit exister avant le lancement.
# Le fichier n'est pas extrait correctement du registre cargo sur Windows
# (symlink POSIX non supporte), on l'extrait directement depuis le .crate.
$destFile  = Join-Path $PSScriptRoot "target\rust-driver-makefile.toml"
$crateFile = "$env:USERPROFILE\.cargo\registry\cache\index.crates.io-1949cf8c6b5b557f\wdk-build-0.5.1.crate"

New-Item -ItemType Directory -Path (Split-Path $destFile) -Force | Out-Null

if (-not (Test-Path $destFile) -or (Get-Item $destFile).LinkType -ne $null) {
    if (-not (Test-Path $crateFile)) { Write-Error "wdk-build-0.5.1.crate introuvable."; exit 1 }
    $content = tar -xOf $crateFile "wdk-build-0.5.1/rust-driver-makefile.toml"
    [System.IO.File]::WriteAllText($destFile, ($content -join "`n"))
    Write-Host "[*] rust-driver-makefile.toml extrait depuis le .crate." -ForegroundColor Cyan
}

Write-Host "[*] Build (cargo make)..." -ForegroundColor Cyan
cargo make
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] cargo make a echoue (exit $LASTEXITCODE)" -ForegroundColor Red
    Read-Host "Appuyez sur Entree pour fermer"
    exit 1
}
Write-Host "[+] Build termine." -ForegroundColor Green
