# Installer le driver

> Charger `WazabiEDR_Driver.sys` pour que l'agent ait quelque chose à interroger.

Le driver est livré sous forme d'un paquet INF + SYS + CAT, signé avec un **certificat de
test**. Un déploiement en production avec un `.sys` correctement signé (attestation Microsoft
ou certificat EV) suit le même flux `pnputil`, mais avec `bcdedit /set testsigning off`.

## Deux façons d'installer

- **Automatisée** — `scripts/Install-Driver.ps1` télécharge la dernière release GitHub et
  installe de bout en bout. Idéal pour une VM de dev fraîche.
- **Manuelle** — `pnputil /add-driver` après compilation locale. Idéal quand on travaille
  *sur* le driver.

## Installation automatisée

```powershell
PS> cd WazabiEDR_Driver\scripts

# Dépôt public :
PS> .\Install-Driver.ps1 -Repo "lululufr/WazabiEDR_Driver"

# Dépôt privé ou accès anonyme limité :
PS> .\Install-Driver.ps1 -Repo "lululufr/WazabiEDR_Driver" -Token "ghp_..."

# Version précise :
PS> .\Install-Driver.ps1 -Repo "lululufr/WazabiEDR_Driver" -Tag "v1.2.0"
```

Ce que fait le script, dans l'ordre :

1. **Vérifie les droits Administrateur** — refuse de tourner sinon.
2. **Récupère la release** via `api.github.com/repos/<repo>/releases/tags/<tag>`.
3. **Télécharge le `.zip`** dans `%TEMP%\WazabiEDR_<random>\`.
4. **Installe le certificat de test** dans les magasins `Root` **et** `TrustedPublisher`
   (pour que le SCM accepte la chaîne de certificat au boot).
5. **Active testsigning** si besoin (`bcdedit /set testsigning on`) — nécessite un redémarrage.
6. **Arrête** toute instance en cours du service `WazabiEDR_Driver`.
7. **`pnputil /add-driver <inf> /install`** — ajoute l'INF au Driver Store et installe.
8. **`pnputil /scan-devices`** — déclenche l'énumération PnP pour instancier le device.
9. **Vérifie le service** `WazabiEDR_Driver`, le démarre si PnP ne l'a pas fait.

Une fois le script terminé, `\\.\WazabiEDR` est joignable depuis l'user-mode et l'agent peut se
connecter.

## Installation manuelle (driver compilé localement)

```powershell
# 1. Compiler le paquet (voir doc/usage/building.md)
PS> cd WazabiEDR_Driver
PS> $env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
PS> cargo make

# 2. Faire confiance au certificat de test (une fois par machine)
PS> certutil -addstore -f Root             target\debug\WazabiEDR_Driver_package\WazabiEDR_Driver.cer
PS> certutil -addstore -f TrustedPublisher target\debug\WazabiEDR_Driver_package\WazabiEDR_Driver.cer

# 3. Activer testsigning si nécessaire
PS> bcdedit /enum '{current}' | Select-String testsigning
PS> bcdedit /set testsigning on    # si off — REDÉMARRAGE REQUIS

# 4. Installer le driver (après redémarrage si testsigning a été activé)
PS> pnputil /add-driver target\debug\WazabiEDR_Driver_package\WazabiEDR_Driver.inf /install

# 5. Forcer PnP à instancier le device racine :
PS> pnputil /scan-devices
```

Vérifier que le service est enregistré et (idéalement) démarré :

```powershell
PS> Get-Service WazabiEDR_Driver
Status   Name                 DisplayName
------   ----                 -----------
Running  WazabiEDR_Driver     WazabiEDR Driver
```

## Vérifier que le driver répond

Le contrôle de bout en bout le plus rapide est de lancer l'agent :

```powershell
PS> cd ..\WazabiEDR_Agent
PS> .\target\release\WazabiEDR_Agent.exe
[agent] connected to \\.\WazabiEDR (Ctrl+C to stop) ...
[2026-05-09T20:53:01.400Z] ProcessCreate pid=8884 ppid=4192 creator=4192 path="...\notepad.exe"
```

S'il reste bloqué sur « connected to » sans événement, le driver est chargé mais inerte
(ouvrez un notepad — les créations de processus sont les plus fréquentes). S'il échoue à
l'ouverture, le device n'est pas joignable — revérifiez l'installation.

## Désinstaller

```powershell
PS> Stop-Service WazabiEDR_Driver
PS> pnputil /enum-drivers | Select-String -Context 0,7 WazabiEDR   # trouver le Published Name
PS> pnputil /delete-driver oem42.inf /uninstall /force

# Optionnel — retirer le cert de test et désactiver testsigning :
PS> certutil -delstore Root             "WazabiEDR Test Certificate"
PS> certutil -delstore TrustedPublisher "WazabiEDR Test Certificate"
PS> bcdedit /set testsigning off    # redémarrage pour prise d'effet
```

## Problèmes d'installation courants

| Symptôme | Cause probable | Correctif |
|---|---|---|
| `pnputil` renvoie `0x800B0109` | Cert de test absent de `Root` ET `TrustedPublisher` | Rejouer `certutil -addstore` pour les deux magasins |
| `pnputil` réussit, aucun service n'apparaît | INF correct mais aucun device PnP ne correspond | `pnputil /scan-devices` ; ou `devcon install <inf> Root\WazabiEDR_Driver` |
| Boot en échec « Driver signature enforcement » | testsigning off alors que le système tente de charger le `.sys` | Mode sans échec, `bcdedit /set testsigning on`, redémarrer |
| Agent : `CreateFile failed: error 2` | Service installé mais non démarré, ou symlink absent | `Start-Service WazabiEDR_Driver` ; vérifier `\\.\WazabiEDR` |
| Agent : `error 5` (accès refusé) | La DACL du device ne vous accorde pas la lecture | Lancer l'agent en Administrateur |
| Avertissements `DROPPED N events` en boucle | Le ring se remplit plus vite que l'agent ne lit | Diagnostiquer le débit de pompage (souvent le canal du spool est plein) |

## Et ensuite

- Côté agent : voir le dépôt [`WazabiEDR_Agent`](../../../WazabiEDR_Agent/).
- Gérer les plugins : dépôt [`WazabiEDR_Utils`](../../../WazabiEDR_Utils/).
