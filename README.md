# WazabiEDR_Driver

Driver kernel (KMDF, Rust) de l'EDR **WazabiEDR**. Il pose cinq callbacks kernel
(process, image, registre, thread, handle de processus) et expose les événements
qu'ils produisent comme un flux binaire via un IOCTL sur le device `\\.\WazabiEDR`.
Il observe seulement — il ne bloque jamais une action. Le consommateur de ce flux est
[`WazabiEDR_Agent`](../WazabiEDR_Agent/).

## Documentation

Toute la documentation vit désormais **dans ce dépôt** (plus de dépôt `WazabiEDR_Doc`).

- 📐 **[ARCHITECTURE.md](ARCHITECTURE.md)** — le document à lire en premier : appel inversé,
  callbacks, format de fil, ring buffer, IPC IOCTL/IRP, synchronisation.
- 🛠️ [doc/usage/building.md](doc/usage/building.md) — compiler le driver (`cargo make`, WDK, LLVM).
- 📦 [doc/usage/installing-driver.md](doc/usage/installing-driver.md) — test signing, `pnputil`, désinstallation.
- 📑 [doc/reference/event-types.md](doc/reference/event-types.md) — chaque événement, champ par champ.
- 🔬 [doc/project/Main.md](doc/project/Main.md) & [doc/project/irp.md](doc/project/irp.md) — notes
  techniques approfondies (flux d'un événement, modèle IRP).

## Démarrage rapide

```powershell
# Prérequis : LLVM 17.0.6 + WDK 10.0.26100 + cargo-make (voir doc/usage/building.md)
PS> $env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
PS> cargo make

# Installer (test signing requis) :
PS> bcdedit /set testsigning on        # redémarrage requis
PS> certutil -addstore Root             target\debug\WazabiEDR_Driver_package\WazabiEDR_Driver.cer
PS> certutil -addstore TrustedPublisher target\debug\WazabiEDR_Driver_package\WazabiEDR_Driver.cer
PS> pnputil /add-driver target\debug\WazabiEDR_Driver_package\WazabiEDR_Driver.inf /install
PS> pnputil /scan-devices
```

Détails complets dans [doc/usage/installing-driver.md](doc/usage/installing-driver.md).
