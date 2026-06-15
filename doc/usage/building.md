# Compiler le driver

> De la machine vierge au paquet `.sys` chargeable.

## Prérequis

- **Windows 10 / 11**, 64 bits. Compiler ailleurs ne marchera pas (KMDF).
- **Toolchain Rust** avec la cible MSVC — [rustup](https://rustup.rs/), puis
  `rustup default stable-x86_64-pc-windows-msvc`.
- **Visual Studio Build Tools 2022** avec la charge « Développement Desktop en C++ » (le
  linker MSVC est requis).
- **Windows Driver Kit (WDK) 10.0.26100** — via NuGet (cf. le workflow CI) ou l'installeur WDK.
- **LLVM 17.0.6** (Clang) pour le bindgen C/C++ du WDK. `LIBCLANG_PATH` doit pointer dessus.
  ```
  winget install -i LLVM.LLVM --version 17.0.6 --force
  ```
- **`cargo-make`** — le driver l'utilise comme *task runner* :
  ```
  cargo install --locked cargo-make --no-default-features --features tls-native
  ```

## Compiler

Le driver se compile via **`cargo make`** (et **pas** `cargo build`) : l'étape de packaging
WDK doit s'exécuter après la compilation de la crate kernel.

```powershell
PS> cd WazabiEDR_Driver
PS> $env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"   # une fois par shell
PS> cargo make
[cargo-make] INFO - Build Done in 53.21 seconds.

PS> ls .\target\debug\WazabiEDR_Driver_package
    WazabiEDR_Driver.sys
    WazabiEDR_Driver.inf
    WazabiEDR_Driver.cer
    ...
```

`cargo make` orchestre une séquence (déclarée dans `Makefile.toml`, qui étend le makefile
généré par `wdk-build`) :

1. `cargo build` de la crate kernel `cdylib` → renommage `.dll` en `.sys` ;
2. `inf2cat` → produit le fichier catalogue `.cat` ;
3. `signtool` avec un certificat de test généré → signe `.sys` et `.cat` (Authenticode).

> **Pourquoi `cargo make` et pas `cargo build` ?** Le flux Windows de signature/packaging de
> driver n'a rien à voir avec cargo. Un `cargo build` nu produit un `.sys` que l'OS refusera
> de charger (non signé). Le `Makefile.toml` déclare les étapes post-build qui transforment ce
> `.sys` en paquet kernel chargeable.

## Configuration de la crate

Extrait de `Cargo.toml` (les points qui ont un sens kernel) :

```toml
[lib]
crate-type = ["cdylib"]              # un driver est une cdylib renommée en .sys

[package.metadata.wdk.driver-model]
driver-type = "KMDF"
kmdf-version-major = 1
target-kmdf-version-minor = 33

[profile.dev]
panic = "abort"                      # pas de unwinding en kernel
[profile.release]
panic = "abort"
```

## Pipeline CI

Le workflow GitHub Actions (`.github/workflows/`) refait la même chose en CI : checkout →
`rustup` MSVC → cache cargo → install `cargo-make` + `rust-script` → LLVM 17.0.6 via winget →
WDK 10.0.26100 via NuGet → `cargo make` → zip du paquet → upload en artefact. Les builds
`main` sont des pré-releases roulantes (`latest`) ; les tags `v*.*.*` deviennent des releases
complètes. `Install-Driver.ps1` ([`installing-driver.md`](installing-driver.md)) télécharge
ces zips.

## Problèmes de compilation courants

| Symptôme | Cause | Correctif |
|---|---|---|
| `link.exe : fatal error LNK1181` | Build Tools MSVC absents ou mauvaise toolchain | Installer VS 2022 Build Tools, `rustup default stable-msvc` |
| `failed to run custom build command for ... wdk-*` | `LIBCLANG_PATH` non défini | `$env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"` |
| `WDKContentRoot not found` | WDK absent ou variable manquante | Installer le WDK, ou lancer depuis un shell « WDK Build Env » |
| `cargo make: command not found` | cargo-make absent | `cargo install cargo-make` |
| Le driver compile mais le `.cat` manque | `inf2cat` a échoué silencieusement (INF invalide) | Vérifier la syntaxe de `WazabiEDR_Driver.inf` |

## Nettoyage

`cargo clean` fonctionne normalement. Le `target/` inclut la sortie bindgen générée par le
WDK (régénérée au build suivant) — à nettoyer en cas de changement de version du WDK.
