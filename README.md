Requirement

```
    winget install -i LLVM.LLVM --version 17.0.6 --force
```

```
 cargo install --locked cargo-make --no-default-features --features tls-native
```

```
  rem Prérequis : test signing activé + cert installé
  bcdedit /set testsigning on
  certutil -addstore Root WDRLocalTestCert.cer
  certutil -addstore TrustedPublisher WDRLocalTestCert.cer

  rem Ajouter le driver au Driver Store et créer le device PnP
  pnputil /add-driver WazabiEDR_Driver.inf /install
  pnputil /scan-devices
```