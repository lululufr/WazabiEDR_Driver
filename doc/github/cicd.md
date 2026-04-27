Pipeline CI/CD — Build WazabiEDR Agent

Déclencheurs

Le pipeline se lance dans 3 cas :

- Push sur main/master → build + release rolling "latest"
- Push d'un tag v*.*.\* → build + release versionnée officielle
- Pull Request vers main/master → build uniquement (vérification)

---

Étapes dans l'ordre

1. Checkout — Récupère le code source.
2. Installation de Rust stable (MSVC) — Installe la toolchain Rust ciblant x86_64-pc-windows-msvc (le projet tourne sur windows-latest).
3. Cache cargo — Met en cache le registre cargo et le dossier target/ pour accélérer les builds suivants (clé basée sur Cargo.lock et sources).
4. Outils Rust — Installe cargo-make (task runner) et rust-script.
5. Installation LLVM 17.0.6 — Installe Clang via winget et expose LIBCLANG_PATH (nécessaire pour les bindings C/C++ dans le driver).
6. Installation du WDK 10.0.26100 — Télécharge le Windows Driver Kit via NuGet (packages Microsoft.Windows.WDK.x64 et ARM64). Configure toutes les variables d'environnement attendues par wdk-build (WDKContentRoot, WDKBinRoot, etc.).
7. Build — Lance simplement cargo make, qui orchestre la compilation du driver Windows.
8. Packaging — Compresse le contenu de target\debug\WazabiEDR_Agent_package\ en WazabiEDR_Agent.zip.
9. Upload artifact — Attache le zip comme artifact GitHub (conservé 30 jours), nommé avec le SHA du
   commit

---

Publication (Release)
Cas: Rolling "latest"  
 Quand: Push sur main/master  
 Ce qui se passe: Recrée le tag latest en force, met à les variables d'environnement attendues par wdk-build (WDKContentRoot, WDKBinRoot, etc.).

7. Build — Lance simplement cargo make, qui orchestre la compilation du driver Windows.
8. Packaging — Compresse le contenu de target\debug\WazabiEDR_Agent_package\ en WazabiEDR_Agent.zip.
9. Upload artifact — Attache le zip comme artifact GitHub (conservé 30 jours), nommé avec le SHA du commit.

---

Cas: Release versionnée
Quand: Push d'un tag v1.2.3
Ce qui se passe: Crée/met à jour une release officielle
