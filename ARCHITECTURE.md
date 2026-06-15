# Architecture du driver WazabiEDR

> Document d'onboarding. Il s'adresse à un développeur qui sait coder et connaît
> grosso modo l'architecture Windows, **mais ne connaît rien à ce projet ni à la
> programmation kernel**. On part donc de zéro : chaque terme propre au projet ou au
> domaine (kernel, IRP, IOCTL, callback…) est expliqué (entre parenthèses) à sa première
> apparition, et on déroule les mécanismes au lieu de seulement les nommer. Les chemins
> entre crochets renvoient au code (`src/...`) et sont cliquables sur GitHub.

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Cycle de vie : `DriverEntry` & `DriverUnload`](#2-cycle-de-vie--driverentry--driverunload)
3. [Les cinq callbacks kernel](#3-les-cinq-callbacks-kernel)
4. [Le format de fil (wire format)](#4-le-format-de-fil-wire-format)
5. [La file d'événements (ring buffer)](#5-la-file-dévénements-ring-buffer)
6. [L'IPC : l'IOCTL en appel inversé](#6-lipc--lioctl-en-appel-inversé)
7. [Synchronisation & sûreté mémoire](#7-synchronisation--sûreté-mémoire)
8. [Par où commencer](#8-par-où-commencer)

---

## 1. Vue d'ensemble

WazabiEDR est un **EDR** (*Endpoint Detection and Response* : un système de sécurité qui
surveille en continu ce qui se passe sur une machine — créations de processus, écritures
dans le registre, etc. — pour détecter et tracer les comportements malveillants). Ce dépôt
contient sa brique la plus basse : le **driver kernel** (pilote qui s'exécute dans le
**noyau Windows**, *kernel*, le cœur du système qui a tous les privilèges, par opposition à
l'*user-mode* où tournent les programmes ordinaires).

Le rôle du driver est d'**observer** les événements système au plus bas niveau et de les
livrer à l'**agent** (`WazabiEDR_Agent/`, un programme user-mode), qui les normalise,
persiste et expédie. Le driver est écrit en Rust avec le framework **KMDF** (*Kernel-Mode
Driver Framework* : la couche Microsoft qui simplifie l'écriture de drivers), via la crate
`wdk-sys` (les liaisons Rust brutes vers les API du **WDK**, *Windows Driver Kit*).

Trois partis pris structurants, expliqués parce qu'ils reviennent partout :

- **Observation seule (*observe-only*).** Le driver ne **bloque jamais** une action : il
  observe via des callbacks « pre-» mais laisse toujours l'opération se poursuivre sans la
  modifier. Il dit à l'agent ce qui se passe, point. (Un mode bloquant — refuser un
  `OpenProcess`, annuler une écriture de registre — serait une extension future ; le code
  marque les endroits où elle s'insérerait.)
- **Appel inversé (*inverted call*).** Contrairement à l'intuition, ce n'est pas le driver
  qui *pousse* les événements vers l'agent ; c'est l'**agent qui appelle le driver en
  boucle** pour réclamer le prochain événement (voir §6). Conséquence clé : pas de thread
  driver à gérer (`PsCreateSystemThread`), tout ce qui produit (les callbacks) ou consomme
  (l'IOCTL) est appelé par quelqu'un d'autre — le scheduler Windows ou l'agent.
- **File bornée (*bounded ring buffer*).** Tant qu'aucun agent n'est connecté, les
  événements s'accumulent dans une file circulaire de 4096 entrées en pool non-paginé. Sous
  pression, les **plus anciens sont évincés** et le compteur `drop_count` du prochain
  événement livré dit à l'agent combien il a manqué.

```text
┌───────────────────────────── KERNEL (driver WazabiEDR) ──────────────────────────────┐
│                                                                                       │
│  callbacks kernel                              ┌─────────────────────────┐            │
│   process create/exit   ─┐                     │  PENDING_IRP (1 slot)   │ ◀── IOCTL  │
│   image load            ─┤                     │        OU               │  GET_EVENT │
│   registry modify       ─┼─► submit_event ───► │  QUEUE_BUF (ring 4096)  │   (agent)  │
│   thread create/exit    ─┤   (3 chemins)       └─────────────────────────┘            │
│   process handle access ─┘                                                            │
│                                                                                       │
│  format binaire repr(C, packed)  ──IOCTL_WEDR_GET_EVENT──►  \\.\WazabiEDR             │
└───────────────────────────────────────────────────────────────────────────────────────┘
                                                                  │
                                                                  ▼  binaire octet-pour-octet
                                                         WazabiEDR_Agent (user-mode)
```

Le point d'entrée du driver est [`src/lib.rs`](src/lib.rs) (`DriverEntry` / `DriverUnload`).
La carte des modules :

| Module | Rôle | Source |
|---|---|---|
| `events` | Le format de fil partagé avec l'agent (structures `repr(C, packed)`) | [`src/events.rs`](src/events.rs) |
| `state` | L'état global mutable (file, lock, IRP en attente, drapeaux…) | [`src/state.rs`](src/state.rs) |
| `callbacks` | Les cinq callbacks kernel (un module par domaine) | [`src/callbacks/`](src/callbacks/) |
| `queue` | Le ring buffer (`ring`) + la soumission producteur (`submit`) | [`src/queue/`](src/queue/) |
| `ipc` | La plomberie IRP : codes IOCTL, helpers IRP, dispatch | [`src/ipc/`](src/ipc/) |
| `util` | `SyncCell`, garde de spinlock RAII, conversions de chaînes | [`src/util/`](src/util/) |

> **Note de version (à lire si vous travaillez aussi sur l'agent).** Le format de fil est
> identifié par `EVENT_VERSION`. À ce jour le driver émet la **version 3**, avec un en-tête
> de 5 champs (sans `trunc_count`, voir §4). La branche `feat/waza-detection` de l'agent et
> l'ancienne doc centralisée décrivaient déjà une **version 4** avec un champ `trunc_count`
> supplémentaire. Les deux côtés **doivent** être synchronisés : si vous montez le driver en
> v4, mettez à jour `WazabiEDR_Agent/src/ipc/events.rs` au même moment. Cette doc décrit
> fidèlement le **code actuel du driver** (v3).

---

## 2. Cycle de vie : `DriverEntry` & `DriverUnload`

Tout le cycle de vie tient dans [`src/lib.rs`](src/lib.rs). Un driver Windows expose deux
fonctions au **I/O Manager** (le composant du noyau qui orchestre les entrées/sorties) :
`DriverEntry` (appelée au chargement) et `DriverUnload` (au déchargement).

### `DriverEntry` — l'ordre de démarrage n'est pas arbitraire

L'ordre est conçu pour que, en cas d'échec d'une étape, on puisse **dérouler proprement**
tout ce qui a déjà été mis en place (chaque échec exécute le démontage inverse) :

1. **Câbler `DriverUnload` et toutes les fonctions majeures.** Le driver remplit le tableau
   `DriverObject->MajorFunction` : un slot par type de requête (`IRP_MJ_CREATE`,
   `IRP_MJ_CLOSE`, `IRP_MJ_CLEANUP`, `IRP_MJ_DEVICE_CONTROL`…). **Tout slot laissé à `NULL`
   provoque un *bug check*** (l'écran bleu) à la première requête correspondante : on remplit
   donc d'abord *tous* les slots avec `dispatch_invalid`, puis on écrase les quatre qu'on
   gère vraiment ([`ipc/dispatch.rs`](src/ipc/dispatch.rs)).
2. **Initialiser le spinlock** (`KeInitializeSpinLock`) qui protège la file (§7).
3. **Créer le device** `\Device\WazabiEDR` (`IoCreateDevice`) — un *device* est le point
   d'accès nommé qu'expose le driver. On active `DO_BUFFERED_IO` (le mode de transfert où le
   noyau copie les buffers user dans un `SystemBuffer` intermédiaire, voir §6).
4. **Créer le lien symbolique** `\DosDevices\WazabiEDR` (`IoCreateSymbolicLink`) : c'est le
   nom que l'user-mode ouvre, sous la forme `\\.\WazabiEDR`.
5. **Enregistrer le callback process** (`PsSetCreateProcessNotifyRoutineEx`). *À partir
   d'ici, `process_notify` peut s'exécuter sur un autre CPU* — donc tout échec ultérieur doit
   le désenregistrer.
6. **Enregistrer le callback image** (`PsSetLoadImageNotifyRoutine`).
7. **Enregistrer le callback registre** (`CmRegisterCallback`). Il renvoie un *cookie* par
   paramètre de sortie ; on stocke son `QuadPart` dans un atomique
   (`REGISTRY_CALLBACK_COOKIE`) pour pouvoir le redonner à `CmUnRegisterCallback` au
   déchargement.
8. **Enregistrer le callback thread** (`PsSetCreateThreadNotifyRoutine`).
9. **Enregistrer le callback objet** (`ObRegisterCallbacks` sur `PsProcessType`) : c'est le
   plus délicat (il faut remplir un petit tableau `OB_OPERATION_REGISTRATION` + une enveloppe
   `OB_CALLBACK_REGISTRATION`, le tout par pointeur). On lui fournit une **altitude** (un
   identifiant de position dans la chaîne de filtres ; ici `321000`, une valeur de la bande
   dev/test des samples WDK Microsoft, faute d'allocation officielle).

Chaque enregistrement réussi positionne son **drapeau dédié** (`PROCESS_CALLBACK_REGISTERED`,
etc., dans [`state.rs`](src/state.rs)). Ces drapeaux sont indispensables : **désenregistrer
un callback jamais enregistré, ou le désenregistrer deux fois, provoque un bug check.**

### `DriverUnload` — l'ordre inverse, et pour de bonnes raisons

`DriverUnload` doit défaire dans un ordre précis :

1. **Couper les sources d'abord** : désenregistrer les cinq callbacks. Sinon, un callback qui
   tournerait sur un autre CPU pourrait allouer un buffer qu'on est sur le point de libérer.
   On lit chaque drapeau avec un `swap(false)` atomique, pour ne jamais double-désenregistrer.
2. **Annuler l'IRP en attente** : si un agent est bloqué dans son IOCTL, on complète l'IRP
   garé avec `STATUS_CANCELLED` (sinon l'agent resterait bloqué pour toujours).
3. **Vider la file** : `queue_pop_locked` en boucle, en libérant (`ExFreePool`) chaque buffer
   restant — sinon fuite mémoire.
4. **Démonter le namespace** : supprimer le lien symbolique *puis* le device.

---

## 3. Les cinq callbacks kernel

Un **callback kernel** est une fonction que Windows appelle automatiquement à chaque
événement système d'un type donné. WazabiEDR en pose cinq, chacun dans son module sous
[`src/callbacks/`](src/callbacks/). Tous suivent le même squelette : *allouer un buffer →
remplir l'en-tête commun (`make_header`) → copier les champs → `submit_event`*.

| Callback | API d'enregistrement | Capture | Source |
|---|---|---|---|
| Process create/exit | `PsSetCreateProcessNotifyRoutineEx` | Création et fin de processus | [`process.rs`](src/callbacks/process.rs) |
| Image load | `PsSetLoadImageNotifyRoutine` | Chargement d'un PE (DLL/EXE user, ou driver kernel) | [`image.rs`](src/callbacks/image.rs) |
| Registry modify | `CmRegisterCallback` | Écritures/suppressions/créations de clés et valeurs | [`registry.rs`](src/callbacks/registry.rs) |
| Thread create/exit | `PsSetCreateThreadNotifyRoutine` | Création et fin de thread | [`thread.rs`](src/callbacks/thread.rs) |
| Process handle access | `ObRegisterCallbacks(PsProcessType)` | Ouverture/duplication de handle vers un processus | [`object.rs`](src/callbacks/object.rs) |

**Contrainte commune (à graver dans le marbre) :** ces callbacks s'exécutent
**synchroniquement** dans le thread qui a déclenché l'action (chaque `CreateProcess` du
système passe par `process_notify`). Ils **ne doivent jamais bloquer**, et l'allocation
mémoire doit rester légère. En cas d'échec d'allocation (`alloc_event` renvoie `null`), on
**abandonne silencieusement** l'événement : il n'y a nulle part où enregistrer « j'ai perdu
un événement faute de pouvoir allouer un buffer pour le signaler » — le prochain événement
livré comblera le trou via `drop_count`.

### L'en-tête commun : `make_header`

[`callbacks/header.rs`](src/callbacks/header.rs) factorise la fabrication de l'`EventHeader` :
il estampille la version, l'horodatage (`KeQuerySystemTimePrecise` → un **FILETIME**, voir
§4) et **vide atomiquement `DROP_COUNT`** (`swap(0)`) pour que le nombre d'événements perdus
depuis la dernière livraison soit reporté exactement une fois.

### Détails par callback

- **Process** ([`process.rs`](src/callbacks/process.rs)) : `create_info` non-null = création,
  null = fin. À la création on copie le chemin NT de l'exécutable (`ImageFileName`,
  potentiellement null pour les processus lancés par le kernel) et on capture trois PID :
  `process_id` (le nouveau), `parent_process_id`, et `creating_process_id` (qui a *demandé*
  la création — souvent le parent, mais pas toujours : WMI, services…).
- **Image** ([`image.rs`](src/callbacks/image.rs)) : tout mapping d'image PE. `process_id ==
  0` signale une **image kernel** (un driver / module système chargé dans l'espace noyau) —
  utile pour repérer un rootkit. Sinon c'est un chargement user (DLL injection,
  search-order hijacking).
- **Registry** ([`registry.rs`](src/callbacks/registry.rs)) : bâti sur le **Configuration
  Manager** (le composant noyau qui gère le registre). *Toutes* les opérations registre
  passent par `registry_notify` ; on ne `match` que les **mutations** « pre-» (`SetValue`,
  `DeleteValue`, `DeleteKey`, `RenameKey`, `CreateKeyEx`) — les lectures génèrent un bruit
  ingérable. Résoudre le chemin d'une clé depuis son objet noyau passe par
  `CmCallbackGetKeyObjectIDEx`, suivi **obligatoirement** de
  `CmCallbackReleaseKeyObjectIDEx` (sinon fuite de pool à chaque écriture). On retourne
  **toujours** `STATUS_SUCCESS` : renvoyer autre chose annulerait l'opération registre.
- **Thread** ([`thread.rs`](src/callbacks/thread.rs)) : le moins cher (trois `u32`, aucune
  copie de chaîne). L'intérêt EDR est la comparaison `creating_process_id` (le *demandeur*,
  via `PsGetCurrentProcessId`) vs `process_id` (le *propriétaire* du thread) : quand ils
  diffèrent, c'est le schéma classique d'une injection `CreateRemoteThread`. Distinguer le
  légitime (ex. CSRSS qui initialise un processus) du malveillant est le travail de l'agent.
- **Object** ([`object.rs`](src/callbacks/object.rs)) : notification à chaque création/
  duplication de handle vers un objet `Process`. C'est *le* signal du credential dumping
  (`OpenProcess(LSASS, VM_READ)`) et de la préparation d'injection. Par défaut **extrêmement
  bruyant**, donc filtré sur deux axes : (1) les ouvertures **même-processus** sont jetées
  (`CreateProcess` ouvre son propre handle au démarrage) ; (2) un **masque d'accès
  dangereux** (`DANGEROUS_PROCESS_MASK` = `TERMINATE | CREATE_THREAD | VM_OPERATION |
  VM_READ | VM_WRITE | DUP_HANDLE | SUSPEND_RESUME`) : on ne forwarde que si
  `original_desired_access` croise ce masque. On filtre sur le masque **original** (ce que
  l'appelant a demandé) pour qu'un filtre amont qui retirerait des bits ne masque pas
  l'intention. On retourne toujours `OB_PREOP_SUCCESS` (observe-only).

---

## 4. Le format de fil (wire format)

Les événements voyagent en **binaire** (pas en texte), définis dans
[`src/events.rs`](src/events.rs). Ce fichier est le **contrat** avec l'agent : toute
modification doit être répercutée dans `WazabiEDR_Agent::ipc::events` **et** incrémenter
`EVENT_VERSION`, faute de quoi l'agent mal-interpréterait des octets.

### `repr(C, packed)` et le piège de l'alignement

Toutes les structures sont déclarées `#[repr(C, packed)]`. `repr(C)` impose une disposition
mémoire identique à celle du langage C (prévisible, identique des deux côtés) ; `packed`
supprime tout octet de remplissage (*padding*) pour que la structure soit **identique octet
pour octet** entre driver et agent. La contrepartie est un **piège de sûreté** : on ne peut
pas prendre une référence (`&mut champ`) vers un champ d'une structure packed — ce serait une
référence potentiellement non alignée, **comportement indéfini (UB) en Rust**. Le code écrit
donc chaque champ via `core::ptr::addr_of_mut!` + `ptr::write` (vous verrez ce motif partout
dans les callbacks). Les buffers sont aussi *zéro-remplis* (`ptr::write_bytes(buf, 0, …)`)
avant remplissage, pour ne pas livrer à l'user-mode des octets de pool non initialisés (fuite
d'information).

### L'en-tête commun (version 3)

```rust
#[repr(C, packed)]
pub struct EventHeader {
    pub version: u16,      // = EVENT_VERSION (3 aujourd'hui)
    pub type_: u16,        // discriminant : 1..=7 (voir tableau)
    pub timestamp: i64,    // FILETIME : tranches de 100 ns depuis le 1er jan. 1601 UTC
    pub size: u32,         // taille totale de l'événement, en octets
    pub drop_count: u32,   // nb d'événements perdus depuis le précédent livré
}
```

- **FILETIME** est la représentation native du temps sous Windows : un entier 64 bits comptant
  les intervalles de 100 ns depuis le 1er janvier 1601 à minuit UTC. L'agent le convertit en
  ISO-8601 lisible.
- **`drop_count`** est un **delta par livraison** : il est remis à 0 dès qu'il est estampillé
  dans un en-tête (`make_header`), de sorte que l'agent voit uniquement le trou accumulé
  depuis son dernier événement reçu.

### Les sept types d'événements

| `type_` | `EventType` | Structure | Charge utile (au-delà de l'en-tête) |
|---|---|---|---|
| 1 | `ProcessCreate` | `ProcessCreateEvent` | `process_id`, `parent_process_id`, `creating_process_id`, `image_path[512]`, `image_path_len` |
| 2 | `ProcessExit` | `ProcessExitEvent` | `process_id` |
| 3 | `ImageLoad` | `ImageLoadEvent` | `process_id` (0 = kernel), `image_base`, `image_size`, `image_path[512]`, `image_path_len` |
| 4 | `RegistryModify` | `RegistryEvent` | `process_id`, `operation`, `value_type`, `data_size`, `key_path[512]`, `value_name[128]`, `data_preview[256]`, + longueurs |
| 5 | `ThreadCreate` | `ThreadCreateEvent` | `process_id`, `thread_id`, `creating_process_id` |
| 6 | `ThreadExit` | `ThreadExitEvent` | `process_id`, `thread_id` |
| 7 | `ProcessHandleAccess` | `ProcessHandleAccessEvent` | `source_process_id`, `target_process_id`, `desired_access`, `original_desired_access`, `operation` |

Les chemins (`image_path`, `key_path`…) sont des buffers **de taille fixe** en UTF-16, avec
un champ `*_len` qui donne le nombre d'unités valides (en *code units* UTF-16, **pas** en
octets, sans NUL terminal). Les chemins trop longs sont **tronqués** : on copie
`min(longueur, MAX - 1)` unités — la réserve d'un slot sous le MAX permet de distinguer un
chemin exactement à la limite d'un chemin tronqué. Les chemins sont des **chemins NT** (ex.
`\Device\HarddiskVolume3\…\foo.exe`) ; la conversion en chemin DOS (`C:\…`) est laissée à
l'agent (la faire dans le kernel coûterait un `ObQueryNameString` lourd par événement).

Le détail champ-par-champ de chaque structure (et l'enveloppe JSON produite par l'agent) est
dans [`doc/reference/event-types.md`](doc/reference/event-types.md).

---

## 5. La file d'événements (ring buffer)

La file vit dans [`src/queue/`](src/queue/), scindée en deux couches volontairement séparées :

- [`queue/ring.rs`](src/queue/ring.rs) — la **mécanique brute** du ring buffer (push/pop).
- [`queue/submit.rs`](src/queue/submit.rs) — la **colle côté producteur** : prend un événement
  fraîchement bâti et choisit quoi en faire (voir §6).

### Le ring buffer

Un **ring buffer** (file circulaire) est un tableau de taille fixe avec des indices `head`
(tête, où l'on lit) et `tail` (queue, où l'on écrit) qui « tournent » modulo la capacité. Ici
`QUEUE_CAP = 4096` *slots* (pas octets). Chaque `Slot` est `{ data: *mut u8, size: u32 }` :
un buffer de pool non-paginé possédé, qui devra être `ExFreePool`-é **exactement une fois**
par qui dépile le slot.

`queue_push_locked` ([`ring.rs`](src/queue/ring.rs)) : si la file est **pleine**, on évince
la **plus ancienne** entrée (on la libère, on avance `head`) et on incrémente `DROP_COUNT`.
On privilégie donc la **récence** : pour un flux EDR, l'activité la plus récente est la plus
précieuse quand un agent se reconnecte. Toutes les fonctions du module **exigent que
l'appelant détienne déjà `QUEUE_LOCK`** (l'acquisition est laissée à l'appelant, qui a souvent
besoin du lock pour d'autres changements d'état dans la même section critique).

Dimensionnement : à quelques dizaines d'événements processus par seconde, 4096 slots donnent
à un agent déconnecté plusieurs minutes de marge avant de commencer à perdre des événements.

---

## 6. L'IPC : l'IOCTL en appel inversé

C'est le cœur du driver. La communication avec l'agent passe par un **IOCTL** (*I/O Control* :
le mécanisme standard Windows pour qu'un programme user-mode envoie une commande à un driver
et reçoive une réponse). Un seul IOCTL existe, défini dans [`src/ipc/mod.rs`](src/ipc/mod.rs) :

```rust
// Agent → driver : « donne-moi le prochain événement (bloquant) ».
pub const IOCTL_WEDR_GET_EVENT: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS);
```

`METHOD_BUFFERED` veut dire que le noyau copie les données via un **`SystemBuffer`**
intermédiaire (alloué par le I/O Manager), ce qui évite de manipuler directement la mémoire
user — plus simple et plus sûr. `FILE_READ_ACCESS` : l'agent ouvre le device en lecture, il
ne peut donc **que recevoir**, jamais envoyer d'ordre au kernel.

### L'IRP : l'enveloppe d'une requête d'I/O

Quand l'agent appelle `DeviceIoControl`, le I/O Manager construit un **IRP** (*I/O Request
Packet* : la structure centrale du modèle d'I/O Windows — une « enveloppe » qui voyage
user-mode → I/O Manager → driver → I/O Manager → user-mode). Les helpers bas niveau qui la
manipulent sont dans [`ipc/irp.rs`](src/ipc/irp.rs) :

- `current_stack_location(irp)` — récupère l'`IO_STACK_LOCATION` courant (où l'on lit le code
  IOCTL demandé et la taille des buffers). Le chemin de membres est long
  (`Tail.Overlay.__bindgen_anon_2…`) parce que bindgen aplatit les unions C.
- `complete_irp(irp, status, info)` — écrit `IoStatus.Status` (un `NTSTATUS`) +
  `IoStatus.Information` (sens dépendant de l'opération ; ici = octets écrits ou taille
  requise), puis appelle `IofCompleteRequest` qui **réveille l'agent**.
- `mark_irp_pending(irp)` — pose le bit `SL_PENDING_RETURNED`. **Obligatoire** quand on
  renvoie `STATUS_PENDING` : sans lui, le I/O Manager croit la requête terminée et libère
  l'IRP sous nos pieds.

### Le dispatch : chemin rapide vs chemin lent

`dispatch_device_control` ([`ipc/dispatch.rs`](src/ipc/dispatch.rs)) traite l'IOCTL :

- **Chemin rapide** : si la file contient déjà un événement (`queue_pop_locked`), on copie
  dans le `SystemBuffer` et on complète l'IRP **synchroniquement**. (Si le buffer de l'agent
  est trop petit, on échoue avec `STATUS_BUFFER_TOO_SMALL` en indiquant la taille requise, et
  on jette l'événement en bumpant `DROP_COUNT`.)
- **Chemin lent** : si la file est **vide**, on **gare l'IRP** dans `PENDING_IRP` via un
  `compare_exchange(null, irp)` et on renvoie `STATUS_PENDING`. L'agent reste bloqué dans son
  `DeviceIoControl` jusqu'à ce que quelqu'un complète cet IRP : `submit_event` (un nouvel
  événement arrive), `dispatch_cleanup` (l'agent ferme son handle), ou `driver_unload`.

C'est ici qu'on voit l'**appel inversé** : l'agent appelle, et soit on lui sert un événement
immédiat, soit on le met en sommeil jusqu'à ce qu'un callback en produise un.

### `submit_event` : les trois chemins du producteur

Côté producteur, `submit_event` ([`queue/submit.rs`](src/queue/submit.rs)) prend le lock,
récupère l'IRP en attente (`PENDING_IRP.swap(null)`) et choisit :

1. **Chemin 1 (le plus rapide)** — un IRP est garé *et* le buffer de l'agent est assez grand :
   on copie l'événement **directement** dans le buffer user et on complète l'IRP. **L'événement
   ne touche jamais la file.** (On relâche le lock *avant* `IofCompleteRequest` : les routines
   de complétion peuvent s'exécuter et il ne faut pas tenir un spinlock DISPATCH-level pendant.)
2. **Chemin 2** — un IRP est garé mais le buffer est **trop petit** : on échoue l'IRP avec
   `STATUS_BUFFER_TOO_SMALL` (`Information` = taille requise), on jette l'événement, on bumpe
   `DROP_COUNT`. L'agent ré-émettra un IOCTL avec un buffer plus grand.
3. **Chemin 3** — **aucun** IRP en attente : on enfile (`queue_push_locked`). Si la file est
   pleine, la plus ancienne entrée est évincée.

### Device mono-client

`PENDING_IRP` est un **slot unique** ([`state.rs`](src/state.rs)) : un seul IOCTL peut être en
attente à la fois. Un second IOCTL concurrent est **refusé** avec `STATUS_UNSUCCESSFUL`
(le `compare_exchange` échoue car `PENDING_IRP` n'est pas null). C'est volontaire : un seul
agent consomme le flux.

### `dispatch_cleanup` : ne jamais écrire dans de la mémoire libérée

`IRP_MJ_CLEANUP` arrive quand la dernière référence sur le handle de l'agent disparaît (sortie
de processus, `CloseHandle`). On **doit** y annuler l'IRP encore garé : le buffer user associé
est sur le point d'être détruit, et le compléter plus tard écrirait dans de la mémoire libérée.

---

## 7. Synchronisation & sûreté mémoire

Trois mécanismes se superposent, chacun choisi selon ce qu'il protège :

| Donnée | Protection | Pourquoi |
|---|---|---|
| `QUEUE_BUF`, `QUEUE_HEAD/TAIL/LEN` | `QUEUE_LOCK` (`KSPIN_LOCK` à DISPATCH_LEVEL) | Accès concurrents possibles depuis l'IOCTL et les callbacks, sur plusieurs CPU |
| `PENDING_IRP`, `CONTROL_DEVICE`, `OBJECT_CALLBACK_HANDLE` | `AtomicPtr` (ordering AcqRel) | Un seul slot, on veut juste un swap atomique |
| `DROP_COUNT` | `AtomicU32` (Relaxed) | Simple compteur, l'ordre n'importe pas |
| `*_CALLBACK_REGISTERED`, `REGISTRY_CALLBACK_COOKIE` | `AtomicBool` / `AtomicI64` | Lus/écrits hors section critique |

- **`SpinLockGuard`** ([`util/spin_lock.rs`](src/util/spin_lock.rs)) est une garde **RAII** :
  elle acquiert le `KSPIN_LOCK` (en montant à DISPATCH_LEVEL) à la construction et le relâche
  au `Drop`. Avantage : chaque chemin de `return` relâche le lock gratuitement, ce qui supprime
  toute une classe de bugs (oublier de relâcher). Pour relâcher avant la fin de portée (ex.
  avant de compléter un IRP), on appelle `drop(guard)` explicitement. Un lock à DISPATCH-level
  épingle le thread sur le CPU courant, d'où l'interdiction d'I/O bloquante en section
  critique.
- **`SyncCell<T>`** ([`util/sync_cell.rs`](src/util/sync_cell.rs)) est une cellule de mutabilité
  intérieure qu'on marque manuellement `Sync`. Elle **n'offre aucune synchronisation par
  elle-même** : elle sert juste à déclarer des globals mutables (le ring, les indices, le
  stockage du spinlock) qu'on s'engage à ne toucher que sous `QUEUE_LOCK`. C'est moins cher
  qu'un `Mutex`/`RefCell` et reflète la réalité (le compilateur ne « voit » pas notre lock
  kernel).

Le **pool tag** `POOL_TAG = "wEDR"` ([`state.rs`](src/state.rs)) marque toutes les
allocations, ce qui les rend repérables dans `poolmon` / `!poolused` sous WinDbg pour traquer
les fuites.

---

## 8. Par où commencer

Pour lire le code dans le bon ordre :

1. [`src/lib.rs`](src/lib.rs) — `DriverEntry`/`DriverUnload` : ce qui se met en place, dans
   quel ordre, et comment on démonte.
2. [`src/events.rs`](src/events.rs) — le contrat binaire avec l'agent (à lire avec
   [`doc/reference/event-types.md`](doc/reference/event-types.md)).
3. [`src/callbacks/process.rs`](src/callbacks/process.rs) — le callback le plus simple, pour
   comprendre le squelette *alloc → header → champs → submit*.
4. [`src/queue/submit.rs`](src/queue/submit.rs) puis
   [`src/ipc/dispatch.rs`](src/ipc/dispatch.rs) — les deux faces de l'appel inversé (producteur
   et consommateur).
5. Les autres callbacks ([`registry.rs`](src/callbacks/registry.rs),
   [`object.rs`](src/callbacks/object.rs)…) une fois le motif assimilé.

Documentation associée :

- **Compiler** le driver : [`doc/usage/building.md`](doc/usage/building.md).
- **Installer** le driver (test signing, `pnputil`) : [`doc/usage/installing-driver.md`](doc/usage/installing-driver.md).
- **Référence** des événements : [`doc/reference/event-types.md`](doc/reference/event-types.md).
- Côté consommateur : `ARCHITECTURE.md` du dépôt [`WazabiEDR_Agent`](../WazabiEDR_Agent/).
