# Référence des types d'événements

Tous les événements kernel émis par le driver, champ par champ.
Source : [`src/events.rs`](../../src/events.rs) — doit rester **identique octet pour octet**
avec `WazabiEDR_Agent/src/ipc/events.rs`.

`EVENT_VERSION` vaut aujourd'hui **3** côté driver. Il est incrémenté à tout changement de
disposition mémoire.

> **Note de version.** La doc historique et la branche `feat/waza-detection` de l'agent
> décrivent une version **4** avec un champ `trunc_count` supplémentaire dans l'en-tête (nombre
> de champs tronqués depuis le dernier événement livré). Le **code actuel du driver** est en
> version 3 et **n'a pas** ce champ. Cette référence décrit le driver tel qu'il est. À
> réconcilier lorsque le driver passera en v4.

La disposition binaire ci-dessous est le **format de fil driver↔agent**. Sur disque (le spool)
et sur le réseau vers le serveur, les événements sont ré-encodés en NDJSON par l'agent — voir
[Enveloppe JSON](#enveloppe-json-produite-par-lagent) en fin de document.

## En-tête commun

Chaque événement commence par cette structure packed :

```rust
#[repr(C, packed)]
pub struct EventHeader {
    pub version:    u16,    // EVENT_VERSION au moment de l'écriture (3)
    pub type_:      u16,    // discriminant (tableau ci-dessous)
    pub timestamp:  i64,    // FILETIME : tranches de 100 ns depuis 1601-01-01 UTC
    pub size:       u32,    // taille totale de l'événement, en octets
    pub drop_count: u32,    // événements perdus entre le précédent livré et celui-ci
}
```

`drop_count` est un **delta par livraison** : il est remis à 0 après avoir été estampillé.
Sa somme sur un flux donne donc le total des pertes depuis la dernière remise à zéro (une
reconnexion de l'agent).

## Discriminants de type

| `type_` | `EventType` | Structure |
|---|---|---|
| 1 | `ProcessCreate` | `ProcessCreateEvent` |
| 2 | `ProcessExit` | `ProcessExitEvent` |
| 3 | `ImageLoad` | `ImageLoadEvent` |
| 4 | `RegistryModify` | `RegistryEvent` |
| 5 | `ThreadCreate` | `ThreadCreateEvent` |
| 6 | `ThreadExit` | `ThreadExitEvent` |
| 7 | `ProcessHandleAccess` | `ProcessHandleAccessEvent` |

## ProcessCreate (1)

```rust
#[repr(C, packed)]
pub struct ProcessCreateEvent {
    pub header: EventHeader,
    pub process_id:          u32,
    pub parent_process_id:   u32,
    pub creating_process_id: u32,
    pub image_path:          [u16; 512],   // IMAGE_PATH_MAX, unités UTF-16
    pub image_path_len:      u16,
}
```

| Champ | Signification |
|---|---|
| `process_id` | PID du nouveau processus. |
| `parent_process_id` | PID du parent. |
| `creating_process_id` | PID qui a **demandé** la création (souvent le parent, mais peut différer : WMI, services…). |
| `image_path` | Chemin NT de l'exécutable, ex. `\Device\HarddiskVolume3\Windows\System32\notepad.exe`. **Jusqu'à 512 unités UTF-16** ; au-delà, tronqué. |
| `image_path_len` | Nombre d'unités UTF-16 (PAS d'octets), sans NUL terminal. |

La conversion chemin NT → chemin DOS est le travail de l'agent (jamais faite dans le kernel :
`ObQueryNameString` serait une étape lourde par événement).

## ProcessExit (2)

```rust
#[repr(C, packed)]
pub struct ProcessExitEvent {
    pub header: EventHeader,
    pub process_id: u32,
}
```

Événement à PID unique. Le code de sortie n'est pas remonté (le PID suffit pour un EDR ; ce
qui compte est la corrélation avec le `ProcessCreate` antérieur).

## ImageLoad (3)

```rust
#[repr(C, packed)]
pub struct ImageLoadEvent {
    pub header: EventHeader,
    pub process_id:     u32,            // 0 = image kernel
    pub image_base:     u64,
    pub image_size:     u64,
    pub image_path:     [u16; 512],
    pub image_path_len: u16,
}
```

| Champ | Signification |
|---|---|
| `process_id` | Processus cible. **`0` = image kernel** (driver / module système). |
| `image_base` | Adresse de chargement dans l'espace d'adressage de la cible (ou du kernel si pid == 0). |
| `image_size` | Taille de l'image en octets. |
| `image_path` | Chemin NT — mêmes conventions que `ProcessCreate`. |

Les chargements côté user attrapent l'injection de DLL / le détournement d'ordre de
recherche ; côté kernel, le chargement de drivers rootkit.

## RegistryModify (4)

```rust
#[repr(C, packed)]
pub struct RegistryEvent {
    pub header: EventHeader,
    pub process_id:       u32,
    pub operation:        u16,        // valeur de l'enum RegistryOp
    pub value_type:       u32,        // REG_SZ / REG_DWORD / … (0 si N/A)
    pub data_size:        u32,        // taille réelle totale des données (non tronquée)
    pub key_path:         [u16; 512], // REGISTRY_KEY_PATH_MAX
    pub key_path_len:     u16,
    pub value_name:       [u16; 128], // REGISTRY_VALUE_NAME_MAX
    pub value_name_len:   u16,
    pub data_preview:     [u8; 256],  // REGISTRY_DATA_PREVIEW_MAX (octets bruts)
    pub data_preview_len: u16,        // = min(data_size, REGISTRY_DATA_PREVIEW_MAX)
}
```

Discriminant `operation` :

| Valeur | `RegistryOp` | Déclenché par | Champs renseignés |
|---|---|---|---|
| 1 | `SetValue` | `RegNtPreSetValueKey` | tous les champs pertinents |
| 2 | `DeleteValue` | `RegNtPreDeleteValueKey` | `key_path`, `value_name` (champs data vides) |
| 3 | `DeleteKey` | `RegNtPreDeleteKey` | `key_path` seul |
| 4 | `RenameKey` | `RegNtPreRenameKey` | `key_path` seul (source — le nouveau nom n'est pas capturé) |
| 5 | `CreateKey` | `RegNtPreCreateKeyEx` | `key_path` seul |

`value_type` reflète les constantes Win32 `REG_*` : `1 = REG_SZ`, `2 = REG_EXPAND_SZ`,
`3 = REG_BINARY`, `4 = REG_DWORD`, `7 = REG_MULTI_SZ`, `11 = REG_QWORD`.

`data_preview` contient jusqu'à 256 octets bruts de la valeur écrite. `data_size` reporte
**toujours** le total réel même si l'aperçu est tronqué : `data_size > data_preview_len` ⇒
tronqué. On n'émet que sur les **mutations** — les notifications de lecture génèrent un bruit
ingérable.

## ThreadCreate (5)

```rust
#[repr(C, packed)]
pub struct ThreadCreateEvent {
    pub header: EventHeader,
    pub process_id:          u32,    // processus propriétaire
    pub thread_id:           u32,    // TID kernel
    pub creating_process_id: u32,    // PID demandeur (PsGetCurrentProcessId)
}
```

Cas intéressant pour un EDR : `creating_process_id != process_id` signifie qu'un processus a
créé un thread *dans* un autre processus — le schéma d'injection `CreateRemoteThread`.

## ThreadExit (6)

```rust
#[repr(C, packed)]
pub struct ThreadExitEvent {
    pub header: EventHeader,
    pub process_id: u32,
    pub thread_id:  u32,
}
```

Symétrique de `ThreadCreate`. On connaît toujours le processus propriétaire, **jamais**
l'acteur qui a demandé la fin (Windows ne le fournit pas aux callbacks de sortie de thread).

## ProcessHandleAccess (7)

```rust
#[repr(C, packed)]
pub struct ProcessHandleAccessEvent {
    pub header: EventHeader,
    pub source_process_id:       u32,
    pub target_process_id:       u32,
    pub desired_access:          u32,    // masque après la chaîne de callbacks
    pub original_desired_access: u32,    // masque demandé par l'appelant
    pub operation:               u16,    // enum HandleAccessOp
}
```

| Champ | Signification |
|---|---|
| `source_process_id` | PID qui réalise l'open/duplicate. |
| `target_process_id` | PID dont le handle est ouvert/dupliqué. |
| `desired_access` | Masque final, après qu'un éventuel callback OB amont a retiré des droits. |
| `original_desired_access` | Ce que l'appelant a demandé à l'origine. À utiliser pour filtrer — il montre l'intention. |
| `operation` | `1 = Create` (`OB_OPERATION_HANDLE_CREATE`), `2 = Duplicate`. |

Le driver filtre sur `original_desired_access & DANGEROUS_PROCESS_MASK != 0` — les événements
qui ne croisent pas le masque dangereux sont jetés dans le kernel. Masque = `TERMINATE |
CREATE_THREAD | VM_OPERATION | VM_READ | VM_WRITE | DUP_HANDLE | SUSPEND_RESUME` (voir
[`callbacks/object.rs`](../../src/callbacks/object.rs)).

Bits d'accès Win32 `PROCESS_*` : `0x0001 TERMINATE`, `0x0002 CREATE_THREAD`,
`0x0008 VM_OPERATION`, `0x0010 VM_READ`, `0x0020 VM_WRITE`, `0x0040 DUP_HANDLE`,
`0x0080 CREATE_PROCESS`, `0x0400 QUERY_INFORMATION`, `0x0800 SUSPEND_RESUME`,
`0x1000 QUERY_LIMITED_INFORMATION`, `0x00100000 SYNCHRONIZE`.

## Résumé des constantes

```rust
pub const EVENT_VERSION:             u16   = 3;
pub const IMAGE_PATH_MAX:            usize = 512;   // unités UTF-16
pub const REGISTRY_KEY_PATH_MAX:     usize = 512;   // unités UTF-16
pub const REGISTRY_VALUE_NAME_MAX:   usize = 128;   // unités UTF-16
pub const REGISTRY_DATA_PREVIEW_MAX: usize = 256;   // octets bruts
pub const QUEUE_CAP:                 usize = 4096;  // slots du ring, pas octets
```

Modifier l'une de ces tailles (sauf `QUEUE_CAP`) impose d'incrémenter `EVENT_VERSION` et de
mettre à jour les deux côtés.

## Enveloppe JSON produite par l'agent

L'agent ré-encode chaque événement en un document JSON sur une ligne (NDJSON) avant de
l'écrire dans le spool, puis l'expédie au serveur. L'enveloppe est alignée sur le schéma
Pydantic `EventIn` du serveur (`WazabiEDR_Server/app/schemas/event.py`) pour atterrir sans
erreur dans OpenSearch (`wazabi-events`). Exemple (événement kernel) :

```json
{
  "ts": "2026-05-12T14:00:01.123Z",
  "module": "kernel_callback",
  "event_type": "process_create",
  "process": { "pid": 1234, "ppid": 4192, "path": "..." },
  "raw": { "pid": 1234, "parent_pid": 4192, "creating_pid": 4192, "image_path": "..." },
  "source": "kernel",
  "kind": "ProcessCreate",
  "event_version": 3,
  "drop_count": 0
}
```

| `event_type` (serveur, snake_case) | `kind` (driver) |
|---|---|
| `process_create` | `ProcessCreate` |
| `process_terminate` | `ProcessExit` |
| `module_load` | `ImageLoad` |
| `registry_write` | `RegistryModify` |
| `thread_create` | `ThreadCreate` |
| `thread_exit` | `ThreadExit` |
| `process_handle_access` | `ProcessHandleAccess` |

Le détail de l'enveloppe et des payloads `raw` par `kind` est documenté côté agent
(`WazabiEDR_Agent` → `src/ipc/json.rs`) et côté serveur ([`WazabiEDR_Server`](../../../WazabiEDR_Server/)
→ `doc/reference/server-api.md`).
