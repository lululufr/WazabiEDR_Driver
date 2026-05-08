Architecture générale

L'EDR fait passer des événements du kernel vers l'userland (process create/exit, image load). Le pattern utilisé est l'inverted call : c'est l'agent qui appelle le driver à répétition, pas le driver qui  
pousse vers l'agent. Concrètement :

[kernel callback]──submit_event──┐                                                                                                                                                                          
                                ▼                        
┌──────────────────────────┐
│  PENDING_IRP  (1 slot)   │  ◄── DeviceIoControl(GET_EVENT)
│       OU                 │
│  QUEUE_BUF (ring 4096)   │
└──────────────────────────┘

Deux raisons à ce choix :
1. Backpressure simple : si l'agent est lent ou déconnecté, les événements s'accumulent dans la queue ; au-delà de 4096 on jette les plus anciens et on incrémente DROP_COUNT. L'agent voit le compteur dans
   le prochain header et sait combien il a manqué.
2. Pas de thread driver : on n'a pas besoin de PsCreateSystemThread. Tout ce qui produit (callbacks) ou consomme (IOCTL) est appelé par quelqu'un d'autre (le scheduler Windows, l'agent).

  ---
Flux d'un événement

Prenons un CreateProcess dans le système :

1. Kernel appelle process_notify (callbacks/process.rs).
2. emit_process_create :
   - alloc_event → buffer en pool non-paginé,
   - make_header → version, timestamp, drop_count atomique,
   - copie des champs (tous via addr_of_mut! parce que la struct est repr(C, packed)),
   - submit_event (queue/submit.rs).
3. submit_event prend le spinlock et choisit un des trois chemins :
   - Path 1 (rapide) : PENDING_IRP ≠ null et le buffer agent est assez grand → on copie directement dans irp.AssociatedIrp.SystemBuffer, on release le lock, on complete l'IRP. L'événement n'a jamais touché
   la queue.
   - Path 2 : PENDING_IRP ≠ null mais buffer trop petit → on échoue l'IRP avec STATUS_BUFFER_TOO_SMALL (Information = taille requise) et on drop l'événement. L'agent va re-issue un IOCTL avec un buffer
   plus grand.
   - Path 3 : pas d'agent en attente → enqueue. Si plein, queue_push_locked éjecte la plus ancienne entrée et bump DROP_COUNT.

Côté agent :

1. DeviceIoControl(IOCTL_WEDR_GET_EVENT, …) arrive dans dispatch_device_control.
2. Si la queue a quelque chose → fast path : pop, copie dans le SystemBuffer, complete.
3. Sinon → on park l'IRP dans PENDING_IRP via compare_exchange(null, irp) et on retourne STATUS_PENDING. L'agent est bloqué jusqu'à ce que :
   - submit_event Path 1 le réveille avec un événement,
   - ou dispatch_cleanup le cancel (l'agent ferme son handle),
   - ou driver_unload le cancel (driver déchargé).

C'est pour ça que le slot est single-client : un seul IRP en attente à la fois. Un deuxième IOCTL concurrent se fait rejeter avec STATUS_UNSUCCESSFUL.

  ---
Synchronisation

Trois mécanismes superposés :

┌────────────────────────────────┬──────────────────────────────────────────┬──────────────────────────────────────────────────────────────────────────────────┐
│             Donnée             │                Protection                │                                     Pourquoi                                     │
├────────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────┤
│ QUEUE_BUF, QUEUE_HEAD/TAIL/LEN │ QUEUE_LOCK (KSPIN_LOCK à DISPATCH_LEVEL) │ accès depuis IOCTL et callbacks, donc potentiellement concurrent multi-CPU       │
├────────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────┤
│ PENDING_IRP                    │ AtomicPtr + ordering AcqRel              │ un seul slot, on veut juste "swap atomique"                                      │
├────────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────┤
│ DROP_COUNT                     │ AtomicU32 Relaxed                        │ compteur, l'ordre n'importe pas                                                  │
├────────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────┤
│ *_CALLBACK_REGISTERED          │ AtomicBool AcqRel                        │ un seul flag par callback pour éviter le double-register/unregister (= bugcheck) │
└────────────────────────────────┴──────────────────────────────────────────┴──────────────────────────────────────────────────────────────────────────────────┘

SpinLockGuard (le refactor qu'on vient de faire) fait que chaque chemin de sortie release le lock automatiquement. Quand on doit release avant un appel à IofCompleteRequest (parce que les completion
routines tournent à un IRQL plus bas), on drop(guard) explicitement.

  ---
Que fait dispatch.rs (ton fichier ouvert)

Quatre routines, une par classe d'IRP :

- dispatch_create_close (IRP_MJ_CREATE / IRP_MJ_CLOSE) — l'agent ouvre/ferme le handle. Rien à faire, on retourne STATUS_SUCCESS.
- dispatch_cleanup (IRP_MJ_CLEANUP) — la dernière référence sur le file object disparaît (l'agent meurt ou ferme). On doit annuler l'IRP parqué dans PENDING_IRP : son buffer userland est sur le point
  d'être démoli, le compléter plus tard écrirait dans de la mémoire libérée.
- dispatch_device_control (IRP_MJ_DEVICE_CONTROL) — le cœur. Filtre sur IOCTL_WEDR_GET_EVENT puis enchaîne fast path / slow path. Le mark_irp_pending avant STATUS_PENDING est obligatoire : sinon le I/O
  manager considère l'IRP comme complétée et la libère.
- dispatch_invalid — fallback pour tout IRP_MJ_* qu'on ne gère pas. Il doit exister parce que DriverEntry initialise tous les slots de MajorFunction (un slot NULL = bugcheck à la première IRP qui matche).

  ---
Module map (pourquoi c'est découpé comme ça)

events.rs      ── format wire : ce que l'agent et le driver doivent partager byte-pour-byte
state.rs       ── tous les globals : si tu veux savoir ce qui est mutable, c'est ici et nulle part ailleurs
ipc/           ── tout ce qui parle au I/O manager (codes IOCTL, helpers IRP, dispatch)
queue/         ── le ring buffer + la submission ; isolé de l'IPC pour ne pas mélanger les couches
callbacks/     ── les routines enregistrées auprès du kernel ; chacune sa source d'événements
util/          ── primitives sans logique métier : SyncCell, SpinLockGuard, wstr16
lib.rs         ── orchestration : DriverEntry monte tout dans le bon ordre, DriverUnload démonte dans l'ordre inverse

Règle qu'on suit : chaque fichier répond à une question. state.rs = "qu'est-ce qui est partagé ?", submit.rs = "comment un événement quitte un callback ?", dispatch.rs = "comment le driver répond à
l'agent ?". Si tu te poses une question et que la réponse est éparpillée dans 3 fichiers, c'est qu'on a raté un découpage.
