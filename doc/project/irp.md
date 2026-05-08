IRP (I/O Request Packet). C'est la structure de données centrale du modèle d'I/O Windows.

C'est quoi concrètement

Un IRP est un gros struct alloué par le I/O Manager qui représente une requête d'I/O en cours de vie. Quand un programme userland fait ReadFile, WriteFile, DeviceIoControl, CreateFile… le I/O Manager     
construit un IRP, le passe au driver concerné, et attend que le driver le marque "complétée".

Tu peux le voir comme une enveloppe qui voyage : userland → I/O Manager → driver(s) → I/O Manager → userland.

Ce que contient un IRP (les champs qu'on touche dans ton code)

typedef struct _IRP {
IO_STATUS_BLOCK   IoStatus;          // ← tu y écris Status + Information à la complétion
PVOID             AssociatedIrp.SystemBuffer;  // ← pour METHOD_BUFFERED, le buffer copié depuis/vers userland
/* ... */
/* + un tableau de IO_STACK_LOCATION : un par couche du stack de drivers */
} IRP;

À chaque "couche" du stack de drivers correspond un IO_STACK_LOCATION. C'est ce que current_stack_location récupère :

let stack = current_stack_location(irp);
let ioctl  = (*stack).Parameters.DeviceIoControl.IoControlCode;
let outlen = (*stack).Parameters.DeviceIoControl.OutputBufferLength;

C'est dans le stack location que tu lis quel IOCTL est demandé, la taille des buffers, etc.

Cycle de vie typique

1. Userland : DeviceIoControl(handle, IOCTL_WEDR_GET_EVENT, …).
2. I/O Manager : alloue un IRP, remplit le stack location (ioctl, buffers), appelle DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] → tombe dans ta dispatch_device_control.
3. Ton driver :
   - soit complète synchrone : IoStatus.Status = STATUS_SUCCESS; IoStatus.Information = N; IofCompleteRequest(irp) → l'IRP retourne au I/O Manager qui réveille userland.
   - soit retourne STATUS_PENDING après IoMarkIrpPending (notre mark_irp_pending) → l'IRP est "garée", userland reste bloqué dans DeviceIoControl. Plus tard, quelqu'un (chez nous : submit_event,
   dispatch_cleanup, ou driver_unload) la complète et userland se réveille.

Les deux champs de complétion

(*irp).IoStatus.__bindgen_anon_1.Status = status;       // NTSTATUS
(*irp).IoStatus.Information             = info;         // ULONG_PTR : sens dépend du Major

Information veut dire des choses différentes selon le major :
- IRP_MJ_READ / IRP_MJ_WRITE : nombre d'octets lus/écrits.
- IRP_MJ_DEVICE_CONTROL : nombre d'octets écrits dans l'output buffer (ce que userland reçoit dans *lpBytesReturned).
- En cas de STATUS_BUFFER_TOO_SMALL : taille requise (c'est pour ça que dans submit_event on fait complete_irp(pending, STATUS_BUFFER_TOO_SMALL, size as usize)).

Pourquoi c'est subtil

- Tu n'as pas le droit d'oublier de la compléter. Une IRP non complétée = thread userland gelé pour toujours.
- Tu n'as pas le droit de la compléter deux fois. Bug check. C'est pour ça qu'on swap PENDING_IRP à null avec un atomic : un seul thread peut "gagner" la complétion.
- Si tu retournes STATUS_PENDING sans IoMarkIrpPending, le I/O Manager pense que tu as fini et libère l'IRP — quand tu vas tenter de la compléter plus tard tu touches de la mémoire libérée. C'est pour ça
  que mark_irp_pending est appelé juste avant return STATUS_PENDING dans dispatch_device_control.

Côté ton code, où ça vit

ipc/irp.rs        ── helpers bas-niveau : current_stack_location, mark_irp_pending, complete_irp
ipc/dispatch.rs   ── les fonctions qui reçoivent l'IRP en argument (les "MajorFunction" du driver)
state.rs          ── PENDING_IRP : le slot où on stocke l'IRP en attente (AtomicPtr)
queue/submit.rs   ── code producteur qui pioche PENDING_IRP et la complète

L'IRP, dans ton EDR, c'est le médium de transport entre l'agent et le driver : à chaque fois que l'agent appelle DeviceIoControl, c'est une IRP qui voyage, et selon qu'elle est complétée tout de suite ou
parquée, ça décide du fast/slow path qu'on a regardé tout à l'heure.