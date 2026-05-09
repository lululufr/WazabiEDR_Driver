//! Wire format shared between the driver and the userland agent.
//!
//! These structs are written to a non-paged pool buffer by the driver and
//! parsed byte-for-byte by the agent. Any change here MUST be mirrored in
//! `WazabiEDR_Agent::ipc::events` and bump `EVENT_VERSION` so the agent
//! refuses to misinterpret an old format.

/// Schema version stamped on every event header.
///
/// The agent rejects any event with a different version instead of
/// guessing field layouts.
///
/// Bumped to 4 when `EventHeader::trunc_count` was added (driver-side
/// counter of fields that had to be truncated to fit fixed-size buffers).
pub const EVENT_VERSION: u16 = 4;

/// Maximum number of UTF-16 code units we copy from a process image path.
///
/// `ProcessCreateEvent` has a fixed-size buffer, so longer NT paths get
/// truncated; `image_path_len` reports the exact number of valid units.
pub const IMAGE_PATH_MAX: usize = 512;

/// Maximum number of UTF-16 code units we copy from a registry key path.
/// Long keys (deep `HKLM\…\…` paths) get truncated, with `key_path_len`
/// reporting the exact number of valid units.
pub const REGISTRY_KEY_PATH_MAX: usize = 512;

/// Maximum number of UTF-16 code units we copy from a registry value name.
/// Value names are typically short — 128 is comfortably above what real
/// software uses while keeping the per-event size reasonable.
pub const REGISTRY_VALUE_NAME_MAX: usize = 128;

/// Maximum number of bytes of value data shipped with a `RegistrySetValue`
/// event. Longer payloads are truncated; `data_size` always reports the
/// real total so the agent can flag truncation.
pub const REGISTRY_DATA_PREVIEW_MAX: usize = 256;

/// Discriminant for `EventHeader::type_`.
#[repr(u16)]
#[allow(dead_code)]
pub enum EventType {
    ProcessCreate = 1,
    ProcessExit = 2,
    ImageLoad = 3,
    RegistryModify = 4,
    ThreadCreate = 5,
    ThreadExit = 6,
    ProcessHandleAccess = 7,
}

/// Sub-discriminant for `ProcessHandleAccessEvent::operation`.
#[repr(u16)]
#[allow(dead_code)]
pub enum HandleAccessOp {
    /// `OB_OPERATION_HANDLE_CREATE` — a new handle is being opened on
    /// the target process (e.g. `OpenProcess`).
    Create = 1,
    /// `OB_OPERATION_HANDLE_DUPLICATE` — an existing handle is being
    /// duplicated (e.g. `DuplicateHandle`). Source/target processes are
    /// also reported so handle-laundering is visible.
    Duplicate = 2,
}

/// Sub-discriminant for `RegistryEvent::operation`.
///
/// We only emit events for operations that mutate the registry — reads
/// (`RegNtPreQueryKey`, …) generate enormous noise and aren't useful for
/// detection at this layer.
#[repr(u16)]
#[allow(dead_code)]
pub enum RegistryOp {
    /// `RegNtPreSetValueKey` — a value is being written. `value_name`,
    /// `value_type` and `data_size` / `data_preview` are populated.
    SetValue = 1,
    /// `RegNtPreDeleteValueKey` — a value is being removed. `value_name`
    /// is populated; data fields are empty.
    DeleteValue = 2,
    /// `RegNtPreDeleteKey` — the whole key is being removed. Only
    /// `key_path` is populated.
    DeleteKey = 3,
    /// `RegNtPreRenameKey` — the key is being renamed. Today we only log
    /// the source key path; the new name is not captured.
    RenameKey = 4,
    /// `RegNtPreCreateKeyEx` — a new subkey is being opened with create
    /// disposition. Only `key_path` is populated.
    CreateKey = 5,
}

/// Common header carried by every event.
///
/// `drop_count` reports how many events the driver had to evict from the
/// queue between the previous delivered event and this one — that lets the
/// agent surface gaps without us emitting a separate "loss" event type.
///
/// `trunc_count` reports how many path/name/data fields had to be
/// truncated to fit the per-event fixed-size buffers since the previous
/// delivered event. A non-zero value tells the agent that some long
/// strings on the wire were cut short.
#[repr(C, packed)]
pub struct EventHeader {
    pub version: u16,
    pub type_: u16,
    /// 100ns ticks since 1601-01-01 UTC (Windows FILETIME).
    pub timestamp: i64,
    pub size: u32,
    pub drop_count: u32,
    pub trunc_count: u32,
}

#[repr(C, packed)]
pub struct ProcessCreateEvent {
    pub header: EventHeader,
    pub process_id: u32,
    pub parent_process_id: u32,
    pub creating_process_id: u32,
    /// NT path of the executable (e.g. `\Device\HarddiskVolume3\…\foo.exe`).
    /// Userland is responsible for any DOS-path conversion.
    pub image_path: [u16; IMAGE_PATH_MAX],
    /// UTF-16 character count (NOT bytes), no terminating NUL.
    pub image_path_len: u16,
}

#[repr(C, packed)]
pub struct ProcessExitEvent {
    pub header: EventHeader,
    pub process_id: u32,
}

/// Image-load event.
///
/// Fires whenever a PE image is mapped — DLL/EXE into a user process, or
/// a kernel-mode driver/module (in which case `process_id == 0`).
///
/// `image_base` and `image_size` come straight from `IMAGE_INFO`; they're
/// the address and length of the loaded image in the target's address
/// space (kernel space when `process_id == 0`).
#[repr(C, packed)]
pub struct ImageLoadEvent {
    pub header: EventHeader,
    /// Target process. `0` denotes a kernel-mode image (driver / system
    /// module loaded into the kernel address space).
    pub process_id: u32,
    /// Load address in the target process (or kernel).
    pub image_base: u64,
    /// Image size in bytes.
    pub image_size: u64,
    /// NT path of the image. Same conventions as `ProcessCreateEvent`.
    pub image_path: [u16; IMAGE_PATH_MAX],
    pub image_path_len: u16,
}

/// Registry-modification event.
///
/// Emitted from `CmRegisterCallback`'s "pre" notifications, so the event
/// describes a change that is *about to* happen — the driver always lets
/// the operation through unmodified, it only observes.
///
/// Field semantics depend on `operation` (see [`RegistryOp`]):
/// - `SetValue` → every field meaningful.
/// - `DeleteValue` → `value_name*` populated, data fields empty.
/// - `DeleteKey`/`RenameKey`/`CreateKey` → only `key_path*` populated.
///
/// `data_preview` carries up to `REGISTRY_DATA_PREVIEW_MAX` bytes of the
/// value being written. `data_size` reflects the real (untruncated) size,
/// so the agent can tell whether the preview is complete.
#[repr(C, packed)]
pub struct RegistryEvent {
    pub header: EventHeader,
    /// PID of the thread that triggered the registry operation. Captured
    /// via `PsGetCurrentProcessId` inside the callback.
    pub process_id: u32,
    /// Which kind of write — see [`RegistryOp`].
    pub operation: u16,
    /// `REG_SZ` / `REG_DWORD` / … — the value type from
    /// `REG_SET_VALUE_KEY_INFORMATION::Type`. Zero when not applicable.
    pub value_type: u32,
    /// Total size of the value data in bytes (NOT clamped to the preview
    /// length). Lets the agent flag truncation.
    pub data_size: u32,
    /// NT path of the affected key (e.g. `\REGISTRY\MACHINE\…`).
    pub key_path: [u16; REGISTRY_KEY_PATH_MAX],
    /// UTF-16 character count of `key_path` (no terminating NUL).
    pub key_path_len: u16,
    /// Value name; empty when the operation targets the key itself.
    pub value_name: [u16; REGISTRY_VALUE_NAME_MAX],
    /// UTF-16 character count of `value_name` (no terminating NUL).
    pub value_name_len: u16,
    /// First bytes of the data being written. Opaque on the wire — its
    /// interpretation depends on `value_type` (string for `REG_SZ`,
    /// little-endian u32 for `REG_DWORD`, raw bytes for `REG_BINARY`, …).
    pub data_preview: [u8; REGISTRY_DATA_PREVIEW_MAX],
    /// Number of valid bytes in `data_preview`. Equals
    /// `min(data_size, REGISTRY_DATA_PREVIEW_MAX)`.
    pub data_preview_len: u16,
}

/// Thread-creation event.
///
/// Captures every new thread system-wide. The interesting field for an
/// EDR is the relationship between `creating_process_id` and `process_id`:
/// when they differ, the creating process spawned a thread *inside*
/// another process — the classic `CreateRemoteThread`-based injection
/// pattern.
#[repr(C, packed)]
pub struct ThreadCreateEvent {
    pub header: EventHeader,
    /// PID of the process the new thread runs in (its owner).
    pub process_id: u32,
    /// Kernel TID of the new thread.
    pub thread_id: u32,
    /// PID of the process that *requested* the thread creation, captured
    /// via `PsGetCurrentProcessId` inside the notification. Equal to
    /// `process_id` for normal in-process threads; different for remote
    /// thread injections.
    pub creating_process_id: u32,
}

/// Thread-exit event. We always know the owning process, never the actor.
#[repr(C, packed)]
pub struct ThreadExitEvent {
    pub header: EventHeader,
    pub process_id: u32,
    pub thread_id: u32,
}

/// Process-handle-access event.
///
/// Emitted by the object-manager `OB_OPERATION_HANDLE_CREATE` /
/// `OB_OPERATION_HANDLE_DUPLICATE` callbacks registered against
/// `PsProcessType`. The driver only forwards events whose requested
/// access intersects [`crate::callbacks::object::DANGEROUS_PROCESS_MASK`]
/// — the noise-to-signal ratio of plain `OpenProcess(QUERY_LIMITED)`
/// from system services would otherwise be unmanageable.
///
/// Both access masks are surfaced because OB callbacks installed by
/// other drivers may strip rights from `DesiredAccess` — comparing it
/// against `original_desired_access` exposes that interception.
#[repr(C, packed)]
pub struct ProcessHandleAccessEvent {
    pub header: EventHeader,
    /// PID of the process performing the open/duplicate.
    pub source_process_id: u32,
    /// PID of the process whose handle is being opened/duplicated.
    pub target_process_id: u32,
    /// Access mask after any prior callback in the chain stripped rights.
    pub desired_access: u32,
    /// Access mask the caller originally asked for.
    pub original_desired_access: u32,
    /// Which OB operation — see [`HandleAccessOp`].
    pub operation: u16,
}
