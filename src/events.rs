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
pub const EVENT_VERSION: u16 = 1;

/// Maximum number of UTF-16 code units we copy from a process image path.
///
/// `ProcessCreateEvent` has a fixed-size buffer, so longer NT paths get
/// truncated; `image_path_len` reports the exact number of valid units.
pub const IMAGE_PATH_MAX: usize = 512;

/// Discriminant for `EventHeader::type_`.
#[repr(u16)]
#[allow(dead_code)]
pub enum EventType {
    ProcessCreate = 1,
    ProcessExit = 2,
    ImageLoad = 3,
}

/// Common header carried by every event.
///
/// `drop_count` reports how many events the driver had to evict from the
/// queue between the previous delivered event and this one — that lets the
/// agent surface gaps without us emitting a separate "loss" event type.
#[repr(C, packed)]
pub struct EventHeader {
    pub version: u16,
    pub type_: u16,
    /// 100ns ticks since 1601-01-01 UTC (Windows FILETIME).
    pub timestamp: i64,
    pub size: u32,
    pub drop_count: u32,
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
