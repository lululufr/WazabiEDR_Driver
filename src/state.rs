//! Driver-wide global state.
//!
//! Anything mutable lives here so the rest of the codebase can be read as
//! "pure" logic. The synchronization rules are:
//!
//! - Items wrapped in `SyncCell` (the queue ring + indices, the spinlock
//!   storage) must only be touched while holding `QUEUE_LOCK`.
//! - `AtomicXxx` items are safe to access without the lock.
//! - Anything mutated outside this scheme is a bug.

use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicPtr, AtomicU32};

use wdk_sys::KSPIN_LOCK;

use crate::util::SyncCell;

/// Pool tag — visible in `poolmon` / WinDbg `!poolused` for leak hunting.
/// Reads as `wEDR` little-endian.
pub const POOL_TAG: u32 = u32::from_ne_bytes(*b"wEDR");

/// Capacity of the in-kernel event queue (in slots, not bytes).
///
/// Sized generously: at ~tens of process events per second, this gives a
/// disconnected agent several minutes of headroom before we start dropping.
pub const QUEUE_CAP: usize = 4096;

/// One queued event: an owned non-paged pool buffer + its size.
///
/// The buffer is `ExAllocatePool2`-allocated and must be `ExFreePool`-d
/// exactly once — typically by whoever pops the slot from the queue.
#[derive(Copy, Clone)]
pub struct Slot {
    pub data: *mut u8,
    pub size: u32,
}

// SAFETY: slots are only manipulated while QUEUE_LOCK is held.
unsafe impl Sync for Slot {}

/// Spinlock protecting `QUEUE_BUF` / `QUEUE_HEAD` / `QUEUE_TAIL` / `QUEUE_LEN`.
pub static QUEUE_LOCK: SyncCell<MaybeUninit<KSPIN_LOCK>> =
    SyncCell::new(MaybeUninit::uninit());

/// Ring buffer storage. Live entries occupy
/// `[QUEUE_HEAD .. QUEUE_HEAD + QUEUE_LEN] mod QUEUE_CAP`.
pub static QUEUE_BUF: SyncCell<MaybeUninit<[Slot; QUEUE_CAP]>> =
    SyncCell::new(MaybeUninit::uninit());

pub static QUEUE_HEAD: SyncCell<usize> = SyncCell::new(0);
pub static QUEUE_TAIL: SyncCell<usize> = SyncCell::new(0);
pub static QUEUE_LEN: SyncCell<usize> = SyncCell::new(0);

/// Total events dropped because the queue was full.
///
/// Reset to 0 each time it's stamped into an outgoing event header, so the
/// agent only sees the gap accumulated since its last delivered event.
pub static DROP_COUNT: AtomicU32 = AtomicU32::new(0);

/// Total fields (image paths, registry key paths, value names, value-data
/// previews) that had to be truncated because they exceeded the event's
/// fixed-size buffer. Same swap-to-zero policy as `DROP_COUNT`: each
/// outgoing header carries the number accumulated since the previous one.
pub static TRUNC_COUNT: AtomicU32 = AtomicU32::new(0);

/// Single-client pending IRP slot.
///
/// `null` means nobody is currently blocked in `IOCTL_WEDR_GET_EVENT`.
/// We allow only one outstanding IOCTL at a time — a second concurrent
/// caller is rejected with `STATUS_UNSUCCESSFUL` rather than queued.
pub static PENDING_IRP: AtomicPtr<wdk_sys::_IRP> =
    AtomicPtr::new(ptr::null_mut());

/// The control device created by `DriverEntry`. `DriverUnload` reads it back
/// to call `IoDeleteDevice`.
pub static CONTROL_DEVICE: AtomicPtr<wdk_sys::_DEVICE_OBJECT> =
    AtomicPtr::new(ptr::null_mut());

/// `true` once `PsSetCreateProcessNotifyRoutineEx(…, FALSE)` has been called
/// successfully, so `DriverUnload` knows whether to deregister it.
///
/// Important: deregistering a callback that was never registered, or
/// deregistering twice, both bug-check the system. Each kernel callback
/// gets its own flag for that reason.
pub static PROCESS_CALLBACK_REGISTERED: AtomicBool = AtomicBool::new(false);

/// `true` once `PsSetLoadImageNotifyRoutine` has been called successfully.
/// Same rationale as `PROCESS_CALLBACK_REGISTERED`.
pub static IMAGE_CALLBACK_REGISTERED: AtomicBool = AtomicBool::new(false);

/// `true` once `CmRegisterCallback` has been called successfully. Used by
/// `DriverUnload` to decide whether to call `CmUnRegisterCallback`.
/// Same double-deregister hazard applies as the other flags above.
pub static REGISTRY_CALLBACK_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Cookie returned by `CmRegisterCallback`. Stored as `i64` because that
/// is the underlying representation of `LARGE_INTEGER::QuadPart`; we
/// reconstruct a fresh `LARGE_INTEGER` whenever we need to call into CM.
///
/// Only meaningful when `REGISTRY_CALLBACK_REGISTERED` is true.
pub static REGISTRY_CALLBACK_COOKIE: AtomicI64 = AtomicI64::new(0);

/// `true` once `PsSetCreateThreadNotifyRoutine` succeeded. Used by
/// `DriverUnload` to decide whether to call `PsRemoveCreateThreadNotifyRoutine`.
pub static THREAD_CALLBACK_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Opaque handle returned by `ObRegisterCallbacks` (an `IRP_MJ`-style
/// allocation, opaque from our side). `null` means we never registered
/// or have already unregistered.
///
/// Stored as a raw pointer because `ObUnRegisterCallbacks` takes the
/// same handle it returned, by value, and we have nowhere else to put it.
pub static OBJECT_CALLBACK_HANDLE: AtomicPtr<core::ffi::c_void> =
    AtomicPtr::new(ptr::null_mut());
