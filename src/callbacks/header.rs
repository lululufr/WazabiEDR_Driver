//! Shared `EventHeader` builder used by every callback.
//!
//! Factored out so each callback module doesn't reinvent the
//! "stamp version + timestamp + drop-count" dance.

use core::ptr;
use core::sync::atomic::Ordering;

use wdk_sys::{ntddk::KeQuerySystemTimePrecise, LARGE_INTEGER};

use crate::events::{EVENT_VERSION, EventHeader};
use crate::queue::submit::alloc_event;
use crate::state::{DROP_COUNT, TRUNC_COUNT};

/// Build a fresh `EventHeader` for an outgoing event of `size` bytes.
///
/// Atomically swaps `DROP_COUNT` and `TRUNC_COUNT` to 0 so each gap /
/// truncation count is reported exactly once, on the first event that
/// follows it.
pub unsafe fn make_header(type_: u16, size: u32) -> EventHeader {
    let mut ts = LARGE_INTEGER { QuadPart: 0 };
    unsafe { KeQuerySystemTimePrecise(&mut ts) };
    EventHeader {
        version: EVENT_VERSION,
        type_,
        timestamp: unsafe { ts.QuadPart },
        size,
        drop_count: DROP_COUNT.swap(0, Ordering::Relaxed),
        trunc_count: TRUNC_COUNT.swap(0, Ordering::Relaxed),
    }
}

/// Allocate a non-paged buffer sized for `T`, zero it, and stamp an
/// `EventHeader` of the given `type_` at offset 0.
///
/// Returns a typed pointer to the freshly-initialised buffer, or null on
/// allocation failure. Every callback uses this to skip the boilerplate
/// "alloc → write_bytes(0) → make_header" dance.
///
/// # Safety
/// `T` MUST start with an `EventHeader` field at offset 0 (i.e. it must be
/// `#[repr(C, packed)]` with `header: EventHeader` first). Caller takes
/// ownership of the returned buffer and must hand it to `submit_event`.
pub unsafe fn alloc_event_for<T>(type_: u16) -> *mut T {
    let size = core::mem::size_of::<T>() as u32;
    unsafe {
        let buf = alloc_event(size);
        if buf.is_null() {
            return ptr::null_mut();
        }
        // Zero everything so unused tail bytes (string buffers, padding)
        // ship as 0 rather than leaking pool memory to userland.
        ptr::write_bytes(buf, 0, size as usize);
        // Stamp the header at offset 0. Caller is responsible for the
        // T-specific fields that follow.
        ptr::write(buf as *mut EventHeader, make_header(type_, size));
        buf as *mut T
    }
}
