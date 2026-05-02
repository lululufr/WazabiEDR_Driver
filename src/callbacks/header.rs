//! Shared `EventHeader` builder used by every callback.
//!
//! Factored out so each callback module doesn't reinvent the
//! "stamp version + timestamp + drop-count" dance.

use core::sync::atomic::Ordering;

use wdk_sys::{ntddk::KeQuerySystemTimePrecise, LARGE_INTEGER};

use crate::events::{EVENT_VERSION, EventHeader};
use crate::state::DROP_COUNT;

/// Build a fresh `EventHeader` for an outgoing event of `size` bytes.
///
/// Atomically swaps `DROP_COUNT` to 0 so the gap accumulated since the
/// last delivered event is reported exactly once.
pub unsafe fn make_header(type_: u16, size: u32) -> EventHeader {
    let mut ts = LARGE_INTEGER { QuadPart: 0 };
    unsafe { KeQuerySystemTimePrecise(&mut ts) };
    EventHeader {
        version: EVENT_VERSION,
        type_,
        timestamp: unsafe { ts.QuadPart },
        size,
        drop_count: DROP_COUNT.swap(0, Ordering::Relaxed),
    }
}
