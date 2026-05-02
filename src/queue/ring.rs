//! Bare ring-buffer mechanics.
//!
//! All functions in this module require the caller to hold `QUEUE_LOCK`.
//! Lock acquisition is left to the caller because callers usually need the
//! lock for additional state changes (touching `PENDING_IRP`, etc.) and we
//! want one critical section, not several.

use core::sync::atomic::Ordering;

use wdk_sys::{ntddk::ExFreePool, PVOID};

use crate::state::{
    DROP_COUNT, QUEUE_BUF, QUEUE_CAP, QUEUE_HEAD, QUEUE_LEN, QUEUE_TAIL, Slot,
};

/// Push an event onto the queue.
///
/// If the queue is full, the **oldest** entry is evicted (and freed) to
/// make room. We prefer recency to first-seen ordering: for an EDR feed,
/// the most recent activity is what matters most when an agent reconnects.
///
/// Returns `true` always. The bool is kept so future failure modes can be
/// added without churning callers.
///
/// # Safety
/// Caller must hold `QUEUE_LOCK`.
pub unsafe fn queue_push_locked(data: *mut u8, size: u32) -> bool {
    unsafe {
        let buf = QUEUE_BUF.as_mut_ptr() as *mut Slot;
        let head = &mut *QUEUE_HEAD.as_mut_ptr();
        let tail = &mut *QUEUE_TAIL.as_mut_ptr();
        let len = &mut *QUEUE_LEN.as_mut_ptr();

        if *len == QUEUE_CAP {
            let old = *buf.add(*head);
            ExFreePool(old.data as PVOID);
            *head = (*head + 1) % QUEUE_CAP;
            *len -= 1;
            DROP_COUNT.fetch_add(1, Ordering::Relaxed);
        }

        *buf.add(*tail) = Slot { data, size };
        *tail = (*tail + 1) % QUEUE_CAP;
        *len += 1;
        true
    }
}

/// Remove and return the oldest queued event, or `None` if the queue is
/// empty.
///
/// # Safety
/// Caller must hold `QUEUE_LOCK`. Caller takes ownership of `slot.data`
/// and is responsible for `ExFreePool`-ing it exactly once.
pub unsafe fn queue_pop_locked() -> Option<Slot> {
    unsafe {
        let buf = QUEUE_BUF.as_mut_ptr() as *mut Slot;
        let head = &mut *QUEUE_HEAD.as_mut_ptr();
        let len = &mut *QUEUE_LEN.as_mut_ptr();

        if *len == 0 {
            return None;
        }
        let s = *buf.add(*head);
        *head = (*head + 1) % QUEUE_CAP;
        *len -= 1;
        Some(s)
    }
}
