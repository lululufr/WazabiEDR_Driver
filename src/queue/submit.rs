//! Producer side of the event queue.
//!
//! `submit_event` is the single entry point used by every kernel callback
//! (process notify today, registry / thread create tomorrow). It hides the
//! "is anyone waiting? if so, complete directly; otherwise enqueue" choice
//! from the callbacks themselves.

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

use wdk_sys::{
    ntddk::{DbgPrint, ExAllocatePool2, ExFreePool},
    KSPIN_LOCK, POOL_FLAG_NON_PAGED, PVOID, STATUS_BUFFER_TOO_SMALL, STATUS_SUCCESS,
};

use crate::ipc::irp::{complete_irp, current_stack_location};
use crate::queue::ring::queue_push_locked;
use crate::state::{DROP_COUNT, PENDING_IRP, POOL_TAG, QUEUE_LOCK};
use crate::util::SpinLockGuard;

/// Cumulative count of `alloc_event` failures since boot. Used purely to
/// drive the rate-limited `DbgPrint` below — never read by anything else.
static OOM_COUNT: AtomicU32 = AtomicU32::new(0);

/// Emit a kernel-debug line every `OOM_LOG_EVERY` allocation failures.
///
/// One line per failure would dominate the system log under memory
/// pressure (where the failures cluster). One line per N gives the
/// operator enough signal to know "this driver is dropping events
/// because of pool exhaustion" without burying everything else.
const OOM_LOG_EVERY: u32 = 256;

/// Allocate a non-paged buffer to hold an outgoing event.
///
/// Returns `null` on allocation failure. On failure we also bump
/// `DROP_COUNT` (the event will never reach the queue) and emit a
/// rate-limited `DbgPrint` so the operator gets a hint without the log
/// being flooded.
pub unsafe fn alloc_event(size: u32) -> *mut u8 {
    unsafe {
        let buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size as u64, POOL_TAG) as *mut u8;
        if buf.is_null() {
            // Account for the loss exactly once per failed allocation:
            // the event we wanted to record is gone, so the next
            // delivered header should report it via `drop_count`.
            DROP_COUNT.fetch_add(1, Ordering::Relaxed);
            // Rate-limited DbgPrint: every Nth failure prints the
            // running total so an operator reading WinDbg / DebugView
            // sees that something is dropping events.
            let n = OOM_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_multiple_of(OOM_LOG_EVERY) {
                DbgPrint(c"[WazabiEDR] alloc_event OOM\n".as_ptr());
            }
        }
        buf
    }
}

/// Submit a fully-built event buffer to userland.
///
/// Behaviour:
/// 1. If an agent IOCTL is currently pending and its output buffer is
///    large enough → copy directly into the user buffer and complete the
///    IRP. The event never touches the queue (the fastest path).
/// 2. If the agent's buffer is too small → fail that IRP with
///    `STATUS_BUFFER_TOO_SMALL`, drop this event, and bump `DROP_COUNT`.
///    The agent will retry with a larger buffer.
/// 3. If no IRP is pending → enqueue. If the queue is already full,
///    `queue_push_locked` evicts the oldest entry.
///
/// Ownership: this function takes ownership of `data` in every path. The
/// caller must NOT touch the buffer after calling.
pub unsafe fn submit_event(data: *mut u8, size: u32) {
    unsafe {
        let guard = SpinLockGuard::acquire(QUEUE_LOCK.as_mut_ptr() as *mut KSPIN_LOCK);

        // Take ownership of any pending IRP up-front. Either we'll satisfy
        // it (success), fail it (buffer-too-small), or put nothing back.
        let pending = PENDING_IRP.swap(ptr::null_mut(), Ordering::AcqRel);

        if !pending.is_null() {
            let stack = current_stack_location(pending);
            let outlen = (*stack).Parameters.DeviceIoControl.OutputBufferLength;

            if outlen >= size {
                // Path 1: directly into the agent's buffer.
                let sysbuf = (*pending).AssociatedIrp.SystemBuffer as *mut u8;
                ptr::copy_nonoverlapping(data, sysbuf, size as usize);

                // Drop lock BEFORE IofCompleteRequest: completion routines
                // can run synchronously and we don't want to hold the
                // spinlock across them.
                drop(guard);
                ExFreePool(data as PVOID);
                complete_irp(pending, STATUS_SUCCESS, size as usize);
                return;
            }

            // Path 2: buffer too small. Tell the agent the size it needs;
            // drop the event so the agent can re-issue.
            drop(guard);
            ExFreePool(data as PVOID);
            DROP_COUNT.fetch_add(1, Ordering::Relaxed);
            complete_irp(pending, STATUS_BUFFER_TOO_SMALL, size as usize);
            return;
        }

        // Path 3: no agent waiting → enqueue. `guard` releases on scope exit.
        queue_push_locked(data, size);
    }
}
