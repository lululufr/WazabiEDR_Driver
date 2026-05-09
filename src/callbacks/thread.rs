//! `PsSetCreateThreadNotifyRoutine` callback.
//!
//! Fires for every thread create and thread exit, system-wide. Cheap by
//! kernel-callback standards: no string copies, no path resolution — just
//! three `u32`s per event.
//!
//! # Why we care about this for an EDR
//!
//! The interesting case is `CreateRemoteThread`-style injection: the
//! creator process opens a handle into a target and spawns a thread inside
//! it. From this callback we can tell that's what happened by comparing
//! the thread's owning process (`process_id`) to the *requester*
//! (`PsGetCurrentProcessId`, captured under the name
//! `creating_process_id`). When they differ, you have either:
//! - a legitimate cross-process thread (e.g. `CSRSS` doing process init), or
//! - a malicious injection.
//!
//! Disambiguating the two is the agent's job; the driver's contract is
//! just to surface the data faithfully.
//!
//! Runtime context: PASSIVE_LEVEL, synchronous, in the requester's thread
//! for *create*, in the exiting thread for *exit*. Same hard rule as the
//! other Ps* callbacks: must NOT block.

use core::ptr::{self, addr_of_mut};

use wdk_sys::{ntddk::PsGetCurrentProcessId, BOOLEAN, HANDLE};

use crate::callbacks::header::alloc_event_for;
use crate::events::{EventType, ThreadCreateEvent, ThreadExitEvent};
use crate::queue::submit::submit_event;

/// Build and submit a `ThreadCreate` event.
unsafe fn emit_thread_create(pid: u32, tid: u32) {
    unsafe {
        let evt = alloc_event_for::<ThreadCreateEvent>(EventType::ThreadCreate as u16);
        if evt.is_null() {
            return;
        }
        // Capture who *requested* the thread creation. For an in-process
        // thread (`CreateThread` from inside the same process) this will
        // equal `pid`; for `CreateRemoteThread` it'll be the attacker.
        let creator = PsGetCurrentProcessId() as usize as u32;

        // Packed struct: write each field through `addr_of_mut!` so we
        // never form a misaligned reference (UB). Header is already in.
        ptr::write(addr_of_mut!((*evt).process_id), pid);
        ptr::write(addr_of_mut!((*evt).thread_id), tid);
        ptr::write(addr_of_mut!((*evt).creating_process_id), creator);

        let size = core::mem::size_of::<ThreadCreateEvent>() as u32;
        submit_event(evt as *mut u8, size);
    }
}

/// Build and submit a `ThreadExit` event. Symmetrical and even cheaper.
unsafe fn emit_thread_exit(pid: u32, tid: u32) {
    unsafe {
        let evt = alloc_event_for::<ThreadExitEvent>(EventType::ThreadExit as u16);
        if evt.is_null() {
            return;
        }
        ptr::write(addr_of_mut!((*evt).process_id), pid);
        ptr::write(addr_of_mut!((*evt).thread_id), tid);

        let size = core::mem::size_of::<ThreadExitEvent>() as u32;
        submit_event(evt as *mut u8, size);
    }
}

/// Entry point registered via `PsSetCreateThreadNotifyRoutine`.
///
/// `Create` is `TRUE` for thread creation, `FALSE` for thread exit. We
/// dispatch and return; the kernel ignores any return value.
pub unsafe extern "C" fn thread_notify(
    process_id: HANDLE,
    thread_id: HANDLE,
    create: BOOLEAN,
) {
    let pid = process_id as usize as u32;
    let tid = thread_id as usize as u32;
    unsafe {
        if create != 0 {
            emit_thread_create(pid, tid);
        } else {
            emit_thread_exit(pid, tid);
        }
    }
}
