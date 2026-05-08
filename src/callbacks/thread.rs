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

use crate::callbacks::header::make_header;
use crate::events::{EventType, ThreadCreateEvent, ThreadExitEvent};
use crate::queue::submit::{alloc_event, submit_event};

/// Build and submit a `ThreadCreate` event.
unsafe fn emit_thread_create(pid: u32, tid: u32) {
    let size = core::mem::size_of::<ThreadCreateEvent>() as u32;
    unsafe {
        let buf = alloc_event(size);
        if buf.is_null() {
            return;
        }
        // Capture who *requested* the thread creation. For an in-process
        // thread (`CreateThread` from inside the same process) this will
        // equal `pid`; for `CreateRemoteThread` it'll be the attacker.
        let creator = PsGetCurrentProcessId() as usize as u32;

        let evt = buf as *mut ThreadCreateEvent;
        ptr::write(
            evt,
            ThreadCreateEvent {
                header: make_header(EventType::ThreadCreate as u16, size),
                process_id: pid,
                thread_id: tid,
                creating_process_id: creator,
            },
        );
        // No `addr_of_mut!` gymnastics needed here: every field is a u32
        // and the struct is small enough that we can just write the
        // whole thing in one go. The `repr(C, packed)` still applies.
        let _ = evt; // keep `evt` named for the safety comment above
        submit_event(buf, size);
    }
}

/// Build and submit a `ThreadExit` event. Symmetrical and even cheaper.
unsafe fn emit_thread_exit(pid: u32, tid: u32) {
    let size = core::mem::size_of::<ThreadExitEvent>() as u32;
    unsafe {
        let buf = alloc_event(size);
        if buf.is_null() {
            return;
        }
        let evt = buf as *mut ThreadExitEvent;
        ptr::write(
            evt,
            ThreadExitEvent {
                header: make_header(EventType::ThreadExit as u16, size),
                process_id: pid,
                thread_id: tid,
            },
        );
        // Keep the `addr_of_mut!` reminder for future maintainers who
        // might add wider fields to ThreadExitEvent: the moment the
        // struct grows beyond same-sized scalars, the one-shot `write`
        // above must be replaced with field-by-field writes.
        let _ = addr_of_mut!((*evt).process_id);
        submit_event(buf, size);
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
