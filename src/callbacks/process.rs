//! `PsSetCreateProcessNotifyRoutineEx` callback.
//!
//! Builds Wazabi events from kernel-supplied process create / exit
//! information and hands them off to `submit_event`.
//!
//! Runtime context: PASSIVE_LEVEL, synchronous, in the context of the
//! creating process (for create) or the exiting process (for exit). It is
//! safe to allocate paged memory here, but we MUST NOT block — every
//! `CreateProcess` in the system passes through this callback.

use core::ptr::{self, addr_of_mut};

use wdk_sys::{PEPROCESS, PPS_CREATE_NOTIFY_INFO};

use crate::callbacks::header::make_header;
use crate::events::{EventType, IMAGE_PATH_MAX, ProcessCreateEvent, ProcessExitEvent};
use crate::queue::submit::{alloc_event, submit_event};

/// Build and submit a `ProcessExit` event.
///
/// On allocation failure we silently return: there is nowhere to record
/// "we lost an event because we couldn't allocate a buffer to record the
/// loss". The next successful event will surface the gap via `DROP_COUNT`.
unsafe fn emit_process_exit(pid: u32) {
    let size = core::mem::size_of::<ProcessExitEvent>() as u32;
    unsafe {
        let buf = alloc_event(size);
        if buf.is_null() {
            return;
        }
        let evt = buf as *mut ProcessExitEvent;
        ptr::write(
            evt,
            ProcessExitEvent {
                header: make_header(EventType::ProcessExit as u16, size),
                process_id: pid,
            },
        );
        submit_event(buf, size);
    }
}

/// Build and submit a `ProcessCreate` event.
///
/// Copies as much of the image path as fits into `IMAGE_PATH_MAX` UTF-16
/// units. Truncated paths are still better than nothing — userland can
/// detect truncation when `image_path_len == IMAGE_PATH_MAX - 1`.
unsafe fn emit_process_create(pid: u32, info: PPS_CREATE_NOTIFY_INFO) {
    let size = core::mem::size_of::<ProcessCreateEvent>() as u32;
    unsafe {
        let buf = alloc_event(size);
        if buf.is_null() {
            return;
        }
        // Zero the whole buffer so any unused bytes of `image_path` ship
        // as 0 instead of leaking uninitialized pool memory to userland.
        ptr::write_bytes(buf, 0, size as usize);

        let evt = buf as *mut ProcessCreateEvent;
        let parent = (*info).ParentProcessId as usize as u32;
        let creator = (*info).CreatingThreadId.UniqueProcess as usize as u32;

        // The struct is `repr(C, packed)`, so we MUST write fields through
        // raw pointers (`addr_of_mut!`). Taking `&mut field` directly on a
        // packed struct produces a misaligned reference — UB.
        ptr::write(
            addr_of_mut!((*evt).header),
            make_header(EventType::ProcessCreate as u16, size),
        );
        ptr::write(addr_of_mut!((*evt).process_id), pid);
        ptr::write(addr_of_mut!((*evt).parent_process_id), parent);
        ptr::write(addr_of_mut!((*evt).creating_process_id), creator);

        // ImageFileName: NT path (e.g. "\Device\HarddiskVolume3\…\foo.exe").
        // May be NULL in rare cases (kernel-launched processes without a
        // backing file) — don't fault if so.
        let img_str = (*info).ImageFileName;
        if !img_str.is_null() {
            let img = &*img_str;
            if !img.Buffer.is_null() && img.Length > 0 {
                let chars = (img.Length / 2) as usize;
                // Reserve one slot below MAX so a fully-truncated path
                // remains distinguishable from one that exactly fills the
                // buffer.
                let copy = chars.min(IMAGE_PATH_MAX - 1);
                let dst = addr_of_mut!((*evt).image_path) as *mut u16;
                ptr::copy_nonoverlapping(img.Buffer, dst, copy);
                ptr::write(addr_of_mut!((*evt).image_path_len), copy as u16);
            }
        }

        submit_event(buf, size);
    }
}

/// Entry point registered via `PsSetCreateProcessNotifyRoutineEx`.
///
/// `create_info` is non-null on process creation, null on process exit.
/// We dispatch to the right emitter and return as fast as possible.
pub unsafe extern "C" fn process_notify(
    _process: PEPROCESS,
    process_id: wdk_sys::HANDLE,
    create_info: PPS_CREATE_NOTIFY_INFO,
) {
    let pid = process_id as usize as u32;
    unsafe {
        if create_info.is_null() {
            emit_process_exit(pid);
        } else {
            emit_process_create(pid, create_info);
        }
    }
}
