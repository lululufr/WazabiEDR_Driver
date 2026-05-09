//! `PsSetLoadImageNotifyRoutine` callback.
//!
//! Fires whenever a PE image gets mapped into a process — DLLs and EXEs
//! into user processes, plus kernel-mode drivers/modules (the latter are
//! reported with `process_id == 0`).
//!
//! For an EDR both flavours matter: user-side image loads catch DLL
//! injection / search-order hijacking, kernel-side ones catch rootkit
//! drivers being loaded.
//!
//! Runtime context: PASSIVE_LEVEL, synchronous, in the loader's calling
//! thread. Same hard rule as the process callback — must NOT block.

use core::ptr::{self, addr_of_mut};
use core::sync::atomic::Ordering;

use wdk_sys::{HANDLE, PIMAGE_INFO, PUNICODE_STRING};

use crate::callbacks::header::alloc_event_for;
use crate::events::{EventType, IMAGE_PATH_MAX, ImageLoadEvent};
use crate::queue::submit::submit_event;
use crate::state::TRUNC_COUNT;

/// Build and submit an `ImageLoad` event.
///
/// Both `full_image_name` and the `ImageInfo` pointer are documented as
/// possibly-NULL by MSDN; we tolerate that by emitting whatever fields we
/// could read and leaving the rest at 0.
unsafe fn emit_image_load(
    pid: u32,
    full_image_name: PUNICODE_STRING,
    image_info: PIMAGE_INFO,
) {
    unsafe {
        let evt = alloc_event_for::<ImageLoadEvent>(EventType::ImageLoad as u16);
        if evt.is_null() {
            return;
        }

        // Packed struct → write fields through raw pointers (`addr_of_mut!`)
        // to avoid forming misaligned references (UB).
        ptr::write(addr_of_mut!((*evt).process_id), pid);

        if !image_info.is_null() {
            let base = (*image_info).ImageBase as usize as u64;
            let img_size = (*image_info).ImageSize as u64;
            ptr::write(addr_of_mut!((*evt).image_base), base);
            ptr::write(addr_of_mut!((*evt).image_size), img_size);
        }

        if !full_image_name.is_null() {
            let img = &*full_image_name;
            if !img.Buffer.is_null() && img.Length > 0 {
                let chars = (img.Length / 2) as usize;
                // Reserve one slot below MAX so a fully-truncated path stays
                // distinguishable from one that exactly fills the buffer.
                let copy = chars.min(IMAGE_PATH_MAX - 1);
                if chars > copy {
                    TRUNC_COUNT.fetch_add(1, Ordering::Relaxed);
                }
                let dst = addr_of_mut!((*evt).image_path) as *mut u16;
                ptr::copy_nonoverlapping(img.Buffer, dst, copy);
                ptr::write(addr_of_mut!((*evt).image_path_len), copy as u16);
            }
        }

        let size = core::mem::size_of::<ImageLoadEvent>() as u32;
        submit_event(evt as *mut u8, size);
    }
}

/// Entry point registered via `PsSetLoadImageNotifyRoutine`.
///
/// `process_id` is `0` (NULL HANDLE) when the image is being loaded into
/// the kernel address space (e.g. a driver). User-mode loads carry the
/// target PID.
pub unsafe extern "C" fn image_load_notify(
    full_image_name: PUNICODE_STRING,
    process_id: HANDLE,
    image_info: PIMAGE_INFO,
) {
    let pid = process_id as usize as u32;
    unsafe { emit_image_load(pid, full_image_name, image_info) };
}
