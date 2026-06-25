//! `CmRegisterCallback` callback — registry modifications.
//!
//! Built on the Configuration Manager's callback model: every registry
//! operation (read or write) flows through `registry_notify`. We dispatch
//! on `REG_NOTIFY_CLASS` and only emit events for *mutations* — reads
//! generate enormous noise and offer little EDR value at this layer.
//!
//! Operations observed (all `Pre*` notifications, so the operation is
//! captured before it actually runs):
//!
//! - `RegNtPreSetValueKey`     → value being written
//! - `RegNtPreDeleteValueKey`  → value being removed
//! - `RegNtPreDeleteKey`       → key being removed
//! - `RegNtPreRenameKey`       → key being renamed (only source path is logged)
//! - `RegNtPreCreateKeyEx`     → new subkey being created
//!
//! Runtime context: PASSIVE_LEVEL, in the calling thread of the requester.
//! We must NOT block — the callback runs synchronously inside `RegSet…` /
//! `RegDelete…` etc., one per registry call system-wide.
//!
//! Filtering policy: this callback is observational. We always return
//! `STATUS_SUCCESS`, allowing the operation to proceed unmodified. A
//! future blocking mode would return `STATUS_ACCESS_DENIED` here, but the
//! current scope is pure telemetry.
//!
//! # Path-prefix gate
//!
//! A bare `CmRegisterCallback` produces *thousands* of events per second
//! during normal Windows operation (every `RegSet…` from every service
//! and every COM object goes through here). To keep the queue useful we
//! resolve the affected key path FIRST, then drop everything that
//! doesn't sit under one of [`CRITICAL_REGISTRY_PREFIXES`]. Resolution
//! uses a stack-local buffer so we don't pay for an event allocation on
//! the dropped paths.

use core::ptr::{self, addr_of_mut};
use core::sync::atomic::Ordering;

use wdk_sys::{
    ntddk::{
        CmCallbackGetKeyObjectIDEx, CmCallbackReleaseKeyObjectIDEx, PsGetCurrentProcessId,
    },
    LARGE_INTEGER, NTSTATUS, PCUNICODE_STRING, PVOID, STATUS_SUCCESS, ULONG_PTR,
    _REG_NOTIFY_CLASS as RegNotify,
    _REG_DELETE_KEY_INFORMATION as RegDeleteKey,
    _REG_DELETE_VALUE_KEY_INFORMATION as RegDeleteValue,
    _REG_CREATE_KEY_INFORMATION as RegCreateKey,
    _REG_RENAME_KEY_INFORMATION as RegRenameKey,
    _REG_SET_VALUE_KEY_INFORMATION as RegSetValue,
};

use crate::callbacks::header::alloc_event_for;
use crate::events::{
    EventType, REGISTRY_DATA_PREVIEW_MAX, REGISTRY_KEY_PATH_MAX, REGISTRY_VALUE_NAME_MAX,
    RegistryEvent, RegistryOp,
};
use crate::queue::submit::submit_event;
use crate::state::{REGISTRY_CALLBACK_COOKIE, TRUNC_COUNT};

/// Critical NT registry path prefixes worth forwarding to the agent.
///
/// Everything not under one of these is silently dropped at the very
/// start of each emitter — this is the single biggest noise-reduction
/// lever in the driver. Add a new entry here to widen coverage; remove
/// one to reduce volume. List was chosen for its EDR value, not for
/// completeness:
///
/// - `Services`          — driver / service registration (persistence,
///                         vulnerable driver loads, …).
/// - `Run` / `RunOnce`   — classic per-machine autoruns (incl. Wow6432).
/// - `IFEO`              — Image File Execution Options debugger hijack.
/// - `Winlogon`          — Userinit / Shell / Notify hijacks.
/// - `SafeBoot`          — boot-state tampering.
/// - `Lsa`               — RunAsPPL toggles, Notification Packages, …
/// - `Windows Defender`  — direct AV neutralisation.
/// - `\REGISTRY\USER`    — every user hive (per-user autoruns).
const CRITICAL_REGISTRY_PREFIXES: &[&[u8]] = &[
    b"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services",
    b"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    b"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    b"\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    b"\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    b"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    b"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    b"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot",
    b"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
    b"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
    b"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender",
    b"\\REGISTRY\\USER",
];

/// Case-insensitive ASCII prefix test on a UTF-16 path.
///
/// Registry NT paths are ASCII in practice, so a byte-by-byte compare
/// with manual case folding is both correct and far cheaper than calling
/// `RtlPrefixUnicodeString` (which would require wrapping each prefix in
/// a `UNICODE_STRING`).
fn key_has_ascii_prefix_ci(key: &[u16], prefix: &[u8]) -> bool {
    if key.len() < prefix.len() {
        return false;
    }
    let mut i = 0;
    while i < prefix.len() {
        let k = key[i];
        if k > 0x7F {
            return false;
        }
        let kb = k as u8;
        // Inline ASCII to-uppercase: avoids pulling in core::ascii or
        // forming references to bytes we already have in registers.
        let ku = if kb.is_ascii_lowercase() { kb - 0x20 } else { kb };
        let pb = prefix[i];
        let pu = if pb.is_ascii_lowercase() { pb - 0x20 } else { pb };
        if ku != pu {
            return false;
        }
        i += 1;
    }
    true
}

/// Does `key` (UTF-16, no NUL) match any prefix in
/// [`CRITICAL_REGISTRY_PREFIXES`]?
fn is_interesting_path(key: &[u16]) -> bool {
    for prefix in CRITICAL_REGISTRY_PREFIXES {
        if key_has_ascii_prefix_ci(key, prefix) {
            return true;
        }
    }
    false
}

/// Same test as [`is_interesting_path`], but reads the key from a raw
/// `PCUNICODE_STRING` straight off the kernel notification info struct.
unsafe fn is_interesting_unicode_string(s: PCUNICODE_STRING) -> bool {
    unsafe {
        if s.is_null() {
            return false;
        }
        let s = &*s;
        if s.Buffer.is_null() || s.Length == 0 {
            return false;
        }
        let chars = (s.Length / 2) as usize;
        let slice = core::slice::from_raw_parts(s.Buffer, chars);
        is_interesting_path(slice)
    }
}

/// Copy a `PUNICODE_STRING` into a fixed-size UTF-16 buffer.
///
/// Returns the number of UTF-16 units written. Reserves one slot below
/// `MAX` so a fully-truncated path stays distinguishable from one that
/// exactly fills the buffer (mirrors the convention used by the process /
/// image callbacks). Bumps `TRUNC_COUNT` whenever the source was longer
/// than the destination could fit.
unsafe fn copy_unicode_into(
    src: PCUNICODE_STRING,
    dst: *mut u16,
    max: usize,
) -> usize {
    unsafe {
        if src.is_null() {
            return 0;
        }
        let s = &*src;
        if s.Buffer.is_null() || s.Length == 0 {
            return 0;
        }
        // `Length` is in BYTES; UTF-16 units = Length / 2.
        let chars = (s.Length / 2) as usize;
        let copy = chars.min(max - 1);
        if chars > copy {
            TRUNC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        ptr::copy_nonoverlapping(s.Buffer, dst, copy);
        copy
    }
}

/// Resolve a registry-callback `Object` pointer to its NT path.
///
/// `CmCallbackGetKeyObjectIDEx` allocates an internal buffer for the name;
/// the matching `CmCallbackReleaseKeyObjectIDEx` MUST be called once we
/// are done copying — otherwise we leak pool inside the registry hive.
///
/// Bumps `TRUNC_COUNT` if the resolved path was longer than `max`.
unsafe fn write_key_path_from_object(
    object: PVOID,
    dst: *mut u16,
    max: usize,
) -> usize {
    unsafe {
        if object.is_null() {
            return 0;
        }
        // Cookie is read by-value; the API expects a `PLARGE_INTEGER`,
        // i.e. a pointer to a writable LARGE_INTEGER, even though it
        // doesn't actually mutate it in this code path.
        let mut cookie = LARGE_INTEGER {
            QuadPart: REGISTRY_CALLBACK_COOKIE.load(Ordering::Acquire),
        };
        let mut object_id: ULONG_PTR = 0;
        let mut name: PCUNICODE_STRING = ptr::null();

        let status = CmCallbackGetKeyObjectIDEx(
            &mut cookie,
            object,
            &mut object_id,
            &mut name,
            0,
        );
        if status < 0 || name.is_null() {
            return 0;
        }

        let written = copy_unicode_into(name, dst, max);
        // Release the buffer the CM allocated for the name. Failing to do
        // so would leak pool every time the callback fires.
        CmCallbackReleaseKeyObjectIDEx(name);
        written
    }
}

/// Resolve an object's key path into a stack-local buffer and gate it
/// through [`is_interesting_path`].
///
/// Returns `Some((buf, len))` for paths we should forward, `None`
/// otherwise. Doing this BEFORE [`alloc_event_for`] is the whole point of
/// the prefix gate — we save a non-paged-pool allocation for every
/// registry op that doesn't sit under a watched prefix.
unsafe fn resolve_and_gate_object(
    object: PVOID,
) -> Option<([u16; REGISTRY_KEY_PATH_MAX], usize)> {
    let mut buf: [u16; REGISTRY_KEY_PATH_MAX] = [0; REGISTRY_KEY_PATH_MAX];
    let len =
        unsafe { write_key_path_from_object(object, buf.as_mut_ptr(), REGISTRY_KEY_PATH_MAX) };
    if len == 0 || !is_interesting_path(&buf[..len]) {
        return None;
    }
    Some((buf, len))
}

/// Stamp the per-event `process_id` + `operation` discriminant. Header
/// is already in by [`alloc_event_for`].
unsafe fn fill_registry_common(evt: *mut RegistryEvent, op: RegistryOp) {
    unsafe {
        let pid = PsGetCurrentProcessId() as usize as u32;
        ptr::write(addr_of_mut!((*evt).process_id), pid);
        ptr::write(addr_of_mut!((*evt).operation), op as u16);
    }
}

/// Copy a pre-resolved key path (already prefix-gated) into the event.
unsafe fn write_resolved_key_path(
    evt: *mut RegistryEvent,
    src: &[u16; REGISTRY_KEY_PATH_MAX],
    len: usize,
) {
    unsafe {
        let dst = addr_of_mut!((*evt).key_path) as *mut u16;
        ptr::copy_nonoverlapping(src.as_ptr(), dst, len);
        ptr::write(addr_of_mut!((*evt).key_path_len), len as u16);
    }
}

/// Emit a `SetValue` event.
unsafe fn emit_set_value(info: *mut RegSetValue) {
    unsafe {
        if info.is_null() {
            return;
        }
        let info = &*info;

        // Path-prefix gate FIRST — saves a pool allocation on every
        // registry write that isn't on our watch-list.
        let Some((key_local, key_len)) = resolve_and_gate_object(info.Object) else {
            return;
        };

        let evt = alloc_event_for::<RegistryEvent>(EventType::RegistryModify as u16);
        if evt.is_null() {
            return;
        }
        fill_registry_common(evt, RegistryOp::SetValue);
        ptr::write(addr_of_mut!((*evt).value_type), info.Type);
        ptr::write(addr_of_mut!((*evt).data_size), info.DataSize);
        write_resolved_key_path(evt, &key_local, key_len);

        // Value name lives in a UNICODE_STRING the caller built.
        let val_dst = addr_of_mut!((*evt).value_name) as *mut u16;
        let val_len = copy_unicode_into(info.ValueName, val_dst, REGISTRY_VALUE_NAME_MAX);
        ptr::write(addr_of_mut!((*evt).value_name_len), val_len as u16);

        // Data preview: per MSDN the data is captured to system memory
        // before the callback fires, so we can copy it straight without
        // probing user space. Truncate to fit; `data_size` already
        // carries the real total length.
        if !info.Data.is_null() && info.DataSize > 0 {
            let data_len = (info.DataSize as usize).min(REGISTRY_DATA_PREVIEW_MAX);
            if (info.DataSize as usize) > data_len {
                TRUNC_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            let data_dst = addr_of_mut!((*evt).data_preview) as *mut u8;
            ptr::copy_nonoverlapping(info.Data as *const u8, data_dst, data_len);
            ptr::write(addr_of_mut!((*evt).data_preview_len), data_len as u16);
        }

        let size = core::mem::size_of::<RegistryEvent>() as u32;
        submit_event(evt as *mut u8, size);
    }
}

/// Emit a `DeleteValue` event. Only the key path + value name are populated.
unsafe fn emit_delete_value(info: *mut RegDeleteValue) {
    unsafe {
        if info.is_null() {
            return;
        }
        let info = &*info;

        let Some((key_local, key_len)) = resolve_and_gate_object(info.Object) else {
            return;
        };

        let evt = alloc_event_for::<RegistryEvent>(EventType::RegistryModify as u16);
        if evt.is_null() {
            return;
        }
        fill_registry_common(evt, RegistryOp::DeleteValue);
        write_resolved_key_path(evt, &key_local, key_len);

        let val_dst = addr_of_mut!((*evt).value_name) as *mut u16;
        let val_len = copy_unicode_into(info.ValueName, val_dst, REGISTRY_VALUE_NAME_MAX);
        ptr::write(addr_of_mut!((*evt).value_name_len), val_len as u16);

        let size = core::mem::size_of::<RegistryEvent>() as u32;
        submit_event(evt as *mut u8, size);
    }
}

/// Emit a `DeleteKey` event. Only the key path is populated.
unsafe fn emit_delete_key(info: *mut RegDeleteKey) {
    unsafe {
        if info.is_null() {
            return;
        }
        let info = &*info;

        let Some((key_local, key_len)) = resolve_and_gate_object(info.Object) else {
            return;
        };

        let evt = alloc_event_for::<RegistryEvent>(EventType::RegistryModify as u16);
        if evt.is_null() {
            return;
        }
        fill_registry_common(evt, RegistryOp::DeleteKey);
        write_resolved_key_path(evt, &key_local, key_len);

        let size = core::mem::size_of::<RegistryEvent>() as u32;
        submit_event(evt as *mut u8, size);
    }
}

/// Emit a `RenameKey` event. We log the *source* path; the `NewName`
/// in the rename info is left out for now.
unsafe fn emit_rename_key(info: *mut RegRenameKey) {
    unsafe {
        if info.is_null() {
            return;
        }
        let info = &*info;

        let Some((key_local, key_len)) = resolve_and_gate_object(info.Object) else {
            return;
        };

        let evt = alloc_event_for::<RegistryEvent>(EventType::RegistryModify as u16);
        if evt.is_null() {
            return;
        }
        fill_registry_common(evt, RegistryOp::RenameKey);
        write_resolved_key_path(evt, &key_local, key_len);

        let size = core::mem::size_of::<RegistryEvent>() as u32;
        submit_event(evt as *mut u8, size);
    }
}

/// Emit a `CreateKey` event.
///
/// `RegNtPreCreateKeyEx` carries the full path in `CompleteName` directly
/// — no need to resolve through `CmCallbackGetKeyObjectIDEx`. We gate
/// directly on the UNICODE_STRING.
unsafe fn emit_create_key(info: *mut RegCreateKey) {
    unsafe {
        if info.is_null() {
            return;
        }
        let info = &*info;

        if !is_interesting_unicode_string(info.CompleteName) {
            return;
        }

        let evt = alloc_event_for::<RegistryEvent>(EventType::RegistryModify as u16);
        if evt.is_null() {
            return;
        }
        fill_registry_common(evt, RegistryOp::CreateKey);

        let key_dst = addr_of_mut!((*evt).key_path) as *mut u16;
        let key_len = copy_unicode_into(info.CompleteName, key_dst, REGISTRY_KEY_PATH_MAX);
        ptr::write(addr_of_mut!((*evt).key_path_len), key_len as u16);

        let size = core::mem::size_of::<RegistryEvent>() as u32;
        submit_event(evt as *mut u8, size);
    }
}

/// Entry point registered via `CmRegisterCallback`.
///
/// Signature is fixed by the kernel:
/// - `Argument1` is a `REG_NOTIFY_CLASS` value disguised as `PVOID`.
/// - `Argument2` is a pointer to the per-class info struct.
///
/// The function MUST always return a status: returning anything other
/// than `STATUS_SUCCESS` from a `Pre*` notification cancels the registry
/// operation. We always succeed — telemetry only.
pub unsafe extern "C" fn registry_notify(
    _context: PVOID,
    argument1: PVOID,
    argument2: PVOID,
) -> NTSTATUS {
    // The kernel passes the notification class as a pointer-sized integer.
    let class = argument1 as usize as RegNotify::Type;

    unsafe {
        match class {
            RegNotify::RegNtPreSetValueKey => {
                emit_set_value(argument2 as *mut RegSetValue);
            }
            RegNotify::RegNtPreDeleteValueKey => {
                emit_delete_value(argument2 as *mut RegDeleteValue);
            }
            RegNotify::RegNtPreDeleteKey => {
                emit_delete_key(argument2 as *mut RegDeleteKey);
            }
            RegNotify::RegNtPreRenameKey => {
                emit_rename_key(argument2 as *mut RegRenameKey);
            }
            RegNotify::RegNtPreCreateKeyEx => {
                emit_create_key(argument2 as *mut RegCreateKey);
            }
            // Every other notification (reads, post-* events, key-handle
            // close, …) is intentionally ignored. Adding them here is a
            // matter of widening the match — but expect a noisy feed.
            _ => {}
        }
    }

    STATUS_SUCCESS
}
