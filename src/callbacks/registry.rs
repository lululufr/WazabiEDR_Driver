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

use crate::callbacks::header::make_header;
use crate::events::{
    EventType, REGISTRY_DATA_PREVIEW_MAX, REGISTRY_KEY_PATH_MAX, REGISTRY_VALUE_NAME_MAX,
    RegistryEvent, RegistryOp,
};
use crate::queue::submit::{alloc_event, submit_event};
use crate::state::REGISTRY_CALLBACK_COOKIE;

/// Copy a `PUNICODE_STRING` into a fixed-size UTF-16 buffer.
///
/// Returns the number of UTF-16 units written. Reserves one slot below
/// `MAX` so a fully-truncated path stays distinguishable from one that
/// exactly fills the buffer (mirrors the convention used by the process /
/// image callbacks).
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
        ptr::copy_nonoverlapping(s.Buffer, dst, copy);
        copy
    }
}

/// Resolve a registry-callback `Object` pointer to its NT path.
///
/// `CmCallbackGetKeyObjectIDEx` allocates an internal buffer for the name;
/// the matching `CmCallbackReleaseKeyObjectIDEx` MUST be called once we
/// are done copying — otherwise we leak pool inside the registry hive.
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

/// Allocate, zero, and stamp the header on a fresh `RegistryEvent` buffer.
///
/// Returns the raw pool pointer (caller treats it as `*mut RegistryEvent`).
/// All fields default to zero, so callers only need to fill in what their
/// operation actually populates.
unsafe fn alloc_registry_event() -> *mut u8 {
    let size = core::mem::size_of::<RegistryEvent>() as u32;
    unsafe {
        let buf = alloc_event(size);
        if buf.is_null() {
            return ptr::null_mut();
        }
        // Zero the whole buffer so unused tail bytes ship as 0 instead
        // of leaking uninitialised pool memory to userland.
        ptr::write_bytes(buf, 0, size as usize);

        let evt = buf as *mut RegistryEvent;
        ptr::write(
            addr_of_mut!((*evt).header),
            make_header(EventType::RegistryModify as u16, size),
        );
        // Capture the requester PID. `PsGetCurrentProcessId` returns a
        // HANDLE-typed thin wrapper; the actual PID fits in u32.
        let pid = PsGetCurrentProcessId() as usize as u32;
        ptr::write(addr_of_mut!((*evt).process_id), pid);
        buf
    }
}

/// Emit a `SetValue` event.
unsafe fn emit_set_value(info: *mut RegSetValue) {
    unsafe {
        if info.is_null() {
            return;
        }
        let buf = alloc_registry_event();
        if buf.is_null() {
            return;
        }
        let evt = buf as *mut RegistryEvent;
        let info = &*info;

        ptr::write(addr_of_mut!((*evt).operation), RegistryOp::SetValue as u16);
        ptr::write(addr_of_mut!((*evt).value_type), info.Type);
        ptr::write(addr_of_mut!((*evt).data_size), info.DataSize);

        // Resolve the parent key path from the registry object handle.
        let key_dst = addr_of_mut!((*evt).key_path) as *mut u16;
        let key_len = write_key_path_from_object(info.Object, key_dst, REGISTRY_KEY_PATH_MAX);
        ptr::write(addr_of_mut!((*evt).key_path_len), key_len as u16);

        // Value name lives in a UNICODE_STRING the caller built — copy
        // straight from there.
        let val_dst = addr_of_mut!((*evt).value_name) as *mut u16;
        let val_len = copy_unicode_into(info.ValueName, val_dst, REGISTRY_VALUE_NAME_MAX);
        ptr::write(addr_of_mut!((*evt).value_name_len), val_len as u16);

        // Data preview: per MSDN the data is captured to system memory
        // before the callback fires, so we can copy it straight without
        // probing user space. Truncate to fit; `data_size` already
        // carries the real total length.
        if !info.Data.is_null() && info.DataSize > 0 {
            let data_len = (info.DataSize as usize).min(REGISTRY_DATA_PREVIEW_MAX);
            let data_dst = addr_of_mut!((*evt).data_preview) as *mut u8;
            ptr::copy_nonoverlapping(info.Data as *const u8, data_dst, data_len);
            ptr::write(addr_of_mut!((*evt).data_preview_len), data_len as u16);
        }

        let size = core::mem::size_of::<RegistryEvent>() as u32;
        submit_event(buf, size);
    }
}

/// Emit a `DeleteValue` event. Only the key path + value name are populated.
unsafe fn emit_delete_value(info: *mut RegDeleteValue) {
    unsafe {
        if info.is_null() {
            return;
        }
        let buf = alloc_registry_event();
        if buf.is_null() {
            return;
        }
        let evt = buf as *mut RegistryEvent;
        let info = &*info;

        ptr::write(addr_of_mut!((*evt).operation), RegistryOp::DeleteValue as u16);

        let key_dst = addr_of_mut!((*evt).key_path) as *mut u16;
        let key_len = write_key_path_from_object(info.Object, key_dst, REGISTRY_KEY_PATH_MAX);
        ptr::write(addr_of_mut!((*evt).key_path_len), key_len as u16);

        let val_dst = addr_of_mut!((*evt).value_name) as *mut u16;
        let val_len = copy_unicode_into(info.ValueName, val_dst, REGISTRY_VALUE_NAME_MAX);
        ptr::write(addr_of_mut!((*evt).value_name_len), val_len as u16);

        let size = core::mem::size_of::<RegistryEvent>() as u32;
        submit_event(buf, size);
    }
}

/// Emit a `DeleteKey` event. Only the key path is populated.
unsafe fn emit_delete_key(info: *mut RegDeleteKey) {
    unsafe {
        if info.is_null() {
            return;
        }
        let buf = alloc_registry_event();
        if buf.is_null() {
            return;
        }
        let evt = buf as *mut RegistryEvent;
        let info = &*info;

        ptr::write(addr_of_mut!((*evt).operation), RegistryOp::DeleteKey as u16);

        let key_dst = addr_of_mut!((*evt).key_path) as *mut u16;
        let key_len = write_key_path_from_object(info.Object, key_dst, REGISTRY_KEY_PATH_MAX);
        ptr::write(addr_of_mut!((*evt).key_path_len), key_len as u16);

        let size = core::mem::size_of::<RegistryEvent>() as u32;
        submit_event(buf, size);
    }
}

/// Emit a `RenameKey` event. We log the *source* path; the `NewName`
/// in the rename info is left out for now.
unsafe fn emit_rename_key(info: *mut RegRenameKey) {
    unsafe {
        if info.is_null() {
            return;
        }
        let buf = alloc_registry_event();
        if buf.is_null() {
            return;
        }
        let evt = buf as *mut RegistryEvent;
        let info = &*info;

        ptr::write(addr_of_mut!((*evt).operation), RegistryOp::RenameKey as u16);

        let key_dst = addr_of_mut!((*evt).key_path) as *mut u16;
        let key_len = write_key_path_from_object(info.Object, key_dst, REGISTRY_KEY_PATH_MAX);
        ptr::write(addr_of_mut!((*evt).key_path_len), key_len as u16);

        let size = core::mem::size_of::<RegistryEvent>() as u32;
        submit_event(buf, size);
    }
}

/// Emit a `CreateKey` event.
///
/// `RegNtPreCreateKeyEx` carries the full path in `CompleteName` directly
/// — no need to resolve through `CmCallbackGetKeyObjectIDEx`.
unsafe fn emit_create_key(info: *mut RegCreateKey) {
    unsafe {
        if info.is_null() {
            return;
        }
        let buf = alloc_registry_event();
        if buf.is_null() {
            return;
        }
        let evt = buf as *mut RegistryEvent;
        let info = &*info;

        ptr::write(addr_of_mut!((*evt).operation), RegistryOp::CreateKey as u16);

        let key_dst = addr_of_mut!((*evt).key_path) as *mut u16;
        let key_len = copy_unicode_into(info.CompleteName, key_dst, REGISTRY_KEY_PATH_MAX);
        ptr::write(addr_of_mut!((*evt).key_path_len), key_len as u16);

        let size = core::mem::size_of::<RegistryEvent>() as u32;
        submit_event(buf, size);
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
