//! `PsSetCreateProcessNotifyRoutineEx` callback.
//!
//! Builds Wazabi events from kernel-supplied process create / exit
//! information and hands them off to `submit_event`.
//!
//! Runtime context: PASSIVE_LEVEL, synchronous, in the context of the
//! creating process (for create) or the exiting process (for exit). It is
//! safe to allocate paged memory here, but we MUST NOT block — every
//! `CreateProcess` in the system passes through this callback.
//!
//! On create, the callback also enriches the event with:
//! - the **command line** of the new process (from `PS_CREATE_NOTIFY_INFO`);
//! - the **parent's image path**, resolved via `PsLookupProcessByProcessId`
//!   + `SeLocateProcessImageName` (best-effort; empty if the parent has
//!   already exited);
//! - the **user SID** in SDDL string form (e.g. `S-1-5-21-…-1001`),
//!   resolved via `PsReferencePrimaryToken` + `SeQueryInformationToken(TokenUser)`
//!   + `RtlConvertSidToUnicodeString` (best-effort).
//!
//! Each resolver is self-contained: it either fills the destination
//! buffer + sets the `_len` field, or leaves both at zero. Failures are
//! silent — they aren't worth dropping the event over, and the agent
//! treats an empty buffer as "kernel couldn't resolve this".

use core::ptr::{self, addr_of_mut};
use core::sync::atomic::Ordering;

// Most of these symbols are only consumed by the disabled resolvers
// (fill_user_sid / fill_parent_image_path / resolve_integrity_level)
// kept around for re-enabling after the SYSTEM_SERVICE_EXCEPTION (0x3B)
// post-mortem. Silence the unused-import warnings rather than tear out
// the code -- ripping it now and re-adding later would lose the
// cleanup orderings we've already proven correct.
#[allow(unused_imports)]
use wdk_sys::{
    ntddk::{
        ExFreePool, ObfDereferenceObject, PsDereferencePrimaryToken, PsGetProcessExitStatus,
        PsLookupProcessByProcessId, PsReferencePrimaryToken, RtlConvertSidToUnicodeString,
        RtlFreeUnicodeString, RtlSubAuthorityCountSid, RtlSubAuthoritySid,
        SeLocateProcessImageName, SeQueryInformationToken,
    },
    HANDLE, PACCESS_TOKEN, PEPROCESS, PPS_CREATE_NOTIFY_INFO, PSID, PUNICODE_STRING,
    STATUS_SUCCESS, TOKEN_INFORMATION_CLASS, UNICODE_STRING, _UNICODE_STRING,
};

use crate::callbacks::header::alloc_event_for;
use crate::events::{
    COMMAND_LINE_MAX, EventType, IMAGE_PATH_MAX, ProcessCreateEvent, ProcessExitEvent,
    USER_SID_MAX,
};
use crate::queue::submit::submit_event;
use crate::state::TRUNC_COUNT;

/// `TOKEN_INFORMATION_CLASS::TokenUser` — picks the variant of
/// `SeQueryInformationToken` that returns a `TOKEN_USER` blob (which
/// begins with the SID pointer). wdk_sys doesn't expose the symbolic
/// constant, but the ABI value is stable across Windows versions.
#[allow(dead_code)]
const TOKEN_USER_CLASS: TOKEN_INFORMATION_CLASS = 1;

/// `TOKEN_INFORMATION_CLASS::TokenIntegrityLevel`. Returns a
/// `TOKEN_MANDATORY_LABEL { SID_AND_ATTRIBUTES Label; }` blob whose
/// SID is `S-1-16-<RID>` — the RID encodes the level.
#[allow(dead_code)]
const TOKEN_INTEGRITY_LEVEL_CLASS: TOKEN_INFORMATION_CLASS = 25;

/// Sentinel returned in `integrity_level` when resolution failed.
#[allow(dead_code)]
const INTEGRITY_LEVEL_UNRESOLVED: u32 = 0xFFFF_FFFF;

/// Build and submit a `ProcessExit` event.
///
/// On allocation failure we silently return: there is nowhere to record
/// "we lost an event because we couldn't allocate a buffer to record the
/// loss". The next successful event will surface the gap via `DROP_COUNT`.
///
/// The exit code is fetched via `PsGetProcessExitStatus(peproc)` — the
/// kernel has already set it by the time the create-process notify
/// fires with `create_info == NULL`. `peproc` is the `PEPROCESS` the
/// notify callback hands us; we do NOT take an extra ref since the
/// kernel guarantees it is valid for the duration of the callback.
unsafe fn emit_process_exit(pid: u32, process: PEPROCESS) {
    unsafe {
        let evt = alloc_event_for::<ProcessExitEvent>(EventType::ProcessExit as u16);
        if evt.is_null() {
            return;
        }
        // Header is already written by `alloc_event_for`; only the
        // ProcessExit-specific tail remains.
        ptr::write(addr_of_mut!((*evt).process_id), pid);
        let exit_code = if process.is_null() {
            0
        } else {
            PsGetProcessExitStatus(process)
        };
        ptr::write(addr_of_mut!((*evt).exit_code), exit_code);
        let size = core::mem::size_of::<ProcessExitEvent>() as u32;
        submit_event(evt as *mut u8, size);
    }
}

/// Build and submit a `ProcessCreate` event.
///
/// Copies as much of the image path as fits into `IMAGE_PATH_MAX` UTF-16
/// units. Truncated paths bump `TRUNC_COUNT` so the agent can surface
/// the loss on the next delivered event.
unsafe fn emit_process_create(pid: u32, info: PPS_CREATE_NOTIFY_INFO) {
    unsafe {
        let evt = alloc_event_for::<ProcessCreateEvent>(EventType::ProcessCreate as u16);
        if evt.is_null() {
            return;
        }

        let parent = (*info).ParentProcessId as usize as u32;
        let creator = (*info).CreatingThreadId.UniqueProcess as usize as u32;

        // The struct is `repr(C, packed)`, so we MUST write fields through
        // raw pointers (`addr_of_mut!`). Taking `&mut field` directly on a
        // packed struct produces a misaligned reference — UB.
        ptr::write(addr_of_mut!((*evt).process_id), pid);
        ptr::write(addr_of_mut!((*evt).parent_process_id), parent);
        ptr::write(addr_of_mut!((*evt).creating_process_id), creator);

        // ---- image_path: NT path of the new executable ---------------
        copy_unicode_string_into(
            (*info).ImageFileName,
            addr_of_mut!((*evt).image_path) as *mut u16,
            IMAGE_PATH_MAX,
            addr_of_mut!((*evt).image_path_len),
        );

        // ---- command_line: full argv as Windows sees it --------------
        copy_unicode_string_into(
            (*info).CommandLine,
            addr_of_mut!((*evt).command_line) as *mut u16,
            COMMAND_LINE_MAX,
            addr_of_mut!((*evt).command_line_len),
        );

        // ---- parent_image_path / user_sid / integrity_level ----
        // DISABLED after a SYSTEM_SERVICE_EXCEPTION (0x3B) BSOD.
        // These three resolvers call into kernel APIs that have
        // edge-case failure modes we haven't blinded yet:
        //   - SeQueryInformationToken on a partially-initialised token
        //   - SeLocateProcessImageName racing a vanishing parent
        //   - RtlSubAuthoritySid walking a malformed SID buffer
        // Userland resolves these post-hoc (OpenProcess +
        // GetTokenInformation + LookupAccountSid) which is slower but
        // can't take the kernel down. The fields stay in the struct
        // (zeroed) so the v6 wire format remains byte-identical and
        // the agent doesn't need a re-bump. To re-enable any of these
        // safely: wrap the inner call site in __try/__except (or a
        // Rust-side equivalent) and validate every kernel-returned
        // pointer before deref.
        ptr::write(addr_of_mut!((*evt).integrity_level), 0xFFFF_FFFFu32);

        let size = core::mem::size_of::<ProcessCreateEvent>() as u32;
        submit_event(evt as *mut u8, size);
    }
}

/// Copy a kernel `PUNICODE_STRING` into a fixed-size UTF-16 buffer at
/// `dst`, capped at `cap` units (minus 1 so a fully-truncated path is
/// distinguishable from one that exactly fills the buffer). Writes the
/// number of valid units into `*len_dst`. Bumps `TRUNC_COUNT` on
/// truncation. A null/empty source string is a no-op (len stays at the
/// pre-zeroed 0).
///
/// # Safety
/// `dst` must point at `cap` writable `u16`s inside the event buffer
/// (zero-initialised by `alloc_event_for`). `len_dst` must point at a
/// `u16` slot inside the same buffer.
unsafe fn copy_unicode_string_into(
    src: *const _UNICODE_STRING,
    dst: *mut u16,
    cap: usize,
    len_dst: *mut u16,
) {
    unsafe {
        if src.is_null() {
            return;
        }
        let s = &*src;
        if s.Buffer.is_null() || s.Length == 0 {
            return;
        }
        // UNICODE_STRING::Length is in bytes; convert to u16 count.
        let chars = (s.Length / 2) as usize;
        let copy = chars.min(cap - 1);
        if chars > copy {
            TRUNC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        ptr::copy_nonoverlapping(s.Buffer, dst, copy);
        ptr::write(len_dst, copy as u16);
    }
}

/// Resolve the parent process's NT image path and copy it into the event.
///
/// Steps (each can fail silently):
/// 1. `PsLookupProcessByProcessId(parent_pid)` → `PEPROCESS` (+1 ref).
/// 2. `SeLocateProcessImageName(peproc)` → `PUNICODE_STRING` allocated
///    from the system pool.
/// 3. Copy into the event buffer.
/// 4. `ExFreePool` the image-name buffer.
/// 5. `ObfDereferenceObject` the `PEPROCESS` ref.
///
/// `PsLookupProcessByProcessId` takes a `HANDLE` (the PID-as-HANDLE
/// alias Windows uses for process IDs).
#[allow(dead_code)] // disabled after BSOD 0x3B; see emit_process_create
unsafe fn fill_parent_image_path(parent_pid: u32, dst: *mut u16, len_dst: *mut u16) {
    if parent_pid == 0 {
        // PID 0 = System Idle; no real image. Skip the lookup entirely.
        return;
    }
    unsafe {
        let mut peproc: PEPROCESS = ptr::null_mut();
        let status = PsLookupProcessByProcessId(parent_pid as usize as HANDLE, &mut peproc);
        if status != STATUS_SUCCESS || peproc.is_null() {
            return;
        }
        let mut image_name: PUNICODE_STRING = ptr::null_mut();
        let status = SeLocateProcessImageName(peproc, &mut image_name);
        if status == STATUS_SUCCESS && !image_name.is_null() {
            copy_unicode_string_into(image_name as *const _, dst, IMAGE_PATH_MAX, len_dst);
            // SeLocateProcessImageName allocates the UNICODE_STRING buffer
            // from the paged pool; the caller frees with ExFreePool.
            ExFreePool(image_name as *mut _);
        }
        ObfDereferenceObject(peproc as *mut _);
    }
}

/// Resolve the **current** process's primary-token user SID and write it
/// into the event as an SDDL string.
///
/// `PsReferencePrimaryToken` runs against `PsGetCurrentProcess()` under
/// the hood, and the create notify callback fires in the context of the
/// process being created — so "current" is what we want.
///
/// Cleanup is layered: token blob → SID string → token ref. Each layer
/// frees what it allocated, in reverse order.
#[allow(dead_code)] // disabled after BSOD 0x3B; see emit_process_create
unsafe fn fill_user_sid(dst: *mut u16, len_dst: *mut u16) {
    unsafe {
        // (1) Grab the primary token (+1 ref).
        let process: PEPROCESS = wdk_sys::ntddk::IoGetCurrentProcess();
        let token: PACCESS_TOKEN = PsReferencePrimaryToken(process);
        if token.is_null() {
            return;
        }

        // (2) Ask the security manager for the TokenUser blob. The system
        //     allocates the buffer; we free it with ExFreePool.
        //     The blob's layout starts with SID_AND_ATTRIBUTES { PSID Sid; ... }
        //     so the very first pointer is the PSID we need.
        let mut token_info: *mut core::ffi::c_void = ptr::null_mut();
        let status = SeQueryInformationToken(token, TOKEN_USER_CLASS, &mut token_info);
        if status == STATUS_SUCCESS && !token_info.is_null() {
            let sid: PSID = ptr::read_unaligned(token_info as *const PSID);
            if !sid.is_null() {
                // (3) Convert the SID to its SDDL string form. We pass
                //     `AllocateDestinationString = TRUE` so the kernel
                //     allocates the buffer; we free it via
                //     RtlFreeUnicodeString.
                let mut sid_str: UNICODE_STRING = core::mem::zeroed();
                let status = RtlConvertSidToUnicodeString(&mut sid_str, sid, 1);
                if status == STATUS_SUCCESS && !sid_str.Buffer.is_null() && sid_str.Length > 0 {
                    let chars = (sid_str.Length / 2) as usize;
                    let copy = chars.min(USER_SID_MAX - 1);
                    if chars > copy {
                        TRUNC_COUNT.fetch_add(1, Ordering::Relaxed);
                    }
                    ptr::copy_nonoverlapping(sid_str.Buffer, dst, copy);
                    ptr::write(len_dst, copy as u16);
                    RtlFreeUnicodeString(&mut sid_str);
                }
            }
            // (4) Free the TokenUser blob.
            ExFreePool(token_info);
        }

        // (5) Drop the token ref.
        PsDereferencePrimaryToken(token);
    }
}

/// Resolve the current process's mandatory integrity level.
///
/// Steps:
/// 1. `PsReferencePrimaryToken(current)` → PACCESS_TOKEN
/// 2. `SeQueryInformationToken(TokenIntegrityLevel)` → TOKEN_MANDATORY_LABEL
///    blob whose first field is a `SID_AND_ATTRIBUTES { PSID Sid; ... }`
/// 3. Walk the SID with `RtlSubAuthority*` to extract the last RID
/// 4. Free everything, deref the token
///
/// Returns `INTEGRITY_LEVEL_UNRESOLVED` on any failure — userland renders
/// it as a sentinel rather than mistaking 0 (Untrusted) for "missing".
#[allow(dead_code)] // disabled after BSOD 0x3B; see emit_process_create
unsafe fn resolve_integrity_level() -> u32 {
    unsafe {
        let process = wdk_sys::ntddk::IoGetCurrentProcess();
        let token = PsReferencePrimaryToken(process);
        if token.is_null() {
            return INTEGRITY_LEVEL_UNRESOLVED;
        }
        let mut blob: *mut core::ffi::c_void = ptr::null_mut();
        let status = SeQueryInformationToken(token, TOKEN_INTEGRITY_LEVEL_CLASS, &mut blob);
        let mut result = INTEGRITY_LEVEL_UNRESOLVED;
        if status == STATUS_SUCCESS && !blob.is_null() {
            // The blob is `TOKEN_MANDATORY_LABEL { SID_AND_ATTRIBUTES Label }`
            // which starts with a `PSID Sid` field — so the very first
            // pointer at the blob's base is the integrity-level SID.
            let sid: PSID = ptr::read_unaligned(blob as *const PSID);
            if !sid.is_null() {
                // Last subauthority of the SID is the integrity RID.
                // RtlSubAuthorityCountSid returns a PUCHAR pointing at
                // the SID's `SubAuthorityCount` byte; minus 1 to get the
                // last entry's index.
                let count_ptr = RtlSubAuthorityCountSid(sid);
                if !count_ptr.is_null() {
                    let count = ptr::read_unaligned(count_ptr);
                    if count > 0 {
                        let sub_ptr = RtlSubAuthoritySid(sid, (count - 1) as u32);
                        if !sub_ptr.is_null() {
                            result = ptr::read_unaligned(sub_ptr);
                        }
                    }
                }
            }
            ExFreePool(blob);
        }
        PsDereferencePrimaryToken(token);
        result
    }
}

/// Entry point registered via `PsSetCreateProcessNotifyRoutineEx`.
///
/// `create_info` is non-null on process creation, null on process exit.
/// We dispatch to the right emitter and return as fast as possible.
pub unsafe extern "C" fn process_notify(
    process: PEPROCESS,
    process_id: wdk_sys::HANDLE,
    create_info: PPS_CREATE_NOTIFY_INFO,
) {
    let pid = process_id as usize as u32;
    unsafe {
        if create_info.is_null() {
            emit_process_exit(pid, process);
        } else {
            emit_process_create(pid, create_info);
        }
    }
}
