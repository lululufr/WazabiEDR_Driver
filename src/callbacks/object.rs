//! `ObRegisterCallbacks` — process handle access notifications.
//!
//! Hooks the object manager so we get a notification every time a handle
//! is created on or duplicated from a `Process` object. This is *the*
//! signal for credential-dumping and cross-process injection prep:
//!
//! - mimikatz and friends `OpenProcess(LSASS, PROCESS_VM_READ | …)` → caught.
//! - DLL injectors `OpenProcess(target, PROCESS_VM_OPERATION | …)` → caught.
//! - Process killers `OpenProcess(av, PROCESS_TERMINATE)` → caught.
//!
//! # Noise control
//!
//! By default this layer is *extremely* noisy: every `OpenProcess`,
//! `GetProcessImageFileNameW`, etc. flows through here. We filter on two
//! axes:
//!
//! 1. **Same-process opens are dropped.** `kernel32!CreateProcess` opens
//!    its own handle as part of process startup; logging that buys us
//!    nothing.
//! 2. **Access-mask gate.** Only requests that include at least one bit
//!    in [`DANGEROUS_PROCESS_MASK`] are forwarded. Everything below that
//!    bar (`PROCESS_QUERY_LIMITED_INFORMATION`, `SYNCHRONIZE`, …) is
//!    silently allowed.
//!
//! The driver never *blocks* an access — `OB_PREOP_SUCCESS` is always
//! returned, in keeping with the "observe only" stance of every other
//! callback in this driver. Future blocking policies could clear bits
//! in `DesiredAccess` here.
//!
//! Runtime context: PASSIVE_LEVEL through DISPATCH_LEVEL depending on the
//! caller. We treat the upper bound (DISPATCH_LEVEL) as the contract:
//! no paged allocations, no blocking, no large copies.

use core::ptr::{self, addr_of_mut};

use wdk_sys::{
    ntddk::{PsGetCurrentProcessId, PsGetProcessId},
    OB_OPERATION_HANDLE_CREATE, PEPROCESS, POB_PRE_OPERATION_INFORMATION, PVOID,
    _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS,
    OB_PREOP_CALLBACK_STATUS,
};

use crate::callbacks::header::make_header;
use crate::events::{EventType, HandleAccessOp, ProcessHandleAccessEvent};
use crate::queue::submit::{alloc_event, submit_event};

// ── Win32 PROCESS_* access-mask bits ────────────────────────────────────
// Repeated locally so we don't pull a Win32 dependency into the driver.
// These values are part of the public Windows ABI and won't change.

const PROCESS_TERMINATE: u32 = 0x0001;
const PROCESS_CREATE_THREAD: u32 = 0x0002;
const PROCESS_VM_OPERATION: u32 = 0x0008;
const PROCESS_VM_READ: u32 = 0x0010;
const PROCESS_VM_WRITE: u32 = 0x0020;
const PROCESS_DUP_HANDLE: u32 = 0x0040;
const PROCESS_SUSPEND_RESUME: u32 = 0x0800;

/// Set of access bits the agent wants to know about. We forward an event
/// when `DesiredAccess & DANGEROUS_PROCESS_MASK != 0`.
///
/// Picked specifically to cover the EDR-relevant operations:
/// - `VM_READ`             → memory reads (credential dumping)
/// - `VM_WRITE`/`VM_OPERATION` → process injection prep
/// - `CREATE_THREAD`       → CreateRemoteThread / shellcode entry
/// - `DUP_HANDLE`          → handle laundering
/// - `TERMINATE`           → process kill (AV tampering)
/// - `SUSPEND_RESUME`      → process suspension (debuggers, hollowing)
///
/// Notably absent: `QUERY_INFORMATION`, `QUERY_LIMITED_INFORMATION`,
/// `SYNCHRONIZE` — too common to be useful at this layer.
pub const DANGEROUS_PROCESS_MASK: u32 = PROCESS_TERMINATE
    | PROCESS_CREATE_THREAD
    | PROCESS_VM_OPERATION
    | PROCESS_VM_READ
    | PROCESS_VM_WRITE
    | PROCESS_DUP_HANDLE
    | PROCESS_SUSPEND_RESUME;

/// Build and submit a `ProcessHandleAccess` event.
///
/// Allocation failures and same-process self-opens are silent — we have
/// already decided this event is interesting by the time we get here.
unsafe fn emit_handle_access(
    source_pid: u32,
    target_pid: u32,
    desired: u32,
    original: u32,
    op: HandleAccessOp,
) {
    let size = core::mem::size_of::<ProcessHandleAccessEvent>() as u32;
    unsafe {
        let buf = alloc_event(size);
        if buf.is_null() {
            return;
        }
        let evt = buf as *mut ProcessHandleAccessEvent;

        // Packed struct: write each field through `addr_of_mut!` so we
        // never form a misaligned reference (UB in Rust).
        ptr::write(
            addr_of_mut!((*evt).header),
            make_header(EventType::ProcessHandleAccess as u16, size),
        );
        ptr::write(addr_of_mut!((*evt).source_process_id), source_pid);
        ptr::write(addr_of_mut!((*evt).target_process_id), target_pid);
        ptr::write(addr_of_mut!((*evt).desired_access), desired);
        ptr::write(addr_of_mut!((*evt).original_desired_access), original);
        ptr::write(addr_of_mut!((*evt).operation), op as u16);

        submit_event(buf, size);
    }
}

/// `OB_PRE_OPERATION_CALLBACK` registered against `PsProcessType`.
///
/// Returns `OB_PREOP_SUCCESS` unconditionally — telemetry only.
pub unsafe extern "C" fn process_object_notify(
    _context: PVOID,
    info: POB_PRE_OPERATION_INFORMATION,
) -> OB_PREOP_CALLBACK_STATUS {
    unsafe {
        if info.is_null() {
            return OB_PREOP_SUCCESS;
        }
        let info = &*info;

        // The OB callback can fire for kernel-mode handles (e.g. handles
        // created by other drivers). They're rarely interesting from an
        // EDR standpoint and would dilute the signal — skip them.
        if info.__bindgen_anon_1.__bindgen_anon_1.KernelHandle() != 0 {
            return OB_PREOP_SUCCESS;
        }

        // The OB API hands us the parent EPROCESS in `Object`; resolve
        // it to a numeric PID for the wire format.
        let target_pid = if info.Object.is_null() {
            0
        } else {
            PsGetProcessId(info.Object as PEPROCESS) as usize as u32
        };
        let source_pid = PsGetCurrentProcessId() as usize as u32;

        // Same-process opens are noise (CreateProcess opens its own
        // handle during startup; `OpenProcess(GetCurrentProcessId(), …)`
        // is also benign).
        if target_pid == source_pid {
            return OB_PREOP_SUCCESS;
        }

        // Decode operation + extract the right access-mask pair from the
        // tagged union. The Operation field is a bit set; in practice
        // exactly one of CREATE / DUPLICATE is set per notification.
        let params = info.Parameters;
        if params.is_null() {
            return OB_PREOP_SUCCESS;
        }

        let (op, desired, original) = if info.Operation == OB_OPERATION_HANDLE_CREATE {
            let p = (*params).CreateHandleInformation;
            (HandleAccessOp::Create, p.DesiredAccess, p.OriginalDesiredAccess)
        } else {
            // The only other defined value is OB_OPERATION_HANDLE_DUPLICATE;
            // anything else is a future op we shouldn't try to render.
            let p = (*params).DuplicateHandleInformation;
            (HandleAccessOp::Duplicate, p.DesiredAccess, p.OriginalDesiredAccess)
        };

        // Access-mask gate: drop everything that doesn't ask for at
        // least one "dangerous" right. Use the *original* mask (what the
        // caller asked for) so an upstream filter clearing bits doesn't
        // hide the original intent from us.
        if (original & DANGEROUS_PROCESS_MASK) == 0 {
            return OB_PREOP_SUCCESS;
        }

        emit_handle_access(source_pid, target_pid, desired, original, op);
    }

    OB_PREOP_SUCCESS
}
