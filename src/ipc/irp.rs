//! Low-level IRP helpers shared by every dispatch routine.
//!
//! These wrap awkward bits of `wdk_sys`: there's no Rust binding for
//! `IoGetCurrentIrpStackLocation` or `IoMarkIrpPending`, so we reach into
//! the bindgen-generated unions ourselves.

use wdk_sys::{ntddk::IofCompleteRequest, IO_NO_INCREMENT, NTSTATUS, PIRP};

/// Bit set in `IO_STACK_LOCATION::Control` to record that the dispatch
/// routine returned `STATUS_PENDING`. The I/O manager checks this bit; if
/// it's missing on a pending IRP, the request is treated as completed and
/// gets freed underneath us.
pub const SL_PENDING_RETURNED: u8 = 0x01;

/// Returns the current `IO_STACK_LOCATION` for an IRP.
///
/// The MSDN macro path is `Tail.Overlay.CurrentStackLocation`; bindgen
/// flattens the unions into anonymous fields, hence the long member chain.
#[inline]
pub unsafe fn current_stack_location(irp: PIRP) -> *mut wdk_sys::_IO_STACK_LOCATION {
    unsafe {
        (*irp)
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation
    }
}

/// Equivalent of `IoMarkIrpPending(irp)`.
///
/// Must be called whenever a dispatch routine returns `STATUS_PENDING`,
/// otherwise the I/O manager will not know to wait and may free the IRP.
#[inline]
pub unsafe fn mark_irp_pending(irp: PIRP) {
    unsafe {
        let stack = current_stack_location(irp);
        (*stack).Control |= SL_PENDING_RETURNED;
    }
}

/// Set the IRP's `Status` + `Information` and complete it.
///
/// Returns the same status so callers can write `return complete_irp(...)`.
#[inline]
pub unsafe fn complete_irp(irp: PIRP, status: NTSTATUS, info: usize) -> NTSTATUS {
    unsafe {
        (*irp).IoStatus.__bindgen_anon_1.Status = status;
        (*irp).IoStatus.Information = info as wdk_sys::ULONG_PTR;
        IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
    }
    status
}
