//! Major-function dispatch routines.
//!
//! `DriverEntry` wires these into `DriverObject->MajorFunction`. Every
//! incoming IRP lands in one of these functions.

use core::ptr;
use core::sync::atomic::Ordering;

use wdk_sys::{
    ntddk::{ExFreePool, KeAcquireSpinLockRaiseToDpc, KeReleaseSpinLock},
    KIRQL, KSPIN_LOCK, NTSTATUS, PIRP, PVOID, STATUS_BUFFER_TOO_SMALL, STATUS_CANCELLED,
    STATUS_INVALID_DEVICE_REQUEST, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};

use crate::ipc::irp::{complete_irp, current_stack_location, mark_irp_pending};
use crate::ipc::IOCTL_WEDR_GET_EVENT;
use crate::queue::ring::queue_pop_locked;
use crate::state::{DROP_COUNT, PENDING_IRP, QUEUE_LOCK};

/// `IRP_MJ_CREATE` / `IRP_MJ_CLOSE` — the agent opens or closes the handle.
/// Nothing to do on either side, just succeed.
pub unsafe extern "C" fn dispatch_create_close(
    _device: *mut wdk_sys::_DEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    unsafe { complete_irp(irp, STATUS_SUCCESS, 0) }
}

/// `IRP_MJ_CLEANUP` — last reference on the agent's file object is going
/// away (process exit, `CloseHandle`, …).
///
/// We must cancel any IOCTL still parked in `PENDING_IRP`, because the
/// associated user-mode buffer is about to be torn down: completing it
/// later would write into freed memory.
pub unsafe extern "C" fn dispatch_cleanup(
    _device: *mut wdk_sys::_DEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    unsafe {
        let pending = PENDING_IRP.swap(ptr::null_mut(), Ordering::AcqRel);
        if !pending.is_null() {
            complete_irp(pending, STATUS_CANCELLED, 0);
        }
        complete_irp(irp, STATUS_SUCCESS, 0)
    }
}

/// `IRP_MJ_DEVICE_CONTROL` — handles `IOCTL_WEDR_GET_EVENT`.
///
/// Two paths:
/// - **Fast**: an event is already queued → copy + complete synchronously.
/// - **Slow**: queue empty → park the IRP in `PENDING_IRP` and return
///   `STATUS_PENDING`. A producer (or `dispatch_cleanup` / `driver_unload`)
///   will eventually complete it.
pub unsafe extern "C" fn dispatch_device_control(
    _device: *mut wdk_sys::_DEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    unsafe {
        let stack = current_stack_location(irp);
        let ioctl = (*stack).Parameters.DeviceIoControl.IoControlCode;
        let outlen = (*stack).Parameters.DeviceIoControl.OutputBufferLength;

        if ioctl != IOCTL_WEDR_GET_EVENT {
            return complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
        }

        let irql: KIRQL =
            KeAcquireSpinLockRaiseToDpc(QUEUE_LOCK.as_mut_ptr() as *mut KSPIN_LOCK);

        // ── Fast path: drain a queued event. ────────────────────────────
        if let Some(slot) = queue_pop_locked() {
            KeReleaseSpinLock(QUEUE_LOCK.as_mut_ptr() as *mut KSPIN_LOCK, irql);

            if outlen < slot.size {
                // Agent's buffer too small — drop the event (it would be
                // hard to "put it back") and tell the agent the size it
                // needs so it can retry.
                ExFreePool(slot.data as PVOID);
                DROP_COUNT.fetch_add(1, Ordering::Relaxed);
                return complete_irp(irp, STATUS_BUFFER_TOO_SMALL, slot.size as usize);
            }

            let sysbuf = (*irp).AssociatedIrp.SystemBuffer as *mut u8;
            ptr::copy_nonoverlapping(slot.data, sysbuf, slot.size as usize);
            ExFreePool(slot.data as PVOID);
            return complete_irp(irp, STATUS_SUCCESS, slot.size as usize);
        }

        // ── Slow path: nothing queued → pend the IRP. ───────────────────
        // Single-client device: refuse a second concurrent IOCTL rather
        // than overwriting `PENDING_IRP`.
        let prev = PENDING_IRP.compare_exchange(
            ptr::null_mut(),
            irp,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        KeReleaseSpinLock(QUEUE_LOCK.as_mut_ptr() as *mut KSPIN_LOCK, irql);

        if prev.is_err() {
            return complete_irp(irp, STATUS_UNSUCCESSFUL, 0);
        }

        mark_irp_pending(irp);
        wdk_sys::STATUS_PENDING
    }
}

/// Catch-all for any `IRP_MJ_*` we don't claim.
///
/// Wired in by `DriverEntry` so that no slot in `MajorFunction` is left at
/// NULL — calling a NULL dispatch routine bug-checks the system.
pub unsafe extern "C" fn dispatch_invalid(
    _device: *mut wdk_sys::_DEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    unsafe { complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0) }
}
