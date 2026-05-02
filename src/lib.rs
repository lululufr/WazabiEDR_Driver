//! WazabiEDR kernel driver — crate root.
//!
//! # Architecture (inverted call)
//!
//! 1. The userland agent opens `\\.\WazabiEDR` and pumps
//!    `IOCTL_WEDR_GET_EVENT` in a loop.
//! 2. Fast path: if an event is already queued, the driver copies it into
//!    the agent's buffer and completes the IRP synchronously.
//! 3. Slow path: if nothing is queued, the IRP is parked. As soon as a
//!    callback produces an event it is delivered straight to the parked
//!    IRP — the event never even hits the queue.
//! 4. While no agent is connected, events accumulate in a bounded ring
//!    buffer; under pressure the oldest get evicted and `drop_count` in
//!    the next delivered event tells the agent how many it missed.
//!
//! # Module map
//!
//! - [`events`]    — wire format shared with the agent
//! - [`state`]     — global mutable state (queue, lock, pending IRP, …)
//! - [`ipc`]       — IRP plumbing: IOCTL codes, IRP helpers, dispatch
//! - [`queue`]     — ring buffer + producer-side submission
//! - [`callbacks`] — kernel callbacks (process create/exit, image load)
//! - [`util`]      — `SyncCell`, string helpers
//!
//! Only `DriverEntry` and `DriverUnload` live in this file.

#![no_std]

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

mod callbacks;
mod events;
mod ipc;
mod queue;
mod state;
mod util;

use core::ptr;
use core::sync::atomic::Ordering;


///Export of WINapi function available in WDK
use wdk_sys::{
    ntddk::{
        DbgPrint, ExFreePool, IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice,
        IoDeleteSymbolicLink, KeAcquireSpinLockRaiseToDpc, KeInitializeSpinLock,
        KeReleaseSpinLock, PsRemoveLoadImageNotifyRoutine, PsSetCreateProcessNotifyRoutineEx,
        PsSetLoadImageNotifyRoutine, RtlInitUnicodeString,
    },
    DO_BUFFERED_IO, FILE_DEVICE_UNKNOWN, IRP_MJ_CLEANUP, IRP_MJ_CLOSE, IRP_MJ_CREATE,
    IRP_MJ_DEVICE_CONTROL, IRP_MJ_MAXIMUM_FUNCTION, KIRQL, KSPIN_LOCK, NTSTATUS,
    PCUNICODE_STRING, PDEVICE_OBJECT, PDRIVER_OBJECT, PVOID, STATUS_CANCELLED, STATUS_SUCCESS,
    UNICODE_STRING,
};

use crate::callbacks::image::image_load_notify;
use crate::callbacks::process::process_notify;
use crate::ipc::dispatch::{
    dispatch_cleanup, dispatch_create_close, dispatch_device_control, dispatch_invalid,
};
use crate::ipc::irp::complete_irp;
use crate::queue::ring::queue_pop_locked;
use crate::state::{
    CONTROL_DEVICE, IMAGE_CALLBACK_REGISTERED, PENDING_IRP, PROCESS_CALLBACK_REGISTERED,
    QUEUE_LOCK,
};
use crate::util::wstr16;

/// Kernel-internal device name. Created by `IoCreateDevice`.
const DEVICE_NAME: &[u8; 18] = b"\\Device\\WazabiEDR\0";

/// DOS-namespace symbolic link. This is what userland opens (as
/// `\\.\WazabiEDR`).
const SYMLINK_NAME: &[u8; 22] = b"\\DosDevices\\WazabiEDR\0";


/// Driver entry point.
///
/// Order of operations is deliberate: we wire dispatch handlers BEFORE
/// creating the device, so any IRP that arrives between `IoCreateDevice`
/// returning and the rest of `DriverEntry` finishing has a valid handler.
///
/// On any failure we tear down whatever was already set up.
#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: PDRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    unsafe {
        DbgPrint(c"[WazabiEDR] DriverEntry called\n".as_ptr());

        // ── 1. Wire DriverUnload + every IRP_MJ_* slot. ─────────────────
        // Every slot in MajorFunction must be non-NULL: a NULL dispatch
        // routine bug-checks the system on the first matching IRP.
        (*driver).DriverUnload = Some(driver_unload);


        let mj = (*driver).MajorFunction.as_mut_ptr();
        for i in 0..=IRP_MJ_MAXIMUM_FUNCTION as usize {
            *mj.add(i) = Some(dispatch_invalid);
        }

        *mj.add(IRP_MJ_CREATE as usize) = Some(dispatch_create_close);
        *mj.add(IRP_MJ_CLOSE as usize) = Some(dispatch_create_close);
        *mj.add(IRP_MJ_CLEANUP as usize) = Some(dispatch_cleanup);
        *mj.add(IRP_MJ_DEVICE_CONTROL as usize) = Some(dispatch_device_control);

        // ── 2. Initialise synchronization primitives. ───────────────────
        KeInitializeSpinLock(QUEUE_LOCK.as_mut_ptr() as *mut KSPIN_LOCK);

        // ── 3. Create \Device\WazabiEDR. ────────────────────────────────
        let mut device_name: UNICODE_STRING = core::mem::zeroed();
        let device_name_buf: [u16; 18] = wstr16(DEVICE_NAME);
        RtlInitUnicodeString(&mut device_name, device_name_buf.as_ptr());

        let mut device: PDEVICE_OBJECT = ptr::null_mut();
        let status = IoCreateDevice(
            driver,
            0,
            &mut device_name,
            FILE_DEVICE_UNKNOWN,
            0,
            0, // Exclusive = FALSE (we still serialize via PENDING_IRP)
            &mut device,
        );
        if status < 0 {
            DbgPrint(c"[WazabiEDR] IoCreateDevice failed\n".as_ptr());
            return status;
        }

        // METHOD_BUFFERED IOCTLs use SystemBuffer, but DO_BUFFERED_IO is
        // also required for read/write paths we may add later.
        (*device).Flags |= DO_BUFFERED_IO;
        CONTROL_DEVICE.store(device, Ordering::Release);

        // ── 4. Create the \DosDevices symlink. ──────────────────────────
        let mut symlink: UNICODE_STRING = core::mem::zeroed();
        let symlink_buf: [u16; 22] = wstr16(SYMLINK_NAME);
        RtlInitUnicodeString(&mut symlink, symlink_buf.as_ptr());
        let status = IoCreateSymbolicLink(&mut symlink, &mut device_name);
        if status < 0 {
            DbgPrint(c"[WazabiEDR] IoCreateSymbolicLink failed\n".as_ptr());
            IoDeleteDevice(device);
            CONTROL_DEVICE.store(ptr::null_mut(), Ordering::Release);
            return status;
        }

        // ── 5. Register the process create/exit callback. ───────────────
        // From this point on `process_notify` may run on another CPU, so
        // any subsequent failure must unwind it.
        let status = PsSetCreateProcessNotifyRoutineEx(Some(process_notify), 0);
        if status < 0 {
            DbgPrint(c"[WazabiEDR] PsSetCreateProcessNotifyRoutineEx failed\n".as_ptr());
            let _ = IoDeleteSymbolicLink(&mut symlink);
            IoDeleteDevice(device);
            CONTROL_DEVICE.store(ptr::null_mut(), Ordering::Release);
            return status;
        }
        PROCESS_CALLBACK_REGISTERED.store(true, Ordering::Release);

        // ── 6. Register the image-load callback. ────────────────────────
        // Same caveat as above: must be the LAST fallible step. On failure
        // we unwind both the process callback (registered above) and the
        // device + symlink.
        let status = PsSetLoadImageNotifyRoutine(Some(image_load_notify));
        if status < 0 {
            DbgPrint(c"[WazabiEDR] PsSetLoadImageNotifyRoutine failed\n".as_ptr());
            let _ = PsSetCreateProcessNotifyRoutineEx(Some(process_notify), 1);
            PROCESS_CALLBACK_REGISTERED.store(false, Ordering::Release);
            let _ = IoDeleteSymbolicLink(&mut symlink);
            IoDeleteDevice(device);
            CONTROL_DEVICE.store(ptr::null_mut(), Ordering::Release);
            return status;
        }
        IMAGE_CALLBACK_REGISTERED.store(true, Ordering::Release);

        DbgPrint(
            c"[WazabiEDR] ready (\\\\.\\WazabiEDR + ProcessNotify + ImageLoadNotify)\n".as_ptr(),
        );
    }

    STATUS_SUCCESS
}

/// Driver unload, called by the I/O manager. The order MUST be:
///
/// 1. Stop new events at the source — deregister every kernel callback,
///    otherwise a callback running on another CPU could allocate a buffer
///    we're about to free.
/// 2. Cancel any IRP we still owe userland.
/// 3. Drain the queue (free remaining buffers).
/// 4. Tear down the symlink + device.
unsafe extern "C" fn driver_unload(_driver: PDRIVER_OBJECT) {
    unsafe {
        DbgPrint(c"[WazabiEDR] DriverUnload — stopping\n".as_ptr());

        // 1. Deregister callbacks. Each one has its own flag so we never
        //    double-remove (which would bug-check). Second arg of
        //    PsSetCreateProcessNotifyRoutineEx is `Remove` (TRUE = remove).
        if PROCESS_CALLBACK_REGISTERED.swap(false, Ordering::AcqRel) {
            let _ = PsSetCreateProcessNotifyRoutineEx(Some(process_notify), 1);
        }
        if IMAGE_CALLBACK_REGISTERED.swap(false, Ordering::AcqRel) {
            let _ = PsRemoveLoadImageNotifyRoutine(Some(image_load_notify));
        }

        // 2. Cancel a still-pending IRP (the agent might be blocked).
        let pending = PENDING_IRP.swap(ptr::null_mut(), Ordering::AcqRel);
        if !pending.is_null() {
            complete_irp(pending, STATUS_CANCELLED, 0);
        }

        // 3. Drain whatever is left in the queue.
        let irql: KIRQL =
            KeAcquireSpinLockRaiseToDpc(QUEUE_LOCK.as_mut_ptr() as *mut KSPIN_LOCK);
        while let Some(slot) = queue_pop_locked() {
            ExFreePool(slot.data as PVOID);
        }
        KeReleaseSpinLock(QUEUE_LOCK.as_mut_ptr() as *mut KSPIN_LOCK, irql);

        // 4. Symlink first (userland namespace), then device.
        let mut symlink: UNICODE_STRING = core::mem::zeroed();
        let symlink_buf: [u16; 22] = wstr16(SYMLINK_NAME);
        RtlInitUnicodeString(&mut symlink, symlink_buf.as_ptr());
        let _ = IoDeleteSymbolicLink(&mut symlink);

        let dev = CONTROL_DEVICE.swap(ptr::null_mut(), Ordering::AcqRel);
        if !dev.is_null() {
            IoDeleteDevice(dev);
        }

        DbgPrint(c"[WazabiEDR] DriverUnload — bye\n".as_ptr());
    }
}
