//! WazabiEDR kernel driver — Phase 3: real process create/exit events.
//!
//! Architecture: inverted call.
//! - Userland agent opens \\.\WazabiEDR and pumps IOCTL_WEDR_GET_EVENT in a loop.
//! - Driver pends the IRP if no event is queued, completes it as soon as one arrives.
//! - PsSetCreateProcessNotifyRoutineEx feeds the queue with ProcessCreate/Exit.

#![no_std]

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::{self, addr_of_mut};
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

use wdk_sys::{
    ntddk::{
        DbgPrint, ExAllocatePool2, ExFreePool, IoCreateDevice, IoCreateSymbolicLink,
        IoDeleteDevice, IoDeleteSymbolicLink, IofCompleteRequest, KeAcquireSpinLockRaiseToDpc,
        KeInitializeSpinLock, KeQuerySystemTimePrecise, KeReleaseSpinLock,
        PsSetCreateProcessNotifyRoutineEx, RtlInitUnicodeString,
    },
    DO_BUFFERED_IO, FILE_DEVICE_UNKNOWN, FILE_READ_ACCESS, IO_NO_INCREMENT,
    IRP_MJ_CLEANUP, IRP_MJ_CLOSE, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, IRP_MJ_MAXIMUM_FUNCTION,
    KIRQL, KSPIN_LOCK, LARGE_INTEGER, METHOD_BUFFERED, NTSTATUS, PCUNICODE_STRING,
    PDEVICE_OBJECT, PDRIVER_OBJECT, PEPROCESS, PIRP, POOL_FLAG_NON_PAGED, PPS_CREATE_NOTIFY_INFO,
    PVOID, STATUS_BUFFER_TOO_SMALL, STATUS_CANCELLED, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_SUCCESS, STATUS_UNSUCCESSFUL, UNICODE_STRING,
};

// ───────────────────────── Constants ─────────────────────────

const POOL_TAG: u32 = u32::from_ne_bytes(*b"wEDR"); // visible in poolmon

const QUEUE_CAP: usize = 4096;

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// Agent → driver: "give me the next event (blocking)".
/// Output: a serialized event written into the agent's buffer.
const IOCTL_WEDR_GET_EVENT: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS);

const SL_PENDING_RETURNED: u8 = 0x01;

// ───────────────────────── Event format ─────────────────────────

const EVENT_VERSION: u16 = 1;
const IMAGE_PATH_MAX: usize = 512;

#[repr(u16)]
#[allow(dead_code)]
enum EventType {
    ProcessCreate = 1,
    ProcessExit = 2,
}

#[repr(C, packed)]
struct EventHeader {
    version: u16,
    type_: u16,
    timestamp: i64,
    size: u32,
    drop_count: u32,
}

#[repr(C, packed)]
struct ProcessCreateEvent {
    header: EventHeader,
    process_id: u32,
    parent_process_id: u32,
    creating_process_id: u32,
    image_path: [u16; IMAGE_PATH_MAX],
    image_path_len: u16, // chars (not bytes), no NUL
}

#[repr(C, packed)]
struct ProcessExitEvent {
    header: EventHeader,
    process_id: u32,
}

// ───────────────────────── SyncCell helper ─────────────────────────

#[repr(transparent)]
struct SyncCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for SyncCell<T> {}
impl<T> SyncCell<T> {
    const fn new(value: T) -> Self { Self(UnsafeCell::new(value)) }
    fn as_mut_ptr(&self) -> *mut T { self.0.get() }
}

// ───────────────────────── Global state ─────────────────────────

static QUEUE_LOCK: SyncCell<MaybeUninit<KSPIN_LOCK>> = SyncCell::new(MaybeUninit::uninit());

#[derive(Copy, Clone)]
struct Slot { data: *mut u8, size: u32 }
unsafe impl Sync for Slot {}

static QUEUE_BUF: SyncCell<MaybeUninit<[Slot; QUEUE_CAP]>> = SyncCell::new(MaybeUninit::uninit());
static QUEUE_HEAD: SyncCell<usize> = SyncCell::new(0);
static QUEUE_TAIL: SyncCell<usize> = SyncCell::new(0);
static QUEUE_LEN: SyncCell<usize> = SyncCell::new(0);

/// Total events dropped because the queue was full. Sent to userland in event header.
static DROP_COUNT: AtomicU32 = AtomicU32::new(0);

/// One pending IRP slot (single client). null = no IOCTL waiting.
static PENDING_IRP: AtomicPtr<wdk_sys::_IRP> = AtomicPtr::new(ptr::null_mut());

static CONTROL_DEVICE: AtomicPtr<wdk_sys::_DEVICE_OBJECT> = AtomicPtr::new(ptr::null_mut());

/// True once PsSetCreateProcessNotifyRoutineEx has been registered, so unload
/// knows whether to deregister.
static CALLBACK_REGISTERED: AtomicBool = AtomicBool::new(false);

// ───────────────────────── IRP inline helpers ─────────────────────────

#[inline]
unsafe fn current_stack_location(irp: PIRP) -> *mut wdk_sys::_IO_STACK_LOCATION {
    unsafe {
        (*irp)
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation
    }
}

#[inline]
unsafe fn mark_irp_pending(irp: PIRP) {
    unsafe {
        let stack = current_stack_location(irp);
        (*stack).Control |= SL_PENDING_RETURNED;
    }
}

#[inline]
unsafe fn complete_irp(irp: PIRP, status: NTSTATUS, info: usize) -> NTSTATUS {
    unsafe {
        (*irp).IoStatus.__bindgen_anon_1.Status = status;
        (*irp).IoStatus.Information = info as wdk_sys::ULONG_PTR;
        IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
    }
    status
}

// ───────────────────────── Queue operations ─────────────────────────
// Caller must hold QUEUE_LOCK.

unsafe fn queue_push_locked(data: *mut u8, size: u32) -> bool {
    unsafe {
        let buf = QUEUE_BUF.as_mut_ptr() as *mut Slot;
        let head = &mut *QUEUE_HEAD.as_mut_ptr();
        let tail = &mut *QUEUE_TAIL.as_mut_ptr();
        let len = &mut *QUEUE_LEN.as_mut_ptr();

        if *len == QUEUE_CAP {
            // Drop oldest to make room — preserve recency.
            let old = *buf.add(*head);
            ExFreePool(old.data as PVOID);
            *head = (*head + 1) % QUEUE_CAP;
            *len -= 1;
            DROP_COUNT.fetch_add(1, Ordering::Relaxed);
        }

        *buf.add(*tail) = Slot { data, size };
        *tail = (*tail + 1) % QUEUE_CAP;
        *len += 1;
        true
    }
}

unsafe fn queue_pop_locked() -> Option<Slot> {
    unsafe {
        let buf = QUEUE_BUF.as_mut_ptr() as *mut Slot;
        let head = &mut *QUEUE_HEAD.as_mut_ptr();
        let len = &mut *QUEUE_LEN.as_mut_ptr();

        if *len == 0 { return None; }
        let s = *buf.add(*head);
        *head = (*head + 1) % QUEUE_CAP;
        *len -= 1;
        Some(s)
    }
}

// ───────────────────────── Event submission ─────────────────────────
// Called from producer (thread / future callbacks).
// Either completes a pending IRP, or queues the event (dropping oldest if full).

unsafe fn submit_event(data: *mut u8, size: u32) {
    unsafe {
        let irql: KIRQL = KeAcquireSpinLockRaiseToDpc(QUEUE_LOCK.as_mut_ptr() as *mut KSPIN_LOCK);

        let pending = PENDING_IRP.swap(ptr::null_mut(), Ordering::AcqRel);

        if !pending.is_null() {
            // Try to fulfil the pending IRP directly.
            let stack = current_stack_location(pending);
            let outlen = (*stack).Parameters.DeviceIoControl.OutputBufferLength;

            if outlen >= size {
                let sysbuf = (*pending).AssociatedIrp.SystemBuffer as *mut u8;
                ptr::copy_nonoverlapping(data, sysbuf, size as usize);

                KeReleaseSpinLock(QUEUE_LOCK.as_mut_ptr() as *mut KSPIN_LOCK, irql);
                ExFreePool(data as PVOID);
                complete_irp(pending, STATUS_SUCCESS, size as usize);
                return;
            } else {
                // Buffer too small — fail this IRP. Drop the event so the agent
                // can retry with the right size (returned in Information).
                KeReleaseSpinLock(QUEUE_LOCK.as_mut_ptr() as *mut KSPIN_LOCK, irql);
                ExFreePool(data as PVOID);
                DROP_COUNT.fetch_add(1, Ordering::Relaxed);
                complete_irp(pending, STATUS_BUFFER_TOO_SMALL, size as usize);
                return;
            }
        }

        // No pending IRP → enqueue.
        queue_push_locked(data, size);
        KeReleaseSpinLock(QUEUE_LOCK.as_mut_ptr() as *mut KSPIN_LOCK, irql);
    }
}

unsafe fn alloc_event(size: u32) -> *mut u8 {
    unsafe {
        ExAllocatePool2(POOL_FLAG_NON_PAGED, size as u64, POOL_TAG) as *mut u8
    }
}

// ───────────────────────── IRP dispatch ─────────────────────────

unsafe extern "C" fn dispatch_create_close(
    _device: *mut wdk_sys::_DEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    unsafe { complete_irp(irp, STATUS_SUCCESS, 0) }
}

unsafe extern "C" fn dispatch_cleanup(
    _device: *mut wdk_sys::_DEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    unsafe {
        // Agent closed its handle (or died) → cancel any pending IRP we owe it.
        let pending = PENDING_IRP.swap(ptr::null_mut(), Ordering::AcqRel);
        if !pending.is_null() {
            complete_irp(pending, STATUS_CANCELLED, 0);
        }
        complete_irp(irp, STATUS_SUCCESS, 0)
    }
}

unsafe extern "C" fn dispatch_device_control(
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

        let irql: KIRQL = KeAcquireSpinLockRaiseToDpc(QUEUE_LOCK.as_mut_ptr() as *mut KSPIN_LOCK);

        // Fast path: there's already an event queued.
        if let Some(slot) = queue_pop_locked() {
            KeReleaseSpinLock(QUEUE_LOCK.as_mut_ptr() as *mut KSPIN_LOCK, irql);

            if outlen < slot.size {
                ExFreePool(slot.data as PVOID);
                DROP_COUNT.fetch_add(1, Ordering::Relaxed);
                return complete_irp(irp, STATUS_BUFFER_TOO_SMALL, slot.size as usize);
            }

            let sysbuf = (*irp).AssociatedIrp.SystemBuffer as *mut u8;
            ptr::copy_nonoverlapping(slot.data, sysbuf, slot.size as usize);
            ExFreePool(slot.data as PVOID);
            return complete_irp(irp, STATUS_SUCCESS, slot.size as usize);
        }

        // No event → pend the IRP. Reject if another one is already pending (one client).
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

// ───────────────────────── Process create/exit callback ─────────────────────────
//
// Runs at PASSIVE_LEVEL, synchronously in the context of the creating process
// (for create) or the exiting process (for exit). Must NOT block.

unsafe fn make_header(type_: u16, size: u32) -> EventHeader {
    let mut ts = LARGE_INTEGER { QuadPart: 0 };
    unsafe { KeQuerySystemTimePrecise(&mut ts) };
    EventHeader {
        version: EVENT_VERSION,
        type_,
        timestamp: unsafe { ts.QuadPart },
        size,
        drop_count: DROP_COUNT.swap(0, Ordering::Relaxed),
    }
}

unsafe fn emit_process_exit(pid: u32) {
    let size = core::mem::size_of::<ProcessExitEvent>() as u32;
    unsafe {
        let buf = alloc_event(size);
        if buf.is_null() { return; }
        let evt = buf as *mut ProcessExitEvent;
        ptr::write(evt, ProcessExitEvent {
            header: make_header(EventType::ProcessExit as u16, size),
            process_id: pid,
        });
        submit_event(buf, size);
    }
}

unsafe fn emit_process_create(pid: u32, info: PPS_CREATE_NOTIFY_INFO) {
    let size = core::mem::size_of::<ProcessCreateEvent>() as u32;
    unsafe {
        let buf = alloc_event(size);
        if buf.is_null() { return; }
        // Zero everything (image_path tail will stay at 0).
        ptr::write_bytes(buf, 0, size as usize);

        let evt = buf as *mut ProcessCreateEvent;
        let parent = (*info).ParentProcessId as usize as u32;
        let creator = (*info).CreatingThreadId.UniqueProcess as usize as u32;

        ptr::write(addr_of_mut!((*evt).header),
                   make_header(EventType::ProcessCreate as u16, size));
        ptr::write(addr_of_mut!((*evt).process_id), pid);
        ptr::write(addr_of_mut!((*evt).parent_process_id), parent);
        ptr::write(addr_of_mut!((*evt).creating_process_id), creator);

        // Copy image path (NT path: \Device\HarddiskVolumeN\…\foo.exe).
        let img_str = (*info).ImageFileName;
        if !img_str.is_null() {
            let img = &*img_str;
            if !img.Buffer.is_null() && img.Length > 0 {
                let chars = (img.Length / 2) as usize;
                let copy = chars.min(IMAGE_PATH_MAX - 1);
                let dst = addr_of_mut!((*evt).image_path) as *mut u16;
                ptr::copy_nonoverlapping(img.Buffer, dst, copy);
                ptr::write(addr_of_mut!((*evt).image_path_len), copy as u16);
            }
        }

        submit_event(buf, size);
    }
}

unsafe extern "C" fn process_notify(
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

// ───────────────────────── DriverUnload ─────────────────────────

unsafe extern "C" fn driver_unload(_driver: PDRIVER_OBJECT) {
    unsafe {
        DbgPrint(c"[WazabiEDR] DriverUnload — stopping\n".as_ptr());

        // 1. Deregister the process notify callback so no more events arrive.
        if CALLBACK_REGISTERED.swap(false, Ordering::AcqRel) {
            let _ = PsSetCreateProcessNotifyRoutineEx(Some(process_notify), 1);
        }

        // 2. Cancel any pending IRP.
        let pending = PENDING_IRP.swap(ptr::null_mut(), Ordering::AcqRel);
        if !pending.is_null() {
            complete_irp(pending, STATUS_CANCELLED, 0);
        }

        // 3. Drain the queue.
        let irql: KIRQL = KeAcquireSpinLockRaiseToDpc(QUEUE_LOCK.as_mut_ptr() as *mut KSPIN_LOCK);
        while let Some(slot) = queue_pop_locked() {
            ExFreePool(slot.data as PVOID);
        }
        KeReleaseSpinLock(QUEUE_LOCK.as_mut_ptr() as *mut KSPIN_LOCK, irql);

        // 4. Tear down the device.
        let mut symlink: UNICODE_STRING = core::mem::zeroed();
        let symlink_buf: [u16; 22] = wstr16(b"\\DosDevices\\WazabiEDR\0");
        RtlInitUnicodeString(&mut symlink, symlink_buf.as_ptr());
        let _ = IoDeleteSymbolicLink(&mut symlink);

        let dev = CONTROL_DEVICE.swap(ptr::null_mut(), Ordering::AcqRel);
        if !dev.is_null() {
            IoDeleteDevice(dev);
        }

        DbgPrint(c"[WazabiEDR] DriverUnload — bye\n".as_ptr());
    }
}

// Helper: builds a UTF-16 NUL-terminated array from an ASCII byte literal that
// already includes the trailing NUL (`b"...\0"`). Used to feed RtlInitUnicodeString.
const fn wstr16<const N: usize>(s: &[u8; N]) -> [u16; N] {
    let mut out = [0u16; N];
    let mut i = 0;
    while i < N {
        out[i] = s[i] as u16;
        i += 1;
    }
    out
}

// ───────────────────────── DriverEntry ─────────────────────────

#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: PDRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    unsafe {
        DbgPrint(c"[WazabiEDR] DriverEntry called\n".as_ptr());

        // Wire up unload + IRP dispatch BEFORE creating the device, so any incoming
        // IRP between IoCreateDevice and the end of DriverEntry is handled.
        (*driver).DriverUnload = Some(driver_unload);

        let mj = (*driver).MajorFunction.as_mut_ptr();
        for i in 0..=IRP_MJ_MAXIMUM_FUNCTION as usize {
            *mj.add(i) = Some(dispatch_invalid);
        }
        *mj.add(IRP_MJ_CREATE as usize) = Some(dispatch_create_close);
        *mj.add(IRP_MJ_CLOSE as usize) = Some(dispatch_create_close);
        *mj.add(IRP_MJ_CLEANUP as usize) = Some(dispatch_cleanup);
        *mj.add(IRP_MJ_DEVICE_CONTROL as usize) = Some(dispatch_device_control);

        // Init synchronization primitives.
        KeInitializeSpinLock(QUEUE_LOCK.as_mut_ptr() as *mut KSPIN_LOCK);

        // Create the control device: \Device\WazabiEDR
        let mut device_name: UNICODE_STRING = core::mem::zeroed();
        let device_name_buf: [u16; 18] = wstr16(b"\\Device\\WazabiEDR\0");
        RtlInitUnicodeString(&mut device_name, device_name_buf.as_ptr());

        let mut device: PDEVICE_OBJECT = ptr::null_mut();
        let status = IoCreateDevice(
            driver,
            0,
            &mut device_name,
            FILE_DEVICE_UNKNOWN,
            0,
            0, // Exclusive = FALSE
            &mut device,
        );
        if status < 0 {
            DbgPrint(c"[WazabiEDR] IoCreateDevice failed\n".as_ptr());
            return status;
        }

        (*device).Flags |= DO_BUFFERED_IO;
        CONTROL_DEVICE.store(device, Ordering::Release);

        // Symbolic link: \DosDevices\WazabiEDR → \Device\WazabiEDR
        let mut symlink: UNICODE_STRING = core::mem::zeroed();
        let symlink_buf: [u16; 22] = wstr16(b"\\DosDevices\\WazabiEDR\0");
        RtlInitUnicodeString(&mut symlink, symlink_buf.as_ptr());
        let status = IoCreateSymbolicLink(&mut symlink, &mut device_name);
        if status < 0 {
            DbgPrint(c"[WazabiEDR] IoCreateSymbolicLink failed\n".as_ptr());
            IoDeleteDevice(device);
            CONTROL_DEVICE.store(ptr::null_mut(), Ordering::Release);
            return status;
        }

        // Register process create/exit callback.
        let status = PsSetCreateProcessNotifyRoutineEx(Some(process_notify), 0);
        if status < 0 {
            DbgPrint(c"[WazabiEDR] PsSetCreateProcessNotifyRoutineEx failed\n".as_ptr());
            let _ = IoDeleteSymbolicLink(&mut symlink);
            IoDeleteDevice(device);
            CONTROL_DEVICE.store(ptr::null_mut(), Ordering::Release);
            return status;
        }
        CALLBACK_REGISTERED.store(true, Ordering::Release);

        DbgPrint(c"[WazabiEDR] ready (\\\\.\\WazabiEDR + ProcessNotify)\n".as_ptr());
    }

    STATUS_SUCCESS
}

unsafe extern "C" fn dispatch_invalid(
    _device: *mut wdk_sys::_DEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    unsafe { complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0) }
}
