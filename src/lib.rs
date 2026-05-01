#![no_std]

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use wdk_sys::{
    _EVENT_TYPE::NotificationEvent,
    _KWAIT_REASON::Executive,
    ntddk::{
        DbgPrint, KeInitializeEvent, KeSetEvent, KeWaitForSingleObject,
        ObReferenceObjectByHandle, ObfDereferenceObject, PsCreateSystemThread,
        PsTerminateSystemThread, ZwClose,
    },
    HANDLE, KEVENT, LARGE_INTEGER, NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT,
    PRKEVENT, PVOID, PsThreadType, STATUS_SUCCESS,
};

#[repr(transparent)]
struct SyncCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for SyncCell<T> {}
impl<T> SyncCell<T> {
    const fn new(value: T) -> Self { Self(UnsafeCell::new(value)) }
    fn as_mut_ptr(&self) -> *mut T { self.0.get() }
}

static STOP_EVENT: SyncCell<MaybeUninit<KEVENT>> = SyncCell::new(MaybeUninit::uninit());
static THREAD_OBJECT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

unsafe extern "C" fn hello_thread(_context: PVOID) {
    loop {
        unsafe {
            DbgPrint(c"[WazabiEDR] Hello World\n".as_ptr());

            let mut interval = LARGE_INTEGER { QuadPart: -20_000_000 };
            let status = KeWaitForSingleObject(
                STOP_EVENT.as_mut_ptr() as PVOID,
                Executive,
                0,
                0,
                &mut interval,
            );
            if status == STATUS_SUCCESS {
                break;
            }
        }
    }
    unsafe {
        DbgPrint(c"[WazabiEDR] Hello-loop thread exiting\n".as_ptr());
        let _ = PsTerminateSystemThread(STATUS_SUCCESS);
    }
}

unsafe extern "C" fn driver_unload(_driver: PDRIVER_OBJECT) {
    unsafe {
        DbgPrint(c"[WazabiEDR] DriverUnload — signaling thread to stop\n".as_ptr());

        KeSetEvent(STOP_EVENT.as_mut_ptr() as PRKEVENT, 0, 0);

        let thread_obj = THREAD_OBJECT.swap(ptr::null_mut(), Ordering::AcqRel);
        if !thread_obj.is_null() {
            let _ = KeWaitForSingleObject(thread_obj, Executive, 0, 0, ptr::null_mut());
            ObfDereferenceObject(thread_obj);
        }

        DbgPrint(c"[WazabiEDR] DriverUnload — bye\n".as_ptr());
    }
}

// SAFETY: "DriverEntry" is the required symbol name for Windows driver entry points.
#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: PDRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    unsafe {
        DbgPrint(c"[WazabiEDR] DriverEntry called — driver loaded\n".as_ptr());

        (*driver).DriverUnload = Some(driver_unload);

        KeInitializeEvent(STOP_EVENT.as_mut_ptr() as PRKEVENT, NotificationEvent, 0);

        let mut thread_handle: HANDLE = ptr::null_mut();
        let status = PsCreateSystemThread(
            &mut thread_handle,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            Some(hello_thread),
            ptr::null_mut(),
        );
        if status < 0 {
            DbgPrint(c"[WazabiEDR] PsCreateSystemThread failed\n".as_ptr());
            return status;
        }

        let mut obj: PVOID = ptr::null_mut();
        let ref_status = ObReferenceObjectByHandle(
            thread_handle,
            0,
            *PsThreadType,
            0,
            &mut obj,
            ptr::null_mut(),
        );
        let _ = ZwClose(thread_handle);

        if ref_status >= 0 {
            THREAD_OBJECT.store(obj, Ordering::Release);
            DbgPrint(c"[WazabiEDR] Hello-loop thread started\n".as_ptr());
        } else {
            DbgPrint(c"[WazabiEDR] ObReferenceObjectByHandle failed\n".as_ptr());
        }
    }

    STATUS_SUCCESS
}
