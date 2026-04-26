#![no_std]

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

use wdk_sys::{
    ntddk::DbgPrint,
    NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT,
    STATUS_SUCCESS,
};

// SAFETY: "DriverEntry" is the required symbol name for Windows driver entry points.
#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    _driver: PDRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    unsafe {
        DbgPrint(c"[WazabiEDR] DriverEntry called — driver loaded\n".as_ptr());
    }

    STATUS_SUCCESS
}
