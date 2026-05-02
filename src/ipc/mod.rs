//! IRP plumbing — everything that talks to the I/O manager.
//!
//! - `irp`      — small inline helpers (IRP completion, stack-location access).
//! - `dispatch` — major-function handlers wired into `DriverObject->MajorFunction`.
//!
//! The IOCTL contract that userland speaks is also defined here, since it's
//! shared by `dispatch` and serves as our public protocol.

use wdk_sys::{FILE_DEVICE_UNKNOWN, FILE_READ_ACCESS, METHOD_BUFFERED};

pub mod dispatch;
pub mod irp;

/// Build a Windows IOCTL code (mirrors the C `CTL_CODE` macro).
const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// Agent → driver: "give me the next event (blocking)".
///
/// - Output buffer: receives one serialized event.
/// - On success: returns `STATUS_SUCCESS`, `Information` = bytes written.
/// - If the agent's buffer is too small: `STATUS_BUFFER_TOO_SMALL`,
///   `Information` = required size.
/// - If a second IOCTL arrives while one is already pending:
///   `STATUS_UNSUCCESSFUL` (single-client device).
pub const IOCTL_WEDR_GET_EVENT: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS);
