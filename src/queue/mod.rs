//! In-kernel event queue.
//!
//! Two layers, separated for clarity:
//!
//! - `ring`   — bare ring-buffer mechanics (push / pop). Caller-locked.
//! - `submit` — producer-side glue: takes a freshly-built event and either
//!              fulfils a pending IRP directly or enqueues it.
//!
//! Consumers (the IRP_MJ_DEVICE_CONTROL dispatch routine and DriverUnload)
//! use `ring::queue_pop_locked` directly.

pub mod ring;
pub mod submit;
