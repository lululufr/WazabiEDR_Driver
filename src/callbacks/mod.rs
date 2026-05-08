//! Kernel callbacks registered with the OS.
//!
//! Coverage today: process create/exit, image load, registry mutations,
//! thread create/exit, and process-handle access. Each domain lives in
//! its own module; common bits (notably the `EventHeader` builder) live
//! in `header`.

pub mod header;
pub mod image;
pub mod object;
pub mod process;
pub mod registry;
pub mod thread;
