//! Kernel callbacks registered with the OS.
//!
//! Today: process create/exit and image load. Future additions (thread
//! create, registry, …) get their own module here.
//!
//! Common bits (notably the `EventHeader` builder) live in `header`.

pub mod header;
pub mod image;
pub mod process;
