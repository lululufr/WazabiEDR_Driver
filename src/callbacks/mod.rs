//! Kernel callbacks registered with the OS.
//!
//! Today: process create/exit, image load, and registry mutations. Future
//! additions (thread create, …) get their own module here.
//!
//! Common bits (notably the `EventHeader` builder) live in `header`.

pub mod header;
pub mod image;
pub mod process;
pub mod registry;
