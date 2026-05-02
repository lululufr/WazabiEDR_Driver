//! Standalone helpers used across the driver: a `Sync`-marked interior
//! mutability cell and small string conversions.

pub mod strings;
pub mod sync_cell;

pub use strings::wstr16;
pub use sync_cell::SyncCell;
