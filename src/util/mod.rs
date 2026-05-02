//! Standalone helpers used across the driver: a `Sync`-marked interior
//! mutability cell, a RAII spinlock guard, and small string conversions.

pub mod spin_lock;
pub mod strings;
pub mod sync_cell;

pub use spin_lock::SpinLockGuard;
pub use strings::wstr16;
pub use sync_cell::SyncCell;
