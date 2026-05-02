//! `SyncCell<T>` — interior-mutability cell that we manually mark as `Sync`.
//!
//! Why we need it: in kernel mode we have several globals (the queue ring,
//! head/tail/len indices, the spinlock storage…) that need interior
//! mutability but are *only* ever touched while we hold our own
//! `KSPIN_LOCK`. The compiler can't see that lock, so we vouch for the
//! invariant by hand instead of paying for `Mutex`/`RefCell`.

use core::cell::UnsafeCell;

#[repr(transparent)]
pub struct SyncCell<T>(UnsafeCell<T>);

// SAFETY: this type provides NO synchronization on its own. Callers must
// serialize access via an external mechanism (spinlock, atomic, …).
unsafe impl<T> Sync for SyncCell<T> {}

impl<T> SyncCell<T> {
    pub const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    /// Returns a raw pointer to the contained value. The caller is fully
    /// responsible for synchronization.
    pub fn as_mut_ptr(&self) -> *mut T {
        self.0.get()
    }
}
