//! RAII guard for `KSPIN_LOCK`.
//!
//! Replaces the manual `KeAcquireSpinLockRaiseToDpc` / `KeReleaseSpinLock`
//! pair: every early-return path through a function gets the release for
//! free via `Drop`, which both shortens the code and removes a class of
//! bug (forgetting to release on one path).
//!
//! Locks raised to DPC level pin the running thread to the current CPU,
//! so the guard is correctly !Send / !Sync by virtue of holding a raw
//! pointer — nothing extra to do.

use wdk_sys::{
    ntddk::{KeAcquireSpinLockRaiseToDpc, KeReleaseSpinLock},
    KIRQL, KSPIN_LOCK,
};

/// Holds a `KSPIN_LOCK` for as long as the guard is alive.
///
/// The saved IRQL is captured on acquisition and replayed on `Drop` so
/// the lock is always released at the right level, regardless of how
/// many `return` paths the caller has.
///
/// To release before the end of scope (e.g. before completing an IRP at
/// PASSIVE_LEVEL), call `drop(guard)` explicitly.
pub struct SpinLockGuard {
    lock: *mut KSPIN_LOCK,
    saved_irql: KIRQL,
}

impl SpinLockGuard {
    /// Acquire `lock` and return a guard.
    ///
    /// # Safety
    /// `lock` must point to a `KSPIN_LOCK` that has been initialised with
    /// `KeInitializeSpinLock` and outlives the guard.
    #[inline]
    pub unsafe fn acquire(lock: *mut KSPIN_LOCK) -> Self {
        let saved_irql = unsafe { KeAcquireSpinLockRaiseToDpc(lock) };
        Self { lock, saved_irql }
    }
}

impl Drop for SpinLockGuard {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: `lock` came from `acquire`, which requires it to be
        // valid for the guard's lifetime.
        unsafe { KeReleaseSpinLock(self.lock, self.saved_irql) };
    }
}
