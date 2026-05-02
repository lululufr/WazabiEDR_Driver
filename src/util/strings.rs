//! Small string helpers for kernel-mode code.

/// Convert an ASCII byte literal that already includes a trailing `\0` into
/// a NUL-terminated UTF-16 array, suitable for `RtlInitUnicodeString`.
///
/// Done as a `const fn` so the array can live in a stack temporary inside
/// `DriverEntry` / `DriverUnload` without needing the heap.
pub const fn wstr16<const N: usize>(s: &[u8; N]) -> [u16; N] {
    let mut out = [0u16; N];
    let mut i = 0;
    while i < N {
        out[i] = s[i] as u16;
        i += 1;
    }
    out
}
