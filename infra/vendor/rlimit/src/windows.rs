use std::io;
use std::os::raw::c_int;

extern "C" {
    fn _setmaxstdio(new_max: c_int) -> c_int;
    fn _getmaxstdio() -> c_int;
}

/// Sets a maximum for the number of simultaneously open files at the stream I/O level.
///
/// The maximum allowed value is platform-dependent, typically 8192 on modern systems.
/// Values that would overflow when converted to `c_int` or exceed the platform's
/// maximum will result in an error.
///
/// See <https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/setmaxstdio?view=msvc-170>
///
/// # Errors
/// Returns an error if:
/// - `new_max` exceeds `c_int::MAX` (typically 2,147,483,647)
/// - `new_max` is below the minimum (typically 20) or above the platform maximum (typically 8192)
/// - The underlying `_setmaxstdio` call fails
#[cfg_attr(docsrs, doc(cfg(windows)))]
pub fn setmaxstdio(new_max: u32) -> io::Result<u32> {
    // Validate that new_max fits in c_int to prevent overflow.
    // SAFETY: c_int::MAX (i32::MAX = 2147483647) fits in u32, so this cast is safe.
    if new_max > c_int::MAX as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "new_max exceeds maximum allowed value",
        ));
    }

    // SAFETY: We've validated that new_max fits in c_int, so the cast is safe
    // (though clippy warns about possible wrapping). The cast back to u32 is
    // safe because we've checked that ret >= 0.
    #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
    unsafe {
        let ret = _setmaxstdio(new_max as c_int);
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ret as u32)
    }
}

/// Returns the number of simultaneously open files permitted at the stream I/O level.
///
/// See <https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/getmaxstdio?view=msvc-170>
#[cfg_attr(docsrs, doc(cfg(windows)))]
#[must_use]
pub fn getmaxstdio() -> u32 {
    // SAFETY: A negative `ret` should never appear.
    // It is safe even if the return value is wrong.
    #[allow(clippy::cast_sign_loss)]
    unsafe {
        let ret = _getmaxstdio();
        debug_assert!(ret >= 0);
        ret as u32
    }
}
