use core::fmt;

/// Returns a value that can be formatted using the [`fmt`] traits.
///
/// Supports [`fmt::LowerHex`], [`fmt::UpperHex`], and [`fmt::Display`]
/// (which is the same as [`fmt::LowerHex`]),
/// as well as using the alternate flag (`:#`) to write the hex prefix.
///
/// # Examples
///
/// ```
/// let bytes: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
/// let displayed = const_hex::display(bytes);
/// let s = format!("{displayed} {displayed:#X}");
/// assert_eq!(s, "deadbeef 0xDEADBEEF");
/// ```
#[inline]
pub fn display<T: AsRef<[u8]>>(input: T) -> impl fmt::Display + fmt::LowerHex + fmt::UpperHex {
    Display(input)
}

struct Display<T: AsRef<[u8]>>(T);

impl<T: AsRef<[u8]>> fmt::Display for Display<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl<T: AsRef<[u8]>> fmt::LowerHex for Display<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write::<false>(f)
    }
}

impl<T: AsRef<[u8]>> fmt::UpperHex for Display<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write::<true>(f)
    }
}

impl<T: AsRef<[u8]>> Display<T> {
    fn write<const UPPER: bool>(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        unsafe { crate::imp::encode::<UPPER>(self.0.as_ref(), f) };
        Ok(())
    }
}
