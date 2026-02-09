use core::fmt::{self, Write};

/// Internal trait for abstracting over output buffer types.
pub(crate) trait Output {
    fn write(&mut self, bytes: &[u8]);

    #[inline]
    fn write_byte(&mut self, byte: u8) {
        self.write(&[byte])
    }

    #[inline]
    fn remaining(&self) -> Option<usize> {
        None
    }
}

impl Output for &mut [u8] {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let src = bytes.as_ptr();
        let dst = self.as_mut_ptr();
        let count = bytes.len();
        debug_assert!(self.len() >= count);
        unsafe {
            dst.copy_from_nonoverlapping(src, count);
            *self = core::slice::from_raw_parts_mut(dst.add(count), self.len() - count);
        }
    }

    #[inline]
    fn remaining(&self) -> Option<usize> {
        Some(self.len())
    }
}

impl Output for &mut fmt::Formatter<'_> {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        if cfg!(debug_assertions) {
            core::str::from_utf8(bytes).unwrap();
        }
        let _ = self.write_str(unsafe { core::str::from_utf8_unchecked(bytes) });
    }

    #[inline]
    fn write_byte(&mut self, byte: u8) {
        let _ = self.write_char(byte as char);
    }
}
