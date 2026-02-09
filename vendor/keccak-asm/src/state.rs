use core::{mem::MaybeUninit, ptr};
use sha3_asm::{Buffer, SHA3_absorb, SHA3_squeeze};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_BUFSZ: usize = (1600 / 8) - 32;

/// Core SHA-3 state.
///
/// Implementation from [OpenSSL](https://github.com/openssl/openssl/blob/eaee1765a49c6a8ba728e3e2d18bb67bff8aaa55/include/internal/sha3.h#L34).
// Note: here block_size, md_size (output size), pad are all compile-time constants,
// while the OpenSSL implementation uses runtime variables stored in this struct
#[derive(Clone)]
#[allow(non_snake_case)]
pub(crate) struct Sha3State<const BITS: usize, const PAD: u8> {
    /// Core state buffer.
    A: Buffer,
    /// Used bytes in the temporary buffer.
    bufsz: usize,
    /// Temporary buffer.
    buf: [MaybeUninit<u8>; MAX_BUFSZ],
}

impl<const BITS: usize, const PAD: u8> Default for Sha3State<BITS, PAD> {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "zeroize")]
impl<const BITS: usize, const PAD: u8> Drop for Sha3State<BITS, PAD> {
    fn drop(&mut self) {
        self.A.zeroize();
        self.buf.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<const BITS: usize, const PAD: u8> ZeroizeOnDrop for Sha3State<BITS, PAD> {}

impl<const BITS: usize, const PAD: u8> Sha3State<BITS, PAD> {
    const OUT_SIZE: usize = BITS / 8;
    const BLOCK_SIZE: usize = (1600 - BITS * 2) / 8;

    #[inline(always)]
    pub(crate) fn new() -> Self {
        Self { A: [0; 25], bufsz: 0, buf: unsafe { MaybeUninit::uninit().assume_init() } }
    }

    #[inline(always)]
    pub(crate) fn reset(&mut self) {
        self.A = [0; 25];
        self.bufsz = 0;
    }

    /// Implementation from [OpenSSL](https://github.com/openssl/openssl/blob/9ff816106c2b2ccbffe5c4e3619a840547088674/providers/implementations/digests/sha3_prov.c#L68).
    ///
    /// # Safety
    ///
    /// `inp` must point to at least `len` bytes.
    #[inline]
    pub(crate) unsafe fn update(&mut self, mut inp: *const u8, mut len: usize) {
        let bsz: usize = Self::BLOCK_SIZE;

        if len == 0 {
            return;
        }

        let num = self.bufsz;
        let mut rem;
        // Is there anything in the buffer already?
        if num != 0 {
            // Calculate how much space is left in the buffer
            rem = bsz - num;
            // If the new input does not fill the buffer then just add it
            if len < rem {
                memcpy(self.buf().add(num), inp, len);
                self.bufsz += len;
                return;
            }
            // otherwise fill up the buffer and absorb the buffer
            memcpy(self.buf().add(num), inp, rem);
            // Update the input pointer
            inp = inp.add(rem);
            len -= rem;
            SHA3_absorb(&mut self.A, self.buf(), bsz, bsz);
            self.bufsz = 0;
        }
        // Absorb the input - rem = leftover part of the input < blocksize)
        rem = if len >= bsz { SHA3_absorb(&mut self.A, inp, len, bsz) } else { len };
        // Copy the leftover bit of the input into the buffer
        if rem > 0 {
            memcpy(self.buf(), inp.add(len).sub(rem), rem);
            self.bufsz = rem;
        }
    }

    /// Implementation from [OpenSSL](https://github.com/openssl/openssl/blob/60421893a286bb9eb7fb7c2454b84af9778ffca4/crypto/sha/sha3.c#L87).
    ///
    /// # Safety
    ///
    /// `out` must point to at least `BITS / 8` bytes.
    #[inline]
    pub(crate) unsafe fn finalize(&mut self, out: *mut u8) {
        let bsz: usize = Self::BLOCK_SIZE;

        let num = self.bufsz;

        // Pad the data with 10*1. Note that |num| can be |bsz - 1|
        // in which case both byte operations below are performed on
        // same byte...
        memset(self.buf().add(num), 0, bsz - num);
        *self.buf().add(num) = PAD;
        *self.buf().add(bsz - 1) |= 0x80;

        SHA3_absorb(&mut self.A, self.buf(), bsz, bsz);

        SHA3_squeeze(&mut self.A, out, Self::OUT_SIZE, bsz);
    }

    #[inline(always)]
    fn buf(&mut self) -> *mut u8 {
        self.buf.as_mut_ptr().cast()
    }
}

#[inline(always)]
unsafe fn memcpy(dst: *mut u8, src: *const u8, count: usize) {
    ptr::copy_nonoverlapping(src, dst, count);
}

#[inline(always)]
unsafe fn memset(dst: *mut u8, val: u8, count: usize) {
    ptr::write_bytes(dst, val, count);
}
