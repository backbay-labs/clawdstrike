#![doc = include_str!("../README.md")]
#![no_std]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(rustdoc::broken_intra_doc_links)]

/// SHA-3 state buffer.
pub type Buffer = [u64; 25];

// Derived from OpenSSL:
// https://github.com/openssl/openssl/blob/60421893a286bb9eb7fb7c2454b84af9778ffca4/crypto/sha/keccak1600.c#L14-L17
#[link(name = "keccak", kind = "static")]
extern "C" {
    /// SHA-3 absorb, defined in assembly.
    ///
    /// `r` is the rate (block size) of the function in bytes.
    ///
    /// C signature:
    ///
    /// ```c
    /// size_t SHA3_absorb(uint64_t A[5][5], const unsigned char *inp, size_t len,
    ///                    size_t r);
    /// ```
    #[link_name = "KECCAK_ASM_SHA3_absorb"]
    pub fn SHA3_absorb(a: *mut Buffer, inp: *const u8, len: usize, r: usize) -> usize;

    /// SHA-3 squeeze, defined in assembly.
    ///
    /// `r` is the rate (block size) of the function in bytes.
    ///
    /// C signature:
    ///
    /// ```c
    /// void SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t len, size_t r);
    /// ```
    #[link_name = "KECCAK_ASM_SHA3_squeeze"]
    pub fn SHA3_squeeze(a: *mut Buffer, out: *mut u8, len: usize, r: usize);
}

/// Safe wrapper for [`SHA3_absorb`]. See its docs for more.
#[inline(always)]
pub fn sha3_absorb(a: &mut Buffer, inp: &[u8], r: usize) -> usize {
    unsafe { SHA3_absorb(a, inp.as_ptr(), inp.len(), r) }
}

/// Safe wrapper for [`SHA3_squeeze`]. See its docs for more.
#[inline(always)]
pub fn sha3_squeeze(a: &mut Buffer, out: &mut [u8], r: usize) {
    unsafe { SHA3_squeeze(a, out.as_mut_ptr(), out.len(), r) }
}

#[doc(hidden)]
pub const IMPL: &str = env!("SHA3_ASM_SRC");
