#![allow(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use super::generic;
use crate::{get_chars_table, Output};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

pub(crate) const USE_CHECK_FN: bool = true;

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        #[inline(always)]
        fn has_sse2() -> bool {
            std::arch::is_x86_feature_detected!("sse2")
        }
        #[inline(always)]
        fn has_avx2() -> bool {
            std::arch::is_x86_feature_detected!("avx2")
        }
    } else {
        cpufeatures::new!(cpuid_sse2, "sse2");
        use cpuid_sse2::get as has_sse2;
        cpufeatures::new!(cpuid_avx2, "avx2");
        use cpuid_avx2::get as has_avx2;
    }
}

// AVX2 versions modified from [`faster-hex`](https://github.com/nervosnetwork/faster-hex/blob/856aba7b141a5fe16113fae110d535065882f25a/src/decode.rs),
// themselves taken from [`zbjornson/fast-hex`](https://github.com/zbjornson/fast-hex/blob/a3487bca95127634a61bfeae8f8bfc8f0e5baa3f/src/hex.cc).

#[inline]
pub(crate) unsafe fn encode<const UPPER: bool>(input: &[u8], output: impl Output) {
    if !has_avx2() {
        return generic::encode::<UPPER>(input, output);
    }
    encode_avx2::<UPPER>(input, output);
}

#[inline(never)]
#[target_feature(enable = "avx2")]
unsafe fn encode_avx2<const UPPER: bool>(input: &[u8], output: impl Output) {
    generic::encode_unaligned_chunks::<UPPER, _, _>(input, output, |av: __m128i| {
        let nibs = byte2nib(av);
        hex::<UPPER>(nibs)
    });
}

#[inline]
pub(crate) fn check(input: &[u8]) -> bool {
    if !has_sse2() {
        return generic::check(input);
    }
    unsafe { check_sse2(input) }
}

/// Modified from [`faster-hex`](https://github.com/nervosnetwork/faster-hex/blob/856aba7b141a5fe16113fae110d535065882f25a/src/decode.rs).
#[target_feature(enable = "sse2")]
unsafe fn check_sse2(input: &[u8]) -> bool {
    let ascii_zero = _mm_set1_epi8((b'0' - 1) as i8);
    let ascii_nine = _mm_set1_epi8((b'9' + 1) as i8);
    let ascii_ua = _mm_set1_epi8((b'A' - 1) as i8);
    let ascii_uf = _mm_set1_epi8((b'F' + 1) as i8);
    let ascii_la = _mm_set1_epi8((b'a' - 1) as i8);
    let ascii_lf = _mm_set1_epi8((b'f' + 1) as i8);

    generic::check_unaligned_chunks(input, |chunk: __m128i| {
        let ge0 = _mm_cmpgt_epi8(chunk, ascii_zero);
        let le9 = _mm_cmplt_epi8(chunk, ascii_nine);
        let valid_digit = _mm_and_si128(ge0, le9);

        let geua = _mm_cmpgt_epi8(chunk, ascii_ua);
        let leuf = _mm_cmplt_epi8(chunk, ascii_uf);
        let valid_upper = _mm_and_si128(geua, leuf);

        let gela = _mm_cmpgt_epi8(chunk, ascii_la);
        let lelf = _mm_cmplt_epi8(chunk, ascii_lf);
        let valid_lower = _mm_and_si128(gela, lelf);

        let valid_letter = _mm_or_si128(valid_lower, valid_upper);
        let valid_mask = _mm_movemask_epi8(_mm_or_si128(valid_digit, valid_letter));
        valid_mask == 0xffff
    })
}

#[inline]
pub(crate) unsafe fn decode_unchecked(input: &[u8], output: &mut [u8]) {
    if !has_avx2() {
        return generic::decode_unchecked(input, output);
    }
    decode_avx2(input, output);
}

#[target_feature(enable = "avx2")]
unsafe fn decode_avx2(input: &[u8], output: &mut [u8]) {
    #[rustfmt::skip]
    let mask_a = _mm256_setr_epi8(
        0, -1, 2, -1, 4, -1, 6, -1, 8, -1, 10, -1, 12, -1, 14, -1,
        0, -1, 2, -1, 4, -1, 6, -1, 8, -1, 10, -1, 12, -1, 14, -1,
    );
    #[rustfmt::skip]
    let mask_b = _mm256_setr_epi8(
        1, -1, 3, -1, 5, -1, 7, -1, 9, -1, 11, -1, 13, -1, 15, -1,
        1, -1, 3, -1, 5, -1, 7, -1, 9, -1, 11, -1, 13, -1, 15, -1
    );
    generic::decode_unchecked_unaligned_chunks(input, output, |[av1, av2]: [__m256i; 2]| {
        let mut a1 = _mm256_shuffle_epi8(av1, mask_a);
        let mut b1 = _mm256_shuffle_epi8(av1, mask_b);
        let mut a2 = _mm256_shuffle_epi8(av2, mask_a);
        let mut b2 = _mm256_shuffle_epi8(av2, mask_b);

        a1 = unhex(a1);
        a2 = unhex(a2);
        b1 = unhex(b1);
        b2 = unhex(b2);

        nib2byte(a1, b1, a2, b2)
    });
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn hex<const UPPER: bool>(value: __m256i) -> __m256i {
    let lut =
        _mm256_broadcastsi128_si256(_mm_lddqu_si128(get_chars_table::<UPPER>().as_ptr().cast()));
    _mm256_shuffle_epi8(lut, value)
}

// a -> [a >> 4, a & 0b1111]
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn byte2nib(val: __m128i) -> __m256i {
    #[rustfmt::skip]
    let rot2 = _mm256_setr_epi8(
        -1, 0, -1, 2, -1, 4, -1, 6, -1, 8, -1, 10, -1, 12, -1, 14,
        -1, 0, -1, 2, -1, 4, -1, 6, -1, 8, -1, 10, -1, 12, -1, 14
    );

    let doubled = _mm256_cvtepu8_epi16(val);
    let hi = _mm256_srli_epi16(doubled, 4);
    let lo = _mm256_shuffle_epi8(doubled, rot2);
    let bytes = _mm256_or_si256(hi, lo);
    _mm256_and_si256(bytes, _mm256_set1_epi8(0b1111))
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn unhex(value: __m256i) -> __m256i {
    let sr6 = _mm256_srai_epi16(value, 6);
    let and15 = _mm256_and_si256(value, _mm256_set1_epi16(0xf));
    let mul = _mm256_maddubs_epi16(sr6, _mm256_set1_epi16(9));
    _mm256_add_epi16(mul, and15)
}

// (a << 4) | b;
// a and b must be 16-bit elements. Output is packed 8-bit elements.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn nib2byte(a1: __m256i, b1: __m256i, a2: __m256i, b2: __m256i) -> __m256i {
    let a4_1 = _mm256_slli_epi16(a1, 4);
    let a4_2 = _mm256_slli_epi16(a2, 4);
    let a4orb_1 = _mm256_or_si256(a4_1, b1);
    let a4orb_2 = _mm256_or_si256(a4_2, b2);
    let pck1 = _mm256_packus_epi16(a4orb_1, a4orb_2); // lo1 lo2 hi1 hi2
    const _0213: i32 = 0b11_01_10_00;
    _mm256_permute4x64_epi64(pck1, _0213)
}

// Not used.
pub(crate) use generic::decode_checked;
