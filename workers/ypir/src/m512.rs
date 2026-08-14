//! Eight-lane u64 SIMD shim.
//!
//! Upstream reached for `_mm512_*` intrinsics directly and provided a fallback
//! only for `not(target_feature = "avx2")`, where it aliased `__m512i` to a bare
//! `u64`. The combination this crate is actually shipped at — AVX2 present,
//! AVX-512 absent — was never expressible, so no non-AVX-512 target compiled.
//!
//! Both implementations below are eight lanes of u64 with identical semantics.
//! `tests::portable_matches_avx512` asserts that on any host where the AVX-512
//! path is compiled, so the two cannot drift apart silently.

#[cfg(target_feature = "avx512f")]
mod imp {
    use core::arch::x86_64::*;

    pub type M512 = __m512i;

    #[inline(always)]
    pub unsafe fn zero() -> M512 {
        _mm512_setzero_si512()
    }

    #[inline(always)]
    pub unsafe fn load(p: *const u64) -> M512 {
        _mm512_loadu_si512(p as *const _)
    }

    #[inline(always)]
    pub unsafe fn store(p: *mut u64, v: M512) {
        _mm512_storeu_si512(p as *mut _, v)
    }

    #[inline(always)]
    pub unsafe fn add64(a: M512, b: M512) -> M512 {
        _mm512_add_epi64(a, b)
    }

    #[inline(always)]
    pub unsafe fn mul_lo32(a: M512, b: M512) -> M512 {
        _mm512_mul_epu32(a, b)
    }

    // The shift amount became a const generic when these intrinsics stabilised.
    #[inline(always)]
    pub unsafe fn srli32(a: M512) -> M512 {
        _mm512_srli_epi64::<32>(a)
    }

    #[inline(always)]
    pub unsafe fn from_u8(p: *const u8) -> M512 {
        _mm512_cvtepu8_epi64(_mm_loadl_epi64(p as *const _))
    }

    #[inline(always)]
    pub unsafe fn from_u16(p: *const u16) -> M512 {
        _mm512_cvtepu16_epi64(_mm_loadu_si128(p as *const _))
    }

    #[inline(always)]
    pub unsafe fn from_u32(p: *const u32) -> M512 {
        _mm512_cvtepu32_epi64(_mm256_loadu_si256(p as *const _))
    }

    #[inline(always)]
    pub unsafe fn to_array(v: M512) -> [u64; 8] {
        let mut out = [0u64; 8];
        store(out.as_mut_ptr(), v);
        out
    }

    #[inline(always)]
    pub unsafe fn from_array(a: [u64; 8]) -> M512 {
        load(a.as_ptr())
    }
}

#[cfg(not(target_feature = "avx512f"))]
mod imp {
    /// Aligned so the portable path has the same layout requirements as the
    /// intrinsic one; loads and stores stay unaligned regardless, because
    /// upstream call sites index into the middle of slices.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(C, align(64))]
    pub struct M512(pub [u64; 8]);

    #[inline(always)]
    pub unsafe fn zero() -> M512 {
        M512([0u64; 8])
    }

    #[inline(always)]
    pub unsafe fn load(p: *const u64) -> M512 {
        let mut out = [0u64; 8];
        core::ptr::copy_nonoverlapping(p, out.as_mut_ptr(), 8);
        M512(out)
    }

    #[inline(always)]
    pub unsafe fn store(p: *mut u64, v: M512) {
        core::ptr::copy_nonoverlapping(v.0.as_ptr(), p, 8);
    }

    #[inline(always)]
    pub unsafe fn add64(a: M512, b: M512) -> M512 {
        let mut out = [0u64; 8];
        for i in 0..8 {
            out[i] = a.0[i].wrapping_add(b.0[i]);
        }
        M512(out)
    }

    /// `_mm512_mul_epu32`: multiply the low 32 bits of each 64-bit lane, keeping
    /// the full 64-bit product. The upper halves of the inputs are ignored.
    #[inline(always)]
    pub unsafe fn mul_lo32(a: M512, b: M512) -> M512 {
        let mut out = [0u64; 8];
        for i in 0..8 {
            out[i] = (a.0[i] & 0xFFFF_FFFF).wrapping_mul(b.0[i] & 0xFFFF_FFFF);
        }
        M512(out)
    }

    #[inline(always)]
    pub unsafe fn srli32(a: M512) -> M512 {
        let mut out = [0u64; 8];
        for i in 0..8 {
            out[i] = a.0[i] >> 32;
        }
        M512(out)
    }

    #[inline(always)]
    pub unsafe fn from_u8(p: *const u8) -> M512 {
        let mut out = [0u64; 8];
        for i in 0..8 {
            out[i] = *p.add(i) as u64;
        }
        M512(out)
    }

    #[inline(always)]
    pub unsafe fn from_u16(p: *const u16) -> M512 {
        let mut out = [0u64; 8];
        for i in 0..8 {
            out[i] = core::ptr::read_unaligned(p.add(i)) as u64;
        }
        M512(out)
    }

    #[inline(always)]
    pub unsafe fn from_u32(p: *const u32) -> M512 {
        let mut out = [0u64; 8];
        for i in 0..8 {
            out[i] = core::ptr::read_unaligned(p.add(i)) as u64;
        }
        M512(out)
    }

    #[inline(always)]
    pub unsafe fn to_array(v: M512) -> [u64; 8] {
        v.0
    }

    #[inline(always)]
    pub unsafe fn from_array(a: [u64; 8]) -> M512 {
        M512(a)
    }
}

pub use imp::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// The portable lane semantics, written independently of `imp` so this is a
    /// real cross-check rather than a restatement of the implementation.
    mod reference {
        pub fn add64(a: [u64; 8], b: [u64; 8]) -> [u64; 8] {
            core::array::from_fn(|i| a[i].wrapping_add(b[i]))
        }
        pub fn mul_lo32(a: [u64; 8], b: [u64; 8]) -> [u64; 8] {
            core::array::from_fn(|i| {
                let x = (a[i] as u32) as u64;
                let y = (b[i] as u32) as u64;
                x.wrapping_mul(y)
            })
        }
        pub fn srli32(a: [u64; 8]) -> [u64; 8] {
            core::array::from_fn(|i| a[i] >> 32)
        }
    }

    fn samples() -> Vec<[u64; 8]> {
        let mut state = 0x243F_6A88_85A3_08D3u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut out = vec![
            [0u64; 8],
            [u64::MAX; 8],
            [0xFFFF_FFFF; 8],
            [0xFFFF_FFFF_0000_0000; 8],
            [1, 2, 3, 4, 5, 6, 7, 8],
        ];
        for _ in 0..256 {
            out.push(core::array::from_fn(|_| next()));
        }
        out
    }

    #[test]
    fn portable_matches_avx512() {
        for a in samples() {
            for b in samples().into_iter().take(16) {
                unsafe {
                    let va = from_array(a);
                    let vb = from_array(b);
                    assert_eq!(
                        to_array(add64(va, vb)),
                        reference::add64(a, b),
                        "add64 {a:?} {b:?}"
                    );
                    assert_eq!(
                        to_array(mul_lo32(va, vb)),
                        reference::mul_lo32(a, b),
                        "mul_lo32 {a:?} {b:?}"
                    );
                    assert_eq!(to_array(srli32(va)), reference::srli32(a), "srli32 {a:?}");
                }
            }
        }
    }

    #[test]
    fn round_trips_through_memory() {
        for a in samples() {
            unsafe {
                let mut out = [0u64; 8];
                store(out.as_mut_ptr(), load(a.as_ptr()));
                assert_eq!(out, a);
            }
        }
    }

    #[test]
    fn widening_loads_zero_extend() {
        let bytes: [u8; 8] = [0, 1, 0x7F, 0x80, 0xFE, 0xFF, 42, 200];
        let shorts: [u16; 8] = [0, 1, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF, 4242, 60000];
        let words: [u32; 8] = [
            0,
            1,
            0x7FFF_FFFF,
            0x8000_0000,
            0xFFFF_FFFE,
            0xFFFF_FFFF,
            7,
            123456789,
        ];
        unsafe {
            assert_eq!(
                to_array(from_u8(bytes.as_ptr())),
                core::array::from_fn(|i| bytes[i] as u64)
            );
            assert_eq!(
                to_array(from_u16(shorts.as_ptr())),
                core::array::from_fn(|i| shorts[i] as u64)
            );
            assert_eq!(
                to_array(from_u32(words.as_ptr())),
                core::array::from_fn(|i| words[i] as u64)
            );
        }
    }
}
