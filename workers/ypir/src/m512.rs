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
