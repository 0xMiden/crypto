#![cfg(target_arch = "x86_64")]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

//! AVX2-accelerated polynomial operations for RPO-Falcon512.
//!
//! This module provides AVX2 (256-bit SIMD) versions of polynomial operations
//! for x86_64 CPUs that support AVX2. Functions in this module use 4-wide
//! vectorization (4 × f64) compared to SSE2's 2-wide vectorization.
//!
//! All functions are marked with `#[target_feature(enable = "avx2")]` and
//! require runtime CPU detection to use safely.

use super::flr::FLR;
use super::poly_flr::GM;
use core::arch::x86_64::*;
use core::mem::transmute;

/// Complex multiplication (scalar fallback for small sizes).
#[inline(always)]
pub(crate) fn flc_mul(x_re: FLR, x_im: FLR, y_re: FLR, y_im: FLR) -> (FLR, FLR) {
    (x_re * y_re - x_im * y_im, x_re * y_im + x_im * y_re)
}

/// Convert a polynomial from normal representation to FFT (AVX2-accelerated).
///
/// Uses 256-bit AVX2 vectors to process 4 f64 values at a time when possible,
/// falling back to scalar operations for small batch sizes.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn FFT(logn: u32, f: &mut [FLR]) {
    // First iteration of FFT would compute f[j] + i*f[j + n/2] for all j < n/2;
    // since this is exactly our storage format, that first iteration is a no-op.

    assert!(logn >= 1);
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut t = hn;
    let fp = transmute::<*mut FLR, *mut f64>(f.as_mut_ptr());

    for lm in 1..logn {
        let m = 1 << lm;
        let hm = m >> 1;
        let ht = t >> 1;
        let mut j0 = 0;

        for i in 0..hm {
            // Use AVX2 (4-wide) when we have at least 4 elements to process
            if ht >= 4 {
                let s_re = _mm256_set1_pd(GM[((m + i) << 1) + 0].to_f64());
                let s_im = _mm256_set1_pd(GM[((m + i) << 1) + 1].to_f64());
                let f1_re = fp.wrapping_add(j0);
                let f1_im = fp.wrapping_add(j0 + hn);
                let f2_re = fp.wrapping_add(j0 + ht);
                let f2_im = fp.wrapping_add(j0 + ht + hn);

                for j in 0..(ht >> 2) {
                    let x_re = _mm256_loadu_pd(f1_re.wrapping_add(j << 2));
                    let x_im = _mm256_loadu_pd(f1_im.wrapping_add(j << 2));
                    let y_re = _mm256_loadu_pd(f2_re.wrapping_add(j << 2));
                    let y_im = _mm256_loadu_pd(f2_im.wrapping_add(j << 2));

                    let z_re = _mm256_sub_pd(_mm256_mul_pd(s_re, y_re), _mm256_mul_pd(s_im, y_im));
                    let z_im = _mm256_add_pd(_mm256_mul_pd(s_re, y_im), _mm256_mul_pd(s_im, y_re));

                    _mm256_storeu_pd(f1_re.wrapping_add(j << 2), _mm256_add_pd(x_re, z_re));
                    _mm256_storeu_pd(f1_im.wrapping_add(j << 2), _mm256_add_pd(x_im, z_im));
                    _mm256_storeu_pd(f2_re.wrapping_add(j << 2), _mm256_sub_pd(x_re, z_re));
                    _mm256_storeu_pd(f2_im.wrapping_add(j << 2), _mm256_sub_pd(x_im, z_im));
                }
            } else {
                // Scalar fallback for small batches
                let s_re = GM[((m + i) << 1) + 0];
                let s_im = GM[((m + i) << 1) + 1];
                for j in 0..ht {
                    let j1 = j0 + j;
                    let j2 = j1 + ht;
                    let x_re = f[j1];
                    let x_im = f[j1 + hn];
                    let y_re = f[j2];
                    let y_im = f[j2 + hn];
                    let (z_re, z_im) = flc_mul(y_re, y_im, s_re, s_im);
                    f[j1] = x_re + z_re;
                    f[j1 + hn] = x_im + z_im;
                    f[j2] = x_re - z_re;
                    f[j2 + hn] = x_im - z_im;
                }
            }
            j0 += t;
        }
        t = ht;
    }
}

/// Convert a polynomial from FFT representation to normal (AVX2-accelerated).
///
/// Inverse FFT using AVX2 vectors for 4-wide parallelism when possible.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn iFFT(logn: u32, f: &mut [FLR]) {
    // Reverse of FFT, using conjugates from GM table.
    // The last iteration is a no-op, so we divide by n/2 at the end.

    assert!(logn >= 1);
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut t = 1;
    let fp = transmute::<*mut FLR, *mut f64>(f.as_mut_ptr());

    for lm in 1..logn {
        let hm = 1 << (logn - lm);
        let dt = t << 1;
        let mut j0 = 0;

        for i in 0..(hm >> 1) {
            // Use AVX2 (4-wide) when we have at least 4 elements to process
            if t >= 4 {
                let s_re = _mm256_set1_pd(GM[((hm + i) << 1) + 0].to_f64());
                let s_im = _mm256_set1_pd(-GM[((hm + i) << 1) + 1].to_f64());
                let f1_re = fp.wrapping_add(j0);
                let f1_im = fp.wrapping_add(j0 + hn);
                let f2_re = fp.wrapping_add(j0 + t);
                let f2_im = fp.wrapping_add(j0 + t + hn);

                for j in 0..(t >> 2) {
                    let x_re = _mm256_loadu_pd(f1_re.wrapping_add(j << 2));
                    let x_im = _mm256_loadu_pd(f1_im.wrapping_add(j << 2));
                    let y_re = _mm256_loadu_pd(f2_re.wrapping_add(j << 2));
                    let y_im = _mm256_loadu_pd(f2_im.wrapping_add(j << 2));

                    _mm256_storeu_pd(f1_re.wrapping_add(j << 2), _mm256_add_pd(x_re, y_re));
                    _mm256_storeu_pd(f1_im.wrapping_add(j << 2), _mm256_add_pd(x_im, y_im));

                    let x_re = _mm256_sub_pd(x_re, y_re);
                    let x_im = _mm256_sub_pd(x_im, y_im);
                    let z_re = _mm256_sub_pd(_mm256_mul_pd(x_re, s_re), _mm256_mul_pd(x_im, s_im));
                    let z_im = _mm256_add_pd(_mm256_mul_pd(x_re, s_im), _mm256_mul_pd(x_im, s_re));

                    _mm256_storeu_pd(f2_re.wrapping_add(j << 2), z_re);
                    _mm256_storeu_pd(f2_im.wrapping_add(j << 2), z_im);
                }
            } else {
                // Scalar fallback for small batches
                let s_re = GM[((hm + i) << 1) + 0];
                let s_im = -GM[((hm + i) << 1) + 1];
                for j in 0..t {
                    let j1 = j0 + j;
                    let j2 = j1 + t;
                    let x_re = f[j1];
                    let x_im = f[j1 + hn];
                    let y_re = f[j2];
                    let y_im = f[j2 + hn];
                    f[j1] = x_re + y_re;
                    f[j1 + hn] = x_im + y_im;
                    let x_re = x_re - y_re;
                    let x_im = x_im - y_im;
                    let (z_re, z_im) = flc_mul(x_re, x_im, s_re, s_im);
                    f[j2] = z_re;
                    f[j2 + hn] = z_im;
                }
            }
            j0 += dt;
        }
        t = dt;
    }

    // Perform delayed halvings (divide by n/2)
    if logn >= 2 {
        let d = _mm256_set1_pd(FLR::INV_POW2[(logn + 126) as usize]);
        for j in 0..(1usize << (logn - 2)) {
            let y = _mm256_loadu_pd(fp.wrapping_add(j << 2));
            let y = _mm256_mul_pd(y, d);
            _mm256_storeu_pd(fp.wrapping_add(j << 2), y);
        }
    } else {
        FLR::slice_div2e(&mut f[..n], logn - 1);
    }
}

/// Set polynomial d from polynomial f with small coefficients (AVX2-accelerated).
///
/// Converts i8 coefficients to FLR (f64) representation using AVX2 for efficient
/// vectorized i8 → i32 → f64 conversion.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_set_small(logn: u32, d: &mut [FLR], f: &[i8]) {
    if logn >= 4 {
        let fp = transmute::<*const i8, *const __m128i>(f.as_ptr());
        let dp = transmute::<*mut FLR, *mut f64>(d.as_mut_ptr());

        for i in 0..(1usize << (logn - 4)) {
            let x0 = _mm_loadu_si128(fp.wrapping_add(i));
            let x1 = _mm_shuffle_epi32(x0, 0x55);
            let x2 = _mm_shuffle_epi32(x0, 0xAA);
            let x3 = _mm_shuffle_epi32(x0, 0xFF);

            let y0 = _mm256_cvtepi32_pd(_mm_cvtepi8_epi32(x0));
            let y1 = _mm256_cvtepi32_pd(_mm_cvtepi8_epi32(x1));
            let y2 = _mm256_cvtepi32_pd(_mm_cvtepi8_epi32(x2));
            let y3 = _mm256_cvtepi32_pd(_mm_cvtepi8_epi32(x3));

            _mm256_storeu_pd(dp.wrapping_add((i << 4) + 0), y0);
            _mm256_storeu_pd(dp.wrapping_add((i << 4) + 4), y1);
            _mm256_storeu_pd(dp.wrapping_add((i << 4) + 8), y2);
            _mm256_storeu_pd(dp.wrapping_add((i << 4) + 12), y3);
        }
    } else {
        for i in 0..(1usize << logn) {
            d[i] = FLR::from_i32(f[i] as i32);
        }
    }
}

/// Add polynomial b to polynomial a (AVX2-accelerated).
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_add(logn: u32, a: &mut [FLR], b: &[FLR]) {
    if logn >= 2 {
        let ap = transmute::<*mut FLR, *mut f64>(a.as_mut_ptr());
        let bp = transmute::<*const FLR, *const f64>(b.as_ptr());

        for i in 0..(1usize << (logn - 2)) {
            let ya = _mm256_loadu_pd(ap.wrapping_add(i << 2));
            let yb = _mm256_loadu_pd(bp.wrapping_add(i << 2));
            _mm256_storeu_pd(ap.wrapping_add(i << 2), _mm256_add_pd(ya, yb));
        }
    } else {
        for i in 0..(1usize << logn) {
            a[i] += b[i];
        }
    }
}

/// Subtract polynomial b from polynomial a (AVX2-accelerated).
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_sub(logn: u32, a: &mut [FLR], b: &[FLR]) {
    if logn >= 2 {
        let ap = transmute::<*mut FLR, *mut f64>(a.as_mut_ptr());
        let bp = transmute::<*const FLR, *const f64>(b.as_ptr());

        for i in 0..(1usize << (logn - 2)) {
            let ya = _mm256_loadu_pd(ap.wrapping_add(i << 2));
            let yb = _mm256_loadu_pd(bp.wrapping_add(i << 2));
            _mm256_storeu_pd(ap.wrapping_add(i << 2), _mm256_sub_pd(ya, yb));
        }
    } else {
        for i in 0..(1usize << logn) {
            a[i] -= b[i];
        }
    }
}

/// Negate polynomial a (AVX2-accelerated).
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_neg(logn: u32, a: &mut [FLR]) {
    if logn >= 2 {
        // Negation by flipping the sign bit (high bit of f64)
        let ap = transmute::<*mut FLR, *mut f64>(a.as_mut_ptr());
        let ym = _mm256_set1_pd(-0.0);

        for i in 0..(1usize << (logn - 2)) {
            let ya = _mm256_loadu_pd(ap.wrapping_add(i << 2));
            _mm256_storeu_pd(ap.wrapping_add(i << 2), _mm256_xor_pd(ya, ym));
        }
    } else {
        for i in 0..(1usize << logn) {
            a[i] = -a[i];
        }
    }
}

/// Multiply polynomial a with polynomial b in FFT representation (AVX2-accelerated).
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_mul_fft(logn: u32, a: &mut [FLR], b: &[FLR]) {
    let hn = 1usize << (logn - 1);

    if logn >= 3 {
        let ap = transmute::<*mut FLR, *mut f64>(a.as_mut_ptr());
        let bp = transmute::<*const FLR, *const f64>(b.as_ptr());

        for i in 0..(1usize << (logn - 3)) {
            let a_re = _mm256_loadu_pd(ap.wrapping_add(i << 2));
            let a_im = _mm256_loadu_pd(ap.wrapping_add((i << 2) + hn));
            let b_re = _mm256_loadu_pd(bp.wrapping_add(i << 2));
            let b_im = _mm256_loadu_pd(bp.wrapping_add((i << 2) + hn));

            let d_re = _mm256_sub_pd(_mm256_mul_pd(a_re, b_re), _mm256_mul_pd(a_im, b_im));
            let d_im = _mm256_add_pd(_mm256_mul_pd(a_re, b_im), _mm256_mul_pd(a_im, b_re));

            _mm256_storeu_pd(ap.wrapping_add(i << 2), d_re);
            _mm256_storeu_pd(ap.wrapping_add((i << 2) + hn), d_im);
        }
    } else {
        for i in 0..hn {
            let (re, im) = flc_mul(a[i], a[i + hn], b[i], b[i + hn]);
            a[i] = re;
            a[i + hn] = im;
        }
    }
}

/// Multiply polynomial a with the adjoint of polynomial b (AVX2-accelerated).
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_muladj_fft(logn: u32, a: &mut [FLR], b: &[FLR]) {
    let hn = 1usize << (logn - 1);

    if logn >= 3 {
        let ap = transmute::<*mut FLR, *mut f64>(a.as_mut_ptr());
        let bp = transmute::<*const FLR, *const f64>(b.as_ptr());

        for i in 0..(1usize << (logn - 3)) {
            let a_re = _mm256_loadu_pd(ap.wrapping_add(i << 2));
            let a_im = _mm256_loadu_pd(ap.wrapping_add((i << 2) + hn));
            let b_re = _mm256_loadu_pd(bp.wrapping_add(i << 2));
            let b_im = _mm256_loadu_pd(bp.wrapping_add((i << 2) + hn));

            let d_re = _mm256_add_pd(_mm256_mul_pd(a_re, b_re), _mm256_mul_pd(a_im, b_im));
            let d_im = _mm256_sub_pd(_mm256_mul_pd(a_im, b_re), _mm256_mul_pd(a_re, b_im));

            _mm256_storeu_pd(ap.wrapping_add(i << 2), d_re);
            _mm256_storeu_pd(ap.wrapping_add((i << 2) + hn), d_im);
        }
    } else {
        for i in 0..hn {
            let (re, im) = flc_mul(a[i], a[i + hn], b[i], -b[i + hn]);
            a[i] = re;
            a[i + hn] = im;
        }
    }
}

/// Multiply polynomial a with its own adjoint (AVX2-accelerated).
///
/// Result is self-adjoint, so coefficients n/2 to n-1 are set to zero.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_mulownadj_fft(logn: u32, a: &mut [FLR]) {
    let hn = 1usize << (logn - 1);

    if logn >= 3 {
        let ap = transmute::<*mut FLR, *mut f64>(a.as_mut_ptr());
        let zero = _mm256_set1_pd(0.0);

        for i in 0..(1usize << (logn - 3)) {
            let a_re = _mm256_loadu_pd(ap.wrapping_add(i << 2));
            let a_im = _mm256_loadu_pd(ap.wrapping_add((i << 2) + hn));
            let d_re = _mm256_add_pd(_mm256_mul_pd(a_re, a_re), _mm256_mul_pd(a_im, a_im));

            _mm256_storeu_pd(ap.wrapping_add(i << 2), d_re);
            _mm256_storeu_pd(ap.wrapping_add((i << 2) + hn), zero);
        }
    } else {
        for i in 0..hn {
            a[i] = a[i].square() + a[i + hn].square();
            a[i + hn] = FLR::ZERO;
        }
    }
}

/// Multiply polynomial a with a real constant x (AVX2-accelerated).
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_mulconst(logn: u32, a: &mut [FLR], x: FLR) {
    if logn >= 2 {
        let ap = transmute::<*mut FLR, *mut f64>(a.as_mut_ptr());
        let ym = _mm256_set1_pd(x.to_f64());

        for i in 0..(1usize << (logn - 2)) {
            let ya = _mm256_loadu_pd(ap.wrapping_add(i << 2));
            _mm256_storeu_pd(ap.wrapping_add(i << 2), _mm256_mul_pd(ya, ym));
        }
    } else {
        for i in 0..(1usize << logn) {
            a[i] *= x;
        }
    }
}
