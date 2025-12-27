//! FN-DSA (FIPS 204 Falcon) implementation modules.
//!
//! This module contains the key generation and sampling logic compatible with fn-dsa-kgen.

use super::polynomial::Polynomial;

pub(crate) mod gauss;
pub(crate) mod ntru;

/// Samples 4 small polynomials f, g, F, G such that f * G - g * F = q mod (X^n + 1).
///
/// This is the optimized key generation algorithm compatible with fn-dsa-kgen, using:
/// - CDT-based Gaussian sampling for f, g (with automatic odd parity)
/// - Optimized NTRU solver from rust-fn-dsa for finding F, G
///
/// It follows Algorithm 5 (NTRUgen) from the Falcon specification [1, p.34] with the
/// following validation checks matching fn-dsa-kgen exactly:
///
/// 1. **Gamma1 check**: Verifies ||f||² + ||g||² < 16823 (squared Gram-Schmidt norm bound)
/// 2. **Invertibility**: Checks that f is invertible mod X^n+1 mod q
/// 3. **Gamma2 check**: Validates orthogonalized Gram-Schmidt norm bound
/// 4. **NTRU solve**: Solves f*G - g*F = q mod (X^n+1) using optimized fixed-point solver
///
/// [1]: https://falcon-sign.info/falcon.pdf
pub(crate) fn ntru_gen<R: fn_dsa_comm::PRNG>(n: usize, rng: &mut R) -> [Polynomial<i8>; 4] {
    let logn = (n as f64).log2() as u32;

    loop {
        let f_i8 = gauss::sample_f_fndsa(n, rng);
        let g_i8 = gauss::sample_f_fndsa(n, rng);

        // Check 1: Gamma1 (first Gram-Schmidt norm)
        // Verify ||f||² + ||g||² < 16823, which equals (1.17*√12289)² ≈ 16822.41
        let mut sn = 0i32;
        for i in 0..n {
            let xf = f_i8[i] as i32;
            let xg = g_i8[i] as i32;
            sn += xf * xf + xg * xg;
        }
        if sn >= 16823 {
            continue;
        }

        // Check 2: Invertibility
        let mut tmp_u16 = vec![0u16; n];
        if !fn_dsa_comm::mq::mqpoly_small_is_invertible(logn, &f_i8, &mut tmp_u16) {
            continue;
        }

        // Check 3: Gamma2 (orthogonalized Gram-Schmidt norm)
        // Verify the squared norm of the second orthogonalized basis vector is bounded
        let mut tmp_fxr = vec![ntru::fxp::FXR::ZERO; (5 * n) / 2];
        if !ntru::check_ortho_norm(logn, &f_i8, &g_i8, &mut tmp_fxr) {
            continue;
        }

        // Solve NTRU equation: f*G - g*F = q mod (X^n + 1)
        let mut capital_f_i8 = vec![0i8; n];
        let mut capital_g_i8 = vec![0i8; n];
        let mut tmp_u32 = vec![0u32; 6 * n];
        let mut tmp_fxr = vec![ntru::fxp::FXR::ZERO; (5 * n) / 2];

        if ntru::solve_NTRU(
            logn,
            &f_i8,
            &g_i8,
            &mut capital_f_i8,
            &mut capital_g_i8,
            &mut tmp_u32,
            &mut tmp_fxr,
        ) {
            // Return basis in storage format [g, f, G, F] as i8 polynomials
            return [
                Polynomial::new(g_i8),
                Polynomial::new(f_i8),
                Polynomial::new(capital_g_i8),
                Polynomial::new(capital_f_i8),
            ];
        }
    }
}
