use alloc::boxed::Box;

#[cfg(not(feature = "std"))]
use num::Float;
use num::{One, Zero};
use num_complex::{Complex, Complex64};
use rand::Rng;

use super::{fft::FastFft, polynomial::Polynomial, samplerz::sampler_z};
use crate::zeroize::{Zeroize, ZeroizeOnDrop};

const SIGMIN: f64 = 1.2778336969128337;

/// Computes the Gram matrix. The argument must be a 2x2 matrix
/// whose elements are equal-length vectors of complex numbers,
/// representing polynomials in FFT domain.
pub fn gram(b: [Polynomial<Complex64>; 4]) -> [Polynomial<Complex64>; 4] {
    const N: usize = 2;
    let mut g: [Polynomial<Complex<f64>>; 4] =
        [Polynomial::zero(), Polynomial::zero(), Polynomial::zero(), Polynomial::zero()];
    for i in 0..N {
        for j in 0..N {
            for k in 0..N {
                g[N * i + j] = g[N * i + j].clone()
                    + b[N * i + k].hadamard_mul(&b[N * j + k].map(|c| c.conj()));
            }
        }
    }
    g
}

/// Computes the LDL decomposition of a 2x2 matrix G such that
///     L D L* = G
/// where D is diagonal, and L is lower-triangular. The elements of the matrices are in FFT domain.
pub fn ldl(
    g: [Polynomial<Complex64>; 4],
) -> ([Polynomial<Complex64>; 4], [Polynomial<Complex64>; 4]) {
    let zero = Polynomial::<Complex64>::zero();
    let one = Polynomial::<Complex64>::one();

    let l10 = g[2].hadamard_div(&g[0]);
    let bc = l10.map(|c| c * c.conj());
    let abc = g[0].hadamard_mul(&bc);
    let d11 = g[3].clone() - abc;

    let l = [one.clone(), zero.clone(), l10.clone(), one];
    let d = [g[0].clone(), zero.clone(), zero, d11];
    (l, d)
}

#[derive(Debug, Clone)]
pub enum LdlTree {
    Branch(Polynomial<Complex64>, Box<LdlTree>, Box<LdlTree>),
    Leaf([Complex64; 2]),
}

impl Zeroize for LdlTree {
    fn zeroize(&mut self) {
        match self {
            LdlTree::Branch(poly, left, right) => {
                // Zeroize polynomial coefficients using write_volatile to prevent compiler
                // optimizations (dead store elimination)
                for coeff in poly.coefficients.iter_mut() {
                    unsafe {
                        core::ptr::write_volatile(coeff, Complex64::new(0.0, 0.0));
                    }
                }

                // Recursively zeroize child nodes
                left.zeroize();
                right.zeroize();

                // Compiler fence AFTER all zeroing operations to prevent reordering.
                // This ensures all writes (both at this level and in recursive calls) are
                // completed before any subsequent code can observe them.
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            },
            LdlTree::Leaf(arr) => {
                // Zeroize leaf array using write_volatile
                for val in arr.iter_mut() {
                    unsafe {
                        core::ptr::write_volatile(val, Complex64::new(0.0, 0.0));
                    }
                }

                // Compiler fence after all writes to prevent reordering with subsequent code
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            },
        }
    }
}

// Manual Drop implementation to ensure zeroization on drop.
// Cannot use #[derive(ZeroizeOnDrop)] because Complex64 doesn't implement Zeroize,
// so we manually implement Drop to call our Zeroize impl.
impl Drop for LdlTree {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for LdlTree {}

/// Computes the LDL Tree of G. Corresponds to Algorithm 9 of the specification [1, p.37].
/// The argument is a 2x2 matrix of polynomials, given in FFT form.
/// [1]: https://falcon-sign.info/falcon.pdf
pub fn ffldl(gram_matrix: [Polynomial<Complex64>; 4]) -> LdlTree {
    let n = gram_matrix[0].coefficients.len();
    let (l, d) = ldl(gram_matrix);

    if n > 2 {
        let (d00, d01) = d[0].split_fft();
        let (d10, d11) = d[3].split_fft();
        let g0 = [d00.clone(), d01.clone(), d01.map(|c| c.conj()), d00];
        let g1 = [d10.clone(), d11.clone(), d11.map(|c| c.conj()), d10];
        LdlTree::Branch(l[2].clone(), Box::new(ffldl(g0)), Box::new(ffldl(g1)))
    } else {
        LdlTree::Branch(
            l[2].clone(),
            Box::new(LdlTree::Leaf(d[0].clone().coefficients.try_into().unwrap())),
            Box::new(LdlTree::Leaf(d[3].clone().coefficients.try_into().unwrap())),
        )
    }
}

/// Normalizes the leaves of an LDL tree using a given normalization value `sigma`.
pub fn normalize_tree(tree: &mut LdlTree, sigma: f64) {
    match tree {
        LdlTree::Branch(_ell, left, right) => {
            normalize_tree(left, sigma);
            normalize_tree(right, sigma);
        },
        LdlTree::Leaf(vector) => {
            vector[0] = Complex::new(sigma / vector[0].re.sqrt(), 0.0);
            vector[1] = Complex64::zero();
        },
    }
}

/// Samples short polynomials using a Falcon tree. Algorithm 11 from the spec [1, p.40].
///
/// [1]: https://falcon-sign.info/falcon.pdf
pub fn ffsampling<R: Rng>(
    t: &(Polynomial<Complex64>, Polynomial<Complex64>),
    tree: &LdlTree,
    mut rng: &mut R,
) -> (Polynomial<Complex64>, Polynomial<Complex64>) {
    match tree {
        LdlTree::Branch(ell, left, right) => {
            let bold_t1 = t.1.split_fft();
            let bold_z1 = ffsampling(&bold_t1, right, rng);
            let z1 = Polynomial::<Complex64>::merge_fft(&bold_z1.0, &bold_z1.1);

            // t0' = t0  + (t1 - z1) * l
            let t0_prime = t.0.clone() + (t.1.clone() - z1.clone()).hadamard_mul(ell);

            let bold_t0 = t0_prime.split_fft();
            let bold_z0 = ffsampling(&bold_t0, left, rng);
            let z0 = Polynomial::<Complex64>::merge_fft(&bold_z0.0, &bold_z0.1);

            (z0, z1)
        },
        LdlTree::Leaf(value) => {
            let z0 = sampler_z(t.0.coefficients[0].re, value[0].re, SIGMIN, &mut rng);
            let z1 = sampler_z(t.1.coefficients[0].re, value[0].re, SIGMIN, &mut rng);
            (
                Polynomial::new(vec![Complex64::new(z0 as f64, 0.0)]),
                Polynomial::new(vec![Complex64::new(z1 as f64, 0.0)]),
            )
        },
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use num_complex::Complex64;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    use super::{gram, ldl};
    use crate::dsa::rpo_falcon512::math::polynomial::Polynomial;

    fn approx_eq(a: Complex64, b: Complex64, tol: f64) -> bool {
        (a - b).norm_sqr() <= tol * tol
    }

    #[test]
    fn ldl_reconstructs_gram_for_random_fft_polys() {
        let mut rng = StdRng::seed_from_u64(0xfaLC0N);
        // test several sizes and trials
        for &n in &[2usize, 4, 8, 16] {
            for _ in 0..8 {
                let mut rand_poly = || -> Polynomial<Complex64> {
                    let coeffs: Vec<Complex64> = (0..n)
                        .map(|_| {
                            let re = rng.random::<f64>() - 0.5;
                            let im = rng.random::<f64>() - 0.5;
                            Complex64::new(re, im)
                        })
                        .collect();
                    Polynomial::new(coeffs)
                };

                // B is 2x2 matrix in row-major: [b00, b01, b10, b11]
                let b = [rand_poly(), rand_poly(), rand_poly(), rand_poly()];

                // Compute Gram matrix in FFT domain
                let g = gram(b);

                // LDL decomposition
                let (l, d) = ldl(g.clone());

                // Reconstruct G' = L D L* with Hadamard ops (per-frequency semantics)
                let one = Polynomial::<Complex64>::one();
                let zero = Polynomial::<Complex64>::zero();

                // L structure is [[1,0],[l10,1]]
                debug_assert!(l[0] == one && l[1] == zero && l[3] == one);

                let l10 = &l[2];
                let d00 = &d[0];
                let d11 = &d[3];

                // M = L * D
                let m00 = d00.clone();
                let m01 = zero.clone();
                let m10 = l10.hadamard_mul(d00);
                let m11 = d11.clone();

                // L* = [[1, conj(l10)],[0,1]]
                let l10_conj = l10.map(|c| c.conj());

                let gp00 = m00.clone();
                let gp01 = m00.hadamard_mul(&l10_conj);
                let gp10 = m10.clone();
                let gp11 = m10.hadamard_mul(&l10_conj).clone() + m11;

                // Compare coefficients
                let tol = 1e-9;
                for i in 0..n {
                    assert!(approx_eq(g[0].coefficients[i], gp00.coefficients[i], tol));
                    assert!(approx_eq(g[1].coefficients[i], gp01.coefficients[i], tol));
                    assert!(approx_eq(g[2].coefficients[i], gp10.coefficients[i], tol));
                    assert!(approx_eq(g[3].coefficients[i], gp11.coefficients[i], tol));
                    // Hermitian check: g01 == conj(g10)
                    assert!(approx_eq(g[1].coefficients[i], g[2].coefficients[i].conj(), tol));
                }
            }
        }
    }
}
