//! Arity-4 FRI folding using inverse FFT.
//!
//! Given evaluations of a polynomial `f` on a coset `s·⟨ω⟩` where `ω = i` is a primitive
//! 4th root of unity, we recover the folded value `g(s⁴)` for a challenge `β`
//! (and when `deg f < 4`, this equals `f(β)`).
//!
//! ## Setup
//!
//! Let `f(X) = c₀ + c₁X + c₂X² + c₃X³` with evaluations on the coset `s·⟨ω⟩`:
//!
//! ```text
//! y₀ = f(s),   y₁ = f(ωs),   y₂ = f(ω²s),   y₃ = f(ω³s)
//! ```
//!
//! We store these in **bit-reversed order**: `[y₀, y₂, y₁, y₃]`.
//!
//! We decompose `f` by residue class modulo 4:
//! `f(X) = Σⱼ X^j · fⱼ(X⁴)` for j ∈ {0,1,2,3}.
//! The folded polynomial is `g(X) = Σⱼ β^j · fⱼ(X)`.
//!
//! ## Algorithm
//!
//! 1. **Inverse FFT**: Recover coefficients of `f(sX)` from evaluations on `⟨ω⟩`.
//! 2. **Evaluate**: Compute `f(sX)` at `X = β/s`, yielding the folded value `g(s⁴)`.

use core::array;

use p3_field::{Algebra, TwoAdicField};

/// Evaluate the folded value `g(s⁴)` from evaluations on a coset
/// (equals `f(β)` when `deg f < 4`).
///
/// ## Inputs
///
/// - `evals`: slice of 4 evaluations `[f(s), f(ω²s), f(ωs), f(ω³s)]` in bit-reversed order,
///   equivalently `[f(s), f(−s), f(is), f(−is)]` since `ω = i`.
/// - `s_inv`: the inverse of the coset generator `s`.
/// - `beta`: the FRI folding challenge `β`.
///
/// ## FRI Context
///
/// In arity-4 FRI, the polynomial `f` is evaluated on cosets of the form `s·⟨ω⟩`.
/// The verifier needs to check that the folded value `g(s⁴)` matches the prover's claim.
/// This function recovers `g(s⁴)` from the four coset evaluations via interpolation.
#[inline(always)]
pub fn fold_evals<F, PF, PEF>(evals: &[PEF], s_inv: PF, beta: PEF) -> PEF
where
    F: TwoAdicField,
    PF: Algebra<F> + Algebra<PF>,
    PEF: Algebra<PF>,
{
    debug_assert_eq!(evals.len(), 4, "evals must have 4 elements");
    let evals = array::from_fn(|i| evals[i].clone());
    // Recover coefficients [c₀, c₁, c₂, c₃] of 4·f(sX) via inverse FFT.
    let [c0, c1, c2, c3] = ifft4::<F, PF, PEF>(evals);

    // Folded value g(s⁴) = (1/4) · (c₀ + c₁·x + c₂·x² + c₃·x³)  where x = β/s.
    let x = beta * s_inv;
    let terms = [
        c0,              // c₀
        c1 * x.clone(),  // c₁ · x
        c2 * x.square(), // c₂ · x²
        c3 * x.cube(),   // c₃ · x³
    ];

    // Divide by 4
    let four_inv: PF = F::ONE.halve().halve().into();
    PEF::sum_array::<4>(&terms) * four_inv
}

/// Size-4 inverse FFT (unscaled), input in bit-reversed order.
///
/// Returns coefficients `[c₀, c₁, c₂, c₃]` of `4·f(sX) = c₀ + c₁X + c₂X² + c₃X³`.
#[inline(always)]
fn ifft4<F, PF, PEF>(evals: [PEF; 4]) -> [PEF; 4]
where
    F: TwoAdicField,
    PF: Algebra<F> + Algebra<PF>,
    PEF: Algebra<PF>,
{
    // ω = i, primitive 4th root of unity
    let w: PF = F::two_adic_generator(2).into();

    // Input (bit-reversed): [y₀, y₂, y₁, y₃]
    let [y0, y2, y1, y3] = evals;

    // Inverse DFT formula (without 1/N normalization):
    //   4cⱼ = Σₖ yₖ · ω^(−jk)
    //
    // Expanded for each coefficient (i = imaginary unit):
    //   4c₀ = y₀ + y₁ + y₂ + y₃
    //   4c₁ = y₀ − i·y₁ − y₂ + i·y₃
    //   4c₂ = y₀ − y₁ + y₂ − y₃
    //   4c₃ = y₀ + i·y₁ − y₂ − i·y₃

    // -------------------------------------------------------------------------
    // Stage 0: length-2 butterflies on bit-reversed pairs
    // -------------------------------------------------------------------------
    let s02 = y0.clone() + y2.clone(); // y₀ + y₂  (used in c₀, c₂)
    let d02 = y0 - y2; // y₀ − y₂  (used in c₁, c₃)
    let s13 = y1.clone() + y3.clone(); // y₁ + y₃  (used in c₀, c₂)
    let d31 = y3 - y1; // y₃ − y₁  (note: negated so we can multiply by ω instead of ω⁻¹)

    // -------------------------------------------------------------------------
    // Stage 1: combine via length-4 butterflies
    //
    // Rewriting the target formulas using stage 0 results:
    //   4c₀ = (y₀ + y₂) + (y₁ + y₃)           = s02 + s13
    //   4c₂ = (y₀ + y₂) − (y₁ + y₃)           = s02 − s13
    //   4c₁ = (y₀ − y₂) + i(y₃ − y₁)          = d02 + i·d31
    //   4c₃ = (y₀ − y₂) − i(y₃ − y₁)          = d02 − i·d31
    // -------------------------------------------------------------------------
    let d31_w = d31 * w; // i · (y₃ − y₁)

    [
        s02.clone() + s13.clone(),   // 4c₀
        d02.clone() + d31_w.clone(), // 4c₁
        s02 - s13,                   // 4c₂
        d02 - d31_w,                 // 4c₃
    ]
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use p3_dft::{NaiveDft, TwoAdicSubgroupDft};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{RngExt, SeedableRng, distr::StandardUniform, prelude::SmallRng};

    use super::ifft4;
    use crate::fri::fold::tests::{EF, F};

    /// Test that ifft4 correctly recovers polynomial coefficients from DFT evaluations.
    #[test]
    fn test_ifft4() {
        let mut rng = SmallRng::seed_from_u64(42);

        // Random polynomial coefficients
        let coeffs: [EF; 4] = core::array::from_fn(|_| rng.sample(StandardUniform));

        // Compute DFT using NaiveDft (standard order)
        let coeffs_matrix = RowMajorMatrix::new(coeffs.to_vec(), 1);
        let evals_matrix = NaiveDft.dft_batch(coeffs_matrix);
        let evals_std = evals_matrix.values;

        // Convert to bit-reversed order for ifft4
        let evals_br: [EF; 4] = [evals_std[0], evals_std[2], evals_std[1], evals_std[3]];

        // Run ifft4 (returns 4 * coefficients)
        let recovered_scaled = ifft4::<F, F, EF>(evals_br);

        // Verify: recovered_scaled[i] == 4 * coeffs[i]
        for (i, (recovered, &original)) in recovered_scaled.iter().zip(coeffs.iter()).enumerate() {
            let expected = original.double().double(); // 4 * original
            assert_eq!(*recovered, expected, "Coefficient mismatch at index {i}");
        }
    }
}
