//! Generic polynomial type and operations used in Falcon.

use alloc::vec::Vec;
use core::{
    default::Default,
    fmt::Debug,
    ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign},
};

use num::{One, Zero};

use super::{Inverse, field::FalconFelt};
use crate::{
    Felt,
    dsa::falcon512_rpo::{MODULUS, N},
    utils::zeroize::{Zeroize, ZeroizeOnDrop},
};

/// Represents a polynomial with coefficients of type F.
#[derive(Debug, Clone, Default)]
pub struct Polynomial<F> {
    /// Coefficients of the polynomial, ordered from lowest to highest degree.
    pub coefficients: Vec<F>,
}

impl<F> Polynomial<F>
where
    F: Clone,
{
    /// Creates a new polynomial from the provided coefficients.
    pub fn new(coefficients: Vec<F>) -> Self {
        Self { coefficients }
    }
}

impl<F: Mul<Output = F> + Sub<Output = F> + AddAssign + Zero + Div<Output = F> + Clone + Inverse>
    Polynomial<F>
{
    /// Multiplies two polynomials coefficient-wise (Hadamard multiplication).
    pub fn hadamard_mul(&self, other: &Self) -> Self {
        Polynomial::new(
            self.coefficients
                .iter()
                .zip(other.coefficients.iter())
                .map(|(a, b)| *a * *b)
                .collect(),
        )
    }
    /// Divides two polynomials coefficient-wise (Hadamard division).
    pub fn hadamard_div(&self, other: &Self) -> Self {
        let other_coefficients_inverse = F::batch_inverse_or_zero(&other.coefficients);
        Polynomial::new(
            self.coefficients
                .iter()
                .zip(other_coefficients_inverse.iter())
                .map(|(a, b)| *a * *b)
                .collect(),
        )
    }

    /// Computes the coefficient-wise inverse (Hadamard inverse).
    pub fn hadamard_inv(&self) -> Self {
        let coefficients_inverse = F::batch_inverse_or_zero(&self.coefficients);
        Polynomial::new(coefficients_inverse)
    }
}

impl<F: Zero + PartialEq + Clone> Polynomial<F> {
    /// Returns the degree of the polynomial.
    pub fn degree(&self) -> Option<usize> {
        if self.coefficients.is_empty() {
            return None;
        }
        let mut max_index = self.coefficients.len() - 1;
        while self.coefficients[max_index] == F::zero() {
            if let Some(new_index) = max_index.checked_sub(1) {
                max_index = new_index;
            } else {
                return None;
            }
        }
        Some(max_index)
    }

    /// Returns the leading coefficient of the polynomial.
    pub fn lc(&self) -> F {
        match self.degree() {
            Some(non_negative_degree) => self.coefficients[non_negative_degree].clone(),
            None => F::zero(),
        }
    }
}

impl<F> PartialEq for Polynomial<F>
where
    F: Zero + PartialEq + Clone + AddAssign,
{
    fn eq(&self, other: &Self) -> bool {
        if self.is_zero() && other.is_zero() {
            true
        } else if self.is_zero() || other.is_zero() {
            false
        } else {
            let self_degree = self.degree().expect("non-zero polynomial must have a degree");
            let other_degree = other.degree().expect("non-zero polynomial must have a degree");
            self.coefficients[0..=self_degree] == other.coefficients[0..=other_degree]
        }
    }
}

impl<F> Eq for Polynomial<F> where F: Zero + PartialEq + Clone + AddAssign {}

impl<F> Add for &Polynomial<F>
where
    F: Add<Output = F> + AddAssign + Clone,
{
    type Output = Polynomial<F>;

    fn add(self, rhs: Self) -> Self::Output {
        let coefficients = if self.coefficients.len() >= rhs.coefficients.len() {
            let mut coefficients = self.coefficients.clone();
            for (i, c) in rhs.coefficients.iter().enumerate() {
                coefficients[i] += c.clone();
            }
            coefficients
        } else {
            let mut coefficients = rhs.coefficients.clone();
            for (i, c) in self.coefficients.iter().enumerate() {
                coefficients[i] += c.clone();
            }
            coefficients
        };
        Self::Output { coefficients }
    }
}

impl<F> Add for Polynomial<F>
where
    F: Add<Output = F> + AddAssign + Clone,
{
    type Output = Polynomial<F>;
    fn add(self, rhs: Self) -> Self::Output {
        let coefficients = if self.coefficients.len() >= rhs.coefficients.len() {
            let mut coefficients = self.coefficients.clone();
            for (i, c) in rhs.coefficients.into_iter().enumerate() {
                coefficients[i] += c;
            }
            coefficients
        } else {
            let mut coefficients = rhs.coefficients.clone();
            for (i, c) in self.coefficients.into_iter().enumerate() {
                coefficients[i] += c;
            }
            coefficients
        };
        Self::Output { coefficients }
    }
}

impl<F> AddAssign for Polynomial<F>
where
    F: Add<Output = F> + AddAssign + Clone,
{
    fn add_assign(&mut self, rhs: Self) {
        if self.coefficients.len() >= rhs.coefficients.len() {
            for (i, c) in rhs.coefficients.into_iter().enumerate() {
                self.coefficients[i] += c;
            }
        } else {
            let mut coefficients = rhs.coefficients.clone();
            for (i, c) in self.coefficients.iter().enumerate() {
                coefficients[i] += c.clone();
            }
            self.coefficients = coefficients;
        }
    }
}

impl<F> Sub for &Polynomial<F>
where
    F: Sub<Output = F> + Clone + Neg<Output = F> + Add<Output = F> + AddAssign,
{
    type Output = Polynomial<F>;

    fn sub(self, rhs: Self) -> Self::Output {
        self + &(-rhs)
    }
}

impl<F> Sub for Polynomial<F>
where
    F: Sub<Output = F> + Clone + Neg<Output = F> + Add<Output = F> + AddAssign,
{
    type Output = Polynomial<F>;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl<F> SubAssign for Polynomial<F>
where
    F: Add<Output = F> + Neg<Output = F> + AddAssign + Clone + Sub<Output = F>,
{
    fn sub_assign(&mut self, rhs: Self) {
        self.coefficients = self.clone().sub(rhs).coefficients;
    }
}

impl<F: Neg<Output = F> + Clone> Neg for &Polynomial<F> {
    type Output = Polynomial<F>;

    fn neg(self) -> Self::Output {
        Self::Output {
            coefficients: self.coefficients.iter().cloned().map(|a| -a).collect(),
        }
    }
}

impl<F: Neg<Output = F> + Clone> Neg for Polynomial<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::Output {
            coefficients: self.coefficients.iter().cloned().map(|a| -a).collect(),
        }
    }
}

impl<F> Mul for &Polynomial<F>
where
    F: Add + AddAssign + Mul<Output = F> + Sub<Output = F> + Zero + PartialEq + Clone,
{
    type Output = Polynomial<F>;

    fn mul(self, other: Self) -> Self::Output {
        if self.is_zero() || other.is_zero() {
            return Polynomial::<F>::zero();
        }
        let mut coefficients =
            vec![F::zero(); self.coefficients.len() + other.coefficients.len() - 1];
        for i in 0..self.coefficients.len() {
            for j in 0..other.coefficients.len() {
                coefficients[i + j] += self.coefficients[i].clone() * other.coefficients[j].clone();
            }
        }
        Polynomial { coefficients }
    }
}

impl<F> Mul for Polynomial<F>
where
    F: Add + AddAssign + Mul<Output = F> + Zero + PartialEq + Clone,
{
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut coefficients =
            vec![F::zero(); self.coefficients.len() + other.coefficients.len() - 1];
        for i in 0..self.coefficients.len() {
            for j in 0..other.coefficients.len() {
                coefficients[i + j] += self.coefficients[i].clone() * other.coefficients[j].clone();
            }
        }
        Self { coefficients }
    }
}

impl<F: Add + Mul<Output = F> + Zero + Clone> Mul<F> for &Polynomial<F> {
    type Output = Polynomial<F>;

    fn mul(self, other: F) -> Self::Output {
        Polynomial {
            coefficients: self.coefficients.iter().cloned().map(|i| i * other.clone()).collect(),
        }
    }
}

impl<F: Add + Mul<Output = F> + Zero + Clone> Mul<F> for Polynomial<F> {
    type Output = Polynomial<F>;

    fn mul(self, other: F) -> Self::Output {
        Polynomial {
            coefficients: self.coefficients.iter().cloned().map(|i| i * other.clone()).collect(),
        }
    }
}

impl<F> One for Polynomial<F>
where
    F: Clone + One + PartialEq + Zero + AddAssign,
{
    fn one() -> Self {
        Self { coefficients: vec![F::one()] }
    }
}

impl<F> Zero for Polynomial<F>
where
    F: Zero + PartialEq + Clone + AddAssign,
{
    fn zero() -> Self {
        Self { coefficients: vec![] }
    }

    fn is_zero(&self) -> bool {
        self.degree().is_none()
    }
}

impl<F: Zero + Clone> Polynomial<F> {
    /// Shifts the polynomial by the specified amount (adds leading zeros).
    pub fn shift(&self, shamt: usize) -> Self {
        Self {
            coefficients: [vec![F::zero(); shamt], self.coefficients.clone()].concat(),
        }
    }

    /// Creates a constant polynomial with a single coefficient.
    pub fn constant(f: F) -> Self {
        Self { coefficients: vec![f] }
    }

    /// Applies a function to each coefficient and returns a new polynomial.
    pub fn map<G: Clone, C: FnMut(&F) -> G>(&self, closure: C) -> Polynomial<G> {
        Polynomial::<G>::new(self.coefficients.iter().map(closure).collect())
    }

    /// Folds the coefficients using the provided function and initial value.
    pub fn fold<G, C: FnMut(G, &F) -> G + Clone>(&self, mut initial_value: G, closure: C) -> G {
        for c in self.coefficients.iter() {
            initial_value = (closure.clone())(initial_value, c);
        }
        initial_value
    }
}

impl<F> Div<Polynomial<F>> for Polynomial<F>
where
    F: Zero
        + One
        + PartialEq
        + AddAssign
        + Clone
        + Mul<Output = F>
        + MulAssign
        + Div<Output = F>
        + Neg<Output = F>
        + Sub<Output = F>,
{
    type Output = Polynomial<F>;

    fn div(self, denominator: Self) -> Self::Output {
        if denominator.is_zero() {
            panic!();
        }
        if self.is_zero() {
            Self::zero();
        }
        let mut remainder = self.clone();
        let mut quotient = Polynomial::<F>::zero();
        while !remainder.is_zero()
            && remainder.degree().expect("non-zero remainder must have degree")
                >= denominator.degree().expect("non-zero denominator must have degree")
        {
            let shift = remainder.degree().expect("non-zero remainder must have degree")
                - denominator.degree().expect("non-zero denominator must have degree");
            let quotient_coefficient = remainder.lc() / denominator.lc();
            let monomial = Self::constant(quotient_coefficient).shift(shift);
            quotient += monomial.clone();
            remainder -= monomial * denominator.clone();
        }
        quotient
    }
}

impl From<Polynomial<FalconFelt>> for Polynomial<Felt> {
    fn from(item: Polynomial<FalconFelt>) -> Self {
        let res: Vec<Felt> =
            item.coefficients.iter().map(|a| Felt::new(a.value() as u64)).collect();
        Polynomial::new(res)
    }
}

impl From<&Polynomial<FalconFelt>> for Polynomial<Felt> {
    fn from(item: &Polynomial<FalconFelt>) -> Self {
        let res: Vec<Felt> =
            item.coefficients.iter().map(|a| Felt::new(a.value() as u64)).collect();
        Polynomial::new(res)
    }
}

impl From<Vec<i16>> for Polynomial<FalconFelt> {
    fn from(item: Vec<i16>) -> Self {
        Polynomial::new(item.iter().map(|&a| FalconFelt::from(a)).collect())
    }
}

impl From<&Vec<i16>> for Polynomial<FalconFelt> {
    fn from(item: &Vec<i16>) -> Self {
        Polynomial::new(item.iter().map(|&a| FalconFelt::from(a)).collect())
    }
}

impl From<Polynomial<i8>> for Polynomial<FalconFelt> {
    fn from(item: Polynomial<i8>) -> Self {
        Polynomial::new(item.coefficients.iter().map(|&a| FalconFelt::from(a)).collect())
    }
}

impl From<&Polynomial<i8>> for Polynomial<FalconFelt> {
    fn from(item: &Polynomial<i8>) -> Self {
        Polynomial::new(item.coefficients.iter().map(|&a| FalconFelt::from(a)).collect())
    }
}

impl From<Vec<i8>> for Polynomial<FalconFelt> {
    fn from(item: Vec<i8>) -> Self {
        Polynomial::new(item.iter().map(|&a| FalconFelt::from(a)).collect())
    }
}

impl From<&Vec<i8>> for Polynomial<FalconFelt> {
    fn from(item: &Vec<i8>) -> Self {
        Polynomial::new(item.iter().map(|&a| FalconFelt::from(a)).collect())
    }
}

impl Polynomial<FalconFelt> {
    /// Converts coefficients to external representation [0, q-1].
    pub fn fill_u16_ext(&self, out: &mut [u16]) {
        debug_assert_eq!(out.len(), N);
        for (dst, coeff) in out.iter_mut().zip(self.coefficients.iter()) {
            *dst = coeff.value();
        }
    }

    /// Returns coefficients in external representation [0, q-1] as a fixed array.
    pub fn to_u16_ext_array(&self) -> [u16; N] {
        let mut out = [0u16; N];
        self.fill_u16_ext(&mut out);
        out
    }

    /// Builds a polynomial from external representation coefficients.
    pub fn from_u16_ext_array(values: &[u16; N]) -> Self {
        let coeffs = values.iter().map(|&v| FalconFelt::new(v)).collect();
        Polynomial::new(coeffs)
    }

    /// Returns coefficients in balanced signed representation as a fixed array.
    pub fn to_i16_balanced_array(&self) -> [i16; N] {
        core::array::from_fn(|i| self.coefficients[i].balanced_value())
    }

    /// Computes the squared L2 norm of the polynomial.
    pub fn norm_squared(&self) -> u64 {
        self.coefficients
            .iter()
            .map(|&i| i.balanced_value() as i64)
            .map(|i| (i * i) as u64)
            .sum::<u64>()
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the coefficients of this polynomial as field elements.
    pub fn to_elements(&self) -> Vec<Felt> {
        self.coefficients.iter().map(|&a| Felt::new(a.value() as u64)).collect()
    }

    // POLYNOMIAL OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Multiplies two polynomials over Z_p\[x\] without reducing modulo p. Given that the degrees
    /// of the input polynomials are less than 512 and their coefficients are less than the modulus
    /// q equal to 12289, the resulting product polynomial is guaranteed to have coefficients less
    /// than the Miden prime.
    ///
    /// Note that this multiplication is not over Z_p\[x\]/(phi).
    pub fn mul_modulo_p(a: &Self, b: &Self) -> [u64; 1024] {
        let mut c = [0; 2 * N];
        for i in 0..N {
            for j in 0..N {
                c[i + j] += a.coefficients[i].value() as u64 * b.coefficients[j].value() as u64;
            }
        }

        c
    }

    /// Reduces a polynomial, that is the product of two polynomials over Z_p\[x\], modulo
    /// the irreducible polynomial phi. This results in an element in Z_p\[x\]/(phi).
    pub fn reduce_negacyclic(a: &[u64; 1024]) -> Self {
        let mut c = [FalconFelt::zero(); N];
        let modulus = MODULUS as u16;
        for i in 0..N {
            let ai = a[N + i] % modulus as u64;
            let neg_ai = (modulus - ai as u16) % modulus;

            let bi = (a[i] % modulus as u64) as u16;
            c[i] = FalconFelt::new((neg_ai + bi) % modulus);
        }

        Self::new(c.to_vec())
    }
}

impl Polynomial<Felt> {
    /// Returns the coefficients of this polynomial as Miden field elements.
    pub fn to_elements(&self) -> Vec<Felt> {
        self.coefficients.to_vec()
    }
}

// ZEROIZE IMPLEMENTATIONS
// ================================================================================================

impl<F: Zeroize> Zeroize for Polynomial<F> {
    fn zeroize(&mut self) {
        self.coefficients.zeroize();
    }
}

impl<F: Zeroize> ZeroizeOnDrop for Polynomial<F> {}
