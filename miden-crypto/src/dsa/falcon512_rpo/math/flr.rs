#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

//! FLR (Fixed-point Linear Real) type for constant-time floating-point emulation.
//!
//! This module provides a type that represents IEEE-754:2008 'binary64' values
//! for use in cryptographic operations. On supported 64-bit platforms (x86_64,
//! aarch64, arm64ec, riscv64), native hardware f64 is used for maximum performance.
//! On other platforms, a constant-time emulation using integer operations is used.
//!
//! The choice of implementation is made at compile time based on the target architecture.

use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

// Use native f64 on 64-bit platforms where hardware support is available
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "riscv64"
))]
#[path = "flr_native.rs"]
mod backend;

// Use emulated fixed-point arithmetic on other platforms
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "riscv64"
)))]
#[path = "flr_emu.rs"]
mod backend;

pub(crate) use backend::FLR;

impl Default for FLR {
    fn default() -> Self {
        FLR::ZERO
    }
}

impl Add<FLR> for FLR {
    type Output = FLR;

    #[inline(always)]
    fn add(self, other: FLR) -> FLR {
        let mut r = self;
        r.set_add(other);
        r
    }
}

impl Add<&FLR> for FLR {
    type Output = FLR;

    #[inline(always)]
    fn add(self, other: &FLR) -> FLR {
        let mut r = self;
        r.set_add(*other);
        r
    }
}

impl Add<FLR> for &FLR {
    type Output = FLR;

    #[inline(always)]
    fn add(self, other: FLR) -> FLR {
        let mut r = *self;
        r.set_add(other);
        r
    }
}

impl Add<&FLR> for &FLR {
    type Output = FLR;

    #[inline(always)]
    fn add(self, other: &FLR) -> FLR {
        let mut r = *self;
        r.set_add(*other);
        r
    }
}

impl AddAssign<FLR> for FLR {
    #[inline(always)]
    fn add_assign(&mut self, other: FLR) {
        self.set_add(other);
    }
}

impl AddAssign<&FLR> for FLR {
    #[inline(always)]
    fn add_assign(&mut self, other: &FLR) {
        self.set_add(*other);
    }
}

impl Div<FLR> for FLR {
    type Output = FLR;

    #[inline(always)]
    fn div(self, other: FLR) -> FLR {
        let mut r = self;
        r.set_div(other);
        r
    }
}

impl Div<&FLR> for FLR {
    type Output = FLR;

    #[inline(always)]
    fn div(self, other: &FLR) -> FLR {
        let mut r = self;
        r.set_div(*other);
        r
    }
}

impl Div<FLR> for &FLR {
    type Output = FLR;

    #[inline(always)]
    fn div(self, other: FLR) -> FLR {
        let mut r = *self;
        r.set_div(other);
        r
    }
}

impl Div<&FLR> for &FLR {
    type Output = FLR;

    #[inline(always)]
    fn div(self, other: &FLR) -> FLR {
        let mut r = *self;
        r.set_div(*other);
        r
    }
}

impl DivAssign<FLR> for FLR {
    #[inline(always)]
    fn div_assign(&mut self, other: FLR) {
        self.set_div(other);
    }
}

impl DivAssign<&FLR> for FLR {
    #[inline(always)]
    fn div_assign(&mut self, other: &FLR) {
        self.set_div(*other);
    }
}

impl Mul<FLR> for FLR {
    type Output = FLR;

    #[inline(always)]
    fn mul(self, other: FLR) -> FLR {
        let mut r = self;
        r.set_mul(other);
        r
    }
}

impl Mul<&FLR> for FLR {
    type Output = FLR;

    #[inline(always)]
    fn mul(self, other: &FLR) -> FLR {
        let mut r = self;
        r.set_mul(*other);
        r
    }
}

impl Mul<FLR> for &FLR {
    type Output = FLR;

    #[inline(always)]
    fn mul(self, other: FLR) -> FLR {
        let mut r = *self;
        r.set_mul(other);
        r
    }
}

impl Mul<&FLR> for &FLR {
    type Output = FLR;

    #[inline(always)]
    fn mul(self, other: &FLR) -> FLR {
        let mut r = *self;
        r.set_mul(*other);
        r
    }
}

impl MulAssign<FLR> for FLR {
    #[inline(always)]
    fn mul_assign(&mut self, other: FLR) {
        self.set_mul(other);
    }
}

impl MulAssign<&FLR> for FLR {
    #[inline(always)]
    fn mul_assign(&mut self, other: &FLR) {
        self.set_mul(*other);
    }
}

impl Neg for FLR {
    type Output = FLR;

    #[inline(always)]
    fn neg(self) -> FLR {
        let mut r = self;
        r.set_neg();
        r
    }
}

impl Neg for &FLR {
    type Output = FLR;

    #[inline(always)]
    fn neg(self) -> FLR {
        let mut r = *self;
        r.set_neg();
        r
    }
}

impl Sub<FLR> for FLR {
    type Output = FLR;

    #[inline(always)]
    fn sub(self, other: FLR) -> FLR {
        let mut r = self;
        r.set_sub(other);
        r
    }
}

impl Sub<&FLR> for FLR {
    type Output = FLR;

    #[inline(always)]
    fn sub(self, other: &FLR) -> FLR {
        let mut r = self;
        r.set_sub(*other);
        r
    }
}

impl Sub<FLR> for &FLR {
    type Output = FLR;

    #[inline(always)]
    fn sub(self, other: FLR) -> FLR {
        let mut r = *self;
        r.set_sub(other);
        r
    }
}

impl Sub<&FLR> for &FLR {
    type Output = FLR;

    #[inline(always)]
    fn sub(self, other: &FLR) -> FLR {
        let mut r = *self;
        r.set_sub(*other);
        r
    }
}

impl SubAssign<FLR> for FLR {
    #[inline(always)]
    fn sub_assign(&mut self, other: FLR) {
        self.set_sub(other);
    }
}

impl SubAssign<&FLR> for FLR {
    #[inline(always)]
    fn sub_assign(&mut self, other: &FLR) {
        self.set_sub(*other);
    }
}
