//! SIMD-packed `Felt` for `<Felt as Field>::Packing`.
//!
//! Currently provides one architecture backend (wasm32+simd128). Other
//! architectures fall back to `Felt::Packing = Self` (WIDTH=1, scalar).
//!
//! Self-contained: no dependency on a Plonky3-shipped packed Goldilocks
//! type. The arithmetic uses platform SIMD intrinsics directly, modeled on
//! Plonky3's `aarch64_neon` / `x86_64_avx2` backends with intrinsic
//! renaming. See `wasm32_simd128.rs` for the translation table.

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
mod wasm32_simd128;

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
pub use wasm32_simd128::PackedFelt;
