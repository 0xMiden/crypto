//! Vendored fn-dsa components (currently the FLR sampler).
//! We keep a copy instead of depending on fn-dsa directly because:
//! 1) fn-dsa is still pre-standard and may diverge from the NIST reference;
//! 2) our variant uses a different hash-to-point (RPO) and signing flow, so we need tight control.

pub(crate) mod flr;
