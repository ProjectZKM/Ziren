//! Deferred-stage **shape carrier**.
//!
//! The legacy FRI-shaped deferred verifier and its witness types
//! (`ZKMDeferredWitnessValues` / `ZKMDeferredWitnessVariable`) have been
//! retired. The production deferred verifier lives in
//! [`super::deferred_basefold::verify_deferred_basefold`]; the recursion-AIR
//! variant lives in [`super::deferred_basefold_recursion`].
//!
//! [`ZKMDeferredShape`] remains the shape-enumeration carrier on the
//! compress branch (consumed by
//! [`super::deferred_basefold::ZKMDeferredBasefoldWitnessValues::dummy`])
//! and references [`super::ZKMCompressShape`] from [`super::compress`].

use super::ZKMCompressShape;

#[derive(Debug, Clone, Hash)]
pub struct ZKMDeferredShape {
    pub(crate) inner: ZKMCompressShape,
    pub(crate) height: usize,
}

impl ZKMDeferredShape {
    pub const fn new(inner: ZKMCompressShape, height: usize) -> Self {
        Self { inner, height }
    }
}
