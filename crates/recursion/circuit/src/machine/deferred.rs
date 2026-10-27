//! Deferred-stage shape carrier.
//!
//! The deferred verifier lives in
//! [`super::deferred_jagged::verify_deferred_jagged`]; the recursion-AIR
//! variant lives in [`super::deferred_recursion`].
//!
//! [`ZKMDeferredShape`] is the shape-enumeration carrier on the
//! compress branch (consumed by
//! [`super::deferred_jagged::ZKMDeferredWitnessValues::dummy`])
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
