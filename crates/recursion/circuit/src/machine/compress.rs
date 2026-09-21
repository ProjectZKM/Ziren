//! Compose-stage **shape carriers** shared by the basefold compose pipeline.
//!
//! The compose verifier is [`super::compress_basefold::verify_compress_basefold`],
//! with the recursion-AIR variant in [`super::compress_basefold_recursion`];
//! both consume the basefold-shaped witness layouts from those modules.
//!
//! - [`PublicValuesOutputDigest`] — imported by all basefold compose
//!   builders (`compress_basefold.rs`, `compress_basefold_recursion.rs`,
//!   `basefold_programs.rs`) to select between
//!   [`super::recursion_public_values_digest`] and
//!   [`super::root_public_values_digest`] in the public-values output stream.
//! - [`ZKMCompressShape`] — the shape-enumeration carrier embedded in
//!   [`super::ZKMCompressWithVkeyShape`] and [`super::ZKMDeferredShape`].

use zkm_pcs::shape::OrderedShape;

/// Selector tag passed to the basefold compose verifiers to choose between
/// [`super::recursion_public_values_digest`] (the standard reduce digest used
/// at intermediate compress layers) and [`super::root_public_values_digest`]
/// (used at the root layer, which is wrap's input).
pub enum PublicValuesOutputDigest {
    Reduce,
    Root,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZKMCompressShape {
    pub(crate) proof_shapes: Vec<OrderedShape>,
}

impl From<Vec<OrderedShape>> for ZKMCompressShape {
    fn from(proof_shapes: Vec<OrderedShape>) -> Self {
        Self { proof_shapes }
    }
}
