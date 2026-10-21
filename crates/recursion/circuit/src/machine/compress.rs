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

/// Which digest a verifier program checks its child's public values against
/// and which it commits: [`super::recursion_public_values_digest`] (the
/// reduce digest, over every hashed public value) or
/// [`super::root_public_values_digest`] (the root digest, over the values the
/// outer circuit exposes).
///
/// The recursion AIR binds only the digest slots of a proof's public values,
/// so a verifier ties a child's other public values to the child proof only
/// by recomputing the digest the child committed and asserting it equal.
pub enum PublicValuesOutputDigest {
    /// The child committed a reduce digest; commit a reduce digest.
    Reduce,
    /// The child committed a reduce digest; commit a root digest (the wrap
    /// program over the shrink proof).
    ReduceToRoot,
    /// The child committed a root digest; commit it (the outer circuit over
    /// the wrap proof).
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
