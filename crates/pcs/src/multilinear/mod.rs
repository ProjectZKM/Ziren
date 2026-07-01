//! Multilinear-polynomial primitives shared across the shard prover.
//!
//! Ported from SP1's `slop/crates/multilinear`.  Currently hosts the
//! SP1-shaped analytic [`padded::PaddedMle`] (#125 INC-1).  The type is
//! referenced by full path (`crate::multilinear::PaddedMle`) and is NOT
//! glob-exported at the crate root, so it never collides with the
//! GKR-round `crate::basefold::PaddedMle`.

pub mod padded;

pub use padded::{Padding, PaddedMle};
