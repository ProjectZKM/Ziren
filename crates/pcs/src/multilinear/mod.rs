//! Multilinear-polynomial primitives shared across the shard prover.
//!
//! Ported from SP1's `slop/crates/multilinear`.  Hosts the SP1-shaped
//! analytic [`padded::PaddedMle`] — the single `PaddedMle` in the
//! crate, used to build the shared trace-MLE.  (The LogUp-GKR layers use
//! `RowMajorTable`, not a `PaddedMle`.)

pub mod base;
pub mod padded;

pub use padded::{Padding, PaddedMle};
