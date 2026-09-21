//! Multilinear-polynomial primitives shared across the shard prover.
//!
//! Hosts the analytic [`padded::PaddedMle`], the single `PaddedMle` in the
//! crate, from which the shared trace-MLE is built.  (The LogUp-GKR layers use
//! `RowMajorTable`, not a `PaddedMle`.)

pub mod base;
pub mod padded;

pub use padded::{PaddedMle, Padding};
