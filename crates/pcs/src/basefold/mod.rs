//! **Basefold multilinear PCS.**
//!
//! Encodes each MLE via DFT individually (`Message<Mle<F>>` flow) — no
//! single dense `Vec<F>` materialization, which keeps peak memory
//! bounded per-MLE instead of per-batch.
//!
//! Layered above this module:
//!   * `stacked` — interleaves heterogeneous batches into stripes of
//!     fixed `log_stacking_height`, then commits via this protocol.
//!   * `jagged_pcs` — the jagged adapter that packs per-chip trace
//!     columns into the dense stacked polynomial this protocol commits.
//!
//! Per-round protocol shape:
//!   * one univariate sumcheck poly (degree-1, two coefficients)
//!   * exactly one merkle commitment to the folded codeword
//!   * no in-round queries — all queries deferred to the FRI
//!     query phase at the end.

pub mod code;
pub mod config;
pub mod encoder;
pub mod fri;
pub mod mle;
pub mod proof;
pub mod prover;
pub mod stacked;
pub mod verifier;

pub use stacked::*;

#[cfg(test)]
mod test;

pub use code::*;
pub use config::*;
pub use encoder::*;
pub use fri::*;
pub use mle::*;
pub use proof::*;
pub use prover::*;
pub use verifier::*;
