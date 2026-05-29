//! **Basefold multilinear PCS — Ziren port of SP1's slop_basefold.**
//!
//! Source-mapped from
//! `slop/crates/basefold` and
//! `slop/crates/basefold-prover`.
//!
//! Replaces the WHIR PCS stack.  Structural OOM cure: encodes each MLE
//! via DFT individually (`Message<Mle<F>>` flow), no single dense
//! `Vec<F>` materialization.  See
//! [`docs/perf_results.md`](docs/perf_results.md) for the WHIR OOM
//! root-cause analysis this addresses.
//!
//! Layered above this module:
//!   * `stacked` — interleaves heterogeneous batches into stripes of
//!     fixed `log_stacking_height`, then commits via this protocol.
//!   * `jagged_pcs` — jagged jagged-PCS adapter
//!     (replaces `whir_late_binding.rs`).
//!
//! Per-round protocol shape (much simpler than WHIR):
//!   * one univariate sumcheck poly (degree-1, two coefficients)
//!   * exactly one merkle commitment to the folded codeword
//!   * **no** STIR-within-rounds — all queries deferred to the FRI
//!     query phase at the end.

pub mod code;
pub mod config;
pub mod encoder;
pub mod fri;
pub mod mle;
pub mod padded;
pub mod proof;
// jagged_per_chip module removed (Ziren #97, May 2 2026): per-chip
// jagged-PCS path was an E3 perf experiment that diverged from SP1's
// single-dense design and never landed.  Removed in favor of the
// SP1-aligned dense path in `jagged_pcs::jagged`.
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
pub use padded::*;
pub use proof::*;
pub use prover::*;
pub use verifier::*;
