//! SP1-style row-only LogUp-GKR backend (task #24, A.2).
//!
//! Bridges the protocol mismatch documented in
//! `docs/task_23_blocker.md`: the recursion verifier (ported from SP1)
//! expects `circuit_output.numerator/denominator` to be MLEs of size
//! `2^(num_interaction_variables + 1)`, while Ziren's existing GKR
//! backend (`crates/stark/src/logup_gkr.rs`) reduces all leaves to a
//! single `(num, denom)` root pair.
//!
//! This module rewrites SP1's GKR algorithm
//! (`/tmp/sp1/crates/hypercube/src/logup_gkr/{cpu.rs,execution.rs,prover.rs,proof.rs}`)
//! against Ziren's MLE/sumcheck APIs — the row dimension reduces
//! `num_row_variables - 1` times until each layer is a degenerate
//! 1-row × `2^num_interaction_variables` table; then the output
//! extraction interleaves the four `(numerator_0/1, denominator_0/1)`
//! sub-MLEs into a single `2^(num_interaction_variables+1)`-length
//! pair.
//!
//! ## Module map (incremental — built in steps per task #24)
//!
//!   - [`layer`] — layer types (`LogUpGkrCpuLayer`,
//!     `InteractionLayer`, `GkrCircuitLayer`, `LogupGkrCpuCircuit`).
//!     **Step 1**: type scaffolding (this commit).
//!   - `first_layer` — `generate_first_layer` from raw
//!     interactions + traces.  **Step 2** (next commit).
//!   - `transition` — `layer_transition` row-halving step.
//!     **Step 3**.
//!   - `extract` — `extract_outputs` interleaved-MLE projection.
//!     **Step 4**.
//!   - `round` — `prove_gkr_round` per-layer sumcheck wrapper.
//!     **Step 5**.
//!   - `top_level` — rewrite of `prove_shard_logup_gkr` to drive the
//!     new pipeline.  **Step 6**.
//!
//! No public surface yet — the new backend wires into
//! [`super::logup_gkr_prover::prove_shard_logup_gkr`] only after step 6.
//! Until then it lives in parallel and only the type scaffolding is
//! exposed for unit-test builds.

pub mod first_layer;
pub mod layer;

pub use first_layer::*;
pub use layer::*;
