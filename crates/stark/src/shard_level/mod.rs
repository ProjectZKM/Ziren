//! Shard-level BaseFold proof pipeline.
//!
//! Production proof shape for KoalaBear MIPS shards as of #13:
//! one `LogupGkrProof` + one `PartialSumcheckProof` per shard
//! (vs. the legacy per-chip lists, retired in #13).
//!
//! Reference: `crates/hypercube/src/{logup_gkr,prover/zerocheck,prover/shard.rs,verifier/proof.rs}`.
//!
//! # Module map
//!
//!   - [`types`] — pure data types (`LogupGkrProof`,
//!     `PartialSumcheckProof`, `LogUpEvaluations`, etc.)
//!   - [`shard_proof`] — host-side `BasefoldShardProof<F, EF>`
//!     mirroring the `ShardProof` (6 fields: public_values,
//!     main_commitment, logup_gkr_proof, zerocheck_proof,
//!     opened_values, evaluation_proof).
//!   - [`logup_gkr_prover`] — shard-level LogUp-GKR prover.
//!     Mirrors `prove_logup_gkr` from
//!     `crates/hypercube/src/logup_gkr/prover.rs:70-215`.
//!   - [`zerocheck_prover`] — shard-level zerocheck prover.
//!     Mirrors `ShardProver::zerocheck` from
//!     `crates/hypercube/src/prover/shard.rs:474-646`.
//!   - [`prover`] — assembly entry `prove_shard_to_basefold`.
//!     Mirrors `ShardProver::prove_shard_with_data` from
//!     `crates/hypercube/src/prover/shard.rs:650-792`.

pub mod basefold_constraint_folder;
pub mod device_first_layer_context;
pub mod device_trace_provider;
pub mod logup_gkr_prover;
pub mod main_trace_loader;
pub mod prover;
pub mod shard_proof;
pub mod row_gkr;
pub mod sumcheck_poly;
pub mod types;
pub mod verifier;
pub mod zerocheck_prover;

pub use device_trace_provider::DeviceTraceProvider;
pub use logup_gkr_prover::*;
pub use main_trace_loader::{EagerHostLoader, LazyDeviceLoader, MainTraceLoader};
pub use prover::*;
pub use shard_proof::*;
pub use sumcheck_poly::{
    reduce_sumcheck_to_evaluation, ComponentPoly, SumcheckPoly, SumcheckPolyBase,
    SumcheckPolyFirstRound,
};
pub use types::*;
pub use zerocheck_prover::*;
