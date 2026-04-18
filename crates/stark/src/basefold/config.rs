//! Basefold protocol configuration.
//!
//! Source-mapped from
//! [`/tmp/sp1/slop/crates/basefold/src/config.rs`](file:///tmp/sp1/slop/crates/basefold/src/config.rs).
//!
//! The SP1 source carries a `BasefoldConfigImpl` enum of
//! Poseidon2{BabyBear,KoalaBear,Bn254Fr} variants; Ziren targets
//! KoalaBear+Poseidon2 only, so we don't carry the variant at the
//! type level.

use core::marker::PhantomData;

use p3_field::Field;

/// Number of bits of grinding required before the verifier samples the
/// random batching coefficients.
///
/// Set to 16 to match WHIR's `pow_bits` and defeat re-randomization
/// attacks on the batching point — without grinding here, an
/// adversary can re-roll the batch coefficients freely until they
/// land on a favorable transcript.  16 bits gives a 65k-attempt
/// barrier per re-roll attempt, matching the per-query PoW.
pub const BATCH_GRINDING_BITS: usize = 16;

/// FRI sub-protocol parameters used by Basefold's commit / query phase.
///
/// `log_blowup` is the Reed-Solomon rate (codeword length =
/// `(1 << num_variables) * (1 << log_blowup)`).  `num_queries` is the
/// number of independent FRI query openings; `proof_of_work_bits` is
/// the grinding requirement before the verifier samples query indices.
#[derive(Clone, Debug)]
pub struct FriConfig<F> {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub proof_of_work_bits: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> FriConfig<F> {
    pub const fn new(log_blowup: usize, num_queries: usize, proof_of_work_bits: usize) -> Self {
        Self { log_blowup, num_queries, proof_of_work_bits, _marker: PhantomData }
    }

    pub const fn log_blowup(&self) -> usize {
        self.log_blowup
    }

    /// Production-default parameters.  `log_blowup = 4` (rate 1/16)
    /// + 100 queries + 16-bit PoW gives **400 bits conjectured** /
    /// **~200 bits proven** (Johnson Bound) FRI soundness — same
    /// rate as WHIR's `whir_parameters(100)` so we inherit the same
    /// proven-100-bit posture.  Combined with sumcheck soundness
    /// (~118 bits over `EF=BinomialExtensionField<KoalaBear, 4>`)
    /// and `BATCH_GRINDING_BITS=16`, the aggregate soundness floor
    /// is **~118 bits** (sumcheck-bound).
    ///
    /// SP1's BaseFold defaults (1 / 100 / 16) match WHIR's default
    /// because WHIR is configured at log_blowup=1 by default in
    /// upstream Plonky3; Ziren chose log_inv_rate=4 to defeat
    /// proximity-gap attacks on KoalaBear^4 (see
    /// [whir_config.rs](crate::whir_config) note 136-141).  We mirror
    /// that choice here.
    pub const fn default_fri_config() -> Self {
        Self::new(4, 100, 16)
    }

    /// Memory-optimised config override via the
    /// `ZIREN_BASEFOLD_LOG_BLOWUP` env var.  Trades soundness margin
    /// for RSS headroom.  With `log_blowup = k` the stacked-PCS LDE
    /// shrinks to `2^k · N` EF bytes (vs `16N` at the default), at
    /// the cost of fewer proximity queries per round.  The query
    /// count scales as `log_inv_rate` for the same security target,
    /// so this knob is a hammer — use only when the default OOMs.
    ///
    /// Accepts integer values in [1, 4].  Any other value falls back
    /// to the production default.  Intended for perf experiments on
    /// wide workloads (tendermint, large-sum) that OOM at the
    /// default rate; **not** a production-sound configuration on its
    /// own (requires a separate re-analysis of the query count).
    pub fn from_env_or_default() -> Self {
        let Ok(val) = std::env::var("ZIREN_BASEFOLD_LOG_BLOWUP") else {
            return Self::default_fri_config();
        };
        let Ok(log_blowup) = val.parse::<usize>() else {
            return Self::default_fri_config();
        };
        if !(1..=4).contains(&log_blowup) {
            return Self::default_fri_config();
        }
        // Keep num_queries + pow unchanged — rate-adjusted soundness
        // analysis is caller's responsibility.  This is purely a
        // memory-measurement knob.
        Self::new(log_blowup, 100, 16)
    }

    /// Test-grade parameters with reduced query counts.  Use only in
    /// unit tests where soundness isn't load-bearing.
    pub const fn test_fri_config() -> Self {
        Self::new(1, 4, 0)
    }
}
