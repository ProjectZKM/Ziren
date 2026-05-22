//! Basefold protocol configuration.
//!
//! Source-mapped from
//! `slop/crates/basefold/src/config.rs`.
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

    /// Production-default parameters: **`(log_blowup=1, num_queries=94, pow_bits=16)`**
    /// — matches SP1's `slop_primitives::FriConfig::default_fri_config`.
    ///
    /// **Rate.** `log_blowup = 1` (rate-1/2) gives an LDE codeword
    /// of `2 · N` extension-field elements per stripe (vs the
    /// previous `log_blowup = 4` (rate-1/16) which materialised
    /// `16 · N` bytes — a structural OOM blocker on wide workloads
    /// such as tendermint and ssz-withdrawals).
    ///
    /// **Queries.** SP1 cites the Gruen-Diamond result for the
    /// 84 → 94 query bump at this rate; we adopt it directly.
    /// 94 queries at rate-1/2 with `pow_bits = 16` of per-query
    /// grinding gives ≥ 100-bit FRI soundness under the Johnson
    /// Bound.  Combined with sumcheck soundness over
    /// `EF = BinomialExtensionField<KoalaBear, 4>` and
    /// `BATCH_GRINDING_BITS = 16`, the aggregate floor stays at
    /// ~100 bits (sumcheck-bound).
    ///
    /// **Why rate-1/16 was chosen previously.** The WHIR-era
    /// configuration used `log_blowup = 4` to defeat proximity-gap
    /// attacks on KoalaBear^4 (see the historical `whir_config.rs`
    /// notes).  WHIR's analysis required a tighter rate; BaseFold
    /// inherits SP1's analysis instead, where `log_blowup = 1` is
    /// sufficient for the same target.
    ///
    /// **Memory impact** (vs the previous default).  ~8× reduction
    /// in LDE bytes per stripe.  Empirical projection from the
    /// 2026-04-18 perf comparison (rate-1/16 measurements):
    /// fib-100k 51.7 GB → ~6 GB; ssz-withdrawals 104 GB → ~13 GB;
    /// tendermint OOM @ 112 GB → fitting under 16 GB.  Re-measured
    /// after this change.
    pub const fn default_fri_config() -> Self {
        Self::new(1, 94, 16)
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
