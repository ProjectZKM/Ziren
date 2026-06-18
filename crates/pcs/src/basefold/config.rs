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

    /// Inner-stage (core / compress / shrink) production parameters:
    /// **`(log_blowup=2, num_queries=124, pow_bits=16)`** — SP1-faithful
    /// per-stage soundness (`core_fri_config` / `recursion_fri_config`,
    /// `crates/primitives/src/fri_params.rs`: `CORE_LOG_BLOWUP = 2`,
    /// `RECURSION_LOG_BLOWUP = 2`,
    /// `unique_decoding_queries(2) = 124`, `SP1_PROOF_OF_WORK_BITS = 16`).
    ///
    /// **Soundness (the #57 fix — provable 100-bit inner chain).** The
    /// BaseFold query-phase / unique-decoding soundness is
    /// `num_queries · (-log2(0.5 + rate/2)) + pow_bits`.  At rate
    /// `1/2^2 = 1/4` (`half_rate_plus_half = 0.625`):
    /// `124 · (-log2(0.625)) + 16 = 124 · 0.6781 + 16 ≈ 100.08` bits.
    /// This is the 100-bit target.
    ///
    /// **Why the OLD `(1, 94, 16)` was UNSOUND.** At rate `1/2`
    /// (`half_rate_plus_half = 0.75`), 94 queries with `pow_bits = 16`
    /// buys only `94 · (-log2(0.75)) + 16 ≈ 55` bits — the old inner
    /// default merely copied SP1's literal `94` (which SP1 uses ONLY at
    /// `blowup=3 / pow=22`) while keeping `blowup=1 / pow=16`.  For
    /// 100 bits at `blowup=1` the formula demands **203** queries; SP1
    /// instead raises the rate to `blowup=2` so 124 queries suffice.
    ///
    /// **Shrink note (deviation from SP1, intentional).** SP1 secures
    /// shrink at `(blowup=3, q=94, pow=22)` (a SIZE optimisation for the
    /// shrink→wrap hand-off).  Ziren's shrink machine shares the inner
    /// `KoalaBearPoseidon2` SC TYPE with core/compress AND is verified
    /// in-circuit by the wrap program through the SAME KoalaBear
    /// `production_default` verifier that verifies compress→core and
    /// shrink→compress children — so a per-stage host/circuit split for
    /// shrink alone would require a third in-circuit param variant wired
    /// into the wrap program's KoalaBear arm.  Ziren therefore runs shrink
    /// at this SAME `(2, 124, 16)` config: still provably 100-bit (100.08),
    /// in fact MORE conservative on query count (124 ≥ 94), at the cost of
    /// a slightly larger shrink proof.  The on-chain WRAP proof (BN254
    /// OuterSC) keeps SP1's `(3, 94, 22)` via `wrap_fri_config`.
    ///
    /// **Two-adicity.** Codeword domain = `num_variables + log_blowup`
    /// where `num_variables = log_stacking_height ≤ DEFAULT_LOG_STACKING_HEIGHT
    /// = 21`.  At `log_blowup = 2` this is `≤ 21 + 2 = 23 ≤ KoalaBear
    /// TWO_ADICITY = 24`, so the LDE domain exists with one bit of headroom.
    ///
    /// **Memory impact.** Rate `1/4` materialises `4 · N` EF bytes per
    /// stripe vs `2 · N` at the old `blowup=1` — a ~2× LDE growth.  Wide
    /// workloads (tendermint, ssz-withdrawals) that were tuned to fit at
    /// `blowup=1` may need the `ZIREN_BASEFOLD_LOG_BLOWUP` escape hatch on
    /// memory-constrained hosts (but that knob DROPS soundness below
    /// 100-bit — see `from_env_or_default`).
    pub const fn default_fri_config() -> Self {
        Self::new(2, 124, 16)
    }

    /// Memory-optimised config override via the
    /// `ZIREN_BASEFOLD_LOG_BLOWUP` env var.  Trades soundness margin
    /// for RSS headroom.  With `log_blowup = k` the stacked-PCS LDE
    /// is `2^k · N` EF bytes per stripe, at the cost of the fixed 100
    /// queries no longer matching the rate's 100-bit target.
    ///
    /// **⚠ SOUNDNESS WARNING.** This knob pins `num_queries = 100` and
    /// `pow = 16` REGARDLESS of `log_blowup`, so it does NOT track the
    /// rate-dependent query count needed for 100-bit soundness.  At the
    /// sound inner default (`blowup=2`, 124 queries — see
    /// `default_fri_config`) this override would DROP to 100 queries
    /// (`100 · 0.6781 + 16 ≈ 84` bits) and at `blowup=1` to ~71 bits.
    /// It is a MEMORY-MEASUREMENT hammer ONLY — using it in production
    /// silently weakens the proof below 100-bit.  Leave it UNSET for the
    /// sound `(2, 124, 16)` default.
    ///
    /// Accepts integer values in [1, 4].  Any other value (or unset)
    /// falls back to the sound production default.
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

    /// **WRAP / SHRINK-grade parameters: `(log_blowup=3, num_queries=94, pow_bits=22)`**
    /// — matches SP1's `wrap_fri_config` / `shrink_fri_config`
    /// (`crates/primitives/src/fri_params.rs`: `WRAP_LOG_BLOWUP=3`,
    /// `SP1_SHRINK_WRAP_POW_BITS=22`,
    /// `unique_decoding_queries_with_custom_grinding(3, 22) = 94`).
    ///
    /// **Soundness.** The query-phase / Johnson-bound soundness of the
    /// BaseFold FRI is `num_queries · (-log2(0.5 + rate/2)) + pow_bits`.
    /// At rate `1/2^3 = 1/8` (`half_rate_plus_half = 0.5625`):
    /// `94 · (-log2(0.5625)) + 22 = 94 · 0.8301 + 22 ≈ 100.03` bits.
    /// This is the 100-bit target.
    ///
    /// **Why the inner default (`(1, 94, 16)`) is NOT used for the wrap.**
    /// At rate `1/2` (`half_rate_plus_half = 0.75`), 94 queries with
    /// `pow_bits = 16` buys only `94 · (-log2(0.75)) + 16 ≈ 55` bits — the
    /// inner default merely copied SP1's literal `94` without SP1's
    /// `blowup=3 / pow=22`.  The wrap proof is the on-chain root, so it
    /// MUST hit the full 100-bit target; this constructor supplies it.
    ///
    /// **Two-adicity.** The wrap BaseFold codeword domain has
    /// `log_codeword_size = num_variables + log_blowup` where
    /// `num_variables = log_stacking_height ≤ DEFAULT_LOG_STACKING_HEIGHT
    /// = 21`.  At `log_blowup = 3` this is `≤ 21 + 3 = 24 = KoalaBear
    /// TWO_ADICITY`, so the LDE domain exists (fits exactly).
    pub const fn wrap_fri_config() -> Self {
        Self::new(3, 94, 22)
    }

    /// Test-grade parameters with reduced query counts.  Use only in
    /// unit tests where soundness isn't load-bearing.
    pub const fn test_fri_config() -> Self {
        Self::new(1, 4, 0)
    }
}
