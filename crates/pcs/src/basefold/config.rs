//! Basefold protocol configuration.
//!
//! Ziren targets
//! KoalaBear+Poseidon2 only, so no config-variant enum is carried at the
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

/// log2 of the FRI folding arity for the INNER (KoalaBear) stages — core,
/// compress and shrink.
///
/// One source of truth: the host `FriConfig`, the GPU prover and the recursion
/// circuit's `BasefoldVerifierParams` must all agree, or the transcript
/// diverges.  The wrap (BN254) stage keeps arity 1.
///
/// **3 is the measured optimum.** A commit-phase round of arity `k` folds `k`
/// variables against ONE Merkle leaf of `2^k` rows, so the recursion verifier
/// walks `num_variables / k` paths instead of `num_variables`, each `k` levels
/// shallower.  Against that, folding a `2^k` block costs `2^k - 1` fold steps
/// per round, which grows faster than the path saving:
///
/// | k | rounds | merkle rows | fold rows | net vs k=1 |
/// |---|---|---|---|---|
/// | 1 | 22 | 306,900 | 30,008 | -- |
/// | 2 | 11 | 147,312 | 38,192 | -10.7% |
/// | 3 | 7 | 93,744 | 52,080 | **-13.5%** |
/// | 4 | 5 | 66,960 | 75,640 | -13.7% |
/// | 5 | 4 | 51,336 | 121,024 | -11.6% |
///
/// The win peaks at 3-4 and REVERSES by 5.  3 takes 98% of what 4 does for
/// two thirds of the fold cost.
pub const INNER_LOG_FOLDING_ARITY: usize = 3;

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
    /// log2 of the FRI folding arity: each commit-phase round folds this many
    /// variables before committing again, so the protocol runs
    /// `num_variables / log_folding_arity` rounds instead of `num_variables`.
    ///
    /// This is the dominant term in the RECURSION VERIFIER's cost, not in the
    /// prover's.  A query walks one Merkle path per round, and each path level
    /// costs eight `Select` rows plus one Poseidon2 permutation in-circuit.
    /// At arity 2 a compose child spends 36,964 path levels -- measured, 23.6%
    /// of the whole child -- because it runs ~23 rounds whose depths sum to
    /// ~299.  Folding `k` variables per round cuts the round count to
    /// `num_variables / k` AND each leaf to `2^k` values, so the depth at each
    /// round drops by `k` as well.
    ///
    /// The extra work is local and small: a query opens a `2^k`-wide coset
    /// instead of a pair, and folds it `k` times itself.
    pub log_folding_arity: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> FriConfig<F> {
    pub const fn new(log_blowup: usize, num_queries: usize, proof_of_work_bits: usize) -> Self {
        Self {
            log_blowup,
            num_queries,
            proof_of_work_bits,
            // Arity 2 -- one variable per round, the classic BaseFold shape.
            log_folding_arity: 1,
            _marker: PhantomData,
        }
    }

    /// Fold `log_folding_arity` variables per commit-phase round.
    pub const fn with_log_folding_arity(mut self, log_folding_arity: usize) -> Self {
        assert!(log_folding_arity >= 1, "folding arity must be at least 2 (log >= 1)");
        self.log_folding_arity = log_folding_arity;
        self
    }

    pub const fn log_folding_arity(&self) -> usize {
        self.log_folding_arity
    }

    pub const fn log_blowup(&self) -> usize {
        self.log_blowup
    }

    /// Inner-stage (core / compress / shrink) production parameters:
    /// **`(log_blowup=2, num_queries=124, pow_bits=16)`** —
    /// per-stage soundness.
    ///
    /// **Soundness (provable 100-bit inner chain).** The
    /// BaseFold query-phase / unique-decoding soundness is
    /// `num_queries · (-log2(0.5 + rate/2)) + pow_bits`.  At rate
    /// `1/2^2 = 1/4` (`half_rate_plus_half = 0.625`):
    /// `124 · (-log2(0.625)) + 16 = 124 · 0.6781 + 16 ≈ 100.08` bits.
    /// This is the 100-bit target.
    ///
    /// **Why the OLD `(1, 94, 16)` was UNSOUND.** At rate `1/2`
    /// (`half_rate_plus_half = 0.75`), 94 queries with `pow_bits = 16`
    /// buys only `94 · (-log2(0.75)) + 16 ≈ 55` bits — the old inner
    /// default used a `94` query count that is only sound at
    /// `blowup=3 / pow=22`, while keeping `blowup=1 / pow=16`.  For
    /// 100 bits at `blowup=1` the formula demands **203** queries;
    /// raising the rate to `blowup=2` lets 124 queries suffice.
    ///
    /// **Shrink note (intentional).** Shrink COULD run at
    /// `(blowup=3, q=94, pow=22)` (a SIZE optimisation for the
    /// shrink→wrap hand-off), but Ziren's shrink machine shares the inner
    /// `KoalaBearPoseidon2` SC TYPE with core/compress AND is verified
    /// in-circuit by the wrap program through the SAME KoalaBear
    /// `production_default` verifier that verifies compress→core and
    /// shrink→compress children — so a per-stage host/circuit split for
    /// shrink alone would require a third in-circuit param variant wired
    /// into the wrap program's KoalaBear arm.  Ziren therefore runs shrink
    /// at this SAME `(2, 124, 16)` config: still provably 100-bit (100.08),
    /// in fact MORE conservative on query count (124 ≥ 94), at the cost of
    /// a slightly larger shrink proof.  The on-chain WRAP proof (BN254
    /// OuterSC) keeps `(3, 94, 22)` via `wrap_fri_config`.
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
        Self::new(2, 124, 16).with_log_folding_arity(INNER_LOG_FOLDING_ARITY)
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
    ///
    /// ⚠ ONLY blowup 2 (the default) survives a RECURSION proof.  Measured:
    /// at 3 and 4 the recursion verifier panics `index out of bounds: the len
    /// is 23 but the index is 23` (`basefold_verifier.rs`, the query-index bit
    /// width does not track the Merkle path length), and at 1 the recursion
    /// program traps on `DivFAssert 1/0`.  The knob is usable for measuring a
    /// CORE commit and nothing beyond it.
    ///
    /// ⚠ AND BLOWUP IS NOT A SIZE LEVER FOR THE RECURSION CIRCUIT.  Measured at
    /// a fixed 100 queries, blowup 1 -> 2 GROWS a leaf program 3,617,952 ->
    /// 3,654,752 instructions (+1.0%) as the Merkle path goes 22 -> 23, which
    /// puts the path-dependent share of the circuit near 22%.  Raising blowup
    /// only helps through the query count it buys at equal soundness --
    /// 124 -> 102 -> 93 for blowup 2 -> 3 -> 4 at 100 bits -- which projects to
    /// about -3% and -4% of the circuit, against 2x and 4x the prover's
    /// codeword.  The recursion circuit's size is set by the PCS it verifies,
    /// not by this parameter.
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

    /// **WRAP / SHRINK-grade parameters:
    /// `(log_blowup=3, num_queries=94, pow_bits=22)`.**
    ///
    /// **Soundness.** The query-phase / Johnson-bound soundness of the
    /// BaseFold FRI is `num_queries · (-log2(0.5 + rate/2)) + pow_bits`.
    /// At rate `1/2^3 = 1/8` (`half_rate_plus_half = 0.5625`):
    /// `94 · (-log2(0.5625)) + 22 = 94 · 0.8301 + 22 ≈ 100.03` bits.
    /// This is the 100-bit target.
    ///
    /// **Why the inner default (`(1, 94, 16)`) is NOT used for the wrap.**
    /// At rate `1/2` (`half_rate_plus_half = 0.75`), 94 queries with
    /// `pow_bits = 16` buys only `94 · (-log2(0.75)) + 16 ≈ 55` bits — a
    /// `94` query count is only sound alongside
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
