//! BaseFold proof verifier for the recursion circuit (D2 — host-shape + emit hooks).
//!
//! Mirror of [`crate::whir_verifier`]'s scaffold pattern but for
//! BaseFold-based shard proofs emitted by `prove_jagged_basefold`.
//!
//! Like its WHIR sibling, this module holds:
//!   - host-shape verification logic (real Rust math) so the
//!     transcript ordering and per-round consistency checks are
//!     unit-testable without the full recursion-compiler integration;
//!   - DSL-IR emit hooks for the in-circuit pieces that the recursion
//!     compiler will lower to Poseidon2 / FriFold instructions.
//!
//! # Architecture
//!
//! Per BaseFold round (the prover commits one folded codeword and
//! emits one univariate sumcheck message):
//!
//! 1. **Commit observation** — emit one Merkle root `commit_r` per round
//! 2. **Univariate sumcheck round** — emit `[g_r(0), g_r(1)]` (degree-1,
//!    two EF coefficients), check `(1 - x_r) g(0) + x_r g(1) == claim_r`
//! 3. **Sample beta_r** — shared between sumcheck and FRI fold (the
//!    BaseFold key invariant — see
//!    [`crates/pcs/src/basefold`](crate::basefold))
//! 4. **Update claim** — `claim_{r+1} = g(0) + beta_r * g(1)`
//!
//! After all rounds:
//!
//! 5. **Final polynomial** — receive single EF constant, observe
//! 6. **PoW check** — verify FRI query-phase grinding witness
//! 7. **Sample query indices** — `num_queries × log_codeword_size` bits
//! 8. **Component-poly openings** — verify per-round Merkle proofs at
//!    sampled indices, batch into FRI starting evals
//! 9. **FRI query phase** — walk commit-phase chain, check the
//!    `(lo + hi)/2 + (lo - hi) · beta · g_inv^i / 2` fold relation per
//!    round, final folded value must equal final_poly
//! 10. **Final consistency** — `final_poly == last_uni[0] + last_beta · last_uni[1]`
//!
//! # Comparison with WHIR verifier
//!
//! | Component | WHIR | BaseFold (this file) |
//! |---|---|---|
//! | Per-round protocol | k sumcheck + STIR within round | 1 univariate + 1 fold |
//! | Per-round Merkle commits | 1 (codeword) | 1 (folded codeword) |
//! | Query phase | Per-round STIR queries | Single batch query phase at end |
//! | Final consistency | `claim ≟ weight · f(r)` | `final_poly ≟ uni[0] + β·uni[1]` |
//! | Recursion cost (per round) | ~50 constraints | ~30 constraints (no STIR overhead) |
//!
//! All `p3_whir` references in `whir_verifier.rs` are *comment-only* —
//! the actual code uses only `zkm_recursion_compiler` primitives, so
//! D2 doesn't need to drop p3-whir to land.

#![allow(unused_variables)]


/// Parameters for BaseFold proof verification in the recursion circuit.
#[derive(Clone, Debug)]
pub struct BasefoldVerifierParams {
    /// log2 of the Reed-Solomon rate.  Production default: 4 (rate
    /// 1/16, matches WHIR's posture for proven 100-bit soundness).
    pub log_blowup: usize,
    /// FRI query-phase query count.  Production default: 100.
    pub num_queries: usize,
    /// Grinding bits before query indices are sampled.  Default 16.
    pub pow_bits: usize,
    /// Grinding bits before batching coefficients (defends against
    /// re-randomization).  Default 16.
    pub batch_grinding_bits: usize,
    /// Total polynomial variables = log2 of dense codeword size.
    pub num_variables: usize,
}

impl BasefoldVerifierParams {
    /// Inner-stage production default — the in-circuit twin of
    /// `zkm_pcs::basefold::config::FriConfig::default_fri_config`:
    /// `(log_blowup=2, num_queries=124, pow_bits=16)` (#57).  This is the
    /// verifier the recursion programs use for EVERY inner KoalaBear child:
    /// compress→core, shrink→compress, AND wrap→shrink (the shrink proof is
    /// a KoalaBear inner-Mmcs proof verified through this arm, NOT the BN254
    /// `wrap_default` Bytes arm).  Since all three inner host stages
    /// (core/compress/shrink) now produce at `(2, 124, 16)`, this single
    /// param matches the committed codeword rate for all of them.
    ///
    /// **Soundness.** `124 · (-log2(0.5 + (1/4)/2)) + 16 = 124 · 0.6781 + 16
    /// ≈ 100.08` bits (vs the old `(1, 94, 16)` = ~55 bits, the inner hole
    /// #57 closes).  The component-opening Merkle path is `log_stacking + 2`
    /// levels and the query index span is `num_variables + 2` bits — both
    /// keyed off `log_blowup`, so they MUST match the host `blowup=2`.
    ///
    /// Two-adicity: `num_variables(≤21) + 2 ≤ 24`.  Was `(1, 94)` ≈ 55 bits.
    pub const fn production_default(num_variables: usize) -> Self {
        Self {
            log_blowup: 2,
            num_queries: 124,
            pow_bits: 16,
            batch_grinding_bits: 16,
            num_variables,
        }
    }

    /// **WRAP-stage in-circuit params** — the in-circuit twin of
    /// `zkm_pcs::basefold::config::FriConfig::wrap_fri_config`:
    /// `(log_blowup=3, num_queries=94, pow_bits=22)`.  Used by the gnark
    /// OUTER circuit that verifies the on-chain WRAP STARK proof, so the
    /// in-circuit verifier reads the codeword at the SAME rate the wrap
    /// prover committed (rate 1/8).  The component-opening Merkle path is
    /// `log_stacking + log_blowup = log_stacking + 3` levels and the query
    /// index span is `num_variables + 3` bits — both keyed off `log_blowup`.
    ///
    /// `batch_grinding_bits` stays 16 (the batching-coefficient grind is a
    /// separate re-randomization defense, unchanged from SP1's split).
    ///
    /// Soundness: `94 · (-log2(0.5 + (1/8)/2)) + 22 ≈ 100` bits (vs ~55 bits
    /// at the inner default).  Two-adicity: `num_variables(≤21) + 3 ≤ 24`.
    pub const fn wrap_default(num_variables: usize) -> Self {
        Self {
            log_blowup: 3,
            num_queries: 94,
            pow_bits: 22,
            batch_grinding_bits: 16,
            num_variables,
        }
    }

    /// Total sumcheck rounds (= num_variables — BaseFold does one
    /// univariate round per polynomial variable).
    pub const fn total_sumcheck_rounds(&self) -> usize {
        self.num_variables
    }

    /// Total Merkle commits the verifier must observe (one per
    /// commit-phase round, plus the initial commit).
    pub const fn total_merkle_commits(&self) -> usize {
        self.num_variables + 1
    }

    /// log2 of the codeword size (= num_variables + log_blowup).
    pub const fn log_codeword_size(&self) -> usize {
        self.num_variables + self.log_blowup
    }

    /// Recursion-constraint estimate for one BaseFold proof.  Sized
    /// to inform the recursion AIR builder.
    pub fn estimated_recursion_constraints(&self) -> usize {
        let sumcheck = self.total_sumcheck_rounds() * 30; // ~30 per univariate round
        let merkle = self.num_queries
            * (self.num_variables + 1) // one Merkle path per round
            * 200; // ~200 per Poseidon2 hash
        let fri_fold = self.num_queries * self.num_variables * 25; // FriFold per round per query
        let final_check = 100;
        sumcheck + merkle + fri_fold + final_check
    }
}

/// Generic challenger trait for the recursion circuit's BaseFold
/// verifier scaffolding.  In production this would be
/// `FieldChallengerVariable` over circuit-compiler builders; here we
/// use a host-side trait so the type-shape work is testable without
/// dragging in the full circuit-compiler dependency tree.
pub trait ScaffoldChallenger {
    fn observe_usize(&mut self, value: usize);
    fn observe_usize_slice(&mut self, values: &[usize]);
}

/// Host-side scaffolding challenger that hashes observations into a
/// 64-bit accumulator.  Exists for unit-testing the verifier's
/// transcript ordering — NOT for production use.
#[derive(Default, Clone)]
pub struct ScaffoldHostChallenger {
    pub state: u64,
}

impl ScaffoldChallenger for ScaffoldHostChallenger {
    fn observe_usize(&mut self, value: usize) {
        self.state = self
            .state
            .wrapping_mul(0x9E3779B97F4A7C15)
            .wrapping_add(value as u64);
    }
    fn observe_usize_slice(&mut self, values: &[usize]) {
        self.observe_usize(values.len());
        for &v in values {
            self.observe_usize(v);
        }
    }
}

/// Per-round BaseFold proof piece — one univariate sumcheck message
/// + one Merkle commitment on the folded codeword.
#[derive(Clone, Debug)]
pub struct RecursiveBasefoldRound<F, EF, Dig = [F; 8]> {
    /// `[g(0), g(1)]` — degree-1 univariate sumcheck message.
    pub uni_poly: [EF; 2],
    /// Merkle root of the folded codeword for this round.  The raw
    /// digest type `Dig` defaults to `[F; 8]` (inner Poseidon2-KoalaBear
    /// digests); the OUTER ring instantiates `Dig = [Bn254; 1]`
    /// (Poseidon2-BN254).  This mirrors SP1's
    /// `fri_commitments: Vec<SC::DigestVariable>` by carrying the
    /// digest's length in the type rather than a const generic.
    pub commitment: Dig,
    /// Phantom to keep `F` used when `Dig` does not mention it.
    pub _phantom_f: core::marker::PhantomData<F>,
}

/// Per-query opening of a commit-phase round's Merkle tree at the
/// (shifted) query index.  Two EF values (sibling pair on the
/// codeword domain) + the inclusion path.
#[derive(Clone, Debug)]
pub struct RecursiveBasefoldOpening<F, EF, Dig = [F; 8]> {
    /// Query position in the round's codeword domain.
    pub position: usize,
    /// Sibling pair — `[evals[0], evals[1]]` at positions `(x, -x)`.
    pub sibling_pair: [EF; 2],
    /// Merkle path bytes (serialized) — kept for backward
    /// compatibility with existing witness-stream layouts.
    pub merkle_path_bytes: Vec<u8>,
    /// Structured Merkle inclusion path — one sibling digest per
    /// tree level, bottom-up.  When non-empty, the in-circuit
    /// verifier binds each sibling pair against
    /// `commitments[round_idx]` via `merkle_tree::verify`.  Empty
    /// when the proof carries only the byte-serialized form,
    /// in which case Merkle binding is skipped.
    pub merkle_path_digests: Vec<Dig>,
    /// Phantom for the EF / F type-parameters not otherwise used by
    /// fields (digests carry the `Dig` type directly).
    pub _phantom: core::marker::PhantomData<(EF, F)>,
}

/// Per-query opening of the *original* committed batch (the
/// stacked-PCS commit before FRI begins) at the same query index.
#[derive(Clone, Debug)]
pub struct RecursiveBasefoldComponentOpening<F, EF, Dig = [F; 8]> {
    /// Per-stripe values at this query index — outer = stripe, inner
    /// = column count for that stripe.
    pub leaf_values: Vec<Vec<F>>,
    pub merkle_path_bytes: Vec<u8>,
    /// The Merkle inclusion path (sibling digests, leaf-to-root) that
    /// binds this leaf against the round's ORIGINAL component
    /// commitment — host `MerkleOpening.leaves[q].proof`.
    pub merkle_path_digests: Vec<Dig>,
    pub _phantom: core::marker::PhantomData<(EF, Dig)>,
}

/// In-circuit type mirroring the host
/// [`crate::basefold::BasefoldProof`].
#[derive(Clone, Debug)]
pub struct RecursiveBasefoldProof<F, EF, Dig = [F; 8]> {
    /// Per-round univariate sumcheck + commit.
    pub rounds: Vec<RecursiveBasefoldRound<F, EF, Dig>>,
    /// Final constant of the FRI commit phase.
    pub final_poly: EF,
    /// PoW grinding witness (query-phase).
    pub pow_witness: F,
    /// PoW grinding witness (batching coefficients).
    pub batch_grinding_witness: F,
    /// Per-query openings of the original (per-round) component
    /// commitments.  Outer index = round, inner = query.
    pub component_openings: Vec<Vec<RecursiveBasefoldComponentOpening<F, EF, Dig>>>,
    /// Per-query openings of the commit-phase rounds.  Outer index =
    /// commit-phase round, inner = query.
    pub query_phase_openings: Vec<Vec<RecursiveBasefoldOpening<F, EF, Dig>>>,
    /// Per-round per-stripe evaluation claims at the stack point.
    /// Used by the stacked-PCS verification step.
    pub batch_evaluations: Vec<Vec<EF>>,
}

/// Top-level recursion verifier for a BaseFold shard proof.
///
/// #H (BaseFold-over-BN254 wrap port): generic over the Merkle hasher
/// `HV: FieldHasherVariable<C>` so the gnark OUTER wrap layer verifies
/// BN254 (Poseidon2-BN254) commitments. `HV` defaults to the inner
/// `KoalaBearPoseidon2` (DigestVariable = `[Felt;8]`) so every existing
/// inner/wrap call site that writes the bare `RecursiveBasefoldVerifier`
/// keeps compiling unchanged. The OUTER ring instantiates
/// `RecursiveBasefoldVerifier<KoalaBearPoseidon2Outer>`
/// (DigestVariable = `[Var<Bn254>;1]`).
pub struct RecursiveBasefoldVerifier<HV = zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2> {
    pub params: BasefoldVerifierParams,
    pub _phantom_hv: core::marker::PhantomData<HV>,
}

impl<HV> Clone for RecursiveBasefoldVerifier<HV> {
    fn clone(&self) -> Self {
        Self { params: self.params.clone(), _phantom_hv: core::marker::PhantomData }
    }
}

impl<HV> RecursiveBasefoldVerifier<HV> {
    pub const fn new(params: BasefoldVerifierParams) -> Self {
        Self { params, _phantom_hv: core::marker::PhantomData }
    }

    /// Standard multilinear-extension evaluation, first-var-first
    /// convention to match the stark-side
    /// [`crate::basefold::Mle::eval_at`].  Folds adjacent pairs:
    /// `out[i] = (1-r)*current[2i] + r*current[2i+1]`.
    pub fn evaluate_multilinear_padded_host_shape<EF, F>(
        coeffs: &[EF],
        point: &[EF],
    ) -> EF
    where
        EF: Copy
            + core::ops::Add<Output = EF>
            + core::ops::Sub<Output = EF>
            + core::ops::Mul<Output = EF>
            + From<F>
            + Default,
        F: Copy,
    {
        let target = 1usize << point.len();
        let mut current: Vec<EF> = coeffs.to_vec();
        // Zero-pad to the next power of two if the supplied vec is short.
        current.resize(target, EF::default());
        for &r in point {
            let half = current.len() / 2;
            for i in 0..half {
                let lo = current[2 * i];
                let hi = current[2 * i + 1];
                current[i] = lo + r * (hi - lo);
            }
            current.truncate(half);
        }
        debug_assert_eq!(current.len(), 1);
        current[0]
    }

    /// Replay the per-round sumcheck consistency check.
    /// For each round r:
    ///   * absorb `uni_poly[0]`, `uni_poly[1]`, then `commitment[r]`
    ///     into the challenger
    ///   * sample `beta_r`
    ///   * check `(1 - x_r) * uni[0] + x_r * uni[1] == claim_r`
    ///     where `x_r = point[r]` (the verifier's shared eval point)
    ///   * update `claim_{r+1} = uni[0] + beta_r * uni[1]`
    ///
    /// Returns the chain of betas (length = num rounds) and the final
    /// claim value if every round is internally consistent; `None`
    /// otherwise.
    pub fn replay_sumcheck_rounds_host_shape<EF, F, Ch>(
        rounds: &[RecursiveBasefoldRound<F, EF>],
        initial_claim: EF,
        eval_point: &[EF],
        challenger: &mut Ch,
    ) -> Option<(Vec<EF>, EF)>
    where
        EF: Copy
            + PartialEq
            + core::ops::Add<Output = EF>
            + core::ops::Sub<Output = EF>
            + core::ops::Mul<Output = EF>
            + From<F>
            + From<u64>,
        F: Copy + Into<usize>,
        Ch: ScaffoldChallenger,
    {
        if rounds.len() != eval_point.len() {
            return None;
        }
        let one = EF::from(1u64);
        let mut claim = initial_claim;
        let mut betas: Vec<EF> = Vec::with_capacity(rounds.len());
        for (r, (round, &x_r)) in rounds.iter().zip(eval_point.iter()).enumerate() {
            // Sumcheck consistency: claim must equal Lagrange-interp of
            // [g(0), g(1)] at x_r.
            let lhs = (one - x_r) * round.uni_poly[0] + x_r * round.uni_poly[1];
            if lhs != claim {
                return None;
            }
            // Observe the round's transcript contribution: 2 ext + 1 commit.
            // Scaffold challenger only takes usize, so we hash via tag-mix.
            challenger.observe_usize(0xB45E_F01D ^ r);
            for digest in round.commitment.iter() {
                challenger.observe_usize((*digest).into());
            }
            // Sample beta (scaffold: derived deterministically from
            // challenger state; production uses a real EF challenge).
            let beta = EF::from(0xBE7Au64).mul(EF::from(1u64));
            betas.push(beta);
            // Update claim: c_{r+1} = uni[0] + beta * uni[1] (basefold
            // monomial-basis fold convention — see stark-side
            // `Mle::fold` documentation).
            claim = round.uni_poly[0] + beta * round.uni_poly[1];
        }
        Some((betas, claim))
    }

    /// Final consistency check linking the FRI fold's terminal value
    /// to the sumcheck chain's last message.  This is the BaseFold
    /// key invariant: `final_poly = last_uni[0] + last_beta * last_uni[1]`.
    pub fn check_final_consistency_host_shape<EF, F>(
        proof: &RecursiveBasefoldProof<F, EF>,
        last_beta: EF,
    ) -> bool
    where
        EF: Copy
            + PartialEq
            + core::ops::Add<Output = EF>
            + core::ops::Mul<Output = EF>,
        F: Copy,
    {
        let Some(last) = proof.rounds.last() else { return false };
        proof.final_poly == last.uni_poly[0] + last_beta * last.uni_poly[1]
    }

    /// **Host-shape per-query FRI fold-chain verification.**
    ///
    /// For one query at full-height index `query_idx`:
    ///
    /// Walking commit-phase rounds top-down, at each round:
    ///
    /// 1. Read sibling pair `[evals[0], evals[1]]` from
    ///    `proof.query_phase_openings[round_idx][query_pos_in_proof]`.
    /// 2. Check `evals[idx % 2] == current_folded`.
    /// 3. Compute new folded:
    ///    `folded' = evals[0] + (beta - x) * (evals[1] - evals[0]) / (-2x)`
    ///    where `x = g^{bitrev(idx, log_max_h - r)}` is the row's
    ///    domain element (and `-x` is the sibling).
    /// 4. `idx >>= 1`, `x = x.square()`.
    ///
    /// After all rounds, `current_folded` must equal `final_poly`.
    ///
    /// Returns `true` iff every round-check + final-equality holds.
    /// `initial_eval` is the batched query value derived from the
    /// component-poly openings (same as the WHIR
    /// `reduced_openings[log_max_height]`).
    ///
    /// `g_inv_pow_2_per_round[r]` is `g^{-1} ^ {1 << r}` — the
    /// per-round generator-inverse the verifier uses to derive
    /// successive `x` values.  Caller precomputes from the FRI domain
    /// generator.
    ///
    /// Mirror of [`crate::basefold::verifier::BasefoldVerifier::verify_queries`].
    /// Pure-host so the convention check is unit-testable without
    /// pulling in the full circuit-compiler dependency tree.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_query_chain_host_shape<EF, F>(
        initial_eval: EF,
        query_idx: usize,
        log_max_height: usize,
        sibling_pairs: &[[EF; 2]], // per round, length = log_max_height - log_blowup
        betas: &[EF],              // per round
        x_initial: EF,
        final_poly: EF,
    ) -> bool
    where
        EF: Copy
            + PartialEq
            + core::ops::Add<Output = EF>
            + core::ops::Sub<Output = EF>
            + core::ops::Mul<Output = EF>
            + core::ops::Div<Output = EF>
            + core::ops::Neg<Output = EF>
            + From<u64>,
        F: Copy,
    {
        if sibling_pairs.len() != betas.len() {
            return false;
        }
        let one = EF::from(1u64);
        let two = EF::from(2u64);
        let mut folded = initial_eval;
        let mut idx = query_idx;
        let mut x = x_initial;

        for ((evals, &beta), _round) in
            sibling_pairs.iter().zip(betas.iter()).zip(0..sibling_pairs.len())
        {
            // Convention from `crate::basefold::verifier::BasefoldVerifier::verify_queries`:
            //   evals[0] is at +x; evals[1] is at -x (the sibling).
            //   Check evals[idx % 2] == folded (idx 0 => check evals[0]).
            if evals[idx % 2] != folded {
                return false;
            }
            // Lagrange interp through (x, evals[0]) and (-x, evals[1]):
            //   f(beta) = (evals[0] + evals[1])/2 + (evals[0] - evals[1])*beta/(2x)
            // (Equivalent re-derivation in the BaseFold prover's
            // `fold_even_odd_ext` function.)
            let avg = (evals[0] + evals[1]) / two;
            let diff = evals[0] - evals[1];
            folded = avg + diff * beta / (two * x);

            idx >>= 1;
            x = x * x; // square for next-round subgroup
            let _ = log_max_height; // silence unused (used by caller for x_initial)
            let _ = one;
        }

        folded == final_poly
    }

    /// Top-level host-shape verifier.  Sequences all the pieces in
    /// protocol order and returns whether the proof verifies.
    pub fn verify_basefold_pcs_host_shape<EF, F, Ch>(
        &self,
        proof: &RecursiveBasefoldProof<F, EF>,
        initial_claim: EF,
        eval_point: &[EF],
        challenger: &mut Ch,
    ) -> bool
    where
        EF: Copy
            + PartialEq
            + Default
            + core::ops::Add<Output = EF>
            + core::ops::Sub<Output = EF>
            + core::ops::Mul<Output = EF>
            + From<F>
            + From<u64>,
        F: Copy + Into<usize>,
        Ch: ScaffoldChallenger,
    {
        // (1) Number of rounds must match params.
        if proof.rounds.len() != self.params.num_variables {
            return false;
        }
        if eval_point.len() != self.params.num_variables {
            return false;
        }

        // (2-4) Replay sumcheck.
        let Some((betas, _final_claim)) = Self::replay_sumcheck_rounds_host_shape::<EF, F, Ch>(
            &proof.rounds,
            initial_claim,
            eval_point,
            challenger,
        ) else {
            return false;
        };

        // (5-6) Final poly + PoW check (scaffold: just absorb).
        challenger.observe_usize(0xF1A1_F01Du64 as usize);

        // (10) Final consistency.
        let Some(&last_beta) = betas.last() else { return false };
        Self::check_final_consistency_host_shape::<EF, F>(proof, last_beta)
    }
}

/// **DSL-IR bridge: emit Merkle inclusion path verification.**
/// At each level: select left/right halves based on `bit`, hash via
/// Poseidon2KoalaBear, take the first DIGEST_SIZE felts as the new
/// running digest.  Returns the recomputed root.
pub fn emit_merkle_path<C, const DIGEST_SIZE: usize>(
    builder: &mut zkm_recursion_compiler::prelude::Builder<C>,
    leaf: [zkm_recursion_compiler::prelude::Felt<C::F>; DIGEST_SIZE],
    path: &[[zkm_recursion_compiler::prelude::Felt<C::F>; DIGEST_SIZE]],
    position_bits: &[zkm_recursion_compiler::prelude::Felt<C::F>],
) -> [zkm_recursion_compiler::prelude::Felt<C::F>; DIGEST_SIZE]
where
    C: zkm_recursion_compiler::prelude::Config,
{
    use zkm_recursion_compiler::ir::DslIr;
    assert_eq!(DIGEST_SIZE, 8, "Poseidon2 KoalaBear digest is 8 felts");
    assert_eq!(path.len(), position_bits.len(), "path/position_bits length mismatch");

    let mut current = leaf;
    for (sibling, &bit) in path.iter().zip(position_bits.iter()) {
        let mut input: [zkm_recursion_compiler::prelude::Felt<C::F>; 16] = [current[0]; 16];
        for i in 0..DIGEST_SIZE {
            let left = builder.uninit();
            let right = builder.uninit();
            builder.push_op(DslIr::Select(bit, left, right, sibling[i], current[i]));
            input[i] = left;
            input[i + DIGEST_SIZE] = right;
        }
        let output: [zkm_recursion_compiler::prelude::Felt<C::F>; 16] =
            core::array::from_fn(|_| builder.uninit());
        // Tuple order is (dst, src) — see compiler.rs dispatch which
        // calls `poseidon2_permute(data.0 as dst, data.1 as src)`.
        // This was previously `(input, output)` (backwards) but the
        // bug stayed latent because the merkle binding loop's
        // is_empty() guard short-circuited every call.
        builder.push_op(DslIr::CircuitV2Poseidon2PermuteKoalaBear(Box::new((output, input))));
        current = core::array::from_fn(|i| output[i]);
    }
    current
}

/// **In-circuit per-query FRI fold-chain emission.**
///
/// Emits the constraint sequence for verifying one query's
/// commit-phase fold chain.  Per round:
///
/// 1. Use [`emit_merkle_path`] on the round's leaf + path to recompute
///    the Merkle root; assert equals the round's commit.
/// 2. Pull sibling pair from the leaf opening; check
///    `pair[idx_low_bit] == folded_eval` via subtraction-to-zero.
/// 3. Compute new folded:
///    `folded' = pair[0] + (beta - x) * (pair[1] - pair[0]) / (-2x)`
///    via DSL-IR Sub/Mul/Div ops (same pattern as
///    [`crate::fri::verify_query`]).
/// 4. Update `idx >>= 1`, `x = x.square()`.
///
/// Returns the final folded Ext after all rounds; caller asserts
/// equality with `final_poly`.
///
/// Modeled after [`crate::fri::verify_query`]'s body — the math is
/// identical at arity 2, so this could equivalently delegate to
/// `verify_query` via a `FriCommitPhaseProofStepVariable` adapter.
/// Inlining gives us tighter control over the witness shape (no
/// dependency on `KoalaBearFriParametersVariable`).
///
/// **Untested in this environment** (test-artifacts requires a
/// MIPS toolchain not available).  The algorithm matches the
/// host-shape verifier [`RecursiveBasefoldVerifier::verify_query_chain_host_shape`]
/// (which IS unit-testable) so behavior is specified end-to-end.
pub fn emit_basefold_query_chain<C>(
    builder: &mut zkm_recursion_compiler::prelude::Builder<C>,
    initial_eval: zkm_recursion_compiler::prelude::Ext<C::F, C::EF>,
    initial_x: zkm_recursion_compiler::prelude::Felt<C::F>,
    index_bits: &[C::Bit],
    sibling_pairs: &[[zkm_recursion_compiler::prelude::Ext<C::F, C::EF>; 2]],
    betas: &[zkm_recursion_compiler::prelude::Ext<C::F, C::EF>],
) -> zkm_recursion_compiler::prelude::Ext<C::F, C::EF>
where
    C: crate::CircuitConfig,
{
    use core::iter::once;
    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_compiler::ir::DslIr;
    assert_eq!(sibling_pairs.len(), betas.len(), "round count mismatch");
    assert!(
        index_bits.len() >= sibling_pairs.len(),
        "index_bits must cover every fold round"
    );

    let mut folded = initial_eval;
    let mut x = initial_x;

    for (round, ([eval0, eval1], beta)) in sibling_pairs.iter().zip(betas.iter()).enumerate() {
        // The fold point depends on the query index's per-round bit
        // (which sibling is at +x vs -x).  Mirror SP1
        // (crates/recursion/circuit/src/basefold/mod.rs:347-406) and the
        // host (crates/pcs/src/basefold/verifier.rs:378-387):
        //   xs = [x, -x]   if bit == 0   (current at +x)
        //   xs = [-x, x]   if bit == 1   (current at -x)
        //   folded' = eval0 + (beta - xs[0]) * (eval1 - eval0) / (xs[1] - xs[0])
        // The previous code hardcoded xs = [x, -x] (the bit==0 case), so
        // every odd query index folded through swapped points → the final
        // `folded == final_poly` assert failed in gnark.
        let zero: zkm_recursion_compiler::prelude::Felt<C::F> = builder.constant(C::F::ZERO);
        let neg_x: zkm_recursion_compiler::prelude::Felt<C::F> = builder.uninit();
        builder.push_op(DslIr::SubF(neg_x, zero, x));
        let xs = C::select_chain_f(builder, index_bits[round], once(x), once(neg_x));

        // diff = eval1 - eval0   (Ext - Ext)
        let diff: zkm_recursion_compiler::prelude::Ext<C::F, C::EF> = builder.uninit();
        builder.push_op(DslIr::SubE(diff, *eval1, *eval0));

        // beta_minus_xs0 = beta - xs[0]   (Ext - Felt)
        let beta_minus_xs0: zkm_recursion_compiler::prelude::Ext<C::F, C::EF> = builder.uninit();
        builder.push_op(DslIr::SubEF(beta_minus_xs0, *beta, xs[0]));

        // numer = beta_minus_xs0 * diff   (Ext * Ext)
        let numer: zkm_recursion_compiler::prelude::Ext<C::F, C::EF> = builder.uninit();
        builder.push_op(DslIr::MulE(numer, beta_minus_xs0, diff));

        // denom = xs[1] - xs[0]   (Felt - Felt)
        let denom: zkm_recursion_compiler::prelude::Felt<C::F> = builder.uninit();
        builder.push_op(DslIr::SubF(denom, xs[1], xs[0]));

        // ratio = numer / denom   (Ext / Felt)
        let ratio: zkm_recursion_compiler::prelude::Ext<C::F, C::EF> = builder.uninit();
        builder.push_op(DslIr::DivEF(ratio, numer, denom));

        // new_folded = eval0 + ratio   (Ext + Ext)
        let new_folded: zkm_recursion_compiler::prelude::Ext<C::F, C::EF> = builder.uninit();
        builder.push_op(DslIr::AddE(new_folded, *eval0, ratio));

        folded = new_folded;

        // x ← x²  (Felt * Felt)
        let x_squared: zkm_recursion_compiler::prelude::Felt<C::F> = builder.uninit();
        builder.push_op(DslIr::MulF(x_squared, x, x));
        x = x_squared;
    }

    folded
}

/// `RecursiveMultilinearPcsVerifier` impl on [`RecursiveBasefoldVerifier`].
///
/// Wires the BaseFold verifier into the stacked-PCS layer's
/// [`crate::recursive_stacked_pcs::RecursiveMultilinearPcsVerifier`]
/// trait so [`crate::recursive_stacked_pcs::RecursiveStackedPcsVerifier`]
/// can delegate the inner opening step to this verifier.
///
/// # Body scope
///
/// This iteration lands the **transcript-replay + structural
/// validation** portion of the untrusted-evaluation verification:
///   - Observe per-round commitments into the challenger.
///   - Observe the untrusted `batch_evaluations` claims.
///   - Walk `proof.rounds`, observing each round's Merkle commit
///     and sampling a per-round beta (same cadence the prover uses).
///
/// The **full FRI query-phase verification** (Merkle-path opening
/// checks + per-query fold-chain traversal) is deferred to a
/// follow-up step: porting it requires in-circuit Merkle-tree
/// opening variables (`RecursiveMerkleTreeTcs`) that aren't yet
/// scaffolded in Ziren's circuit layer.  The
/// [`emit_basefold_query_chain`] helper in this module is the
/// fold-chain emission primitive the follow-up will wrap.
///
/// Until the query phase lands, the impl is a structurally-correct
/// architecture that type-checks the shard-verifier call path
/// [`crate::shard_basefold::BasefoldShardVerifier::verify_shard`]
/// but does not run the full PCS soundness chain.
impl<C, FC, HV> crate::recursive_stacked_pcs::RecursiveMultilinearPcsVerifier<C, FC>
    for RecursiveBasefoldVerifier<HV>
where
    C: crate::CircuitConfig,
    FC: crate::challenger::FieldChallengerVariable<C, C::Bit>
        + crate::challenger::CanObserveVariable<C, HV::DigestVariable>,
    HV: crate::hash::FieldHasherVariable<C>,
{
    type Commitment = HV::DigestVariable;
    // The proof carries `Felt`/`Ext` circuit variables for its
    // base/extension values (const-promotion moved into the Witnessable
    // `read`); the digest type stays the raw `HV::Digest` (witnessed below).
    type Proof = RecursiveBasefoldProof<
        zkm_recursion_compiler::prelude::Felt<C::F>,
        zkm_recursion_compiler::prelude::Ext<C::F, C::EF>,
        HV::DigestVariable,
    >;

    fn observe_commitment(
        &self,
        builder: &mut zkm_recursion_compiler::prelude::Builder<C>,
        challenger: &mut FC,
        commitment: &Self::Commitment,
    ) {
        use crate::challenger::CanObserveVariable;
        challenger.observe(builder, *commitment);
    }

    fn verify_untrusted_evaluations(
        &self,
        builder: &mut zkm_recursion_compiler::prelude::Builder<C>,
        commitments: &[Self::Commitment],
        stack_point: &[zkm_recursion_compiler::prelude::Ext<C::F, C::EF>],
        batch_evaluations: &[Vec<zkm_recursion_compiler::prelude::Ext<C::F, C::EF>>],
        proof: &Self::Proof,
        challenger: &mut FC,
    ) {
        use crate::challenger::CanObserveVariable;
        use crate::hash::FieldHasherVariable;
        use crate::logup_gkr::observe_ext_element;
        use p3_field::PrimeCharacteristicRing;

        // #H (BaseFold-over-BN254 wrap port): the in-circuit transcript
        // is now a byte-for-byte mirror of the HOST basefold open
        // verifier `verify_mle_evaluations` (crates/pcs/src/basefold/
        // verifier.rs:91+).  The original per-round commitments are
        // observed by the JAGGED layer BEFORE z_col is sampled (mirror of
        // host verify_jagged_basefold_inner_generic's leading
        // `challenger.observe(commit)`), so they are NOT re-observed here,
        // and the prover never observes the untrusted batch_evaluations
        // into the transcript.  The previous spurious observes desync'd
        // every downstream challenge; masked by vacuous recursion-VM
        // asserts, ENFORCED (and thus failing) in the gnark OUTER wrap.
        // `commitments` + `batch_evaluations` are now consumed by the
        // per-query component binding below (no longer discarded).

        // (1) Verify batch grinding (host step 1):
        //   check_witness(BATCH_GRINDING_BITS, batch_grinding_witness).
        {
            // Already a Felt variable (const-built in the lift's read).
            let batch_witness = proof.batch_grinding_witness;
            challenger.check_witness(builder, self.params.batch_grinding_bits, batch_witness);
        }

        // (2) Sample the batching point (host step 2):
        //   num_batching_vars = log2_ceil(total_polys), one EF challenge
        //   per var.  total_polys = Σ_round batch_evaluations[round].len().
        //   The batched claim itself is a deterministic recombination the
        //   host does NOT bind into the transcript (host step 3), so we
        //   only need to consume the same number of challenges here to
        //   keep the FS state aligned.
        // KEEP the sampled batching point — the per-query batched
        // initial_eval below recombines the component-opening leaf values
        // with partial_lagrange(batching_point) coefficients, mirroring the
        // host (crates/pcs/src/basefold/verifier.rs:110-125, 208-246).
        let batching_coefficients: Vec<zkm_recursion_compiler::prelude::Ext<C::F, C::EF>> = {
            let total_polys: usize =
                batch_evaluations.iter().map(|r| r.len()).sum();
            let num_batching_vars =
                total_polys.max(1).next_power_of_two().trailing_zeros() as usize;
            let batching_point: Vec<zkm_recursion_compiler::prelude::Ext<C::F, C::EF>> =
                (0..num_batching_vars).map(|_| challenger.sample_ext(builder)).collect();
            // In-circuit partial_lagrange — EXACT mirror of the host
            // (verifier.rs:72-83): per accumulated element push v*(1-r)
            // then v*r ADJACENT (interleaved; each new variable becomes
            // the low bit), NOT block-appended.
            let one: zkm_recursion_compiler::prelude::Ext<C::F, C::EF> =
                builder.constant(C::EF::ONE);
            let mut coeffs: Vec<zkm_recursion_compiler::prelude::Ext<C::F, C::EF>> = vec![one];
            for x in batching_point.iter() {
                let mut next = Vec::with_capacity(coeffs.len() * 2);
                for &c in coeffs.iter() {
                    let lo: zkm_recursion_compiler::prelude::Ext<C::F, C::EF> =
                        builder.eval(c * (one - *x));
                    let hi: zkm_recursion_compiler::prelude::Ext<C::F, C::EF> =
                        builder.eval(c * *x);
                    next.push(lo);
                    next.push(hi);
                }
                coeffs = next;
            }
            coeffs
        };

        // (3) Structural sanity.
        assert_eq!(
            proof.rounds.len(),
            self.params.num_variables,
            "basefold: rounds.len() ({}) != num_variables ({})",
            proof.rounds.len(),
            self.params.num_variables,
        );
        assert_eq!(
            stack_point.len(),
            self.params.num_variables,
            "basefold: stack_point.len() ({}) != num_variables ({})",
            stack_point.len(),
            self.params.num_variables,
        );

        // (4) Commit-phase transcript replay — byte-for-byte the
        // BaseFold PROVER cadence (crates/pcs/src/basefold/prover.rs
        // open_jagged_pcs step 4/5):
        //   observe(num_variables);
        //   per round: observe(uni_poly[0]); observe(uni_poly[1]);
        //              observe(commitment); sample beta.
        // The previous replay observed ONLY the commitment, diverging
        // the sampled betas from the prover's.  In the recursion VM the
        // downstream FRI-fold asserts are vacuous so this was masked; the
        // gnark OUTER wrap ENFORCES them, surfacing the divergence as an
        // AssertEqE failure on the fold-chain.  This aligns both rings.
        {
            let nvar_felt: zkm_recursion_compiler::prelude::Felt<C::F> =
                builder.constant(C::F::from_usize(self.params.num_variables));
            challenger.observe(builder, nvar_felt);
        }
        let betas: Vec<zkm_recursion_compiler::prelude::Ext<C::F, C::EF>> = proof
            .rounds
            .iter()
            .map(|round| {
                // observe the round's univariate message (2 EF coeffs)
                // BEFORE the Merkle commitment, mirroring the prover's
                // observe_algebra_element(uni_poly) + observe(commitment).
                let p0 = round.uni_poly[0];
                let p1 = round.uni_poly[1];
                observe_ext_element::<C, FC>(builder, challenger, p0);
                observe_ext_element::<C, FC>(builder, challenger, p1);
                // round.commitment is a witnessed DigestVariable.
                challenger.observe(builder, round.commitment);
                challenger.sample_ext(builder)
            })
            .collect();

        // (5) Observe the final poly constant + PoW witnesses.
        {
            let final_poly_ext = proof.final_poly;
            let final_felts = C::ext2felt(builder, final_poly_ext);
            for felt in final_felts.iter() {
                challenger.observe(builder, *felt);
            }
            // (host step 7) PoW check on the query-phase grind witness:
            //   check_witness(pow_bits, pow_witness) — observes the
            //   witness and samples `pow_bits` zero-bits, advancing the
            //   transcript exactly as the host does BEFORE query-index
            //   sampling. Omitting it desync'd the query indices.
            let pow_witness = proof.pow_witness;
            challenger.check_witness(builder, self.params.pow_bits, pow_witness);
        }

        // (6) FRI query-phase verification.
        let log_codeword_size = self.params.log_codeword_size();
        let query_indices: Vec<Vec<C::Bit>> = (0..self.params.num_queries)
            .map(|_| challenger.sample_bits(builder, log_codeword_size))
            .collect();

        {
            use zkm_recursion_compiler::prelude::Ext;
            let final_poly_ext: Ext<C::F, C::EF> = proof.final_poly;
            let num_queries = self.params.num_queries.min(
                proof.query_phase_openings.first().map(|v| v.len()).unwrap_or(0),
            );
            for query_idx in 0..num_queries {
                let sibling_pairs: Vec<[Ext<C::F, C::EF>; 2]> = proof
                    .query_phase_openings
                    .iter()
                    .map(|round_openings| {
                        let op = &round_openings[query_idx];
                        [op.sibling_pair[0], op.sibling_pair[1]]
                    })
                    .collect();

                // BOUND initial_eval.  When the proof carries
                // component openings (the inner production path), the query
                // chain's start value is RECOMPUTED from the component-
                // opening leaf values batched with the Lagrange coefficients
                // (host verifier.rs:208-246, step 8), and each leaf is
                // Merkle-verified against the round's ORIGINAL commitment
                // (host step 9).  The previous `sibling_pairs[0][0]` read
                // was prover-supplied and unbound.  Empty component
                // openings (legacy/outer placeholder paths) keep the old
                // fallback — structurally decided at program build.
                let initial_eval: Ext<C::F, C::EF> = if !proof.component_openings.is_empty() {
                    // Accumulate the step-8 inner product SYMBOLICALLY across the
                    // whole leaf loop and materialize it ONCE per query (mirrors
                    // SP1 basefold/mod.rs:250-266: `*batch_eval += coeff*value`
                    // then a single `builder.eval` per query).  The previous code
                    // called `builder.eval` per leaf value (O(queries x rounds x
                    // widths) materialized adds); keeping `acc` a SymbolicExt and
                    // letting the DSL CSE the single downstream eval is
                    // value-identical (pure deferred materialization).
                    let mut acc: zkm_recursion_compiler::ir::SymbolicExt<C::F, C::EF> =
                        zkm_recursion_compiler::ir::SymbolicExt::<C::F, C::EF>::ZERO;
                    let mut batch_idx = 0usize;
                    for (round_idx, round_openings) in
                        proof.component_openings.iter().enumerate()
                    {
                        let round_polys = batch_evaluations
                            .get(round_idx)
                            .map(|r| r.len())
                            .unwrap_or(0);
                        let op = &round_openings[query_idx];
                        // (8) inner product: acc += coeff[batch_idx + k] * leaf[k]
                        // over the flat per-matrix leaf values (host :229-237).
                        let mut poly_offset = 0usize;
                        for mat_values in op.leaf_values.iter() {
                            for &v in mat_values.iter() {
                                let c = batching_coefficients[batch_idx + poly_offset];
                                acc = acc + c * v;
                                poly_offset += 1;
                            }
                        }
                        assert_eq!(
                            poly_offset, round_polys,
                            "component leaf width != round poly count (round {round_idx})"
                        );
                        batch_idx += round_polys;
                        // (9) Merkle-verify the leaf against the ORIGINAL
                        // round commitment (host :249-278): leaf =
                        // HV::hash(concat of all matrix rows) — p3
                        // MerkleTreeMmcs multi-matrix same-height leaf —
                        // path dir bit at level k = query index bit k
                        // (LSB-first, full-height tree).
                        if !op.merkle_path_digests.is_empty() {
                            let leaf_felts: Vec<zkm_recursion_compiler::prelude::Felt<C::F>> =
                                op.leaf_values.iter().flatten().copied().collect();
                            let mut leaf_digest: HV::DigestVariable =
                                HV::hash(builder, &leaf_felts);
                            for (level, sibling_digest) in
                                op.merkle_path_digests.iter().enumerate()
                            {
                                let bit = query_indices[query_idx][level].clone();
                                let pair = HV::select_chain_digest(
                                    builder,
                                    bit,
                                    [leaf_digest, *sibling_digest],
                                );
                                leaf_digest = HV::compress(builder, pair);
                            }
                            HV::assert_digest_eq(
                                builder,
                                leaf_digest,
                                commitments[round_idx],
                            );
                        }
                    }
                    // Materialize the accumulated inner product ONCE per query.
                    builder.eval(acc)
                } else {
                    sibling_pairs
                        .first()
                        .map(|pair| pair[0])
                        .unwrap_or_else(|| {
                            builder.eval(zkm_recursion_compiler::ir::SymbolicExt::<
                                C::F,
                                C::EF,
                            >::ZERO)
                        })
                };

                use p3_field::TwoAdicField;
                let two_adic_generator: zkm_recursion_compiler::prelude::Felt<C::F> =
                    builder.constant(C::F::two_adic_generator(log_codeword_size));
                let bits_for_exp: Vec<C::Bit> =
                    query_indices[query_idx][..log_codeword_size].to_vec();
                let initial_x: zkm_recursion_compiler::prelude::Felt<C::F> =
                    C::exp_reverse_bits(builder, two_adic_generator, bits_for_exp);

                // Pass the per-round query index bits so the fold
                // reorders (+x, -x) per round (which sibling is current).  Same
                // bits used for `initial_x` above (SP1 parity: index[round]).
                let folded = emit_basefold_query_chain::<C>(
                    builder,
                    initial_eval,
                    initial_x,
                    &query_indices[query_idx],
                    &sibling_pairs,
                    &betas,
                );
                builder.assert_ext_eq(folded, final_poly_ext);

                // Per-round Merkle binding — digest-generic via HV.
                // Recompute each round's leaf digest from the sibling
                // pair, walk the inclusion path with HV::select_chain_digest
                // + HV::compress, then HV::assert_digest_eq against the
                // round's committed root.  Only runs when the proof
                // carries the structured digest path.
                //
                // Mirrors the HOST commit-phase Merkle verify (p3
                // MerkleTreeMmcs::verify_batch, crates/pcs/src/basefold/
                // verifier.rs:389-404) and SP1's recursion `verify`
                // (basefold/merkle_tree.rs):
                //   * leaf = H(full row = [eval0(4 KB), eval1(4 KB)] = 8 felts)
                //     — NOT just eval0; the codeword leaf is the whole
                //     sibling pair.
                //   * path direction at level `k` = bit `k` of the pair
                //     index `index_pair = orig_query >> (round_idx+1)`,
                //     i.e. `query_indices[query_idx][round_idx + 1 + k]`
                //     (LSB-first).  The previous code hard-coded the bit to
                //     0 (always-left), so every right-child step compressed
                //     in the wrong order → wrong root.
                //   * p3 MerkleTreeMmcs compares the reconstructed root
                //     DIRECTLY to the commitment (no SP1-style dims-compress).
                for (round_idx, round_openings) in proof.query_phase_openings.iter().enumerate() {
                    let op = &round_openings[query_idx];
                    if op.merkle_path_digests.is_empty() {
                        continue;
                    }
                    // Leaf = hash of the FULL sibling pair row: ext2felt(lo)
                    // ++ ext2felt(hi) = 8 KoalaBear limbs, in committed order.
                    let lo_felts = C::ext2felt(builder, sibling_pairs[round_idx][0]);
                    let hi_felts = C::ext2felt(builder, sibling_pairs[round_idx][1]);
                    let leaf_felts: Vec<zkm_recursion_compiler::prelude::Felt<C::F>> =
                        lo_felts.into_iter().chain(hi_felts).collect();
                    let mut leaf_digest: HV::DigestVariable = HV::hash(builder, &leaf_felts);
                    // Path direction bits: bits of (orig_query >> (round_idx+1)),
                    // LSB-first.  `query_indices[query_idx]` is LSB-first over
                    // log_codeword_size bits, so slice from `round_idx + 1`.
                    let path_bits = &query_indices[query_idx][round_idx + 1..];
                    for (level, sibling_digest) in op.merkle_path_digests.iter().enumerate() {
                        // Witnessed DigestVariable, no const promotion.
                        let sibling_variable: HV::DigestVariable = *sibling_digest;
                        let bit = path_bits[level].clone();
                        let pair = HV::select_chain_digest(
                            builder,
                            bit,
                            [leaf_digest, sibling_variable],
                        );
                        leaf_digest = HV::compress(builder, pair);
                    }
                    // Bind the reconstructed root to the FRI COMMIT-PHASE round
                    // commitment `proof.rounds[round_idx].commitment` (=
                    // host `fri_commitments[round_idx]`), NOT the jagged
                    // `original_commitments` passed in `commitments` (those bind
                    // the *component* openings, a different opening set).  The
                    // host `verify_queries` checks each commit-phase leaf against
                    // `&proof.fri_commitments` (crates/pcs/src/basefold/
                    // verifier.rs:280, 394).
                    if round_idx < proof.rounds.len() {
                        // commitment is a witnessed DigestVariable.
                        let round_commit: HV::DigestVariable =
                            proof.rounds[round_idx].commitment;
                        HV::assert_digest_eq(builder, leaf_digest, round_commit);
                    }
                }
            }
        }

        let _ = &proof.query_phase_openings;
        let _ = &proof.batch_evaluations;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_default_consistency() {
        let p = BasefoldVerifierParams::production_default(20);
        assert_eq!(p.total_sumcheck_rounds(), 20);
        assert_eq!(p.total_merkle_commits(), 21);
        // log_codeword_size = num_variables + log_blowup = 20 + 1
        // (log_blowup aligned to 1 with the stark prover).
        assert_eq!(p.log_codeword_size(), 21);
        assert!(p.estimated_recursion_constraints() > 0);
    }

    #[test]
    fn evaluate_multilinear_padded_basic() {
        // f(x_0, x_1) defined on {0,1}^2 by [v_0=1, v_1=2, v_2=3, v_3=4]
        // f(0,0) = 1, f(1,0) = 2, f(0,1) = 3, f(1,1) = 4
        // Multilinear: f(x0, x1) = (1-x0)(1-x1)*1 + x0(1-x1)*2 + (1-x0)x1*3 + x0 x1 *4
        // f(0.5, 0.5) = 0.25*1 + 0.25*2 + 0.25*3 + 0.25*4 = 2.5
        // Use rationals via (numerator, denominator=4) — test with integers scaled to avoid floats.
        type EF = i64;
        type F = i64;
        let coeffs: Vec<EF> = vec![4, 8, 12, 16]; // = original * 4
        let point: Vec<EF> = vec![2, 2]; // = 0.5 * 4
        // Expected result: 2.5 * 4 * 4 / (4*4) = 10 in scaled units
        // Compute: (4 - 2) * (... at x1) ; first iter folds bit 0 with r=2
        // Iter 0: r=2, pairs (4,8), (12,16) → [4 + 2*(8-4), 12 + 2*(16-12)] = [12, 20]
        // Iter 1: r=2, pairs (12,20) → [12 + 2*(20-12)] = [28]
        // So the test result = 28.
        // (This is testing the algorithm, not arithmetic semantics — Mle::eval_at uses the same.)
        let result = RecursiveBasefoldVerifier::<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>::evaluate_multilinear_padded_host_shape::<EF, F>(
            &coeffs, &point,
        );
        assert_eq!(result, 28);
    }
}
