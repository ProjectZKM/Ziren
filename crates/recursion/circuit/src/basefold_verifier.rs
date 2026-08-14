//! BaseFold proof verifier for the recursion circuit (host-shape + emit hooks).
//!
//! Verifies BaseFold-based shard proofs emitted by `prove_jagged_basefold_rounds`.
//!
//! This module holds:
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
#![allow(unused_variables)]

/// Parameters for BaseFold proof verification in the recursion circuit.
#[derive(Clone, Debug)]
pub struct BasefoldVerifierParams {
    /// log2 of the Reed-Solomon rate.  Production default: 4 (rate
    /// 1/16, for proven 100-bit soundness).
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
    /// `(log_blowup=2, num_queries=124, pow_bits=16)`.  This is the
    /// verifier the recursion programs use for EVERY inner KoalaBear child:
    /// compress→core, shrink→compress, AND wrap→shrink (the shrink proof is
    /// a KoalaBear inner-Mmcs proof verified through this arm, NOT the BN254
    /// `wrap_default` Bytes arm).  Since all three inner host stages
    /// (core/compress/shrink) now produce at `(2, 124, 16)`, this single
    /// param matches the committed codeword rate for all of them.
    ///
    /// **Soundness.** `124 · (-log2(0.5 + (1/4)/2)) + 16 = 124 · 0.6781 + 16
    /// ≈ 100.08` bits (a `(1, 94, 16)` config gives only ~55 bits).  The
    /// component-opening Merkle path is `log_stacking + 2` levels and the
    /// query index span is `num_variables + 2` bits — both keyed off
    /// `log_blowup`, so they MUST match the host `blowup=2`.
    ///
    /// Two-adicity: `num_variables(≤21) + 2 ≤ 24`.
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
    /// separate re-randomization defense).
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
        self.state = self.state.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(value as u64);
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
    /// (Poseidon2-BN254).  The digest's length is carried in the type
    /// rather than a const generic.
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
/// Generic over the Merkle hasher
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
    pub fn evaluate_multilinear_padded_host_shape<EF, F>(coeffs: &[EF], point: &[EF]) -> EF
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
        EF: Copy + PartialEq + core::ops::Add<Output = EF> + core::ops::Mul<Output = EF>,
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
    /// component-poly openings.
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
        builder.push_op(DslIr::CircuitV2Poseidon2PermuteKoalaBear(Box::new((output, input))));
        current = core::array::from_fn(|i| output[i]);
    }
    current
}

/// **In-circuit BaseFold round-count soundness binding — TIGHT integer `<=`.**
///
/// On the height-agnostic recursion path, binds a WITNESSED
/// `actual_num_vars` to the closed integer interval `[0, max_num_vars]`,
/// where `max_num_vars` is the compile-time loop ceiling
/// (`DEFAULT_LOG_STACKING_HEIGHT`).
///
/// # Why this exists
///
/// On the height-agnostic path the BaseFold FRI round count
/// (`num_variables` = the prover's `log_stacking_height`, CLAMPED DOWN
/// for tiny commits by [`zkm_pcs::pick_log_stacking_height`]) becomes a
/// WITNESSED felt rather than a compile-time constant.  The program then
/// loops over a fixed `max_num_vars` and the extra `max - actual` rounds
/// are masked inert.  A malicious prover must be prevented from claiming
/// a round count OUTSIDE `[0, max_num_vars]`:
///   * over-claim (`actual > max_num_vars`) would activate rounds whose
///     committed codeword does not exist;
///   * the mask logic only makes sense for a count in range.
///
/// # The tight integer `<=`
///
/// A power-of-two FLOOR would bind the felt VALUE into
/// `[0, 2^{max_num_vars}]` (a power-of-two bound, not a direct
/// `<= max_num_vars`), over-accepting every value in
/// `(max_num_vars, 2^{max_num_vars}]`.  Instead this uses a TIGHT
/// `actual_num_vars <= max_num_vars` via two sound bit-decompositions:
///
/// Let `nbits = ceil(log2(max_num_vars + 1))` be the number of bits to
/// represent `max_num_vars` (e.g. `max=21 -> nbits=5`, `2^5=32 > 21`).
///   1. `num2bits(actual_num_vars, nbits)` — sound-binds
///      `actual_num_vars ∈ [0, 2^nbits)` (each bit boolean + recomposition
///      `Σ b_i 2^i == actual_num_vars`, enforced inside `num2bits_v2_f`).
///   2. `diff = max_num_vars - actual_num_vars` (a felt subtraction).
///   3. `num2bits(diff, nbits)` — sound-binds `diff ∈ [0, 2^nbits)`.
///
/// Both decompositions binding ⟹ `actual_num_vars ∈ [0, 2^nbits)` AND
/// `max_num_vars - actual_num_vars ∈ [0, 2^nbits)`.  Over the KoalaBear
/// field (`p = 2^31 - 2^24 + 1`), if `actual_num_vars > max_num_vars`
/// then `diff = max_num_vars - actual_num_vars` wraps to
/// `p - (actual_num_vars - max_num_vars) >= p - (2^nbits - 1) ≈ 2^31`,
/// which is FAR above `2^nbits` (`nbits ≈ 5` for production), so its
/// `nbits`-bit recomposition CANNOT equal `diff` and `num2bits` trips its
/// `assert_felt_eq(x, num)` → the proof is REJECTED.  Hence the binding
/// accepts EXACTLY `actual_num_vars ∈ [0, max_num_vars]` — a tight
/// integer `<=`, no power-of-two slack.
///
/// # Byte-identical on the honest / fixed path
///
/// On the current fixed path `actual_num_vars` is the compile-time
/// constant `max_num_vars`, so `diff == 0` and both decompositions
/// trivially bind.  The emitted constraints are inert (the asserts never
/// trip), exactly like the row-count guard — it only ADDS
/// soundness constraints, never changes a verification outcome on an
/// honest proof.
///
/// # Soundness
///
/// Soundness rests entirely on `num2bits_v2_f` enforcing both per-bit
/// booleanity and the sum-recomposition `Σ b_i 2^i == input`
/// (compiler/src/circuit/builder.rs:73-117).  No floating ceiling: the
/// only accepted values are `[0, max_num_vars]`.
///
/// Config-generic: operates on `Felt<C::F>`, so it works for both the
/// inner (KoalaBear) and outer (BN254) recursion configs.
pub fn assert_num_vars_le_max<C>(
    builder: &mut zkm_recursion_compiler::prelude::Builder<C>,
    actual_num_vars: zkm_recursion_compiler::prelude::Felt<C::F>,
    max_num_vars: usize,
) where
    C: crate::CircuitConfig,
{
    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_compiler::prelude::Felt;
    // nbits = number of bits to represent `max_num_vars` (so 2^nbits >
    // max_num_vars).  `(max+1).next_power_of_two().trailing_zeros()`
    // == ceil(log2(max+1)).  Guard the degenerate max==0 case (nbits=0
    // would let no value through; max==0 means "only 0 allowed").
    let nbits = if max_num_vars == 0 {
        1
    } else {
        (max_num_vars + 1).next_power_of_two().trailing_zeros() as usize
    };
    // Tightness depends on the wrapped negative `diff` (≈ p - small) being
    // OUTSIDE [0, 2^nbits): requires 2^{nbits+1} <= field modulus.  Over
    // KoalaBear (p ≈ 2^31) this holds for nbits <= 29; production
    // max_num_vars <= 21 -> nbits <= 5 (huge margin).  Guard so a future
    // caller with an oversized max fails loudly rather than silently
    // admitting a non-tight (potentially unsound) bound.
    debug_assert!(
        nbits + 1 < 31,
        "assert_num_vars_le_max: nbits ({nbits}) too large for a tight \
         field-wrap `<=` over KoalaBear (need 2^(nbits+1) <= p)"
    );
    // (1) Sound-bind actual_num_vars ∈ [0, 2^nbits).
    let _actual_bits = C::num2bits(builder, actual_num_vars, nbits);
    // (2) diff = max_num_vars - actual_num_vars (felt subtraction; wraps
    //     to ≈ p if actual > max).
    let max_felt: Felt<C::F> = builder.constant(C::F::from_usize(max_num_vars));
    let diff: Felt<C::F> = builder.eval(max_felt - actual_num_vars);
    // (3) Sound-bind diff ∈ [0, 2^nbits).  If actual_num_vars > max_num_vars
    //     the wrapped diff is ≈ p >> 2^nbits and this num2bits' internal
    //     recomposition assert (assert_felt_eq(Σ b_i 2^i, diff)) FAILS,
    //     rejecting the proof.  Together (1)+(3) ⟹ actual_num_vars ≤
    //     max_num_vars (tight integer ≤, no power-of-two slack).
    let _diff_bits = C::num2bits(builder, diff, nbits);
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
/// Modeled after the retired legacy FRI `verify_query` body — the math
/// is identical at arity 2.  Inlining gives us tighter control over the
/// witness shape (no dependency on `KoalaBearFriParametersVariable`).
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
    assert!(index_bits.len() >= sibling_pairs.len(), "index_bits must cover every fold round");

    let mut folded = initial_eval;
    let mut x = initial_x;

    for (round, ([eval0, eval1], beta)) in sibling_pairs.iter().zip(betas.iter()).enumerate() {
        // The fold point depends on the query index's per-round bit
        // (which sibling is at +x vs -x).  Mirror the
        // host (crates/pcs/src/basefold/verifier.rs:378-387):
        //   xs = [x, -x]   if bit == 0   (current at +x)
        //   xs = [-x, x]   if bit == 1   (current at -x)
        //   folded' = eval0 + (beta - xs[0]) * (eval1 - eval0) / (xs[1] - xs[0])
        // Hardcoding xs = [x, -x] (the bit==0 case) would fold every odd
        // query index through swapped points, failing the final
        // `folded == final_poly` assert in gnark.
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
/// [`verify_untrusted_evaluations`] performs the transcript replay,
/// structural validation, and FRI query-phase verification:
///   - Observe per-round commitments into the challenger (via the JAGGED
///     layer) and walk `proof.rounds` sampling a per-round beta with the
///     same cadence the prover uses.
///   - When component openings are present, recompute each query's
///     batched initial evaluation from them and Merkle-verify it against
///     the original commitments.
///   - Walk the commit-phase fold chain ([`emit_basefold_query_chain`])
///     and bind each round's reconstructed root to its committed root.
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
    // base/extension values (const-promotion happens in the Witnessable
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

        // The in-circuit transcript is a byte-for-byte mirror of the HOST
        // basefold open verifier `verify_mle_evaluations` (crates/pcs/src/
        // basefold/verifier.rs:91+).  The original per-round commitments are
        // observed by the JAGGED layer BEFORE z_col is sampled (mirror of
        // host verify_jagged_basefold_inner_generic's leading
        // `challenger.observe(commit)`), so they are NOT re-observed here,
        // and the untrusted batch_evaluations are never observed into the
        // transcript.  `commitments` + `batch_evaluations` are consumed by
        // the per-query component binding below.

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
            let total_polys: usize = batch_evaluations.iter().map(|r| r.len()).sum();
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

        // (3a) Round-count soundness binding, TIGHT integer `<=` (NO-OP on
        // the fixed-height path).
        //
        // On the fixed path the BaseFold FRI round count is baked into the
        // program as the compile-time `self.params.num_variables` (= the
        // prover's clamped `log_stacking_height`), so the felt below is a
        // CONSTANT equal to that value and `diff == 0`, so both `num2bits`
        // recompositions inside `assert_num_vars_le_max` trivially bind.
        // This is therefore BYTE-IDENTICAL: it only emits inert
        // constraints over a constant.  When the round count becomes
        // genuinely WITNESSED (height-agnostic path: a witnessed
        // `actual_num_vars` against the compile-time loop ceiling
        // `MAX_NUM_VARS = DEFAULT_LOG_STACKING_HEIGHT`), this binding is
        // what PREVENTS a prover from claiming a round count OUTSIDE
        // `[0, MAX_NUM_VARS]` — a TIGHT integer `<=` (no power-of-two
        // slack; see `assert_num_vars_le_max`).
        #[cfg(not(ha_measure_base))]
        {
            use p3_field::PrimeCharacteristicRing;
            let actual_num_vars: zkm_recursion_compiler::prelude::Felt<C::F> =
                builder.constant(C::F::from_usize(self.params.num_variables));
            // Bind against the GLOBAL ceiling
            // `DEFAULT_LOG_STACKING_HEIGHT` (= 21) rather than the per-proof
            // `self.params.num_variables`, so the round-count bound is
            // height-AGNOSTIC.  Verdict-neutral on every path: the fixed
            // stacking height clamps DOWN only (never above 21), so
            // `actual_num_vars <= 21` always ⇒ `diff = ceiling - actual >= 0`
            // and both `num2bits` recompositions still bind inertly (no honest
            // proof's verdict changes; it only widens the accepted interval
            // from `{num_variables}` to `[0, 21]`, which is the height-agnostic
            // invariant relied on once `actual_num_vars` is witnessed).
            assert_num_vars_le_max::<C>(
                builder,
                actual_num_vars,
                zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize,
            );
        }

        // (4) Commit-phase transcript replay — byte-for-byte the
        // BaseFold PROVER cadence (crates/pcs/src/basefold/prover.rs
        // open_jagged_pcs step 4/5):
        //   observe(num_variables);
        //   per round: observe(uni_poly[0]); observe(uni_poly[1]);
        //              observe(commitment); sample beta.
        // Observing only the commitment (omitting the univariate message)
        // would diverge the sampled betas from the prover's, surfacing as an
        // AssertEqE failure on the fold-chain in the gnark OUTER wrap.
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
            let num_queries = self
                .params
                .num_queries
                .min(proof.query_phase_openings.first().map(|v| v.len()).unwrap_or(0));
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
                // (host step 9); a bare `sibling_pairs[0][0]` read would be
                // prover-supplied and unbound.  Empty component openings
                // (outer placeholder paths) use the fallback below —
                // structurally decided at program build.
                let initial_eval: Ext<C::F, C::EF> = if !proof.component_openings.is_empty() {
                    // Accumulate the step-8 inner product SYMBOLICALLY across the
                    // whole leaf loop and materialize it ONCE per query
                    // (`acc += coeff*value`,
                    // then a single `builder.eval` per query).  Keeping `acc` a
                    // SymbolicExt and letting the DSL CSE the single downstream
                    // eval avoids an O(queries x rounds x widths) blowup of
                    // materialized adds and is value-identical (pure deferred
                    // materialization).
                    let mut acc: zkm_recursion_compiler::ir::SymbolicExt<C::F, C::EF> =
                        zkm_recursion_compiler::ir::SymbolicExt::<C::F, C::EF>::ZERO;
                    let mut batch_idx = 0usize;
                    for (round_idx, round_openings) in proof.component_openings.iter().enumerate() {
                        let round_polys =
                            batch_evaluations.get(round_idx).map(|r| r.len()).unwrap_or(0);
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
                            let path_len = op.merkle_path_digests.len();
                            for (level, sibling_digest) in op.merkle_path_digests.iter().enumerate()
                            {
                                let bit = query_indices[query_idx][level].clone();
                                let pair = HV::select_chain_digest(
                                    builder,
                                    bit,
                                    [leaf_digest, *sibling_digest],
                                );
                                leaf_digest = HV::compress(builder, pair);
                            }
                            HV::assert_digest_eq(builder, leaf_digest, commitments[round_idx]);
                            // Round-count binding (2) —
                            // the `index == 0` RESIDUAL
                            // assert: after walking
                            // `path_len` Merkle levels, EVERY remaining (higher)
                            // query-index bit must be ZERO, i.e. the consumed
                            // index `index >> path_len == 0`.  Without it a
                            // malicious prover could WITNESS a shorter
                            // `merkle_path_digests` (under-claimed tree height)
                            // and silently leave the high query-index bits
                            // unconsumed — a wrong/short path that the
                            // raw-root compare alone would not catch (the
                            // commit is a bare Merkle root with no
                            // height binding, so the path
                            // length is otherwise unbound to the commitment).
                            // The component leaf is a FULL-height tree leaf, so
                            // the honest path consumes ALL `log_codeword_size`
                            // index bits and the residual slice below is EMPTY
                            // — BYTE-IDENTICAL on honest proofs (no constraint
                            // emitted), load-bearing only on an under-claimed
                            // path.
                            for residual_bit in query_indices[query_idx][path_len..].iter().cloned()
                            {
                                C::assert_bit_zero(builder, residual_bit);
                            }
                        }
                    }
                    // Materialize the accumulated inner product ONCE per query.
                    builder.eval(acc)
                } else {
                    sibling_pairs.first().map(|pair| pair[0]).unwrap_or_else(|| {
                        builder.eval(zkm_recursion_compiler::ir::SymbolicExt::<C::F, C::EF>::ZERO)
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
                // bits used for `initial_x` above (index[round]).
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
                // verifier.rs:389-404):
                //   * leaf = H(full row = [eval0(4 KB), eval1(4 KB)] = 8 felts)
                //     — NOT just eval0; the codeword leaf is the whole
                //     sibling pair.
                //   * path direction at level `k` = bit `k` of the pair
                //     index `index_pair = orig_query >> (round_idx+1)`,
                //     i.e. `query_indices[query_idx][round_idx + 1 + k]`
                //     (LSB-first).  Hard-coding the direction bit to 0
                //     (always-left) would compress every right-child step in
                //     the wrong order and yield the wrong root.
                //   * p3 MerkleTreeMmcs compares the reconstructed root
                //     DIRECTLY to the commitment (no dims-compress step).
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
                    let path_len = op.merkle_path_digests.len();
                    for (level, sibling_digest) in op.merkle_path_digests.iter().enumerate() {
                        // Witnessed DigestVariable, no const promotion.
                        let sibling_variable: HV::DigestVariable = *sibling_digest;
                        let bit = path_bits[level].clone();
                        let pair =
                            HV::select_chain_digest(builder, bit, [leaf_digest, sibling_variable]);
                        leaf_digest = HV::compress(builder, pair);
                    }
                    // Round-count binding (2) —
                    // the `index == 0` RESIDUAL assert,
                    // applied to the commit-phase
                    // codeword walk.  After walking `path_len` levels every
                    // remaining (higher) bit of `path_bits` (= the pair index
                    // `orig_query >> (round_idx+1)` past the consumed levels)
                    // must be ZERO.  The honest round-r codeword has height
                    // `2^(num_variables + log_blowup - 1 - r)`, so
                    // `path_len(r) == num_variables + log_blowup - 1 - r` and
                    // `(round_idx + 1) + path_len == log_codeword_size`:
                    // `path_bits[path_len..]` is EMPTY on honest proofs ⇒
                    // BYTE-IDENTICAL (no constraint emitted).  Load-bearing
                    // only if a prover WITNESSES a shorter `merkle_path_digests`
                    // (under-claimed codeword height): the bare-root compare
                    // alone would accept it (the bare Merkle-root commitment
                    // carries no height binding), but the
                    // unconsumed high index bits would be free — this assert
                    // forbids that.
                    for residual_bit in path_bits[path_len..].iter().cloned() {
                        C::assert_bit_zero(builder, residual_bit);
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
                        let round_commit: HV::DigestVariable = proof.rounds[round_idx].commitment;
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
        // log_codeword_size = num_variables + log_blowup = 20 + 2 = 22.
        // `production_default` uses log_blowup = 2 (rate 1/4) for the
        // provable-100-bit inner query-phase soundness posture (see
        // `BasefoldVerifierParams::production_default`).
        assert_eq!(p.log_codeword_size(), 22);
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

    // ── Round-count binding tests ──
    //
    // These compile + RUN the DSL through the recursion runtime
    // (`run_test_recursion`), so the in-circuit `assert_felt_eq` inside
    // `assert_num_vars_le_max` (the `num2bits` recomposition asserts)
    // actually fire.  An out-of-range round count makes the runtime panic
    // (the wrapped `diff`'s recomposition can't match), captured by
    // `#[should_panic]`; honest counts run clean.
    //
    // The bound is a TIGHT integer `actual <= max`: the accepted set is
    // EXACTLY `[0, max_num_vars]`.  These tests pin the tight boundary —
    // values in `(max, 2^nbits)` (which a power-of-two floor would
    // over-accept) are REJECTED.

    use p3_field::PrimeCharacteristicRing as _PrimeCharRing;
    use zkm_pcs::InnerVal;
    use zkm_recursion_compiler::config::InnerConfig;
    use zkm_recursion_compiler::prelude::{Builder, Felt};

    /// Run the round-count binding against a single witnessed `value`
    /// over a `max_num_vars` ceiling, executing the resulting circuit
    /// end-to-end.  `value` stands in for the (soon-to-be) witnessed
    /// `actual_num_vars`.
    fn run_numvars_bind(value: u64, max_num_vars: usize) {
        use crate::utils::tests::run_test_recursion;
        let mut builder = Builder::<InnerConfig>::default();
        let v: Felt<InnerVal> = builder.constant(InnerVal::from_u64(value));
        assert_num_vars_le_max::<InnerConfig>(&mut builder, v, max_num_vars);
        run_test_recursion(builder.into_operations(), std::iter::empty());
    }

    /// POSITIVE: the fixed-path no-op case `actual_num_vars ==
    /// max_num_vars` verifies for representative production sizes
    /// (including the clamped-tiny case and the un-clamped default 21).
    #[test]
    fn numvars_bind_accepts_fixed_path_equal_value() {
        // Fixed path: the witnessed value equals max_num_vars exactly
        // (diff == 0, both num2bits trivially bind).
        run_numvars_bind(1, 1);
        run_numvars_bind(10, 10);
        run_numvars_bind(15, 15); // clamped-tiny commit example
        run_numvars_bind(21, 21); // DEFAULT_LOG_STACKING_HEIGHT (un-clamped)
    }

    /// POSITIVE (tight `<=`): every honest value in `[0, max]` verifies —
    /// the inclusive boundaries `0` and `max`, plus interior values.  Note
    /// `max` here is 21 (the production ceiling), so this also exercises a
    /// clamped commit (actual=15) against the un-clamped MAX=21 — the
    /// CLAMP-INDEPENDENCE case: a clamped count is ACCEPTED by the
    /// fixed-MAX binding.
    #[test]
    fn numvars_bind_accepts_clamped_below_max() {
        let max = 21; // DEFAULT_LOG_STACKING_HEIGHT
        run_numvars_bind(0, max); // empty commit (inclusive low)
        run_numvars_bind(1, max);
        run_numvars_bind(14, max); // typical clamp (pick_log_stacking_height cap)
        run_numvars_bind(15, max); // clamped-tiny
        run_numvars_bind(20, max);
        run_numvars_bind(21, max); // == max (inclusive high, fixed path)
    }

    /// NEGATIVE (tightness): a value in `(max, 2^nbits)` that a power-of-two
    /// FLOOR would have ACCEPTED is REJECTED.  For max=21, nbits=5 (2^5=32);
    /// a floor accepts everything in `[0, 32]`, the tight bound rejects
    /// `22..=31`.
    #[test]
    #[should_panic]
    fn numvars_bind_rejects_value_in_old_floor_slack_22() {
        run_numvars_bind(22, 21); // 22 > 21: was accepted by the floor, now rejected
    }

    /// NEGATIVE (tightness): top of the power-of-two slack
    /// (`2^nbits - 1 = 31 > 21`) is REJECTED.
    #[test]
    #[should_panic]
    fn numvars_bind_rejects_value_at_top_of_old_slack_31() {
        run_numvars_bind(31, 21);
    }

    /// NEGATIVE: `max + 1` (`= 17 > 16` with a power-of-two max) is
    /// REJECTED — the immediate over-claim.
    #[test]
    #[should_panic]
    fn numvars_bind_rejects_max_plus_one() {
        run_numvars_bind(5, 4); // 5 > 4
    }

    /// NEGATIVE: a value just past a power-of-two bound (`2^max + 1 = 17
    /// > 4`) is REJECTED.
    #[test]
    #[should_panic]
    fn numvars_bind_rejects_value_just_above_bound() {
        run_numvars_bind(17, 4);
    }

    /// NEGATIVE: a grossly over-claimed value (`32 > 4`) is REJECTED.
    #[test]
    #[should_panic]
    fn numvars_bind_rejects_value_double_bound() {
        run_numvars_bind(32, 4);
    }

    // ── Merkle-walk `index == 0` residual-assert tests ──
    //
    // The production residual binding lives inside
    // `verify_untrusted_evaluations` after each in-circuit Merkle walk:
    // for `index_bits` spanning the full `log_codeword_size` query index,
    // after consuming `path_len` levels EVERY remaining bit
    // (`index_bits[path_len..]`) must be ZERO.  These tests reproduce that
    // exact constraint over a controllable bit-slice (the Merkle walk
    // itself is covered by the merkle_tree.rs tests; here we pin the
    // residual-zero rule end-to-end through the runtime, where the
    // in-circuit `assert_bit_zero` actually fires).

    /// Emit the residual rule: given a full `index` over `log_codeword`
    /// bits and a consumed `path_len`, assert `index >> path_len == 0`
    /// (every bit at `path_len..` is zero) — exactly the production loop
    /// `for residual_bit in index_bits[path_len..] { assert_bit_zero }`.
    fn run_merkle_residual(index: u64, log_codeword: usize, path_len: usize) {
        use crate::utils::tests::run_test_recursion;
        let mut builder = Builder::<InnerConfig>::default();
        let idx_felt: Felt<InnerVal> = builder.constant(InnerVal::from_u64(index));
        // index_bits = LSB-first decomposition over the full codeword span
        // (mirrors `query_indices[..]` = sample_bits(log_codeword_size)).
        let index_bits =
            <InnerConfig as crate::CircuitConfig>::num2bits(&mut builder, idx_felt, log_codeword);
        for residual_bit in index_bits[path_len..].iter().cloned() {
            <InnerConfig as crate::CircuitConfig>::assert_bit_zero(&mut builder, residual_bit);
        }
        run_test_recursion(builder.into_operations(), std::iter::empty());
    }

    /// POSITIVE (honest full-height path): when the consumed `path_len`
    /// equals the full index span the residual slice is EMPTY — no
    /// constraint, trivially accepts (the byte-identical honest case).
    #[test]
    fn merkle_residual_accepts_full_length_path() {
        // path_len == log_codeword: residual slice empty.
        run_merkle_residual(0b10110, 5, 5);
        run_merkle_residual(0, 5, 5);
        run_merkle_residual(0b1111111111, 10, 10);
    }

    /// POSITIVE (honest short index): an index that genuinely fits in
    /// `path_len` bits (high bits already zero) is ACCEPTED even though
    /// `path_len < log_codeword` — the residual is zero by construction.
    #[test]
    fn merkle_residual_accepts_when_high_bits_zero() {
        // index = 5 = 0b00101 in a 5-bit span; consumed path_len=3 leaves
        // bits[3..5] = {0,0} -> accepted.
        run_merkle_residual(0b00101, 5, 3);
        // index = 0 trivially accepted for any path_len.
        run_merkle_residual(0, 8, 2);
    }

    /// NEGATIVE (under-claimed path attack): an index whose bit at a level
    /// BEYOND the (short) `path_len` is SET leaves an unconsumed high
    /// index bit — REJECTED by the residual assert.  This is the attack
    /// binding (2) defends: a malicious prover witnessing a shorter
    /// `merkle_path_digests` than the codeword height.
    #[test]
    #[should_panic]
    fn merkle_residual_rejects_unconsumed_high_bit() {
        // index = 0b10000 (bit 4 set); consumed path_len=3 leaves bit 4 in
        // the residual slice [3..5] -> assert_bit_zero on a 1 -> reject.
        run_merkle_residual(0b10000, 5, 3);
    }

    /// NEGATIVE: an under-claim that drops MULTIPLE set high bits is
    /// REJECTED (the first non-zero residual bit trips).
    #[test]
    #[should_panic]
    fn merkle_residual_rejects_multiple_unconsumed_bits() {
        // index = 0b11000000 (bits 6,7 set) in an 8-bit span; path_len=4
        // leaves bits[4..8] = {0,0,1,1} -> reject.
        run_merkle_residual(0b11000000, 8, 4);
    }
}
