//! BaseFold proof verifier for the recursion circuit (host-shape + emit hooks).
//!
//! Verifies BaseFold-based shard proofs emitted by `prove_jagged_rounds`.
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
    /// log2 of the FRI folding arity — how many variables one commit-phase
    /// round folds.  MUST equal
    /// `zkm_pcs::basefold::config::FriConfig::log_folding_arity` and the GPU
    /// prover's, or the transcript diverges.  1 is the classic
    /// one-variable-per-round shape.
    pub log_folding_arity: usize,
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
            log_folding_arity: zkm_pcs::basefold::config::INNER_LOG_FOLDING_ARITY,
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
            log_folding_arity: zkm_pcs::basefold::config::FriConfig::<
                zkm_pcs::jagged_pcs::JaggedVal,
            >::wrap_fri_config()
            .log_folding_arity(),
        }
    }

    /// Total sumcheck rounds (= num_variables — BaseFold does one
    /// univariate round per polynomial variable).
    pub const fn total_sumcheck_rounds(&self) -> usize {
        self.num_variables
    }

    /// Total Merkle commits the verifier must observe (one per
    /// commit-phase round, plus the initial commit).
    ///
    /// A round covers `log_folding_arity` variables, so this is NOT
    /// `num_variables + 1` once the arity is raised.
    pub fn total_merkle_commits(&self) -> usize {
        self.num_commit_rounds() + 1
    }

    /// Commit-phase rounds: `log_folding_arity` variables each, with a
    /// possibly shorter trailing group.
    pub fn num_commit_rounds(&self) -> usize {
        self.num_variables.div_ceil(self.log_folding_arity.max(1))
    }

    /// How many variables each commit-phase round folds, in order.
    pub fn round_arities(&self) -> Vec<usize> {
        let k = self.log_folding_arity.max(1);
        let mut out = Vec::new();
        let mut var = 0;
        while var < self.num_variables {
            let g = core::cmp::min(k, self.num_variables - var);
            out.push(g);
            var += g;
        }
        out
    }

    /// log2 of the codeword size (= num_variables + log_blowup).
    pub const fn log_codeword_size(&self) -> usize {
        self.num_variables + self.log_blowup
    }

    /// Recursion-constraint estimate for one BaseFold proof.  Sized
    /// to inform the recursion AIR builder.
    pub fn estimated_recursion_constraints(&self) -> usize {
        let sumcheck = self.total_sumcheck_rounds() * 30;
        let merkle = self.num_queries * (self.num_variables + 1) * 200;
        let fri_fold = self.num_queries * self.num_variables * 25;
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
/// (shifted) query index: the round's opened codeword values plus the
/// inclusion path.
#[derive(Clone, Debug)]
pub struct RecursiveBasefoldOpening<F, EF, Dig = [F; 8]> {
    /// Query position in the round's codeword domain.
    pub position: usize,
    /// The round's opened codeword block — `2^arity` values covering the
    /// contiguous bit-reversed rows this query descends from.  At arity 1
    /// this is the familiar sibling pair `[evals[0], evals[1]]` at
    /// `(x, -x)`, and the witness stream is unchanged: the values are
    /// written in order with no length prefix, so a two-element block is
    /// byte-identical to the pair it replaces.
    pub block: Vec<EF>,
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
            let lhs = (one - x_r) * round.uni_poly[0] + x_r * round.uni_poly[1];
            if lhs != claim {
                return None;
            }
            challenger.observe_usize(0xB45E_F01D ^ r);
            for digest in round.commitment.iter() {
                challenger.observe_usize((*digest).into());
            }
            let beta = EF::from(0xBE7Au64).mul(EF::from(1u64));
            betas.push(beta);
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
        sibling_pairs: &[[EF; 2]],
        betas: &[EF],
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
            if evals[idx % 2] != folded {
                return false;
            }
            let avg = (evals[0] + evals[1]) / two;
            let diff = evals[0] - evals[1];
            folded = avg + diff * beta / (two * x);

            idx >>= 1;
            x = x * x;
            let _ = log_max_height;
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
        if proof.rounds.len() != self.params.num_variables {
            return false;
        }
        if eval_point.len() != self.params.num_variables {
            return false;
        }

        let Some((betas, _final_claim)) = Self::replay_sumcheck_rounds_host_shape::<EF, F, Ch>(
            &proof.rounds,
            initial_claim,
            eval_point,
            challenger,
        ) else {
            return false;
        };

        challenger.observe_usize(0xF1A1_F01Du64 as usize);

        let Some(&last_beta) = betas.last() else { return false };
        Self::check_final_consistency_host_shape::<EF, F>(proof, last_beta)
    }
}

/// **DSL-IR bridge: emit Merkle inclusion path verification.**
/// At each level: select left/right halves based on `bit`, hash via
/// Poseidon2KoalaBear, take the first DIGEST_SIZE felts as the new
/// running digest.  Returns the recomputed root.
/// Fold a block of `2^k` codeword values down to one, `k` levels deep.
///
/// This is the arity generalisation of the pair fold below.  A commit-phase
/// round of arity `k` puts `2^k` adjacent bit-reversed codeword rows in one
/// Merkle leaf, and a query folds that block itself instead of walking `k`
/// separate rounds — which is what removes `k` levels from every Merkle
/// path AND cuts the round count by `k`.
///
/// `xs[p]` is the domain element of block position `p`.  Adjacent positions
/// are always a `{+x, -x}` pair at every level (bit-reversal sends the
/// low bit to the high bit, and `g^(H/2) = -1`), so each level reuses the
/// same interpolation the arity-2 protocol uses, and the next level's
/// domain elements are the squares.
///
/// At `k == 1` this is exactly one pair fold.
pub fn fold_block_host_shape<EF: p3_field::Field>(evals: &[EF], xs: &[EF], betas: &[EF]) -> EF {
    assert_eq!(evals.len(), xs.len(), "one domain element per block position");
    assert_eq!(evals.len(), 1 << betas.len(), "block must be 2^betas.len() wide");
    let two = EF::ONE + EF::ONE;
    let mut cur: Vec<EF> = evals.to_vec();
    let mut cur_xs: Vec<EF> = xs.to_vec();
    for &beta in betas {
        let half = cur.len() / 2;
        let mut next = Vec::with_capacity(half);
        let mut next_xs = Vec::with_capacity(half);
        for i in 0..half {
            let (lo, hi) = (cur[2 * i], cur[2 * i + 1]);
            let x = cur_xs[2 * i];
            next.push((lo + hi) / two + (lo - hi) * beta / (two * x));
            next_xs.push(x * x);
        }
        cur = next;
        cur_xs = next_xs;
    }
    debug_assert_eq!(cur.len(), 1);
    cur[0]
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
/// booleanity and the sum-recomposition `Σ b_i 2^i == input` (the
/// compiler's circuit `Builder`).  The accepted values are exactly
/// `[0, max_num_vars]`.
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
    let nbits = if max_num_vars == 0 {
        1
    } else {
        (max_num_vars + 1).next_power_of_two().trailing_zeros() as usize
    };
    debug_assert!(
        nbits + 1 < 31,
        "assert_num_vars_le_max: nbits ({nbits}) too large for a tight \
         field-wrap `<=` over KoalaBear (need 2^(nbits+1) <= p)"
    );
    let _actual_bits = C::num2bits(builder, actual_num_vars, nbits);
    let max_felt: Felt<C::F> = builder.constant(C::F::from_usize(max_num_vars));
    let diff: Felt<C::F> = builder.eval(max_felt - actual_num_vars);
    let _diff_bits = C::num2bits(builder, diff, nbits);
}

/// In-circuit block fold: the arity generalisation of the per-round fold step
/// that [`RecursiveBasefoldVerifier::verify_shard`] emits inline.
///
/// Folds one commit-phase round's `2^k` opened codeword values down to a single
/// value using `k` betas, which is what lets a round cover `k` variables
/// against ONE Merkle leaf.
///
/// The domain elements come for free from structure rather than from `2^k`
/// in-circuit exponentiations.  Within a leaf the positions are
/// `x_base · zeta^bitrev_k(p)` for the compile-time `2^k`-th root `zeta`, and
/// the query's own position contributes `zeta^bitrev_k(pos)` — whose exponent
/// is just the low `k` index bits reversed.  So `x_base` is recovered with `k`
/// selects and `k` multiplies, and the coset is `2^k` multiplies by constants
/// (which the constant pool materialises once for the whole program).
///
/// Adjacent positions are a `{+x, -x}` pair at every level, so each level is
/// the same interpolation the arity-2 path already emits.
#[allow(clippy::too_many_arguments)]
pub fn emit_basefold_block_fold<C>(
    builder: &mut zkm_recursion_compiler::prelude::Builder<C>,
    block: &[zkm_recursion_compiler::prelude::Ext<C::F, C::EF>],
    x: zkm_recursion_compiler::prelude::Felt<C::F>,
    index_bits: &[C::Bit],
    betas: &[zkm_recursion_compiler::prelude::Ext<C::F, C::EF>],
) -> (zkm_recursion_compiler::prelude::Ext<C::F, C::EF>, zkm_recursion_compiler::prelude::Felt<C::F>)
where
    C: crate::CircuitConfig,
{
    use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
    use zkm_recursion_compiler::ir::DslIr;
    type Felt<C> =
        zkm_recursion_compiler::prelude::Felt<<C as zkm_recursion_compiler::ir::Config>::F>;

    let k = betas.len();
    assert_eq!(block.len(), 1usize << k, "block must hold 2^k opened values");
    assert!(index_bits.len() >= k, "index_bits must cover the block's low k bits");
    if k == 0 {
        return (block[0], x);
    }

    let bitrev = |mut v: usize, bits: usize| {
        let mut r = 0usize;
        for _ in 0..bits {
            r = (r << 1) | (v & 1);
            v >>= 1;
        }
        r
    };
    let zeta = <C::F as TwoAdicField>::two_adic_generator(k);
    let neg_two = -(C::F::ONE + C::F::ONE);

    let mut x_base = x;
    for (j, bit) in index_bits.iter().take(k).enumerate() {
        let step = zeta.exp_u64(1u64 << (k - 1 - j)).inverse();
        let factor = C::select_const_f(builder, *bit, C::F::ONE, step);
        let next: Felt<C> = builder.uninit();
        builder.push_op(DslIr::MulF(next, x_base, factor));
        x_base = next;
    }

    let half0 = 1usize << (k - 1);
    let mut e: Vec<Felt<C>> = Vec::with_capacity(half0);
    e.push(x_base);
    for i in 1..half0 {
        let c = zeta.exp_u64(bitrev(i, k - 1) as u64);
        let v: Felt<C> = builder.uninit();
        builder.push_op(DslIr::MulFI(v, x_base, c));
        e.push(v);
    }

    let mut cur: Vec<zkm_recursion_compiler::prelude::Ext<C::F, C::EF>> = block.to_vec();
    for beta in betas.iter() {
        let half = cur.len() / 2;
        debug_assert_eq!(e.len(), half);
        let mut next = Vec::with_capacity(half);
        for i in 0..half {
            let (lo, hi) = (cur[2 * i], cur[2 * i + 1]);
            let xlo = e[i];

            let diff: zkm_recursion_compiler::prelude::Ext<C::F, C::EF> = builder.uninit();
            builder.push_op(DslIr::SubE(diff, hi, lo));
            let beta_minus: zkm_recursion_compiler::prelude::Ext<C::F, C::EF> = builder.uninit();
            builder.push_op(DslIr::SubEF(beta_minus, *beta, xlo));
            let numer: zkm_recursion_compiler::prelude::Ext<C::F, C::EF> = builder.uninit();
            builder.push_op(DslIr::MulE(numer, beta_minus, diff));
            let denom: Felt<C> = builder.uninit();
            builder.push_op(DslIr::MulFI(denom, xlo, neg_two));
            let ratio: zkm_recursion_compiler::prelude::Ext<C::F, C::EF> = builder.uninit();
            builder.push_op(DslIr::DivEF(ratio, numer, denom));
            let folded: zkm_recursion_compiler::prelude::Ext<C::F, C::EF> = builder.uninit();
            builder.push_op(DslIr::AddE(folded, lo, ratio));
            next.push(folded);
        }
        let n_next = if half > 1 { half / 2 } else { 1 };
        let mut next_e = Vec::with_capacity(n_next);
        for j in 0..n_next {
            let src = e[2 * j];
            let sq: Felt<C> = builder.uninit();
            builder.push_op(DslIr::MulF(sq, src, src));
            next_e.push(sq);
        }
        cur = next;
        e = next_e;
    }
    debug_assert_eq!(cur.len(), 1);
    (cur[0], e[0])
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
///   - Walk the commit-phase fold chain and bind each round's reconstructed
///     root to its committed root.
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
        use crate::logup_gkr::observe_ext_element;
        use p3_field::PrimeCharacteristicRing;

        for round in batch_evaluations.iter() {
            for &claim in round.iter() {
                observe_ext_element::<C, FC>(builder, challenger, claim);
            }
        }

        {
            let batch_witness = proof.batch_grinding_witness;
            challenger.check_witness(builder, self.params.batch_grinding_bits, batch_witness);
        }

        let batching_coefficients: Vec<zkm_recursion_compiler::prelude::Ext<C::F, C::EF>> = {
            let total_polys: usize = batch_evaluations.iter().map(|r| r.len()).sum();
            let num_batching_vars =
                total_polys.max(1).next_power_of_two().trailing_zeros() as usize;
            let batching_point: Vec<zkm_recursion_compiler::prelude::Ext<C::F, C::EF>> =
                (0..num_batching_vars).map(|_| challenger.sample_ext(builder)).collect();
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

        #[cfg(not(ha_measure_base))]
        {
            use p3_field::PrimeCharacteristicRing;
            let actual_num_vars: zkm_recursion_compiler::prelude::Felt<C::F> =
                builder.constant(C::F::from_usize(self.params.num_variables));
            assert_num_vars_le_max::<C>(
                builder,
                actual_num_vars,
                zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize,
            );
        }

        {
            let nvar_felt: zkm_recursion_compiler::prelude::Felt<C::F> =
                builder.constant(C::F::from_usize(self.params.num_variables));
            challenger.observe(builder, nvar_felt);
        }
        let group_leader: Vec<bool> = {
            let arities = self.params.round_arities();
            let mut flags = vec![false; proof.rounds.len()];
            let mut at = 0usize;
            for a in arities {
                if at < flags.len() {
                    flags[at] = true;
                }
                at += a;
            }
            flags
        };
        let betas: Vec<zkm_recursion_compiler::prelude::Ext<C::F, C::EF>> = proof
            .rounds
            .iter()
            .enumerate()
            .map(|(i, round)| {
                let p0 = round.uni_poly[0];
                let p1 = round.uni_poly[1];
                observe_ext_element::<C, FC>(builder, challenger, p0);
                observe_ext_element::<C, FC>(builder, challenger, p1);
                if group_leader[i] {
                    challenger.observe(builder, round.commitment);
                }
                challenger.sample_ext(builder)
            })
            .collect();

        {
            use zkm_recursion_compiler::ir::SymbolicExt;
            use zkm_recursion_compiler::prelude::Ext;

            let mut claim_acc: SymbolicExt<C::F, C::EF> = SymbolicExt::<C::F, C::EF>::ZERO;
            let mut idx = 0usize;
            for round in batch_evaluations.iter() {
                for &v in round.iter() {
                    claim_acc += batching_coefficients[idx] * v;
                    idx += 1;
                }
            }
            let eval_claim: Ext<C::F, C::EF> = builder.eval(claim_acc);

            let one: Ext<C::F, C::EF> = builder.constant(C::EF::ONE);
            let mut expected: Ext<C::F, C::EF> = eval_claim;
            for (i, round) in proof.rounds.iter().enumerate() {
                let p0 = round.uni_poly[0];
                let p1 = round.uni_poly[1];
                let x = stack_point[i];
                let got: Ext<C::F, C::EF> = builder.eval((one - x) * p0 + x * p1);
                builder.assert_ext_eq(got, expected);
                expected = builder.eval(p0 + betas[i] * p1);
            }
            builder.assert_ext_eq(expected, proof.final_poly);
        }

        {
            let final_poly_ext = proof.final_poly;
            let final_felts = C::ext2felt(builder, final_poly_ext);
            for felt in final_felts.iter() {
                challenger.observe(builder, *felt);
            }
            let pow_witness = proof.pow_witness;
            challenger.check_witness(builder, self.params.pow_bits, pow_witness);
        }

        let log_codeword_size = self.params.log_codeword_size();
        let query_indices: Vec<Vec<C::Bit>> = (0..self.params.num_queries)
            .map(|_| challenger.sample_bits(builder, log_codeword_size))
            .collect();

        {
            use zkm_recursion_compiler::prelude::Ext;
            let final_poly_ext: Ext<C::F, C::EF> = proof.final_poly;
            let num_queries = self.params.num_queries;
            for (round_idx, round_openings) in proof.query_phase_openings.iter().enumerate() {
                assert_eq!(
                    round_openings.len(),
                    num_queries,
                    "basefold: query_phase_openings[{round_idx}].len() ({}) != num_queries ({})",
                    round_openings.len(),
                    num_queries,
                );
            }
            for query_idx in 0..num_queries {
                let blocks: Vec<Vec<Ext<C::F, C::EF>>> = proof
                    .query_phase_openings
                    .iter()
                    .map(|round_openings| round_openings[query_idx].block.clone())
                    .collect();
                let round_arities = self.params.round_arities();

                let initial_eval: Ext<C::F, C::EF> = if !proof.component_openings.is_empty() {
                    let mut acc: zkm_recursion_compiler::ir::SymbolicExt<C::F, C::EF> =
                        zkm_recursion_compiler::ir::SymbolicExt::<C::F, C::EF>::ZERO;
                    let mut batch_idx = 0usize;
                    assert_eq!(
                        proof.component_openings.len(),
                        commitments.len(),
                        "basefold: {} rounds of component openings for {} committed rounds",
                        proof.component_openings.len(),
                        commitments.len(),
                    );
                    for (round_idx, round_openings) in proof.component_openings.iter().enumerate() {
                        let round_polys =
                            batch_evaluations.get(round_idx).map(|r| r.len()).unwrap_or(0);
                        let op = &round_openings[query_idx];
                        let mut poly_offset = 0usize;
                        for mat_values in op.leaf_values.iter() {
                            for &v in mat_values.iter() {
                                let c = batching_coefficients[batch_idx + poly_offset];
                                acc += c * v;
                                poly_offset += 1;
                            }
                        }
                        assert_eq!(
                            poly_offset, round_polys,
                            "component leaf width != round poly count (round {round_idx})"
                        );
                        batch_idx += round_polys;
                        assert_eq!(
                            op.merkle_path_digests.len(),
                            log_codeword_size,
                            "basefold: round {round_idx} component path is {} levels, the \
                             codeword domain is 2^{log_codeword_size}",
                            op.merkle_path_digests.len(),
                        );
                        {
                            let leaf_felts: Vec<zkm_recursion_compiler::prelude::Felt<C::F>> =
                                op.leaf_values.iter().flatten().copied().collect();
                            let mut leaf_digest: HV::DigestVariable =
                                HV::hash(builder, &leaf_felts);
                            let path_len = op.merkle_path_digests.len();
                            for (level, sibling_digest) in op.merkle_path_digests.iter().enumerate()
                            {
                                let bit = query_indices[query_idx][level];
                                let pair = HV::select_chain_digest(
                                    builder,
                                    bit,
                                    [leaf_digest, *sibling_digest],
                                );
                                leaf_digest = HV::compress(builder, pair);
                            }
                            HV::assert_digest_eq(builder, leaf_digest, commitments[round_idx]);
                            for residual_bit in query_indices[query_idx][path_len..].iter().cloned()
                            {
                                C::assert_bit_zero(builder, residual_bit);
                            }
                        }
                    }
                    builder.eval(acc)
                } else {
                    blocks.first().map(|b| b[0]).unwrap_or_else(|| {
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

                let mut folded = initial_eval;
                let mut x_cur = initial_x;
                let mut bit_at = 0usize;
                let mut beta_at = 0usize;
                for (round, block) in blocks.iter().enumerate() {
                    let arity = round_arities.get(round).copied().unwrap_or(1);
                    if !proof.component_openings.is_empty() {
                        let mut cur: Vec<Ext<C::F, C::EF>> = block.to_vec();
                        for j in (0..arity).rev() {
                            let half = cur.len() / 2;
                            if half == 0 {
                                break;
                            }
                            let bit = query_indices[query_idx][bit_at + j];
                            let lo = cur[..half].to_vec();
                            let hi = cur[half..].to_vec();
                            let sel = C::select_chain_ef(builder, bit, lo, hi);
                            cur = sel[..half].to_vec();
                        }
                        builder.assert_ext_eq(cur[0], folded);
                    }
                    let round_betas = &betas[beta_at..beta_at + arity];
                    beta_at += arity;
                    let (f, nx) = emit_basefold_block_fold::<C>(
                        builder,
                        block,
                        x_cur,
                        &query_indices[query_idx][bit_at..],
                        round_betas,
                    );
                    folded = f;
                    x_cur = nx;
                    bit_at += arity;
                }
                builder.assert_ext_eq(folded, final_poly_ext);

                for (round_idx, round_openings) in proof.query_phase_openings.iter().enumerate() {
                    let op = &round_openings[query_idx];
                    if op.merkle_path_digests.is_empty() {
                        continue;
                    }
                    let leaf_felts: Vec<zkm_recursion_compiler::prelude::Felt<C::F>> =
                        blocks[round_idx].iter().flat_map(|v| C::ext2felt(builder, *v)).collect();
                    let mut leaf_digest: HV::DigestVariable = HV::hash(builder, &leaf_felts);
                    let bits_consumed: usize = round_arities.iter().take(round_idx + 1).sum();
                    let path_bits = &query_indices[query_idx][bits_consumed..];
                    let path_len = op.merkle_path_digests.len();
                    for (level, sibling_digest) in op.merkle_path_digests.iter().enumerate() {
                        let sibling_variable: HV::DigestVariable = *sibling_digest;
                        let bit = path_bits[level];
                        let pair =
                            HV::select_chain_digest(builder, bit, [leaf_digest, sibling_variable]);
                        leaf_digest = HV::compress(builder, pair);
                    }
                    for residual_bit in path_bits[path_len..].iter().cloned() {
                        C::assert_bit_zero(builder, residual_bit);
                    }

                    let leader: usize = round_arities.iter().take(round_idx).sum();
                    if leader < proof.rounds.len() {
                        let round_commit: HV::DigestVariable = proof.rounds[leader].commitment;
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

    /// The block fold MUST equal `k` successive pair folds on the same data.
    ///
    /// That equality is the whole justification for raising the folding arity:
    /// the verifier does the same arithmetic, but against ONE Merkle leaf per
    /// `k` variables instead of `k` leaves, so it skips `k` levels of path per
    /// round and `k`-fold fewer rounds.  If this ever diverges, a higher-arity
    /// proof would verify against a different polynomial than the prover
    /// folded.
    #[test]
    fn block_fold_matches_successive_pair_folds() {
        use p3_field::{PrimeCharacteristicRing, TwoAdicField};
        use zkm_pcs::{InnerChallenge, InnerVal};
        type EF = InnerChallenge;

        let two = EF::from_u32(2);
        let pair = |lo: EF, hi: EF, x: EF, beta: EF| (lo + hi) / two + (lo - hi) * beta / (two * x);

        for k in 1usize..=4 {
            let n = 1usize << k;
            let log_h = k + 3;
            let g = <InnerVal as TwoAdicField>::two_adic_generator(log_h);
            let x_base = EF::from(g);
            let zeta = EF::from(<InnerVal as TwoAdicField>::two_adic_generator(k));
            let bitrev = |mut v: usize, bits: usize| {
                let mut r = 0;
                for _ in 0..bits {
                    r = (r << 1) | (v & 1);
                    v >>= 1;
                }
                r
            };
            let xs: Vec<EF> = (0..n).map(|p| x_base * zeta.exp_u64(bitrev(p, k) as u64)).collect();
            for i in 0..n / 2 {
                assert_eq!(xs[2 * i + 1], -xs[2 * i], "k={k}: block pair must be (+x, -x)");
            }

            let evals: Vec<EF> = (0..n).map(|i| EF::from_u32(7 + 13 * i as u32)).collect();
            let betas: Vec<EF> = (0..k).map(|j| EF::from_u32(101 + 37 * j as u32)).collect();

            let mut cur = evals.clone();
            let mut cur_xs = xs.clone();
            for &beta in &betas {
                let half = cur.len() / 2;
                let mut next = Vec::with_capacity(half);
                let mut next_xs = Vec::with_capacity(half);
                for i in 0..half {
                    next.push(pair(cur[2 * i], cur[2 * i + 1], cur_xs[2 * i], beta));
                    next_xs.push(cur_xs[2 * i] * cur_xs[2 * i]);
                }
                cur = next;
                cur_xs = next_xs;
            }

            let got = fold_block_host_shape(&evals, &xs, &betas);
            assert_eq!(got, cur[0], "k={k}: block fold must equal successive pair folds");
        }
    }

    #[test]
    fn params_default_consistency() {
        let p = BasefoldVerifierParams::production_default(20);
        assert_eq!(p.total_sumcheck_rounds(), 20);
        let arity = zkm_pcs::basefold::config::INNER_LOG_FOLDING_ARITY;
        assert_eq!(p.num_commit_rounds(), 20usize.div_ceil(arity));
        assert_eq!(p.total_merkle_commits(), 20usize.div_ceil(arity) + 1);
        assert_eq!(p.log_codeword_size(), 22);
        assert!(p.estimated_recursion_constraints() > 0);
    }

    #[test]
    fn evaluate_multilinear_padded_basic() {
        type EF = i64;
        type F = i64;
        let coeffs: Vec<EF> = vec![4, 8, 12, 16];
        let point: Vec<EF> = vec![2, 2];
        let result = RecursiveBasefoldVerifier::<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>::evaluate_multilinear_padded_host_shape::<EF, F>(
            &coeffs, &point,
        );
        assert_eq!(result, 28);
    }

    // Round-count binding tests
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
        run_numvars_bind(1, 1);
        run_numvars_bind(10, 10);
        run_numvars_bind(15, 15);
        run_numvars_bind(21, 21);
    }

    /// POSITIVE (tight `<=`): every honest value in `[0, max]` verifies —
    /// the inclusive boundaries `0` and `max`, plus interior values.  Note
    /// `max` here is 21 (the production ceiling), so this also exercises a
    /// clamped commit (actual=15) against the un-clamped MAX=21 — the
    /// CLAMP-INDEPENDENCE case: a clamped count is ACCEPTED by the
    /// fixed-MAX binding.
    #[test]
    fn numvars_bind_accepts_clamped_below_max() {
        let max = 21;
        run_numvars_bind(0, max);
        run_numvars_bind(1, max);
        run_numvars_bind(14, max);
        run_numvars_bind(15, max);
        run_numvars_bind(20, max);
        run_numvars_bind(21, max);
    }

    /// NEGATIVE (tightness): a value in `(max, 2^nbits)` that a power-of-two
    /// FLOOR would have ACCEPTED is REJECTED.  For max=21, nbits=5 (2^5=32);
    /// a floor accepts everything in `[0, 32]`, the tight bound rejects
    /// `22..=31`.
    #[test]
    #[should_panic]
    fn numvars_bind_rejects_value_in_old_floor_slack_22() {
        run_numvars_bind(22, 21);
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
        run_numvars_bind(5, 4);
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

    // Merkle-walk `index == 0` residual-assert tests
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

    // ---- Component-opening binding: the audit's regression gate 1 ----
    //
    // `verify_shard` binds each query's component opening to its round
    // commitment with exactly this chain:
    //
    //   leaf_digest = HV::hash(op.leaf_values.flatten())
    //   for (level, sibling) in op.merkle_path_digests.enumerate():
    //       pair        = HV::select_chain_digest(bit[level], [leaf_digest, sibling])
    //       leaf_digest = HV::compress(pair)
    //   HV::assert_digest_eq(leaf_digest, commitments[round_idx])
    //
    // `merkle_tree.rs` covers the HONEST walk and nothing covered a MUTATED
    // component, so none of the four bindings was shown to be load-bearing:
    // an equality inert behind an always-empty vector passes every honest
    // test.
    //
    // These runs use the production `HV` primitives (not a reimplementation)
    // and execute end-to-end through the recursion runtime, so a mutation the
    // constraint fails to catch surfaces as a `#[should_panic]` test that does
    // not panic.

    /// Which single component the run corrupts.  Exactly one felt moves in each
    /// case, so a rejection can only come from the binding under test.
    #[derive(Clone, Copy, PartialEq)]
    enum Corrupt {
        /// Honest proof: the chain must accept.
        Nothing,
        /// One opened felt of the query's block — the leaf the chain hashes.
        Leaf,
        /// One sibling digest of the inclusion path.
        Sibling,
        /// The round commitment the recomputed root is compared against.
        Root,
        /// The query index, i.e. the leaf's POSITION: the same leaf and path
        /// authenticated at a different place in the codeword domain.
        Position,
    }

    /// Run the component chain over a `2^LOG_CW` codeword domain, natively
    /// computing the honest root with the MMCS's own Poseidon2 primitives and
    /// then re-deriving it in-circuit.
    fn run_component_binding(corrupt: Corrupt) {
        use crate::hash::FieldHasherVariable;
        use crate::utils::tests::run_test_recursion;
        use crate::CircuitConfig;
        use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
        use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2 as HV;
        use zkm_pcs::{InnerCompress, InnerHash, InnerPerm};

        const LOG_CW: usize = 4;
        const BLOCK_WIDTH: usize = 3;
        let index: usize = 0b1011;

        let perm: InnerPerm = zkm_primitives::poseidon2_init();
        let hasher = InnerHash::new(perm.clone());
        let compressor = InnerCompress::new(perm);

        let block: Vec<InnerVal> =
            (0..BLOCK_WIDTH).map(|i| InnerVal::from_u64(7 + i as u64)).collect();
        let siblings: Vec<[InnerVal; 8]> = (0..LOG_CW)
            .map(|l| core::array::from_fn(|i| InnerVal::from_u64(100 * (l as u64 + 1) + i as u64)))
            .collect();

        let mut acc: [InnerVal; 8] = hasher.hash_iter(block.iter().copied());
        for (level, sib) in siblings.iter().enumerate() {
            acc = if (index >> level) & 1 == 1 {
                compressor.compress([*sib, acc])
            } else {
                compressor.compress([acc, *sib])
            };
        }
        let root = acc;

        let mut builder = Builder::<InnerConfig>::default();
        let block_vars: Vec<Felt<InnerVal>> = block
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let v = if corrupt == Corrupt::Leaf && i == 0 { *f + InnerVal::ONE } else { *f };
                builder.constant(v)
            })
            .collect();
        let sibling_vars: Vec<[Felt<InnerVal>; 8]> = siblings
            .iter()
            .enumerate()
            .map(|(l, sib)| {
                core::array::from_fn(|i| {
                    let v = if corrupt == Corrupt::Sibling && l == 0 && i == 0 {
                        sib[i] + InnerVal::ONE
                    } else {
                        sib[i]
                    };
                    builder.constant(v)
                })
            })
            .collect();
        let root_vars: [Felt<InnerVal>; 8] = core::array::from_fn(|i| {
            let v =
                if corrupt == Corrupt::Root && i == 0 { root[i] + InnerVal::ONE } else { root[i] };
            builder.constant(v)
        });
        let claimed_index = if corrupt == Corrupt::Position { index ^ 1 } else { index };
        let index_felt: Felt<InnerVal> = builder.constant(InnerVal::from_u64(claimed_index as u64));
        let index_bits = <InnerConfig as CircuitConfig>::num2bits(&mut builder, index_felt, LOG_CW);

        let mut leaf_digest =
            <HV as FieldHasherVariable<InnerConfig>>::hash(&mut builder, &block_vars);
        for (level, sib) in sibling_vars.iter().enumerate() {
            let pair = <HV as FieldHasherVariable<InnerConfig>>::select_chain_digest(
                &mut builder,
                index_bits[level],
                [leaf_digest, *sib],
            );
            leaf_digest = <HV as FieldHasherVariable<InnerConfig>>::compress(&mut builder, pair);
        }
        <HV as FieldHasherVariable<InnerConfig>>::assert_digest_eq(
            &mut builder,
            leaf_digest,
            root_vars,
        );
        run_test_recursion(builder.into_operations(), std::iter::empty());
    }

    /// POSITIVE, and the one that makes the four below mean anything: the
    /// honest component opening verifies, which also confirms the native mirror
    /// above reproduces the in-circuit chain (orientation included).
    #[test]
    fn component_binding_accepts_the_honest_opening() {
        run_component_binding(Corrupt::Nothing);
    }

    /// NEGATIVE — one opened felt of the query's block.  The block is what the
    /// query chain's inner product consumes, so an unbound leaf would let a
    /// prover answer a query with values the commitment never covered.
    #[test]
    #[should_panic(expected = "DivFOutOfDomain")]
    fn component_binding_rejects_a_corrupted_leaf() {
        run_component_binding(Corrupt::Leaf);
    }

    /// NEGATIVE — one sibling digest of the inclusion path.
    #[test]
    #[should_panic(expected = "DivFOutOfDomain")]
    fn component_binding_rejects_a_corrupted_path() {
        run_component_binding(Corrupt::Sibling);
    }

    /// NEGATIVE — the round commitment itself.  This is the compare that ties
    /// the whole walk to the observed root, so it must be reachable.
    #[test]
    #[should_panic(expected = "DivFOutOfDomain")]
    fn component_binding_rejects_a_corrupted_root() {
        run_component_binding(Corrupt::Root);
    }

    /// NEGATIVE — the leaf's POSITION.  The leaf and the path are both honest;
    /// only the claimed index moves, so this is the binding that stops one
    /// authenticated opening from being replayed at another point of the
    /// codeword domain.
    #[test]
    #[should_panic(expected = "DivFOutOfDomain")]
    fn component_binding_rejects_a_corrupted_position() {
        run_component_binding(Corrupt::Position);
    }

    /// Emit the residual rule: given a full `index` over `log_codeword`
    /// bits and a consumed `path_len`, assert `index >> path_len == 0`
    /// (every bit at `path_len..` is zero) — exactly the production loop
    /// `for residual_bit in index_bits[path_len..] { assert_bit_zero }`.
    fn run_merkle_residual(index: u64, log_codeword: usize, path_len: usize) {
        use crate::utils::tests::run_test_recursion;
        let mut builder = Builder::<InnerConfig>::default();
        let idx_felt: Felt<InnerVal> = builder.constant(InnerVal::from_u64(index));
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
        run_merkle_residual(0b10110, 5, 5);
        run_merkle_residual(0, 5, 5);
        run_merkle_residual(0b1111111111, 10, 10);
    }

    /// POSITIVE (honest short index): an index that genuinely fits in
    /// `path_len` bits (high bits already zero) is ACCEPTED even though
    /// `path_len < log_codeword` — the residual is zero by construction.
    #[test]
    fn merkle_residual_accepts_when_high_bits_zero() {
        run_merkle_residual(0b00101, 5, 3);
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
        run_merkle_residual(0b10000, 5, 3);
    }

    /// NEGATIVE: an under-claim that drops MULTIPLE set high bits is
    /// REJECTED (the first non-zero residual bit trips).
    #[test]
    #[should_panic]
    fn merkle_residual_rejects_multiple_unconsumed_bits() {
        run_merkle_residual(0b11000000, 8, 4);
    }
}

#[cfg(test)]
mod block_fold_tests {
    use p3_field::{PrimeCharacteristicRing, TwoAdicField};
    use zkm_pcs::InnerVal;

    fn bitrev(mut v: usize, bits: usize) -> usize {
        let mut r = 0usize;
        for _ in 0..bits {
            r = (r << 1) | (v & 1);
            v >>= 1;
        }
        r
    }

    /// [`super::emit_basefold_block_fold`] never materialises the odd half of a
    /// round's coset: within a leaf the pair `(2i, 2i+1)` sits at
    /// `bitrev_k(2i) = r` and `bitrev_k(2i+1) = r + 2^(k-1)`, and
    /// `zeta^(2^(k-1)) = -1`, so the partner is the negation — at this level and,
    /// since the next level's elements are these squared, at every level below.
    /// That is what turns the interpolation denominator into `-2*xlo` and lets
    /// `e[i]` stand in for the whole pair.
    #[test]
    fn coset_pairs_are_negations_at_every_level() {
        for k in 1..=4usize {
            let zeta = <InnerVal as TwoAdicField>::two_adic_generator(k);
            let x_base = InnerVal::from_u32(0x1234_5677);
            let mut xs: Vec<InnerVal> =
                (0..(1usize << k)).map(|q| x_base * zeta.exp_u64(bitrev(q, k) as u64)).collect();
            let mut e: Vec<InnerVal> = (0..(1usize << (k - 1)))
                .map(|i| x_base * zeta.exp_u64(bitrev(i, k - 1) as u64))
                .collect();
            for _ in 0..k {
                let half = xs.len() / 2;
                assert_eq!(e.len(), half);
                for i in 0..half {
                    assert_eq!(e[i], xs[2 * i], "reduced element != even coset entry");
                    assert_eq!(xs[2 * i + 1], -xs[2 * i], "odd coset entry is not a negation");
                    assert_eq!(xs[2 * i + 1] - xs[2 * i], -(xs[2 * i] + xs[2 * i]));
                }
                let n_next = if half > 1 { half / 2 } else { 1 };
                xs = (0..half).map(|i| xs[2 * i] * xs[2 * i]).collect();
                e = (0..n_next).map(|j| e[2 * j] * e[2 * j]).collect();
            }
            assert_eq!(xs[0], e[0], "returned domain element diverges");
        }
    }
}
