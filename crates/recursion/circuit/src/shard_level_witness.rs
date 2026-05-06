//! Witnessable impls for the SP1-style shard-level proof types
//! that live in [`zkm_stark::shard_level`].
//!
//! Bridges the host-side types (raw `F`/`EF`) into recursion
//! circuit variables (`Felt<F>` / `Ext<F, EF>`).  Mirrors the
//! impls in [`crate::basefold_witness`] which serve the
//! recursion-circuit-internal copies of these types — both sets
//! coexist during the parallel-codebase window so the legacy
//! verifier can keep using the recursion-circuit-internal types
//! while the new shard-level prover output drives the new
//! verifier through these impls.
//!

use std::collections::BTreeMap;

use zkm_recursion_compiler::ir::{Builder, Ext, Felt};
use zkm_stark::septic_curve::SepticCurve;
use zkm_stark::septic_digest::SepticDigest;
use zkm_stark::septic_extension::SepticExtension;
use zkm_stark::shard_level::shard_proof::ChipCumulativeSums;
use zkm_stark::shard_level::types as st;

use crate::witness::{Witnessable, WitnessWriter};
use crate::CircuitConfig;
use zkm_stark::{InnerChallenge, InnerVal};

// ── Per-chip cumulative sums (META #59 swap 1+2) ────────────────

impl<C> Witnessable<C> for ChipCumulativeSums<InnerVal, InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = ChipCumulativeSums<Felt<C::F>, Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let local = self.local.read(builder);
        let global_x = self.global.0.x.0.read(builder);
        let global_y = self.global.0.y.0.read(builder);
        ChipCumulativeSums {
            local,
            global: SepticDigest(SepticCurve {
                x: SepticExtension(global_x),
                y: SepticExtension(global_y),
            }),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.local.write(witness);
        self.global.0.x.0.write(witness);
        self.global.0.y.0.write(witness);
    }
}

// ── Univariate + sumcheck types ──────────────────────────────────

impl<C> Witnessable<C> for st::UnivariatePolynomial<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = st::UnivariatePolynomial<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        st::UnivariatePolynomial { coefficients: self.coefficients.read(builder) }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.coefficients.write(witness);
    }
}

impl<C> Witnessable<C> for st::PartialSumcheckProof<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = st::PartialSumcheckProof<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        st::PartialSumcheckProof {
            univariate_polys: self.univariate_polys.read(builder),
            claimed_sum: self.claimed_sum.read(builder),
            point_and_eval: self.point_and_eval.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.univariate_polys.write(witness);
        self.claimed_sum.write(witness);
        self.point_and_eval.write(witness);
    }
}

// ── LogUp-GKR proof types ────────────────────────────────────────

impl<C> Witnessable<C> for st::LogUpGkrOutput<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = st::LogUpGkrOutput<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        st::LogUpGkrOutput {
            numerator: self.numerator.read(builder),
            denominator: self.denominator.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.numerator.write(witness);
        self.denominator.write(witness);
    }
}

impl<C> Witnessable<C> for st::LogupGkrRoundProof<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = st::LogupGkrRoundProof<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        st::LogupGkrRoundProof {
            numerator_0: self.numerator_0.read(builder),
            numerator_1: self.numerator_1.read(builder),
            denominator_0: self.denominator_0.read(builder),
            denominator_1: self.denominator_1.read(builder),
            sumcheck_proof: self.sumcheck_proof.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.numerator_0.write(witness);
        self.numerator_1.write(witness);
        self.denominator_0.write(witness);
        self.denominator_1.write(witness);
        self.sumcheck_proof.write(witness);
    }
}

impl<C> Witnessable<C> for st::ChipEvaluation<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = st::ChipEvaluation<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        st::ChipEvaluation {
            main_trace_evaluations: self.main_trace_evaluations.read(builder),
            preprocessed_trace_evaluations: self
                .preprocessed_trace_evaluations
                .as_ref()
                .map(|v| v.read(builder)),
            log_degree: self.log_degree,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.main_trace_evaluations.write(witness);
        if let Some(prep) = self.preprocessed_trace_evaluations.as_ref() {
            prep.write(witness);
        }
    }
}

impl<C> Witnessable<C> for st::LogUpEvaluations<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = st::LogUpEvaluations<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let chip_openings: BTreeMap<String, st::ChipEvaluation<Ext<C::F, C::EF>>> = self
            .chip_openings
            .iter()
            .map(|(name, eval)| (name.clone(), eval.read(builder)))
            .collect();
        st::LogUpEvaluations { point: self.point.read(builder), chip_openings }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.point.write(witness);
        for (_name, eval) in self.chip_openings.iter() {
            eval.write(witness);
        }
    }
}

impl<C> Witnessable<C> for st::LogupGkrProof<InnerVal, InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = st::LogupGkrProof<Felt<C::F>, Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        st::LogupGkrProof {
            circuit_output: self.circuit_output.read(builder),
            round_proofs: self.round_proofs.read(builder),
            logup_evaluations: self.logup_evaluations.read(builder),
            witness: self.witness.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.circuit_output.write(witness);
        self.round_proofs.write(witness);
        self.logup_evaluations.write(witness);
        self.witness.write(witness);
    }
}

// ── Top-level: BasefoldShardProof ────────────────────────────────
//
// Bridges `zkm_stark::shard_level::shard_proof::BasefoldShardProof`
// (host) to a tuple of recursion-variable pieces.  The full
// `BasefoldShardProofVariable` mapping (which includes
// chip_height_bits and the jagged-PCS evaluation_proof) lands
// once those pieces have host-side definitions; this impl
// exposes the typed pieces (logup_gkr_proof, zerocheck_proof)
// + raw felts (main_commitment, public_values) so call sites
// can already begin reading them through the witness stream.
//
// Returned tuple shape:
//   (main_commitment_felts, public_values_felts,
//    logup_gkr_proof_var, zerocheck_proof_var,
//    evaluation_proof_bytes_passthrough)
//
// `evaluation_proof_bytes_passthrough` carries the raw bytes
// out of the witness so the next stage (jagged-PCS variable
// reconstruction) can consume them without re-routing through
// the witness layer.
impl<C> Witnessable<C>
    for zkm_stark::shard_level::shard_proof::BasefoldShardProof<InnerVal, InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = (
        [Felt<C::F>; 8],
        Vec<Felt<C::F>>,
        st::LogupGkrProof<Felt<C::F>, Ext<C::F, C::EF>>,
        st::PartialSumcheckProof<Ext<C::F, C::EF>>,
        Vec<u8>,
    );

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let main_commitment_arr: [Felt<C::F>; 8] =
            core::array::from_fn(|i| self.main_commitment[i].read(builder));
        let public_values = self.public_values.read(builder);
        let logup_gkr_proof = self.logup_gkr_proof.read(builder);
        let zerocheck_proof = self.zerocheck_proof.read(builder);
        // evaluation_proof passes through as raw bytes — the
        // jagged-PCS-variable reconstruction step consumes them
        // separately (no felt-level witness reads here).
        let evaluation_proof_bytes = self.evaluation_proof.clone();
        (
            main_commitment_arr,
            public_values,
            logup_gkr_proof,
            zerocheck_proof,
            evaluation_proof_bytes,
        )
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for f in self.main_commitment.iter() {
            f.write(witness);
        }
        self.public_values.write(witness);
        self.logup_gkr_proof.write(witness);
        self.zerocheck_proof.write(witness);
        // evaluation_proof bytes are not written through the
        // felt-witness stream — they're transported out-of-band
        // and consumed by the jagged-PCS layer directly.
    }
}

// ── Jagged-PCS bundle Witnessable surface (#241 Phase 1) ─────────
//
// Additive Witnessable bridges for the host-side jagged-PCS bundle
// pieces.  These compile against the existing in-circuit verifier
// surface but are NOT yet wired into call sites — that's Phase 2-4
// per task #241.  Phase 1's purpose is to establish the field-by-
// field witness mapping so subsequent phases can compose the full
// `JaggedBasefoldBundle::Witnessable` from these primitives.
//
// Reference: SP1's [`JaggedSumcheckEvalProof` / `JaggedPcsProof`
// Witnessable](file:///tmp/sp1/crates/recursion/circuit/src/jagged/witness.rs).
// The Ziren bundle stores per-round eval-form sumcheck rounds
// (`JaggedReductionRound { evals: [EF; 3] }`) where SP1 stores
// coefficient-form (`UnivariatePolynomial { coefficients }`); the
// eval→coeff conversion lives at the Phase 2 bundle assembly site,
// not in these per-piece witness reads.

use zkm_stark::basefold::proof::{BasefoldProof, LeafOpening, MerkleOpening};
use zkm_stark::basefold::stacked::StackedBasefoldProof;
use zkm_stark::basefold_late_binding::jagged::JaggedBasefoldBundle;
use zkm_stark::basefold_late_binding::LbMmcs;
use zkm_stark::jagged_sumcheck::{JaggedReductionProof, JaggedReductionRound};

use crate::basefold_verifier::{
    RecursiveBasefoldComponentOpening, RecursiveBasefoldOpening, RecursiveBasefoldProof,
    RecursiveBasefoldRound,
};
use crate::jagged_circuit::{
    JaggedDimensionMetadata, JaggedPcsProofVariable, JaggedSumcheckEvalProof,
    RecursiveStackedPcsProof,
};
use crate::partial_sumcheck::PartialSumcheckProof;
use crate::univariate::{interpolate_3point_evals_at_012, UnivariatePolynomial};

impl<C> Witnessable<C> for JaggedReductionRound<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = JaggedReductionRound<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        JaggedReductionRound { evals: self.evals.read(builder) }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.evals.write(witness);
    }
}

impl<C> Witnessable<C> for JaggedReductionProof<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = JaggedReductionProof<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        JaggedReductionProof {
            rounds: self.rounds.read(builder),
            eval_point: self.eval_point.read(builder),
            q_at_z: self.q_at_z.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.rounds.write(witness);
        self.eval_point.write(witness);
        self.q_at_z.write(witness);
    }
}

/// In-circuit companion to [`zkm_stark::basefold::proof::LeafOpening`].
///
/// `values` is the matrix-of-leaves grid that comes through the witness
/// stream as `Felt` cells; `proof` (Merkle path siblings) is treated as
/// constant base-field digests passed through verbatim — matching the
/// existing pattern in [`crate::basefold_witness`] for
/// `RecursiveBasefoldOpening::merkle_path_digests`.
pub struct LeafOpeningVar<F> {
    pub values: Vec<Vec<Felt<F>>>,
    pub proof: Vec<[F; 8]>,
}

/// In-circuit companion to [`zkm_stark::basefold::proof::MerkleOpening`].
pub struct MerkleOpeningVar<F> {
    pub leaves: Vec<LeafOpeningVar<F>>,
}

impl<C> Witnessable<C> for LeafOpening<InnerVal, LbMmcs>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = LeafOpeningVar<C::F>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        LeafOpeningVar {
            values: self.values.read(builder),
            // Merkle path siblings are constants in the proof — they
            // ride out-of-band; no felt-witness allocation here.
            proof: self.proof.clone(),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.values.write(witness);
        // Constant-valued; no witness-stream writes.
    }
}

impl<C> Witnessable<C> for MerkleOpening<InnerVal, LbMmcs>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = MerkleOpeningVar<C::F>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        MerkleOpeningVar {
            leaves: self.leaves.iter().map(|l| l.read(builder)).collect(),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for leaf in &self.leaves {
            leaf.write(witness);
        }
    }
}

/// Convert a host-side BaseFold component opening (one
/// [`MerkleOpening`]) into the per-round per-query
/// [`RecursiveBasefoldComponentOpening`] vector.
///
/// `leaf_values` passes through verbatim.  `merkle_path_bytes` is
/// left empty — the in-circuit verifier doesn't read these bytes,
/// it walks the Merkle path through the digest field; bytes are a
/// legacy carrier the existing recursion-circuit retains for
/// witness-stream layout compatibility but no longer consumes.
fn host_component_opening_to_recursive(
    opening: &MerkleOpening<InnerVal, LbMmcs>,
) -> Vec<RecursiveBasefoldComponentOpening<InnerVal, InnerChallenge, 8>> {
    opening
        .leaves
        .iter()
        .map(|leaf| RecursiveBasefoldComponentOpening {
            leaf_values: leaf.values.clone(),
            merkle_path_bytes: Vec::new(),
            _phantom: core::marker::PhantomData,
        })
        .collect()
}

/// Convert a host-side BaseFold commit-phase opening (one
/// [`MerkleOpening`]) into the per-round per-query
/// [`RecursiveBasefoldOpening`] vector.
///
/// Per FRI commit-phase shape (see
/// [`zkm_stark::basefold::fri::commit_phase_round`]), each leaf
/// bundles `2 * EF::DIMENSION` base-field elements representing two
/// adjacent EF codeword values (the sibling pair).  This converter
/// parses those into the in-circuit `[EF; 2]` shape and copies the
/// Merkle siblings into `merkle_path_digests` for binding.
///
/// **Position field**: set to `0` placeholder.  Real positions come
/// from the FRI challenger transcript and must be re-derived at the
/// verifier call site (Phase 4 of #241).  The in-circuit verifier
/// recomputes positions from its own challenger anyway, so the
/// `position` field passed through is informational only.
fn host_query_opening_to_recursive(
    opening: &MerkleOpening<InnerVal, LbMmcs>,
) -> Vec<RecursiveBasefoldOpening<InnerVal, InnerChallenge, 8>> {
    use p3_field::BasedVectorSpace;
    const D: usize = 4; // InnerChallenge = BinomialExtensionField<InnerVal, 4>
    opening
        .leaves
        .iter()
        .map(|leaf| {
            assert_eq!(
                leaf.values.len(),
                1,
                "commit-phase leaf must have exactly one inner matrix",
            );
            let row = &leaf.values[0];
            assert_eq!(
                row.len(),
                2 * D,
                "commit-phase leaf row must have 2*EF::DIMENSION = {} base elements, got {}",
                2 * D,
                row.len(),
            );
            let lo = <InnerChallenge as BasedVectorSpace<InnerVal>>::from_basis_coefficients_iter(
                row[..D].iter().copied(),
            )
            .expect("EF parse from D base elements");
            let hi = <InnerChallenge as BasedVectorSpace<InnerVal>>::from_basis_coefficients_iter(
                row[D..2 * D].iter().copied(),
            )
            .expect("EF parse from D base elements");
            RecursiveBasefoldOpening {
                position: 0,
                sibling_pair: [lo, hi],
                merkle_path_bytes: Vec::new(),
                merkle_path_digests: leaf.proof.clone(),
                _phantom: core::marker::PhantomData,
            }
        })
        .collect()
}

/// Convert a host-side [`BasefoldProof`] into the recursion-circuit
/// [`RecursiveBasefoldProof`] shape.
///
/// Mapping:
/// * `rounds[i]` ← (`univariate_messages[i]`, `fri_commitments[i]` 1-cap root)
/// * `final_poly` / `pow_witness` / `batch_grinding_witness` pass through
/// * `component_openings[r]` ← [`host_component_opening_to_recursive`]
/// * `query_phase_openings[r]` ← [`host_query_opening_to_recursive`]
/// * `batch_evaluations` ← caller-supplied (lives on
///   [`StackedBasefoldProof`] one level up; see
///   [`host_stacked_basefold_to_recursive`])
///
/// Output is host-typed; pair with the existing
/// [`RecursiveBasefoldProof`] Witnessable in
/// [`crate::basefold_witness`] for a one-line `.read(builder)` flow.
pub fn host_basefold_proof_to_recursive(
    proof: &BasefoldProof<InnerVal, InnerChallenge, LbMmcs>,
    batch_evaluations: Vec<Vec<InnerChallenge>>,
) -> RecursiveBasefoldProof<InnerVal, InnerChallenge, 8> {
    assert_eq!(
        proof.univariate_messages.len(),
        proof.fri_commitments.len(),
        "BasefoldProof: univariate_messages.len() != fri_commitments.len()",
    );

    let rounds: Vec<RecursiveBasefoldRound<InnerVal, InnerChallenge, 8>> = proof
        .univariate_messages
        .iter()
        .zip(proof.fri_commitments.iter())
        .map(|(uni, commit)| {
            let cap_roots = commit.roots();
            assert_eq!(
                cap_roots.len(),
                1,
                "FRI commitment cap must have exactly 1 root (height-0 cap), got {}",
                cap_roots.len(),
            );
            RecursiveBasefoldRound { uni_poly: *uni, commitment: cap_roots[0] }
        })
        .collect();

    let component_openings: Vec<Vec<RecursiveBasefoldComponentOpening<_, _, 8>>> = proof
        .component_polynomials_query_openings_and_proofs
        .iter()
        .map(host_component_opening_to_recursive)
        .collect();

    let query_phase_openings: Vec<Vec<RecursiveBasefoldOpening<_, _, 8>>> = proof
        .query_phase_openings_and_proofs
        .iter()
        .map(host_query_opening_to_recursive)
        .collect();

    RecursiveBasefoldProof {
        rounds,
        final_poly: proof.final_poly,
        pow_witness: proof.pow_witness,
        batch_grinding_witness: proof.batch_grinding_witness,
        component_openings,
        query_phase_openings,
        batch_evaluations,
    }
}

/// Convert a host-side [`StackedBasefoldProof`] into the
/// recursion-circuit [`RecursiveBasefoldProof`] shape, threading
/// `batch_evaluations` through.  Companion to
/// [`host_basefold_proof_to_recursive`] for the stacked-PCS layer.
pub fn host_stacked_basefold_to_recursive(
    proof: &StackedBasefoldProof<InnerVal, InnerChallenge, LbMmcs>,
) -> RecursiveBasefoldProof<InnerVal, InnerChallenge, 8> {
    host_basefold_proof_to_recursive(&proof.basefold_proof, proof.batch_evaluations.clone())
}

/// Bytes-input adapter for [`lift_jagged_basefold_bundle`].
///
/// Deserializes `evaluation_proof_bytes` (rmp-serde wire format) into
/// a [`JaggedBasefoldBundle`] then calls
/// [`lift_jagged_basefold_bundle`].  When bytes are empty (the
/// scaffolding-test path that the existing
/// [`crate::jagged_pcs_lift::lift_evaluation_proof_bytes`] handles
/// gracefully) or malformed, falls back to the all-zero placeholder
/// from `lift_evaluation_proof_bytes` so behavior matches the existing
/// recursion-circuit machine flows byte-for-byte.
///
/// Phase 4a callers (compress/wrap/deferred/core_basefold +
/// shard_proof_variable_lift) can adopt this adapter via a one-line
/// swap from `lift_evaluation_proof_bytes(...)` →
/// `lift_evaluation_proof_via_bundle(...)`.  Phase 4b will then
/// finish the cutover by changing the upstream
/// `BasefoldShardProof.evaluation_proof` field type from `Vec<u8>` to
/// `JaggedBasefoldBundle`, eliminating this adapter and the
/// rmp-serde round trip — which is the actual fix for the #240
/// determinism cascade.
pub fn lift_evaluation_proof_via_bundle<C>(
    builder: &mut Builder<C>,
    bytes: &[u8],
    max_log_row_count: usize,
    column_counts_by_round: &[Vec<usize>],
) -> JaggedPcsProofVariable<
    RecursiveBasefoldProof<C::F, C::EF, 8>,
    [Felt<C::F>; 8],
    C::F,
    C::EF,
>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    if let Some(bundle) = JaggedBasefoldBundle::from_bytes(bytes) {
        lift_jagged_basefold_bundle(builder, &bundle, max_log_row_count, column_counts_by_round)
    } else {
        // Empty / malformed bytes — fall back to the all-zero
        // placeholder (preserves shape compatibility with scaffolding
        // tests and the BasefoldShardProof::empty() construction
        // path).
        crate::jagged_pcs_lift::lift_evaluation_proof_bytes::<C>(
            builder,
            bytes,
            max_log_row_count,
            column_counts_by_round,
        )
    }
}

/// Lift a host-side [`JaggedBasefoldBundle`] into the in-circuit
/// [`JaggedPcsProofVariable`] shape — the structured replacement for
/// [`crate::jagged_pcs_lift::lift_evaluation_proof_bytes`].
///
/// **Phase 4a substance** (real data threaded into the variable):
/// * `sumcheck_proof` ← [`jagged_reduction_to_partial_sumcheck`] on `bundle.reduction`
///   (eval-form rounds → coeff-form polys, claimed_sum derived).
/// * `pcs_proof.batch_evaluations` ← witnessed copy of
///   `bundle.basefold_proof.batch_evaluations`.
/// * `pcs_proof.pcs_proof` ← [`host_stacked_basefold_to_recursive`] on
///   `bundle.basefold_proof` (rounds, openings, scalar fields).
/// * `original_commitments[0]` ← `bundle.commit.commitment` 1-cap root
///   (witnessed as `[Felt<F>; 8]`).
/// * `column_counts` ← caller-supplied `column_counts_by_round` (verbatim).
///
/// **Phase 4b TODO** (still-placeholder, awaiting cross-context derivation):
/// * `params.col_prefix_sums` — needs bit-decomposition of
///   `bundle.packing.offsets` against `max_log_row_count`; currently
///   zero-felts of the right shape (matches existing lift placeholder).
/// * `jagged_eval_proof` — Ziren's bundle does not carry the SP1
///   jagged-eval sub-proof yet (the prover only emits the reduction
///   sumcheck); placeholder polynomial set to zero coeffs of the
///   right degree.
/// * `row_counts` — per-round per-chip Felt-witnessed bit-decomp;
///   currently zero felts shape-aligned with `column_counts_by_round`.
///
/// **NOT a placeholder anymore (Phase 4a follow-up)**:
/// * `expected_eval` ← `bundle.reduction.q_at_z` — the verifier's
///   closing identity at recursive_jagged_pcs.rs:279 asserts
///   `jagged_eval * expected_eval == sumcheck.point_and_eval.1`
///   which mirrors the host verifier's terminal
///   `q_at_z * w(z) == current_claim` (jagged_sumcheck.rs verify
///   path); `q_at_z` is exactly the prover-emitted `expected_eval`.
///
/// Output type matches [`crate::jagged_pcs_lift::lift_evaluation_proof_bytes`]
/// so downstream callers can swap with no shape change.
pub fn lift_jagged_basefold_bundle<C>(
    builder: &mut Builder<C>,
    bundle: &JaggedBasefoldBundle,
    max_log_row_count: usize,
    column_counts_by_round: &[Vec<usize>],
) -> JaggedPcsProofVariable<
    RecursiveBasefoldProof<C::F, C::EF, 8>,
    [Felt<C::F>; 8],
    C::F,
    C::EF,
>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    use p3_field::PrimeCharacteristicRing;

    let zero_felt = |b: &mut Builder<C>| -> Felt<C::F> { b.constant(C::F::ZERO) };
    let zero_ext = |b: &mut Builder<C>| -> Ext<C::F, C::EF> { b.constant(C::EF::ZERO) };
    let zero_uni_poly =
        |b: &mut Builder<C>, degree: usize| -> UnivariatePolynomial<Ext<C::F, C::EF>> {
            UnivariatePolynomial { coefficients: (0..=degree).map(|_| zero_ext(b)).collect() }
        };

    // ── Padding shape (mirror of jagged_pcs_lift.rs:111-137) ──
    let total_cols_before_pad: usize = column_counts_by_round
        .iter()
        .map(|cc| {
            let flattened = cc.iter().sum::<usize>();
            let added = if cc.len() >= 2 { cc[cc.len() - 2] + 1 } else { 1 };
            flattened + added
        })
        .sum();
    let padded_cols = total_cols_before_pad.max(1).next_power_of_two();
    let col_prefix_sums_len = padded_cols + 1;
    let num_col_variables = padded_cols.trailing_zeros() as usize;
    let num_rounds = column_counts_by_round.len().max(1);

    // ── REAL: sumcheck_proof from bundle.reduction ──
    // Convert eval-form rounds to coeff-form polys, then witness via
    // the existing PartialSumcheckProof Witnessable impl
    // (basefold_witness.rs:73).
    let host_sumcheck = jagged_reduction_to_partial_sumcheck(&bundle.reduction);
    let sumcheck_proof: PartialSumcheckProof<Ext<C::F, C::EF>> =
        <_ as Witnessable<C>>::read(&host_sumcheck, builder);

    // ── REAL: basefold proof from bundle.basefold_proof ──
    // host_stacked_basefold_to_recursive folds the basefold rounds,
    // commit-phase openings, and component openings into the
    // RecursiveBasefoldProof shape.  The existing Witnessable impl
    // on RecursiveBasefoldProof (basefold_witness.rs:443) treats the
    // EF/F scalar fields as constants (uni_poly, commitment,
    // final_poly, pow_witness, etc.) and witnesses the component +
    // query_phase openings.
    let host_basefold = host_stacked_basefold_to_recursive(&bundle.basefold_proof);
    let basefold_proof_var = <_ as Witnessable<C>>::read(&host_basefold, builder);

    // ── REAL: batch_evaluations as Ext (witnessed for stacked layer) ──
    // The RecursiveStackedPcsProof wrapper keeps batch_evaluations
    // separately at Ext<F,EF> level (so they can flow through the
    // sumcheck identity in-circuit), in addition to the constant
    // copy living inside the RecursiveBasefoldProof itself.
    let batch_evaluations_ext: Vec<Vec<Ext<C::F, C::EF>>> = bundle
        .basefold_proof
        .batch_evaluations
        .iter()
        .map(|round| {
            round
                .iter()
                .map(|ef| <_ as Witnessable<C>>::read(ef, builder))
                .collect()
        })
        .collect();

    let stacked_pcs_proof = RecursiveStackedPcsProof::<
        RecursiveBasefoldProof<C::F, C::EF, 8>,
        C::F,
        C::EF,
    > {
        batch_evaluations: batch_evaluations_ext,
        pcs_proof: basefold_proof_var,
    };

    // ── REAL: original_commitments[0] from bundle.commit ──
    // The committed cap is height-0 (1 root) for the BaseFold
    // late-binding adapter — see basefold_late_binding.rs.
    let cap_roots = bundle.commit.commitment.roots();
    assert_eq!(
        cap_roots.len(),
        1,
        "BasefoldLateBindingCommit cap must have exactly 1 root, got {}",
        cap_roots.len(),
    );
    let first_commit_digest: [Felt<C::F>; 8] =
        core::array::from_fn(|i| <_ as Witnessable<C>>::read(&cap_roots[0][i], builder));
    // For multi-round (jagged with rotating commits) the bundle
    // would have one cap per round.  Currently Ziren commits the
    // jagged-PCS to one batched cap, so subsequent round slots get
    // zero-felt placeholders to match the verifier's
    // num_rounds-shape expectation.
    let mut original_commitments: Vec<[Felt<C::F>; 8]> = Vec::with_capacity(num_rounds);
    original_commitments.push(first_commit_digest);
    for _ in 1..num_rounds {
        original_commitments.push(core::array::from_fn(|_| zero_felt(builder)));
    }

    // ── PLACEHOLDER (Phase 4b): jagged_eval_proof + params + row_counts ──
    //
    // jagged_eval_proof: the sub-protocol proof.  Ziren's bundle
    // does not carry this — the prover only emits the outer
    // reduction sumcheck.  Until SP1's full eval-sub-protocol is
    // ported, keep a degree-1 zero placeholder of the right shape.
    let jagged_eval_proof = JaggedSumcheckEvalProof::<Ext<C::F, C::EF>> {
        partial_sumcheck_proof: PartialSumcheckProof {
            univariate_polys: (0..num_col_variables)
                .map(|_| zero_uni_poly(builder, 1))
                .collect(),
            claimed_sum: zero_ext(builder),
            point_and_eval: (
                (0..num_col_variables).map(|_| zero_ext(builder)).collect(),
                zero_ext(builder),
            ),
        },
    };

    let jagged_dim_metadata = JaggedDimensionMetadata::<Felt<C::F>> {
        col_prefix_sums: (0..col_prefix_sums_len)
            .map(|_| (0..max_log_row_count + 1).map(|_| zero_felt(builder)).collect())
            .collect(),
    };

    let row_counts: Vec<Vec<Felt<C::F>>> = column_counts_by_round
        .iter()
        .map(|cc| cc.iter().map(|_| zero_felt(builder)).collect())
        .collect();

    // ── REAL: expected_eval from bundle.reduction.q_at_z ──
    // The in-circuit verifier's closing identity
    // (recursive_jagged_pcs.rs:279) asserts
    //     jagged_eval * expected_eval == sumcheck.point_and_eval.1
    // which mirrors the host verifier's terminal check
    //     q_at_z * w(z) == current_claim
    // (jagged_sumcheck.rs verify_jagged_reduction).  `expected_eval`
    // therefore takes the role of `q_at_z` — the dense-trace
    // evaluation at the reduction's z*.  Witness through the
    // existing InnerChallenge Witnessable.
    let expected_eval: Ext<C::F, C::EF> =
        <_ as Witnessable<C>>::read(&bundle.reduction.q_at_z, builder);

    // ── Top-level assembly ──
    JaggedPcsProofVariable {
        params: jagged_dim_metadata,
        sumcheck_proof,
        jagged_eval_proof,
        pcs_proof: stacked_pcs_proof,
        column_counts: column_counts_by_round.to_vec(),
        row_counts,
        original_commitments,
        expected_eval,
    }
}

/// Convert a host-side eval-form jagged sumcheck proof into the
/// coefficient-form [`PartialSumcheckProof`] that the in-circuit
/// jagged-PCS verifier consumes.
///
/// Field mapping:
/// * `univariate_polys[i]` ← Lagrange-interpolate `rounds[i].evals`
///   at `x ∈ {0, 1, 2}` via [`interpolate_3point_evals_at_012`].
/// * `claimed_sum` ← `rounds[0].evals[0] + rounds[0].evals[1]`
///   (the round-0 sum-hypothesis identity `g(0) + g(1) = S`).
/// * `point_and_eval.0` ← `eval_point`.
/// * `point_and_eval.1` ← last round's polynomial evaluated at
///   `eval_point[last]`.
///
/// Output is a host-typed `PartialSumcheckProof<InnerChallenge>` that
/// can be `.read(builder)` via the existing impl in
/// [`crate::basefold_witness`].  No witness-stream interaction here.
pub fn jagged_reduction_to_partial_sumcheck(
    proof: &JaggedReductionProof<InnerChallenge>,
) -> PartialSumcheckProof<InnerChallenge> {
    assert_eq!(
        proof.rounds.len(),
        proof.eval_point.len(),
        "jagged reduction: rounds.len() must equal eval_point.len()",
    );
    assert!(
        !proof.rounds.is_empty(),
        "jagged reduction: at least one round required for claimed_sum",
    );

    let univariate_polys: Vec<UnivariatePolynomial<InnerChallenge>> = proof
        .rounds
        .iter()
        .map(|r| interpolate_3point_evals_at_012(r.evals))
        .collect();

    let claimed_sum = proof.rounds[0].evals[0] + proof.rounds[0].evals[1];

    let last_idx = proof.rounds.len() - 1;
    let final_eval = univariate_polys[last_idx].eval_at_point(proof.eval_point[last_idx]);

    PartialSumcheckProof {
        univariate_polys,
        claimed_sum,
        point_and_eval: (proof.eval_point.clone(), final_eval),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;

    type C = InnerConfig;

    /// Construction smoke test: BasefoldShardProof Witnessable
    /// can be invoked against an empty proof shape.  Verifies the
    /// trait composition compiles end-to-end.
    #[test]
    fn shard_proof_witness_compiles() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let proof = zkm_stark::shard_level::shard_proof::BasefoldShardProof::<
            InnerVal,
            InnerChallenge,
        >::empty(std::array::from_fn(|_| InnerVal::ZERO), 8);
        let (main_commit, pvs, _logup, _zerocheck, evbytes) =
            <_ as Witnessable<C>>::read(&proof, &mut builder);
        assert_eq!(main_commit.len(), 8);
        assert_eq!(pvs.len(), 8);
        assert!(evbytes.is_empty());
    }

    /// #241 Phase 1: JaggedReductionRound Witnessable round-trips a
    /// 3-EF struct through the witness stream.
    #[test]
    fn jagged_reduction_round_witnessable_reads() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let host = JaggedReductionRound::<InnerChallenge> {
            evals: [InnerChallenge::ZERO; 3],
        };
        let var: JaggedReductionRound<Ext<InnerVal, InnerChallenge>> =
            <_ as Witnessable<C>>::read(&host, &mut builder);
        assert_eq!(var.evals.len(), 3);
    }

    /// #241 Phase 1: JaggedReductionProof Witnessable cascades through
    /// rounds + eval_point + q_at_z.
    #[test]
    fn jagged_reduction_proof_witnessable_reads() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let host = JaggedReductionProof::<InnerChallenge> {
            rounds: vec![
                JaggedReductionRound { evals: [InnerChallenge::ZERO; 3] },
                JaggedReductionRound { evals: [InnerChallenge::ZERO; 3] },
            ],
            eval_point: vec![InnerChallenge::ZERO; 4],
            q_at_z: InnerChallenge::ZERO,
        };
        let var = <_ as Witnessable<C>>::read(&host, &mut builder);
        assert_eq!(var.rounds.len(), 2);
        assert_eq!(var.eval_point.len(), 4);
    }

    /// #241 Phase 1: LeafOpening Witnessable handles the (Vec<Vec<F>>,
    /// MT::Proof const-passthrough) split correctly.
    #[test]
    fn leaf_opening_witnessable_reads() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let host = LeafOpening::<InnerVal, LbMmcs> {
            values: vec![vec![InnerVal::ZERO; 4], vec![InnerVal::ZERO; 4]],
            proof: vec![[InnerVal::ZERO; 8]; 3],
        };
        let var = <_ as Witnessable<C>>::read(&host, &mut builder);
        assert_eq!(var.values.len(), 2);
        assert_eq!(var.values[0].len(), 4);
        assert_eq!(var.proof.len(), 3);
    }

    /// #241 Phase 1: MerkleOpening Witnessable composes through a Vec
    /// of LeafOpenings.
    #[test]
    fn merkle_opening_witnessable_reads() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let leaf = LeafOpening::<InnerVal, LbMmcs> {
            values: vec![vec![InnerVal::ZERO; 2]],
            proof: vec![[InnerVal::ZERO; 8]; 2],
        };
        let host = MerkleOpening::<InnerVal, LbMmcs> {
            leaves: vec![leaf.clone(), leaf],
        };
        let var = <_ as Witnessable<C>>::read(&host, &mut builder);
        assert_eq!(var.leaves.len(), 2);
    }

    /// #241 Phase 2: eval-form → coeff-form converter shape sanity.
    /// Output univariate count matches input round count and the
    /// reconstructed polys agree with the input evals at x ∈ {0,1,2}.
    #[test]
    fn jagged_reduction_converter_shape_and_roundtrip() {
        use p3_field::PrimeCharacteristicRing;
        let mk = |a: u16, b: u16, c: u16| JaggedReductionRound::<InnerChallenge> {
            evals: [
                InnerChallenge::from_u16(a),
                InnerChallenge::from_u16(b),
                InnerChallenge::from_u16(c),
            ],
        };
        let proof = JaggedReductionProof::<InnerChallenge> {
            rounds: vec![mk(1, 2, 7), mk(0, 5, 12), mk(3, 3, 3)],
            eval_point: vec![
                InnerChallenge::from_u16(11),
                InnerChallenge::from_u16(13),
                InnerChallenge::from_u16(17),
            ],
            q_at_z: InnerChallenge::from_u16(99),
        };
        let psp = jagged_reduction_to_partial_sumcheck(&proof);
        assert_eq!(psp.univariate_polys.len(), 3);
        assert_eq!(psp.point_and_eval.0.len(), 3);
        // Round 0: p(0)=1, p(1)=2 → claimed_sum = 3.
        assert_eq!(psp.claimed_sum, InnerChallenge::from_u16(3));
        // Each univariate poly's evals at 0/1/2 round-trip to the
        // original [p0, p1, p2].
        for (round, poly) in proof.rounds.iter().zip(psp.univariate_polys.iter()) {
            assert_eq!(
                poly.eval_at_point(InnerChallenge::ZERO),
                round.evals[0],
            );
            assert_eq!(
                poly.eval_at_point(InnerChallenge::ONE),
                round.evals[1],
            );
            assert_eq!(
                poly.eval_at_point(InnerChallenge::from_u8(2)),
                round.evals[2],
            );
        }
        // final_eval = last round's poly evaluated at last
        // eval_point coordinate.
        let last = psp.univariate_polys.last().unwrap();
        let expected_final = last.eval_at_point(proof.eval_point[2]);
        assert_eq!(psp.point_and_eval.1, expected_final);
    }

    /// #241 Phase 2: converter output flows through the existing
    /// `PartialSumcheckProof` Witnessable impl.  Confirms the bridge
    /// composes with the pre-existing recursion-circuit witness
    /// surface (basefold_witness.rs:73).
    #[test]
    fn jagged_reduction_converter_witnessable_composition() {
        use p3_field::PrimeCharacteristicRing;
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let proof = JaggedReductionProof::<InnerChallenge> {
            rounds: vec![JaggedReductionRound {
                evals: [InnerChallenge::ONE, InnerChallenge::ZERO, InnerChallenge::ZERO],
            }],
            eval_point: vec![InnerChallenge::ZERO],
            q_at_z: InnerChallenge::ZERO,
        };
        let psp = jagged_reduction_to_partial_sumcheck(&proof);
        let _var: PartialSumcheckProof<Ext<InnerVal, InnerChallenge>> =
            <_ as Witnessable<C>>::read(&psp, &mut builder);
    }

    /// #241 Phase 3: empty BaseFold proof converts to empty
    /// recursive shape — exercises the rounds.iter().zip path with
    /// zero rounds and the components/query_phase pass-through.
    #[test]
    fn host_basefold_proof_converter_empty() {
        let proof = BasefoldProof::<InnerVal, InnerChallenge, LbMmcs> {
            univariate_messages: vec![],
            fri_commitments: vec![],
            component_polynomials_query_openings_and_proofs: vec![],
            query_phase_openings_and_proofs: vec![],
            final_poly: InnerChallenge::ZERO,
            pow_witness: InnerVal::ZERO,
            batch_grinding_witness: InnerVal::ZERO,
        };
        let recur = host_basefold_proof_to_recursive(&proof, vec![]);
        assert_eq!(recur.rounds.len(), 0);
        assert_eq!(recur.component_openings.len(), 0);
        assert_eq!(recur.query_phase_openings.len(), 0);
        assert_eq!(recur.batch_evaluations.len(), 0);
    }

    /// #241 Phase 3: rounds preserve uni_poly + extracted cap root.
    /// The cap-extraction asserts the 1-cap invariant in
    /// host_basefold_proof_to_recursive.
    #[test]
    fn host_basefold_proof_converter_round_shape() {
        use p3_field::PrimeCharacteristicRing;
        use p3_symmetric::MerkleCap;
        let uni_poly: [InnerChallenge; 2] =
            [InnerChallenge::from_u8(7), InnerChallenge::from_u8(11)];
        let digest: [InnerVal; 8] = core::array::from_fn(|i| InnerVal::from_u16(i as u16));
        let cap = MerkleCap::<InnerVal, [InnerVal; 8]>::new(vec![digest]);
        let proof = BasefoldProof::<InnerVal, InnerChallenge, LbMmcs> {
            univariate_messages: vec![uni_poly],
            fri_commitments: vec![cap],
            component_polynomials_query_openings_and_proofs: vec![],
            query_phase_openings_and_proofs: vec![],
            final_poly: InnerChallenge::from_u8(99),
            pow_witness: InnerVal::from_u8(13),
            batch_grinding_witness: InnerVal::from_u8(17),
        };
        let recur = host_basefold_proof_to_recursive(&proof, vec![]);
        assert_eq!(recur.rounds.len(), 1);
        assert_eq!(recur.rounds[0].uni_poly, uni_poly);
        assert_eq!(recur.rounds[0].commitment, digest);
        assert_eq!(recur.final_poly, InnerChallenge::from_u8(99));
        assert_eq!(recur.pow_witness, InnerVal::from_u8(13));
        assert_eq!(recur.batch_grinding_witness, InnerVal::from_u8(17));
    }

    /// #241 Phase 3: query-phase opening parses leaf row
    /// `[F; 2*D]` into `[EF; 2]` sibling pair via the binomial
    /// extension's `from_basis_coefficients_iter`.
    #[test]
    fn host_query_opening_extracts_sibling_pair() {
        use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
        let lo_basis: [InnerVal; 4] = [
            InnerVal::from_u8(1),
            InnerVal::from_u8(2),
            InnerVal::from_u8(3),
            InnerVal::from_u8(4),
        ];
        let hi_basis: [InnerVal; 4] = [
            InnerVal::from_u8(5),
            InnerVal::from_u8(6),
            InnerVal::from_u8(7),
            InnerVal::from_u8(8),
        ];
        let mut row = lo_basis.to_vec();
        row.extend_from_slice(&hi_basis);
        let leaf = LeafOpening::<InnerVal, LbMmcs> {
            values: vec![row],
            proof: vec![[InnerVal::ZERO; 8]; 5],
        };
        let opening = MerkleOpening::<InnerVal, LbMmcs> { leaves: vec![leaf] };
        let recur = host_query_opening_to_recursive(&opening);
        assert_eq!(recur.len(), 1);
        let expected_lo =
            <InnerChallenge as BasedVectorSpace<InnerVal>>::from_basis_coefficients_iter(
                lo_basis.iter().copied(),
            )
            .unwrap();
        let expected_hi =
            <InnerChallenge as BasedVectorSpace<InnerVal>>::from_basis_coefficients_iter(
                hi_basis.iter().copied(),
            )
            .unwrap();
        assert_eq!(recur[0].sibling_pair, [expected_lo, expected_hi]);
        assert_eq!(recur[0].merkle_path_digests.len(), 5);
        assert_eq!(recur[0].position, 0);
    }

    /// #241 Phase 3: stacked converter threads batch_evaluations from
    /// the host StackedBasefoldProof verbatim.
    #[test]
    fn host_stacked_basefold_threads_batch_evaluations() {
        use p3_field::PrimeCharacteristicRing;
        let bf_proof = BasefoldProof::<InnerVal, InnerChallenge, LbMmcs> {
            univariate_messages: vec![],
            fri_commitments: vec![],
            component_polynomials_query_openings_and_proofs: vec![],
            query_phase_openings_and_proofs: vec![],
            final_poly: InnerChallenge::ZERO,
            pow_witness: InnerVal::ZERO,
            batch_grinding_witness: InnerVal::ZERO,
        };
        let stacked = StackedBasefoldProof::<InnerVal, InnerChallenge, LbMmcs> {
            basefold_proof: bf_proof,
            batch_evaluations: vec![
                vec![InnerChallenge::from_u8(1), InnerChallenge::from_u8(2)],
                vec![InnerChallenge::from_u8(3)],
            ],
        };
        let recur = host_stacked_basefold_to_recursive(&stacked);
        assert_eq!(recur.batch_evaluations.len(), 2);
        assert_eq!(recur.batch_evaluations[0].len(), 2);
        assert_eq!(recur.batch_evaluations[1].len(), 1);
        assert_eq!(recur.batch_evaluations[0][0], InnerChallenge::from_u8(1));
    }

    /// #241 Phase 3: converter output flows through the existing
    /// `RecursiveBasefoldProof` Witnessable impl
    /// (basefold_witness.rs:443) — confirms the bridge composes
    /// end-to-end with the pre-existing witness surface.
    #[test]
    fn host_basefold_converter_witnessable_composition() {
        use p3_field::PrimeCharacteristicRing;
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let proof = BasefoldProof::<InnerVal, InnerChallenge, LbMmcs> {
            univariate_messages: vec![],
            fri_commitments: vec![],
            component_polynomials_query_openings_and_proofs: vec![],
            query_phase_openings_and_proofs: vec![],
            final_poly: InnerChallenge::ZERO,
            pow_witness: InnerVal::ZERO,
            batch_grinding_witness: InnerVal::ZERO,
        };
        let recur = host_basefold_proof_to_recursive(&proof, vec![]);
        let _var = <_ as Witnessable<C>>::read(&recur, &mut builder);
    }

    /// #241 Phase 4a: bytes adapter falls back to zero placeholder
    /// for empty bytes (matches the BasefoldShardProof::empty path).
    #[test]
    fn lift_evaluation_proof_via_bundle_empty_bytes_falls_back() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let cols: Vec<Vec<usize>> = vec![vec![3], vec![5]];
        let var = lift_evaluation_proof_via_bundle::<C>(&mut builder, &[], 21, &cols);
        assert_eq!(var.column_counts, cols);
        assert_eq!(var.original_commitments.len(), 2);
    }

    /// #241 Phase 4a: bytes adapter routes a real bundle's bytes
    /// through lift_jagged_basefold_bundle.  Round-trips serialize +
    /// deserialize via rmp-serde, then lifts.
    #[test]
    fn lift_evaluation_proof_via_bundle_real_bundle_bytes() {
        use p3_field::PrimeCharacteristicRing;
        use p3_symmetric::MerkleCap;
        use zkm_stark::basefold_late_binding::jagged::PackingMeta;
        use zkm_stark::basefold_late_binding::BasefoldLateBindingCommit;

        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let cap_digest: [InnerVal; 8] = [InnerVal::ZERO; 8];
        let bundle = JaggedBasefoldBundle {
            reduction: JaggedReductionProof::<InnerChallenge> {
                rounds: vec![JaggedReductionRound {
                    evals: [InnerChallenge::ZERO; 3],
                }],
                eval_point: vec![InnerChallenge::ZERO],
                q_at_z: InnerChallenge::ZERO,
            },
            basefold_proof: StackedBasefoldProof::<InnerVal, InnerChallenge, LbMmcs> {
                basefold_proof: BasefoldProof {
                    univariate_messages: vec![],
                    fri_commitments: vec![],
                    component_polynomials_query_openings_and_proofs: vec![],
                    query_phase_openings_and_proofs: vec![],
                    final_poly: InnerChallenge::ZERO,
                    pow_witness: InnerVal::ZERO,
                    batch_grinding_witness: InnerVal::ZERO,
                },
                batch_evaluations: vec![],
            },
            y_per_chip: vec![],
            commit: BasefoldLateBindingCommit {
                commitment: MerkleCap::<InnerVal, [InnerVal; 8]>::new(vec![cap_digest]),
                chip_dims: vec![],
                area: 0,
                log_stacking_height: 0,
            },
            packing: PackingMeta {
                offsets: vec![],
                total_values: 0,
                log_dense_size: 0,
                column_counts: vec![],
            },
        };
        let bytes = bundle.to_bytes();
        let cols: Vec<Vec<usize>> = vec![vec![3]];
        let var = lift_evaluation_proof_via_bundle::<C>(&mut builder, &bytes, 21, &cols);
        assert_eq!(var.column_counts, cols);
        // sumcheck_proof has the real reduction round (1 univariate poly).
        assert_eq!(var.sumcheck_proof.univariate_polys.len(), 1);
    }

    /// #241 Phase 4a: bundle lift produces a structurally valid
    /// JaggedPcsProofVariable with shape matching the existing
    /// lift_evaluation_proof_bytes placeholder for empty bundles.
    #[test]
    fn lift_jagged_basefold_bundle_smoke() {
        use p3_field::PrimeCharacteristicRing;
        use p3_symmetric::MerkleCap;
        use zkm_stark::basefold_late_binding::jagged::PackingMeta;
        use zkm_stark::basefold_late_binding::BasefoldLateBindingCommit;

        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        // Minimal-but-valid bundle: one reduction round, empty
        // basefold proof, single-cap commit.
        let cap_digest: [InnerVal; 8] = [InnerVal::ZERO; 8];
        let bundle = JaggedBasefoldBundle {
            reduction: JaggedReductionProof::<InnerChallenge> {
                rounds: vec![JaggedReductionRound {
                    evals: [InnerChallenge::ZERO; 3],
                }],
                eval_point: vec![InnerChallenge::ZERO],
                q_at_z: InnerChallenge::ZERO,
            },
            basefold_proof: StackedBasefoldProof::<InnerVal, InnerChallenge, LbMmcs> {
                basefold_proof: BasefoldProof {
                    univariate_messages: vec![],
                    fri_commitments: vec![],
                    component_polynomials_query_openings_and_proofs: vec![],
                    query_phase_openings_and_proofs: vec![],
                    final_poly: InnerChallenge::ZERO,
                    pow_witness: InnerVal::ZERO,
                    batch_grinding_witness: InnerVal::ZERO,
                },
                batch_evaluations: vec![],
            },
            y_per_chip: vec![],
            commit: BasefoldLateBindingCommit {
                commitment: MerkleCap::<InnerVal, [InnerVal; 8]>::new(vec![cap_digest]),
                chip_dims: vec![],
                area: 0,
                log_stacking_height: 0,
            },
            packing: PackingMeta {
                offsets: vec![],
                total_values: 0,
                log_dense_size: 0,
                column_counts: vec![],
            },
        };
        let cols: Vec<Vec<usize>> = vec![vec![3], vec![5]];
        let var = lift_jagged_basefold_bundle::<C>(&mut builder, &bundle, 21, &cols);
        // column_counts pass through verbatim.
        assert_eq!(var.column_counts, cols);
        // num_rounds == 2 → 2 commitment slots, first from bundle,
        // rest zero placeholders.
        assert_eq!(var.original_commitments.len(), 2);
        // sumcheck_proof has one univariate poly (one reduction round).
        assert_eq!(var.sumcheck_proof.univariate_polys.len(), 1);
    }
}
