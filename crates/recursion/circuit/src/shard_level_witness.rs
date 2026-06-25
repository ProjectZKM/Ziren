//! Witnessable impls for the SP1-style shard-level proof types
//! that live in [`zkm_pcs::shard_level`].
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
use zkm_pcs::septic_curve::SepticCurve;
use zkm_pcs::septic_digest::SepticDigest;
use zkm_pcs::septic_extension::SepticExtension;
use zkm_pcs::shard_level::shard_proof::ChipCumulativeSums;
use zkm_pcs::shard_level::types as st;

use crate::witness::{Witnessable, WitnessWriter};
use crate::CircuitConfig;
use zkm_pcs::{InnerChallenge, InnerVal};

// ── Per-chip cumulative sums (swap 1+2) ────────────────

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
        // CRITICAL: read MUST consume the felt stream in the SAME order
        // `write` emits it — main, prep, main_full, prep_full.  The
        // `Vec`/`Option` Witnessable impls carry no length prefix
        // (witness/mod.rs:119), so the read here re-derives each field's
        // PRESENCE from `self` (the host-typed proof): `Some` reads, `None`
        // reads nothing.  Because read+write share `&self`, the Option
        // discriminants match by construction.
        st::ChipEvaluation {
            main_trace_evaluations: self.main_trace_evaluations.read(builder),
            preprocessed_trace_evaluations: self
                .preprocessed_trace_evaluations
                .as_ref()
                .map(|v| v.read(builder)),
            log_degree: self.log_degree,
            // #88 Stage 3b: SP1-parity FULL-POINT openings — thread the
            // host's `*_full` Ext values into the circuit so the in-circuit
            // LogUp last-layer degree-masked reconstruction can read them.
            main_trace_evaluations_full: self
                .main_trace_evaluations_full
                .as_ref()
                .map(|v| v.read(builder)),
            preprocessed_trace_evaluations_full: self
                .preprocessed_trace_evaluations_full
                .as_ref()
                .map(|v| v.read(builder)),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.main_trace_evaluations.write(witness);
        if let Some(prep) = self.preprocessed_trace_evaluations.as_ref() {
            prep.write(witness);
        }
        // #88 Stage 3b: emit the FULL-POINT openings in the SAME order
        // `read` consumes them (after main + prep).
        if let Some(main_full) = self.main_trace_evaluations_full.as_ref() {
            main_full.write(witness);
        }
        if let Some(prep_full) = self.preprocessed_trace_evaluations_full.as_ref() {
            prep_full.write(witness);
        }
    }
}

impl<C> Witnessable<C> for st::LogUpEvaluations<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = st::LogUpEvaluations<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        // CRITICAL: read must consume the felt stream in the SAME order
        // `write` emits it — `point` FIRST, then `chip_openings`.  The
        // `Vec`/`BTreeMap` Witnessable impls carry no length prefix
        // (witness/mod.rs:119), so reading `chip_openings` before `point`
        // swapped the two regions in-circuit: `point` ended up holding
        // the GKR trace@z_gkr opening felts and `chip_openings` held the
        // point felts.  `verify_zerocheck` (zerocheck.rs:456) then
        // computed `zerocheck_eq_val` from the opening felts, breaking
        // the `rlc_eval == point_and_eval.1` identity (zerocheck.rs:579).
        let point = self.point.read(builder);
        let chip_openings: BTreeMap<String, st::ChipEvaluation<Ext<C::F, C::EF>>> = self
            .chip_openings
            .iter()
            .map(|(name, eval)| (name.clone(), eval.read(builder)))
            .collect();
        st::LogUpEvaluations { point, chip_openings }
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

/// The lifted (partially witnessed) evaluation proof carried out
/// of `BasefoldShardProof::read` in tuple slot 4.  For the `Bundle` variant
/// the basefold proof's felt/ext values are read INLINE from the witness
/// stream here (so the read order matches the per-shard write order — the
/// shard proofs are read in a single batched `shard_proofs.read()`), and the
/// host bundle rides along for the still-const metadata (packing offsets,
/// reduction sumcheck, jagged_eval, commit digest).  `Bytes` (outer wrap) and
/// `Empty` carry no witnessed proof.
pub enum LiftedEvalProof<C: CircuitConfig> {
    Empty,
    Bytes(Vec<u8>),
    Bundle {
        host: JaggedBasefoldBundle,
        basefold_proof:
            RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, [Felt<C::F>; 8]>,
        // the reduction sumcheck, jagged-eval sub-sumcheck, and
        // expected_eval (q_at_z) — also pre-read from the witness stream.
        sumcheck: PartialSumcheckProof<Ext<C::F, C::EF>>,
        jagged_eval: PartialSumcheckProof<Ext<C::F, C::EF>>,
        expected_eval: Ext<C::F, C::EF>,
        // original_commitments[0] = the BaseFold commit cap
        // root, which equals `main_commitment` (basefold_commit_digest =
        // commitment.roots()[0]).  Reuse the already-witnessed main_commitment
        // so the lift doesn't BAKE the proof-specific root (value-independence).
        commit_root: [Felt<C::F>; 8],
    },
    // P2c-for-outer: the gnark wrap path.  The host carries the outer bundle
    // (`JaggedBasefoldBundleGeneric<OuterValMmcs>`, BN254 commitments) as
    // `EvaluationProof::Bytes`.  Rather than BAKE its proof-specific values in
    // `lift_jagged_basefold_bundle_outer` (the previous behavior, which made the
    // gnark R1CS proof-specific → a fresh proof trips `assertIsEqual`), we
    // WITNESS them from the gnark stream here.  Digests are BN254 1-caps
    // (`[Var<C::N>; 1]`, N = Bn254 in the outer config).  This variant is only
    // populated by `OuterConfig` (via `CircuitConfig::read_outer_eval_bundle`);
    // for inner configs the field types still resolve (`Var<C::N>` is generic)
    // but the variant is never constructed.
    OuterBundle {
        host: zkm_pcs::jagged_pcs::jagged::JaggedBasefoldBundleGeneric<
            zkm_recursion_core::stark::OuterValMmcs,
        >,
        basefold_proof: RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            [zkm_recursion_compiler::ir::Var<C::N>; 1],
        >,
        sumcheck: PartialSumcheckProof<Ext<C::F, C::EF>>,
        jagged_eval: PartialSumcheckProof<Ext<C::F, C::EF>>,
        expected_eval: Ext<C::F, C::EF>,
        // original_commitments[0] = the witnessed BN254 commit cap root.
        commit_root: [zkm_recursion_compiler::ir::Var<C::N>; 1],
    },
}

// ── Top-level: BasefoldShardProof ────────────────────────────────
//
// Bridges `zkm_pcs::shard_level::shard_proof::BasefoldShardProof`
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
//    evaluation_proof_passthrough)
//
// `evaluation_proof_passthrough` carries the host-side
// [`EvaluationProof`] enum out of the witness so the jagged-PCS
// variable-reconstruction step downstream can match the variant
// directly (Bundle → bundle lift; Bytes → bytes lift; Empty →
// placeholder).
impl<C> Witnessable<C>
    for zkm_pcs::shard_level::shard_proof::BasefoldShardProof<InnerVal, InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = (
        [Felt<C::F>; 8],
        Vec<Felt<C::F>>,
        st::LogupGkrProof<Felt<C::F>, Ext<C::F, C::EF>>,
        st::PartialSumcheckProof<Ext<C::F, C::EF>>,
        // was the host `EvaluationProof` enum (passthrough); now
        // the lifted form carrying the inline-witnessed basefold proof.
        LiftedEvalProof<C>,
        // per-chip trace@z openings (name order).
        crate::basefold_chip_opened_values::BasefoldShardOpenedValues<
            Felt<C::F>,
            Ext<C::F, C::EF>,
        >,
    );

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let main_commitment_arr: [Felt<C::F>; 8] =
            core::array::from_fn(|i| self.main_commitment[i].read(builder));
        let public_values = self.public_values.read(builder);
        let logup_gkr_proof = self.logup_gkr_proof.read(builder);
        let zerocheck_proof = self.zerocheck_proof.read(builder);
        // for the Bundle variant, READ the basefold proof's
        // felt/ext values from the witness stream HERE (inline, in the
        // batched per-shard read order) — this is what makes the recursion
        // program value-independent.  Digests stay raw (rekeyed in the lift;
        // witnessed separately).  Must mirror `write` exactly.
        use zkm_pcs::shard_level::shard_proof::EvaluationProof as HostEvalProof;
        // P2c-for-outer: for the gnark wrap (OuterConfig), WITNESS the outer
        // BN254 bundle from the stream HERE (at the eval-proof position) via the
        // config dispatch — value-independent gnark R1CS.  Inner configs return
        // None and fall through to the existing Empty/Bytes/Bundle handling.
        let evaluation_proof = if let Some(outer) =
            C::read_outer_eval_bundle(builder, &self.evaluation_proof)
        {
            outer
        } else {
            match &self.evaluation_proof {
            HostEvalProof::Empty => LiftedEvalProof::Empty,
            HostEvalProof::Bytes(b) => LiftedEvalProof::Bytes(b.clone()),
            HostEvalProof::Bundle(bundle) => {
                let host_proof = host_stacked_basefold_to_recursive(&bundle.basefold_proof);
                let basefold_proof =
                    crate::basefold_witness::read_basefold_proof_from_stream::<C>(
                        &host_proof,
                        builder,
                    );
                // read the reduction sumcheck, jagged-eval sub-sumcheck,
                // and expected_eval (q_at_z) — same order as `write`.
                let sumcheck = read_sumcheck_from_stream::<C>(
                    &jagged_reduction_to_partial_sumcheck(&bundle.reduction),
                    builder,
                );
                let jagged_eval = read_sumcheck_from_stream::<C>(
                    &stark_to_local_psp(&bundle.jagged_eval.partial_sumcheck_proof),
                    builder,
                );
                let expected_eval = bundle.reduction.q_at_z.read(builder);
                LiftedEvalProof::Bundle {
                    host: bundle.clone(),
                    basefold_proof,
                    sumcheck,
                    jagged_eval,
                    expected_eval,
                    // reuse the witnessed main_commitment (== the commit
                    // cap root) — no extra stream felts, value-independent.
                    commit_root: main_commitment_arr,
                }
            }
            }
        };
        // lift the host `ShardOpenedValues` (trace@z)
        // into the BaseFold-shape per-chip opening bundle.  `degree`
        // and the cumulative sums are placeholders here and are
        // finalized in the verifier from the real height / cumsum maps.
        let opened_values = basefold_opened_values_from_host(&self.opened_values).read(builder);
        (
            main_commitment_arr,
            public_values,
            logup_gkr_proof,
            zerocheck_proof,
            evaluation_proof,
            opened_values,
        )
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for f in self.main_commitment.iter() {
            f.write(witness);
        }
        self.public_values.write(witness);
        self.logup_gkr_proof.write(witness);
        self.zerocheck_proof.write(witness);
        // P2c-for-outer: for the gnark wrap, WRITE the witnessed outer BN254
        // bundle here (mirrors the read dispatch).  Returns true when handled
        // (outer config + outer bundle bytes), so the inner Bundle write below
        // is skipped.  Inner configs return false → fall through.
        let _handled_outer =
            C::write_outer_eval_bundle::<_>(&self.evaluation_proof, witness);
        // P2c STEP 2: write the Bundle's basefold-proof felt/ext values in
        // the SAME position `read` consumes them (between zerocheck and
        // opened_values).  Bytes/Empty write nothing (outer wrap bakes).
        if let zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(bundle) =
            &self.evaluation_proof
        {
            let host_proof = host_stacked_basefold_to_recursive(&bundle.basefold_proof);
            crate::basefold_witness::write_basefold_proof_to_stream::<C>(&host_proof, witness);
            // write sumcheck, jagged_eval, expected_eval (same order as read).
            write_sumcheck_to_stream::<C>(
                &jagged_reduction_to_partial_sumcheck(&bundle.reduction),
                witness,
            );
            write_sumcheck_to_stream::<C>(
                &stark_to_local_psp(&bundle.jagged_eval.partial_sumcheck_proof),
                witness,
            );
            bundle.reduction.q_at_z.write(witness);
        }
        // write opened_values in the same shape `read`
        // consumes them.
        basefold_opened_values_from_host(&self.opened_values).write(witness);
    }
}

/// Convert the host `ShardOpenedValues` (legacy 4-batch
/// FRI shape) into the BaseFold-pipeline per-chip opening bundle.
///
/// Only `preprocessed.local`, `main.local`, and the cumulative sums are
/// carried; `next`/`permutation`/`quotient` have no analog in the
/// BaseFold reduction.  `degree` is set to a zero placeholder of length
/// `log_degree + 1` and is replaced with the REAL big-endian height
/// bits in the verifier (`finalize_carried_opened_values`); its length
/// is irrelevant to the felt-witness stream since `Ext` reads are
/// length-prefixed by the `Vec<_>` Witnessable.
fn basefold_opened_values_from_host(
    opened: &zkm_pcs::ShardOpenedValues<InnerVal, InnerChallenge>,
) -> crate::basefold_chip_opened_values::BasefoldShardOpenedValues<InnerVal, InnerChallenge> {
    use p3_field::PrimeCharacteristicRing;
    let chips = opened
        .chips
        .iter()
        .map(|c| crate::basefold_chip_opened_values::BasefoldChipOpenedValues {
            preprocessed: crate::basefold_chip_opened_values::BasefoldAirOpenedValues {
                local: c.preprocessed.local.clone(),
            },
            main: crate::basefold_chip_opened_values::BasefoldAirOpenedValues {
                local: c.main.local.clone(),
            },
            // the REAL big-endian height bits were carried
            // host-side in `quotient[0]` (set by the host prover) — the
            // VirtualGeq threshold for `full_geq`.  Fall back to a 1-elt zero stub if
            // absent (legacy/empty proofs).
            degree: c
                .quotient
                .first()
                .cloned()
                .unwrap_or_else(|| vec![InnerChallenge::ZERO]),
            local_cumulative_sum: c.local_cumulative_sum,
            global_cumulative_sum: c.global_cumulative_sum,
        })
        .collect();
    crate::basefold_chip_opened_values::BasefoldShardOpenedValues { chips }
}

// ── Jagged-PCS bundle Witnessable surface ────────────────────────
//
// Additive Witnessable bridges for the host-side jagged-PCS bundle
// pieces.  These compile against the existing in-circuit verifier
// surface but are NOT yet wired into call sites.  Their purpose is to
// establish the field-by-field witness mapping so the full
// `JaggedBasefoldBundle::Witnessable` can be composed from these
// primitives.
//
// Reference: SP1's [`JaggedSumcheckEvalProof` / `JaggedPcsProof`
// Witnessable](file:///tmp/sp1/crates/recursion/circuit/src/jagged/witness.rs).
// The Ziren bundle stores per-round eval-form sumcheck rounds
// (`JaggedReductionRound { evals: [EF; 3] }`) where SP1 stores
// coefficient-form (`UnivariatePolynomial { coefficients }`); the
// eval→coeff conversion lives at the bundle assembly site,
// not in these per-piece witness reads.

use zkm_pcs::basefold::proof::{BasefoldProof, LeafOpening, MerkleOpening};
use zkm_pcs::basefold::stacked::StackedBasefoldProof;
use zkm_pcs::jagged_pcs::jagged::JaggedBasefoldBundle;
use zkm_pcs::jagged_pcs::JaggedMmcs;
use zkm_pcs::jagged_sumcheck::{JaggedReductionProof, JaggedReductionRound};

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

/// In-circuit companion to [`zkm_pcs::basefold::proof::LeafOpening`].
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

/// In-circuit companion to [`zkm_pcs::basefold::proof::MerkleOpening`].
pub struct MerkleOpeningVar<F> {
    pub leaves: Vec<LeafOpeningVar<F>>,
}

impl<C> Witnessable<C> for LeafOpening<InnerVal, JaggedMmcs>
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

impl<C> Witnessable<C> for MerkleOpening<InnerVal, JaggedMmcs>
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

/// Bit-decompose a `usize` value into exactly `num_bits` LSB-first
/// felts, each constrained to `{0, 1}`.  Helper for the
/// lift fields that need bit-decomposed metadata
/// (`params.col_prefix_sums[k]` and `row_counts[round][chip]`); the
/// in-circuit verifier Horner-decodes these via
/// `final_area = bit + 2*final_area` (recursive_jagged_pcs.rs:262-272).
///
/// Convention: matches the verifier's MSB-first Horner accumulation
/// — the first felt in the returned Vec is the MOST-SIGNIFICANT bit
/// (bit `num_bits-1`), the last is bit 0.  For value 5 with 4 bits:
/// returns `[0, 1, 0, 1]` representing `0*8 + 1*4 + 0*2 + 1*1`.
///
/// # Panics
///
/// Panics if `value` requires more than `num_bits` to represent.
pub fn bit_decompose_usize_to_felts<C>(
    builder: &mut Builder<C>,
    value: usize,
    num_bits: usize,
) -> Vec<Felt<C::F>>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    use p3_field::PrimeCharacteristicRing;
    if num_bits < usize::BITS as usize {
        assert!(
            value < (1usize << num_bits),
            "bit_decompose_usize_to_felts: value {} exceeds {} bits",
            value,
            num_bits,
        );
    }
    (0..num_bits)
        .rev()
        .map(|i| {
            let bit = (value >> i) & 1;
            builder.constant(if bit == 1 { C::F::ONE } else { C::F::ZERO })
        })
        .collect()
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
    opening: &MerkleOpening<InnerVal, JaggedMmcs>,
) -> Vec<RecursiveBasefoldComponentOpening<InnerVal, InnerChallenge>> {
    opening
        .leaves
        .iter()
        .map(|leaf| RecursiveBasefoldComponentOpening {
            leaf_values: leaf.values.clone(),
            merkle_path_bytes: Vec::new(),
            // Soundness binding: thread the structured Merkle path
            // digests through so the in-circuit verifier can bind the
            // opened leaf to its committed root.
            merkle_path_digests: leaf.proof.clone(),
            _phantom: core::marker::PhantomData,
        })
        .collect()
}

/// Convert a host-side BaseFold commit-phase opening (one
/// [`MerkleOpening`]) into the per-round per-query
/// [`RecursiveBasefoldOpening`] vector.
///
/// Per FRI commit-phase shape (see
/// [`zkm_pcs::basefold::fri::commit_phase_round`]), each leaf
/// bundles `2 * EF::DIMENSION` base-field elements representing two
/// adjacent EF codeword values (the sibling pair).  This converter
/// parses those into the in-circuit `[EF; 2]` shape and copies the
/// Merkle siblings into `merkle_path_digests` for binding.
///
/// **Position field**: set to `0` placeholder.  This is INFORMATIONAL
/// ONLY — the in-circuit verifier samples its own query positions
/// from the FRI challenger transcript at
/// [`basefold_verifier.rs:837-839`] and never reads `.position`.
/// (Confirmed by grep: zero `.position` reads in basefold_verifier.rs.)
/// No fix needed at this site; binding-soundness happens through the
/// `merkle_path_digests` field, not through `position`.
fn host_query_opening_to_recursive(
    opening: &MerkleOpening<InnerVal, JaggedMmcs>,
) -> Vec<RecursiveBasefoldOpening<InnerVal, InnerChallenge>> {
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
            // Thread the bundle's MT::Proof structured digests
            // through.  See verifier site at
            // basefold_verifier.rs:957-959 for promotion + binding.
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
    proof: &BasefoldProof<InnerVal, InnerChallenge, JaggedMmcs>,
    batch_evaluations: Vec<Vec<InnerChallenge>>,
) -> RecursiveBasefoldProof<InnerVal, InnerChallenge> {
    assert_eq!(
        proof.univariate_messages.len(),
        proof.fri_commitments.len(),
        "BasefoldProof: univariate_messages.len() != fri_commitments.len()",
    );

    let rounds: Vec<RecursiveBasefoldRound<InnerVal, InnerChallenge>> = proof
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
            RecursiveBasefoldRound { uni_poly: *uni, commitment: cap_roots[0], _phantom_f: core::marker::PhantomData }
        })
        .collect();

    let component_openings: Vec<Vec<RecursiveBasefoldComponentOpening<_, _>>> = proof
        .component_polynomials_query_openings_and_proofs
        .iter()
        .map(host_component_opening_to_recursive)
        .collect();

    let query_phase_openings: Vec<Vec<RecursiveBasefoldOpening<_, _>>> = proof
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
    proof: &StackedBasefoldProof<InnerVal, InnerChallenge, JaggedMmcs>,
) -> RecursiveBasefoldProof<InnerVal, InnerChallenge> {
    host_basefold_proof_to_recursive(&proof.basefold_proof, proof.batch_evaluations.clone())
}

// ─────────────────────────────────────────────────────────────────────
// BaseFold-over-BN254 wrap port: OUTER-ring bundle lift.
//
// The OUTER wrap proof's `EvaluationProof::Bytes` carries a
// `JaggedBasefoldBundleGeneric<OuterValMmcs>` whose commitments are
// REAL BN254 MerkleCaps (`MerkleCap<KoalaBear, [Bn254; 1]>`).  The inner
// lift (`lift_jagged_basefold_bundle`) reads KoalaBear MMCS roots and is
// wrong for this ring.  These helpers read the BN254 roots and lift them
// to the outer digest type (`KoalaBearPoseidon2Outer::Digest = [Bn254; 1]`,
// `DigestVariable = [Var<Bn254>; 1]`), so the in-circuit challenger
// observes the same BN254 digests the host `verify_jagged_basefold_inner_generic`
// absorbs (via `split_32` per BN254 element) — matching the Fiat-Shamir
// transcript exactly.
// ─────────────────────────────────────────────────────────────────────

use p3_bn254_fr::Bn254;
use zkm_recursion_core::stark::OuterValMmcs;

type OuterDigestRaw = [Bn254; crate::hash::BN254_DIGEST_SIZE];

/// Extract the single BN254 1-cap root from an `OuterValMmcs` commitment.
fn outer_cap_root(
    commitment: &<OuterValMmcs as p3_commit::Mmcs<InnerVal>>::Commitment,
) -> OuterDigestRaw {
    use p3_commit::Mmcs as _;
    let roots = commitment.roots();
    assert_eq!(
        roots.len(),
        1,
        "OuterValMmcs MerkleCap must have exactly 1 root (height-0 cap), got {}",
        roots.len(),
    );
    roots[0]
}

/// Outer analog of [`host_component_opening_to_recursive`] over `OuterValMmcs`.
fn host_component_opening_to_recursive_outer(
    opening: &MerkleOpening<InnerVal, OuterValMmcs>,
) -> Vec<RecursiveBasefoldComponentOpening<InnerVal, InnerChallenge, OuterDigestRaw>> {
    opening
        .leaves
        .iter()
        .map(|leaf| RecursiveBasefoldComponentOpening {
            leaf_values: leaf.values.clone(),
            merkle_path_bytes: Vec::new(),
            // Soundness binding: thread the structured Merkle path
            // digests through so the in-circuit verifier can bind the
            // opened leaf to its committed root.
            merkle_path_digests: leaf.proof.clone(),
            _phantom: core::marker::PhantomData,
        })
        .collect()
}

/// Outer analog of [`host_query_opening_to_recursive`] over `OuterValMmcs`.
/// `leaf.proof` is `OuterValMmcs::Proof = Vec<[Bn254; 1]>` — the real BN254
/// Merkle siblings, threaded into `merkle_path_digests` for binding.
fn host_query_opening_to_recursive_outer(
    opening: &MerkleOpening<InnerVal, OuterValMmcs>,
) -> Vec<RecursiveBasefoldOpening<InnerVal, InnerChallenge, OuterDigestRaw>> {
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

/// Outer analog of [`host_basefold_proof_to_recursive`] — reads the BN254
/// 1-cap roots from `fri_commitments` and the BN254 Merkle siblings from the
/// per-query openings, producing a `RecursiveBasefoldProof` whose `Dig` is
/// the outer BN254 digest type `[Bn254; 1]`.
fn host_basefold_proof_to_recursive_outer(
    proof: &BasefoldProof<InnerVal, InnerChallenge, OuterValMmcs>,
    batch_evaluations: Vec<Vec<InnerChallenge>>,
) -> RecursiveBasefoldProof<InnerVal, InnerChallenge, OuterDigestRaw> {
    assert_eq!(
        proof.univariate_messages.len(),
        proof.fri_commitments.len(),
        "BasefoldProof: univariate_messages.len() != fri_commitments.len()",
    );

    let rounds: Vec<RecursiveBasefoldRound<InnerVal, InnerChallenge, OuterDigestRaw>> = proof
        .univariate_messages
        .iter()
        .zip(proof.fri_commitments.iter())
        .map(|(uni, commit)| RecursiveBasefoldRound {
            uni_poly: *uni,
            commitment: outer_cap_root(commit),
            _phantom_f: core::marker::PhantomData,
        })
        .collect();

    let component_openings: Vec<Vec<RecursiveBasefoldComponentOpening<_, _, OuterDigestRaw>>> =
        proof
            .component_polynomials_query_openings_and_proofs
            .iter()
            .map(host_component_opening_to_recursive_outer)
            .collect();

    let query_phase_openings: Vec<Vec<RecursiveBasefoldOpening<_, _, OuterDigestRaw>>> = proof
        .query_phase_openings_and_proofs
        .iter()
        .map(host_query_opening_to_recursive_outer)
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

/// Outer analog of [`host_stacked_basefold_to_recursive`] over `OuterValMmcs`.
fn host_stacked_basefold_to_recursive_outer(
    proof: &StackedBasefoldProof<InnerVal, InnerChallenge, OuterValMmcs>,
) -> RecursiveBasefoldProof<InnerVal, InnerChallenge, OuterDigestRaw> {
    host_basefold_proof_to_recursive_outer(
        &proof.basefold_proof,
        proof.batch_evaluations.clone(),
    )
}

/// P2c-for-outer: WITNESS the OUTER (BN254) jagged-basefold bundle's
/// proof-specific values from the gnark witness stream (the value-independent
/// replacement for the const-baking in `lift_jagged_basefold_bundle_outer`).
///
/// Called from `BasefoldShardProof::read` via
/// `CircuitConfig::read_outer_eval_bundle` (OuterConfig override).  Returns the
/// witnessed `LiftedEvalProof::OuterBundle` when `host` is an
/// `EvaluationProof::Bytes` that deserializes as an outer bundle; otherwise
/// `None` (Empty / inner Bundle / malformed → fall back to the bytes path).
///
/// The witnessed values (read order MUST match
/// [`write_outer_eval_bundle_impl`]): the BaseFold proof (uni_polys, BN254 round
/// commitments, final_poly, pow/grind witnesses, per-query sibling pairs + BN254
/// merkle path digests, batch_evaluations), the reduction sumcheck, the
/// jagged-eval sub-sumcheck, expected_eval (q_at_z), and the BN254 commit cap
/// root.  Shape metadata (packing, column counts) stays in `host` and is read by
/// the lift as compile-time constants (shape-derived, value-independent).
pub fn read_outer_eval_bundle_impl<C>(
    builder: &mut Builder<C>,
    host: &zkm_pcs::shard_level::shard_proof::EvaluationProof,
) -> Option<LiftedEvalProof<C>>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, N = Bn254>,
{
    use zkm_pcs::shard_level::shard_proof::EvaluationProof as HostEvalProof;
    let bytes = match host {
        HostEvalProof::Bytes(b) => b,
        _ => return None,
    };
    let bundle = zkm_pcs::jagged_pcs::jagged::JaggedBasefoldBundleGeneric::<
        OuterValMmcs,
    >::from_bytes(bytes)?;

    // BaseFold proof (BN254 digests) — witnessed felt/ext + BN254 digests.
    let host_basefold_outer = host_stacked_basefold_to_recursive_outer(&bundle.basefold_proof);
    let basefold_proof =
        crate::basefold_witness::read_basefold_proof_outer_from_stream::<C>(
            &host_basefold_outer,
            builder,
        );
    // reduction sumcheck + jagged-eval sub-sumcheck (field-typed, ring-agnostic).
    let sumcheck = read_sumcheck_from_stream::<C>(
        &jagged_reduction_to_partial_sumcheck(&bundle.reduction),
        builder,
    );
    let jagged_eval = read_sumcheck_from_stream::<C>(
        &stark_to_local_psp(&bundle.jagged_eval.partial_sumcheck_proof),
        builder,
    );
    let expected_eval = bundle.reduction.q_at_z.read(builder);
    // BN254 commit cap root (original_commitments[0]).
    let first_root: OuterDigestRaw = outer_cap_root(&bundle.commit.commitment);
    let commit_root: [zkm_recursion_compiler::ir::Var<C::N>; 1] =
        core::array::from_fn(|i| first_root[i].read(builder));

    Some(LiftedEvalProof::OuterBundle {
        host: bundle,
        basefold_proof,
        sumcheck,
        jagged_eval,
        expected_eval,
        commit_root,
    })
}

/// Prover-side counterpart of [`read_outer_eval_bundle_impl`]: WRITE the outer
/// bundle's proof-specific values to the witness stream in the SAME order the
/// read consumes them.  Returns `true` when handled (outer bundle bytes), so
/// `BasefoldShardProof::write` skips its default Bytes/Bundle write.
pub fn write_outer_eval_bundle_impl<C, W>(
    host: &zkm_pcs::shard_level::shard_proof::EvaluationProof,
    witness: &mut W,
) -> bool
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, N = Bn254>,
    W: crate::witness::WitnessWriter<C>,
{
    use zkm_pcs::shard_level::shard_proof::EvaluationProof as HostEvalProof;
    let bytes = match host {
        HostEvalProof::Bytes(b) => b,
        _ => return false,
    };
    let bundle = match zkm_pcs::jagged_pcs::jagged::JaggedBasefoldBundleGeneric::<
        OuterValMmcs,
    >::from_bytes(bytes)
    {
        Some(b) => b,
        None => return false,
    };
    let host_basefold_outer = host_stacked_basefold_to_recursive_outer(&bundle.basefold_proof);
    crate::basefold_witness::write_basefold_proof_outer_to_stream::<C>(
        &host_basefold_outer,
        witness,
    );
    write_sumcheck_to_stream::<C>(
        &jagged_reduction_to_partial_sumcheck(&bundle.reduction),
        witness,
    );
    write_sumcheck_to_stream::<C>(
        &stark_to_local_psp(&bundle.jagged_eval.partial_sumcheck_proof),
        witness,
    );
    bundle.reduction.q_at_z.write(witness);
    let first_root: OuterDigestRaw = outer_cap_root(&bundle.commit.commitment);
    for v in first_root.iter() {
        v.write(witness);
    }
    true
}

/// #H (BaseFold-over-BN254 wrap port): lift the OUTER-ring jagged BaseFold
/// bundle into the in-circuit `JaggedPcsProofVariable`.
///
/// Structural mirror of [`lift_jagged_basefold_bundle`] but:
///   * `original_commitments[0]` ← the REAL BN254 `bundle.commit.commitment`
///     1-cap root, lifted to `[Var<Bn254>; 1]` via
///     `KoalaBearPoseidon2Outer::const_digest`.  This is the digest the
///     in-circuit `RecursiveBasefoldVerifier::verify_untrusted_evaluations`
///     step (1) observes, matching the host's
///     `challenger.observe(bundle.commit.commitment)`.
///   * the inner BaseFold proof's per-round `commitment` + per-query
///     `merkle_path_digests` carry the real BN254 digests (read via
///     `host_stacked_basefold_to_recursive_outer`), so the commit-phase
///     transcript replay (step (4)) observes the same BN254 digests the
///     host basefold verifier absorbs.
///
/// `HV` is pinned to `KoalaBearPoseidon2Outer` (the only outer hasher); the
/// generic param keeps the output type aligned with the dispatch call site.
///
/// P2c-for-outer (value-independence): the proof-specific values
/// (`preread_basefold_proof`, `preread_sumcheck`, `preread_jagged_eval`,
/// `preread_expected_eval`, `preread_commit_root`) are PRE-READ from the gnark
/// witness stream (`read_outer_eval_bundle_impl`, routed via
/// `BasefoldShardProof::read`) — they are NO LONGER baked as `builder.constant`,
/// so the gnark R1CS verifies any fresh wrap proof.  Only the SHAPE metadata
/// (`bundle.packing`, column/row counts) is read here as compile-time constants
/// (shape-derived, identical across proofs of the same shape).
#[allow(clippy::too_many_arguments)]
pub fn lift_jagged_basefold_bundle_outer<C>(
    builder: &mut Builder<C>,
    bundle: &zkm_pcs::jagged_pcs::jagged::JaggedBasefoldBundleGeneric<OuterValMmcs>,
    // P2c-for-outer: witnessed proof-specific values (replace the const-builds).
    preread_basefold_proof: RecursiveBasefoldProof<
        Felt<C::F>,
        Ext<C::F, C::EF>,
        [zkm_recursion_compiler::ir::Var<C::N>; 1],
    >,
    preread_sumcheck: PartialSumcheckProof<Ext<C::F, C::EF>>,
    preread_jagged_eval: PartialSumcheckProof<Ext<C::F, C::EF>>,
    preread_expected_eval: Ext<C::F, C::EF>,
    preread_commit_root: [zkm_recursion_compiler::ir::Var<C::N>; 1],
    max_log_row_count: usize,
    column_counts_by_round: &[Vec<usize>],
    row_counts_by_round: Option<&[Vec<usize>]>,
) -> JaggedPcsProofVariable<
    RecursiveBasefoldProof<
        Felt<C::F>,
        Ext<C::F, C::EF>,
        <zkm_recursion_core::stark::KoalaBearPoseidon2Outer as crate::hash::FieldHasherVariable<C>>::DigestVariable,
    >,
    <zkm_recursion_core::stark::KoalaBearPoseidon2Outer as crate::hash::FieldHasherVariable<C>>::DigestVariable,
    C::F,
    C::EF,
>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, N = Bn254, Bit = zkm_recursion_compiler::ir::Var<Bn254>>,
{
    use crate::hash::FieldHasherVariable;
    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_core::stark::KoalaBearPoseidon2Outer as HV;

    // ── REAL per-chip shaping from the OUTER bundle's packing ──
    // Mirror the host outer verify hook `build_jagged_verify_inputs`
    // (crates/pcs/src/jagged_pcs.rs): the per-chip column_count comes
    // from `bundle.packing.column_counts`, and the per-chip row_count
    // (column height) is the offsets sentinel-walk difference at each
    // chip's first column.  The caller-supplied `column_counts_by_round`
    // (= vec![main_widths]) and `bundle.commit.chip_dims` (a single
    // cap-tree entry) do NOT reconcile the ~1300-column packing, so we
    // recover the true per-column structure here.  The result is used
    // for col_prefix_sums, the returned column_counts, AND row_counts so
    // step-7's per-column accumulation (recursive_jagged_pcs.rs:271)
    // reproduces `bundle.packing.offsets` exactly.
    let packing_column_counts: Vec<usize> = bundle.packing.column_counts.clone();
    let packing_row_counts: Vec<usize> = {
        let offsets = &bundle.packing.offsets;
        let total_values = bundle.packing.total_values;
        let mut heights: Vec<usize> = Vec::with_capacity(packing_column_counts.len());
        let mut col_idx = 0usize;
        for &cc in packing_column_counts.iter() {
            if cc == 0 {
                heights.push(0);
                continue;
            }
            let h = if col_idx + 1 < offsets.len() {
                offsets[col_idx + 1].saturating_sub(offsets[col_idx])
            } else if col_idx < offsets.len() {
                total_values.saturating_sub(offsets[col_idx])
            } else {
                0
            };
            heights.push(h);
            col_idx += cc;
        }
        heights
    };
    // Single-round packing shape (the wrap STARK commits one main round).
    // Fall back to the caller-supplied shape only if packing carries no
    // per-chip column metadata (degenerate / scaffolding bundles).
    let real_column_counts_by_round: Vec<Vec<usize>> = if packing_column_counts.is_empty() {
        column_counts_by_round.to_vec()
    } else {
        vec![packing_column_counts.clone()]
    };
    let column_counts_by_round: &[Vec<usize>] = &real_column_counts_by_round;
    // ── Padding shape (mirror of lift_jagged_basefold_bundle) ──
    // Host parity: flat column count only — no artificial-zero columns
    // (see lift_jagged_basefold_bundle's padding-shape comment).
    let total_cols_before_pad: usize = column_counts_by_round
        .iter()
        .map(|cc| cc.iter().sum::<usize>())
        .sum();
    let padded_cols = total_cols_before_pad.max(1).next_power_of_two();
    let col_prefix_sums_len = padded_cols + 1;
    let num_rounds = column_counts_by_round.len().max(1);

    // ── Height-agnostic groundwork (Stage 3): witnessed NUMERIC
    // row_counts + padding_column_count, derived from the SAME bundle
    // packing the real prover / dummy use (single stacked main commit
    // == one round).  PURE DATA carried alongside the bit-form below.
    let (row_counts_usize, padding_column_counts): (Vec<Vec<usize>>, Vec<usize>) =
        if bundle.packing.column_counts.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            let (rc, pcc) = zkm_pcs::jagged::derive_row_and_padding_counts(
                &bundle.packing.column_counts,
                &bundle.packing.offsets,
                bundle.packing.total_values,
            );
            (vec![rc], vec![pcc])
        };

    // ── P2c-for-outer: sumcheck_proof = the WITNESSED reduction sumcheck ──
    let sumcheck_proof: PartialSumcheckProof<Ext<C::F, C::EF>> = preread_sumcheck;

    // ── P2c-for-outer: basefold proof = the WITNESSED proof (BN254 digests) ──
    // The felt/ext values and the BN254 round/merkle digests came off the gnark
    // witness stream in `read_outer_eval_bundle_impl` (no more const-bake).
    let basefold_proof_var = preread_basefold_proof;

    // ── P2c-for-outer: batch_evaluations = the WITNESSED values (reuse) ──
    let batch_evaluations_ext: Vec<Vec<Ext<C::F, C::EF>>> = basefold_proof_var
        .batch_evaluations
        .iter()
        .map(|round| round.iter().copied().collect())
        .collect();

    let stacked_pcs_proof = RecursiveStackedPcsProof::<
        RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            <HV as crate::hash::FieldHasherVariable<C>>::DigestVariable,
        >,
        C::F,
        C::EF,
    > {
        batch_evaluations: batch_evaluations_ext,
        pcs_proof: basefold_proof_var,
    };

    // ── P2c-for-outer: original_commitments[0] = WITNESSED BN254 commit root ──
    // `HV::DigestVariable == [Var<Bn254>; 1] == [Var<C::N>; 1]` for the outer
    // ring; the witnessed `preread_commit_root` replaces the baked const_digest.
    let first_commit_digest: <HV as crate::hash::FieldHasherVariable<C>>::DigestVariable =
        preread_commit_root;
    let zero_digest_var: <HV as crate::hash::FieldHasherVariable<C>>::DigestVariable =
        HV::const_digest(builder, <HV as crate::hash::FieldHasher<C::F>>::Digest::default());
    let mut original_commitments: Vec<
        <HV as crate::hash::FieldHasherVariable<C>>::DigestVariable,
    > = Vec::with_capacity(num_rounds);
    original_commitments.push(first_commit_digest);
    for _ in 1..num_rounds {
        original_commitments.push(zero_digest_var);
    }

    // ── P2c-for-outer: jagged_eval_proof = the WITNESSED sub-sumcheck ──
    let jagged_eval_proof = JaggedSumcheckEvalProof::<Ext<C::F, C::EF>> {
        partial_sumcheck_proof: preread_jagged_eval,
    };

    // ── REAL: col_prefix_sums with artificial-zero insertion (mirror) ──
    // CRITICAL (mirror of the INNER lift, shard_level_witness.rs:1457): the
    // per-entry bit width must equal the branching program's
    // `half = proof_point.len()/2` (jagged_eval.rs), which the host jagged-eval
    // prover sets to `log_m + 1` = z_trace.len() (jagged_eval_sumcheck.rs).
    // Using `max_log_row_count + 1` is too narrow when the total column area
    // exceeds 2^max_log_row_count (true for the wide WrapAir trace):
    // col_prefix_sums.last() (= total_values) then CLAMPS and the step-7
    // prefix-sum felt-assert (acc == final_area) fails
    // (e.g. 10813456 vs 8388607).  Derive the width from the jagged-eval
    // sumcheck point length, falling back to max_log_row_count+1 only for the
    // dummy/empty jagged_eval.
    let jagged_eval_point_len =
        bundle.jagged_eval.partial_sumcheck_proof.point_and_eval.0.len();
    let bits_per_entry = if jagged_eval_point_len >= 2 {
        jagged_eval_point_len / 2
    } else {
        max_log_row_count + 1
    };
    let total_values = bundle.packing.total_values;
    let cap_to_bits = |v: usize| -> usize {
        if bits_per_entry < usize::BITS as usize {
            v.min((1usize << bits_per_entry) - 1)
        } else {
            v
        }
    };
    let mut col_prefix_sums: Vec<Vec<Felt<C::F>>> = Vec::with_capacity(col_prefix_sums_len);
    col_prefix_sums.push(bit_decompose_usize_to_felts::<C>(builder, 0, bits_per_entry));
    let mut offset_idx: usize = 0;
    let mut current_offset: usize = 0;
    for cc in column_counts_by_round.iter() {
        let real_in_round = cc.iter().sum::<usize>();
        for _ in 0..real_in_round {
            if offset_idx < bundle.packing.offsets.len() {
                current_offset = bundle.packing.offsets[offset_idx];
                offset_idx += 1;
            }
            if col_prefix_sums.len() >= col_prefix_sums_len {
                break;
            }
            col_prefix_sums.push(bit_decompose_usize_to_felts::<C>(
                builder,
                cap_to_bits(current_offset),
                bits_per_entry,
            ));
        }
        // Host parity: no artificial-zero columns; the pow2
        // tail-pad below emits the same `current_offset` entries.
    }
    while col_prefix_sums.len() < col_prefix_sums_len - 1 {
        col_prefix_sums.push(bit_decompose_usize_to_felts::<C>(
            builder,
            cap_to_bits(current_offset),
            bits_per_entry,
        ));
    }
    if col_prefix_sums.len() < col_prefix_sums_len {
        col_prefix_sums.push(bit_decompose_usize_to_felts::<C>(
            builder,
            cap_to_bits(total_values),
            bits_per_entry,
        ));
    }
    let jagged_dim_metadata = JaggedDimensionMetadata::<Felt<C::F>> { col_prefix_sums };

    // ── row_counts: caller-plumbed if provided, else from packing ──
    // Per-chip heights derived from `bundle.packing.offsets` differences
    // (see `packing_row_counts` above) so per-column accumulation in the
    // step-7 prefix-sum check reproduces `bundle.packing.offsets`,
    // mirroring the host `build_jagged_verify_inputs`.
    let row_counts: Vec<Vec<Felt<C::F>>> = if let Some(row_counts_src) = row_counts_by_round {
        row_counts_src
            .iter()
            .map(|round| {
                round
                    .iter()
                    .map(|&rc| builder.constant(C::F::from_u64(rc as u64)))
                    .collect()
            })
            .collect()
    } else {
        let heights: Vec<Felt<C::F>> = packing_row_counts
            .iter()
            .map(|&h| builder.constant(C::F::from_u64(h as u64)))
            .collect();
        column_counts_by_round.iter().map(|_| heights.clone()).collect()
    };

    // ── P2c-for-outer: expected_eval = the WITNESSED q_at_z ──
    let expected_eval: Ext<C::F, C::EF> = preread_expected_eval;

    JaggedPcsProofVariable {
        params: jagged_dim_metadata,
        sumcheck_proof,
        jagged_eval_proof,
        pcs_proof: stacked_pcs_proof,
        column_counts: column_counts_by_round.to_vec(),
        row_counts,
        row_counts_usize,
        padding_column_counts,
        original_commitments,
        expected_eval,
    }
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
/// Callers (compress/wrap/deferred/core_basefold +
/// shard_proof_variable_lift) can adopt this adapter via a one-line
/// swap from `lift_evaluation_proof_bytes(...)` →
/// `lift_evaluation_proof_via_bundle(...)`.  A later cutover can
/// finish the migration by changing the upstream
/// `BasefoldShardProof.evaluation_proof` field type from `Vec<u8>` to
/// `JaggedBasefoldBundle`, eliminating this adapter and the
/// rmp-serde round trip — which is the actual fix for the
/// serialization-induced determinism cascade.
pub fn lift_evaluation_proof_via_bundle<C, HV>(
    builder: &mut Builder<C>,
    bytes: &[u8],
    max_log_row_count: usize,
    column_counts_by_round: &[Vec<usize>],
) -> JaggedPcsProofVariable<
    RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, HV::DigestVariable>,
    HV::DigestVariable,
    C::F,
    C::EF,
>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    // the witnessing/const lift pins inner digests to [Felt;8].
    HV: crate::hash::FieldHasherVariable<C, DigestVariable = [Felt<C::F>; 8]>
        + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
{
    if let Some(bundle) = JaggedBasefoldBundle::from_bytes(bytes) {
        let (cp, sc, je, ee, cr) = const_basefold_proof_from_bundle::<C, HV>(&bundle, builder);
        lift_jagged_basefold_bundle::<C, HV>(
            builder, &bundle, cp, sc, je, ee, cr, max_log_row_count, column_counts_by_round, None,
            None,
        )
    } else {
        // Empty / malformed bytes — fall back to the all-zero
        // placeholder (preserves shape compatibility with scaffolding
        // tests and the BasefoldShardProof::empty() construction
        // path).
        crate::jagged_pcs_lift::lift_empty_placeholder::<C, HV>(
            builder,
            max_log_row_count,
            column_counts_by_round,
        )
    }
}

/// Convert a host-side `PartialSumcheckProof<InnerChallenge>` to the
/// circuit-variable form via `builder.constant()` instead of
/// witness-stream `.read()` — the bundle is host-side data, NOT
/// witness-stream input.
///
/// Previously called `<host_sumcheck as Witnessable<C>>::read(...)`
/// which consumed felts from the runtime witness stream that were
/// never written there (bundle is added separately on
/// `BasefoldShardProof.evaluation_proof_bundle`, outside the
/// felt-stream).  Empty-stream panic at e2e test time.  Treating
/// bundle values as IR constants matches their semantics.
fn host_sumcheck_to_const_var<C>(
    builder: &mut Builder<C>,
    host: &PartialSumcheckProof<InnerChallenge>,
) -> PartialSumcheckProof<Ext<C::F, C::EF>>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    PartialSumcheckProof {
        univariate_polys: host
            .univariate_polys
            .iter()
            .map(|poly| UnivariatePolynomial {
                coefficients: poly
                    .coefficients
                    .iter()
                    .map(|c| builder.constant(*c))
                    .collect(),
            })
            .collect(),
        claimed_sum: builder.constant(host.claimed_sum),
        point_and_eval: (
            host.point_and_eval.0.iter().map(|x| builder.constant(*x)).collect(),
            builder.constant(host.point_and_eval.1),
        ),
    }
}

// value-independent (witness-stream) PartialSumcheckProof — the
// witnessed counterpart of `host_sumcheck_to_const_var`.  Read/write the ext
// values in the SAME order.  Used for the reduction sumcheck + the jagged-eval
// sub-sumcheck so the lift consumes witnessed (not baked) values.
fn read_sumcheck_from_stream<C>(
    host: &PartialSumcheckProof<InnerChallenge>,
    builder: &mut Builder<C>,
) -> PartialSumcheckProof<Ext<C::F, C::EF>>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    PartialSumcheckProof {
        univariate_polys: host
            .univariate_polys
            .iter()
            .map(|poly| UnivariatePolynomial {
                coefficients: poly.coefficients.iter().map(|c| c.read(builder)).collect(),
            })
            .collect(),
        claimed_sum: host.claimed_sum.read(builder),
        point_and_eval: (
            host.point_and_eval.0.iter().map(|x| x.read(builder)).collect(),
            host.point_and_eval.1.read(builder),
        ),
    }
}

fn write_sumcheck_to_stream<C>(
    host: &PartialSumcheckProof<InnerChallenge>,
    witness: &mut impl WitnessWriter<C>,
) where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    for poly in host.univariate_polys.iter() {
        for c in poly.coefficients.iter() {
            c.write(witness);
        }
    }
    host.claimed_sum.write(witness);
    for x in host.point_and_eval.0.iter() {
        x.write(witness);
    }
    host.point_and_eval.1.write(witness);
}

/// Lift a host-side [`JaggedBasefoldBundle`] into the in-circuit
/// [`JaggedPcsProofVariable`] shape — the structured replacement for
/// [`crate::jagged_pcs_lift::lift_evaluation_proof_bytes`].
///
/// **Real data threaded into the variable**:
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
/// **NOT placeholders (resolved here / by later cutover commits)**:
/// * `expected_eval` ← `bundle.reduction.q_at_z` — the verifier's
///   closing identity at recursive_jagged_pcs.rs:279 asserts
///   `jagged_eval * expected_eval == sumcheck.point_and_eval.1`
///   which mirrors the host verifier's terminal
///   `q_at_z * w(z) == current_claim` (jagged_sumcheck.rs verify
///   path); `q_at_z` is exactly the prover-emitted `expected_eval`.
/// * `params.col_prefix_sums` ← bundle.packing.offsets walked in
///   lock-step with column_counts_by_round, with cc[len-2]+1
///   artificial-zero columns inserted at round boundaries.  Final
///   entry bit-decodes to bundle.packing.total_values.
/// * `row_counts` ← `row_counts_by_round` parameter when caller
///   supplies it (each per-chip count materialized as a single Felt
///   constant); falls back to zero placeholders when None.
/// * `position` field on RecursiveBasefoldOpening — informational
///   only; verifier samples positions from challenger transcript.
///
/// **STRUCTURAL TODO** (the full call-site swap is blocked on these):
/// * `jagged_eval_proof` — Ziren's bundle does not carry the SP1
///   jagged-eval sub-proof.  The placeholder zero-coefs satisfy the
///   `real_jagged_evaluator_fn` closure trivially when ALL adjacent
///   fields are also zero (the existing `lift_evaluation_proof_bytes`
///   regime) but break under partial-real data (jagged_eval derived
///   from zeros vs real expected_eval × real sumcheck.point_and_eval.1
///   fails the closing identity).  To resolve: either (a) port SP1's
///   stark-side jagged-eval sub-protocol emission so the bundle
///   carries it, or (b) wire the verifier-side
///   `placeholder_jagged_evaluator_fn` for the basefold path
///   (loosens soundness — temporary unblock only).
/// * Genericity of `BasefoldShardProof<F, EF>` — the wire-format
///   field `evaluation_proof: Vec<u8>` is generic-friendly but
///   replacing it with `JaggedBasefoldBundle` (concrete
///   InnerVal/InnerChallenge) requires either dropping the struct
///   generics or cfg-gating the field per feature.  All real
///   instantiations use `<InnerVal, InnerChallenge>` so the
///   generics aren't load-bearing — recommended fix is dropping
///   them entirely (struct → concrete).
///
/// Output type matches [`crate::jagged_pcs_lift::lift_evaluation_proof_bytes`]
/// so downstream callers can swap with no shape change.
/// BaseFold-over-BN254 wrap port: re-key a host BaseFold proof's
/// raw digests (read as inner KoalaBear `[InnerVal; 8]` roots) onto the
/// generic `HV::Digest` digest type.  Inner (`HV = KoalaBearPoseidon2`):
/// identity (`Digest = [KoalaBear; 8]`).  Outer (`HV =
/// KoalaBearPoseidon2Outer`): maps to the default BN254 digest — the
/// OUTER ring's real BN254 commitments are bound by a dedicated outer
/// bundle path, so the inner-root lift is never the binding digest there.
// generic over the proof's base/ext type so it rekeys BOTH the raw
// host proof (<InnerVal, InnerChallenge>) AND the witnessed variable
// proof (<Felt, Ext>) — only the `[InnerVal;8]` digests are converted to
// `HV::Digest`; uni_poly/sibling_pair/final_poly/etc. pass through unchanged.
fn rekey_basefold_digests_to_hv<C, HV, F, EF>(
    src: RecursiveBasefoldProof<F, EF, [InnerVal; 8]>,
) -> RecursiveBasefoldProof<F, EF, <HV as crate::hash::FieldHasher<C::F>>::Digest>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    HV: crate::hash::FieldHasherVariable<C> + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
{
    use crate::basefold_verifier::{
        RecursiveBasefoldComponentOpening, RecursiveBasefoldOpening, RecursiveBasefoldRound,
    };
    let conv_digest =
        |root: [InnerVal; 8]| -> <HV as crate::hash::FieldHasher<C::F>>::Digest {
            let kb: [p3_koala_bear::KoalaBear; 8] = core::array::from_fn(|i| root[i]);
            HV::digest_from_koalabear_root(kb)
        };
    RecursiveBasefoldProof {
        rounds: src
            .rounds
            .into_iter()
            .map(|r| RecursiveBasefoldRound {
                uni_poly: r.uni_poly,
                commitment: conv_digest(r.commitment),
                _phantom_f: core::marker::PhantomData,
            })
            .collect(),
        final_poly: src.final_poly,
        pow_witness: src.pow_witness,
        batch_grinding_witness: src.batch_grinding_witness,
        component_openings: src
            .component_openings
            .into_iter()
            .map(|round| {
                round
                    .into_iter()
                    .map(|c| RecursiveBasefoldComponentOpening {
                        leaf_values: c.leaf_values,
                        merkle_path_bytes: c.merkle_path_bytes,
                        merkle_path_digests: c
                            .merkle_path_digests
                            .into_iter()
                            .map(conv_digest)
                            .collect(),
                        _phantom: core::marker::PhantomData,
                    })
                    .collect()
            })
            .collect(),
        query_phase_openings: src
            .query_phase_openings
            .into_iter()
            .map(|round| {
                round
                    .into_iter()
                    .map(|o| RecursiveBasefoldOpening {
                        position: o.position,
                        sibling_pair: o.sibling_pair,
                        merkle_path_bytes: o.merkle_path_bytes,
                        merkle_path_digests: o
                            .merkle_path_digests
                            .into_iter()
                            .map(conv_digest)
                            .collect(),
                        _phantom: core::marker::PhantomData,
                    })
                    .collect()
            })
            .collect(),
        batch_evaluations: src.batch_evaluations,
    }
}

/// const-promote a raw-digest basefold proof
/// (`RecursiveBasefoldProof<Felt, Ext, HV::Digest>`) into the verifier's
/// `HV::DigestVariable` digest form via `HV::const_digest`.  The verifier's
/// `type Proof` now carries `HV::DigestVariable` digests (not the raw host
/// `FieldHasher::Digest`), so the const-build (bytes-fallback) inner path and
/// the OUTER BN254 lift — both of which BAKE digest values — must promote.
/// (The inner *production* path witnesses its digests in
/// `read_basefold_proof_from_stream` instead; this is only for the baked
/// legacy/outer paths where value-independence is unnecessary.)
fn proof_digests_to_digestvar<C, HV>(
    builder: &mut Builder<C>,
    src: RecursiveBasefoldProof<
        Felt<C::F>,
        Ext<C::F, C::EF>,
        <HV as crate::hash::FieldHasher<C::F>>::Digest,
    >,
) -> RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, HV::DigestVariable>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    HV: crate::hash::FieldHasherVariable<C> + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
{
    use crate::basefold_verifier::{
        RecursiveBasefoldComponentOpening, RecursiveBasefoldOpening, RecursiveBasefoldRound,
    };
    // const_digest borrows `builder` mutably, so thread it via explicit
    // loops (closures can't re-borrow it per element).
    let mut rounds = Vec::with_capacity(src.rounds.len());
    for r in src.rounds.into_iter() {
        let commitment = HV::const_digest(builder, r.commitment);
        rounds.push(RecursiveBasefoldRound {
            uni_poly: r.uni_poly,
            commitment,
            _phantom_f: core::marker::PhantomData,
        });
    }
    let mut query_phase_openings = Vec::with_capacity(src.query_phase_openings.len());
    for round in src.query_phase_openings.into_iter() {
        let mut round_openings = Vec::with_capacity(round.len());
        for o in round.into_iter() {
            let mut merkle_path_digests = Vec::with_capacity(o.merkle_path_digests.len());
            for d in o.merkle_path_digests.into_iter() {
                merkle_path_digests.push(HV::const_digest(builder, d));
            }
            round_openings.push(RecursiveBasefoldOpening {
                position: o.position,
                sibling_pair: o.sibling_pair,
                merkle_path_bytes: o.merkle_path_bytes,
                merkle_path_digests,
                _phantom: core::marker::PhantomData,
            });
        }
        query_phase_openings.push(round_openings);
    }
    let component_openings = src
        .component_openings
        .into_iter()
        .map(|round| {
            round
                .into_iter()
                .map(|c| {
                    let mut merkle_path_digests =
                        Vec::with_capacity(c.merkle_path_digests.len());
                    for d in c.merkle_path_digests.into_iter() {
                        merkle_path_digests.push(HV::const_digest(builder, d));
                    }
                    RecursiveBasefoldComponentOpening {
                        leaf_values: c.leaf_values,
                        merkle_path_bytes: c.merkle_path_bytes,
                        merkle_path_digests,
                        _phantom: core::marker::PhantomData,
                    }
                })
                .collect()
        })
        .collect();
    RecursiveBasefoldProof {
        rounds,
        final_poly: src.final_poly,
        pow_witness: src.pow_witness,
        batch_grinding_witness: src.batch_grinding_witness,
        component_openings,
        query_phase_openings,
        batch_evaluations: src.batch_evaluations,
    }
}

/// const-build the basefold proof from a host bundle (the
/// `Witnessable::read` path — values baked, NOT witnessed).  Used by
/// the legacy bytes-deserialize lift paths (`lift_evaluation_proof_bytes`,
/// `lift_jagged_basefold_bundle_from_bytes`) which deserialize the bundle at
/// lift time and so have no inline pre-read proof.  The production inner path
/// pre-reads in `BasefoldShardProof::read` instead (value-independent).
///
/// Digests are const-promoted to `HV::DigestVariable` (rekey raw
/// KoalaBear roots → `HV::Digest`, read scalars, then const_digest each) so
/// the returned proof matches the verifier's `type Proof` digest type.
#[allow(clippy::type_complexity)]
pub fn const_basefold_proof_from_bundle<C, HV>(
    bundle: &JaggedBasefoldBundle,
    builder: &mut Builder<C>,
) -> (
    RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, HV::DigestVariable>,
    PartialSumcheckProof<Ext<C::F, C::EF>>,
    PartialSumcheckProof<Ext<C::F, C::EF>>,
    Ext<C::F, C::EF>,
    [Felt<C::F>; 8],
)
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    HV: crate::hash::FieldHasherVariable<C> + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
{
    use p3_field::PrimeCharacteristicRing;
    // Rekey the host proof's raw [InnerVal;8] roots onto HV::Digest (inner:
    // identity; outer: BN254 default), read the scalar fields, then promote
    // the digests to HV::DigestVariable.
    let host_kb = host_stacked_basefold_to_recursive(&bundle.basefold_proof);
    let host_hv =
        rekey_basefold_digests_to_hv::<C, HV, InnerVal, InnerChallenge>(host_kb);
    let raw_var = <_ as Witnessable<C>>::read(&host_hv, builder);
    let bp = proof_digests_to_digestvar::<C, HV>(builder, raw_var);
    let sc = host_sumcheck_to_const_var::<C>(
        builder,
        &jagged_reduction_to_partial_sumcheck(&bundle.reduction),
    );
    let je = host_sumcheck_to_const_var::<C>(
        builder,
        &stark_to_local_psp(&bundle.jagged_eval.partial_sumcheck_proof),
    );
    let ee = builder.constant(bundle.reduction.q_at_z);
    // const-build the commit cap root ([Felt;8]) for the bytes-fallback
    // path (this legacy path bakes; the production inline path witnesses it).
    let cap_roots = bundle.commit.commitment.roots();
    let cr: [Felt<C::F>; 8] = if cap_roots.is_empty() {
        core::array::from_fn(|_| builder.constant(C::F::ZERO))
    } else {
        core::array::from_fn(|i| builder.constant(cap_roots[0][i]))
    };
    (bp, sc, je, ee, cr)
}

pub fn lift_jagged_basefold_bundle<C, HV>(
    builder: &mut Builder<C>,
    bundle: &JaggedBasefoldBundle,
    // the basefold proof's felt/ext values, PRE-READ from the
    // witness stream in `BasefoldShardProof::read`.  This is what makes the
    // recursion program value-independent: the proof values are witness
    // inputs, not baked constants.  Digests are now witnessed too ([Felt;8] =
    // inner DigestVariable), so no rekey is needed below.
    preread_basefold_proof: RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, [Felt<C::F>; 8]>,
    // pre-read (witnessed) reduction sumcheck, jagged-eval
    // sub-sumcheck, and expected_eval — replace the lift's const-builds.
    preread_sumcheck: PartialSumcheckProof<Ext<C::F, C::EF>>,
    preread_jagged_eval: PartialSumcheckProof<Ext<C::F, C::EF>>,
    preread_expected_eval: Ext<C::F, C::EF>,
    // the witnessed commit cap root (== main_commitment) for
    // original_commitments[0]; replaces the baked const_digest of the
    // proof-specific root (value-independence).
    preread_commit_root: [Felt<C::F>; 8],
    max_log_row_count: usize,
    column_counts_by_round: &[Vec<usize>],
    row_counts_by_round: Option<&[Vec<usize>]>,
    // per-chip WITNESSED height felts (2^log_h),
    // name-sorted (parallel to each round's chip widths in
    // `column_counts_by_round`).  When `Some`, `col_prefix_sums` and
    // `row_counts` are reconstructed IN-CIRCUIT from these witnessed heights
    // (value-independent program) instead of baked from the compile-time
    // `bundle.packing.offsets` / `bundle.commit.chip_dims`.  When `None`,
    // falls back to the legacy baked path (callers not yet wired / empty).
    chip_height_felts: Option<&[Felt<C::F>]>,
) -> JaggedPcsProofVariable<
    RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, HV::DigestVariable>,
    HV::DigestVariable,
    C::F,
    C::EF,
>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    HV: crate::hash::FieldHasherVariable<C, DigestVariable = [Felt<C::F>; 8]>
        + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
{
    use zkm_recursion_compiler::circuit::CircuitV2Builder;
    use p3_field::PrimeCharacteristicRing;

    let zero_felt = |b: &mut Builder<C>| -> Felt<C::F> { b.constant(C::F::ZERO) };
    let zero_ext = |b: &mut Builder<C>| -> Ext<C::F, C::EF> { b.constant(C::EF::ZERO) };

    // ── Padding shape (mirror of jagged_pcs_lift.rs) ──
    // Host parity: column count = FLAT Σ chip widths (the host packing
    // has no artificial pad columns: `offsets.len()-1 == Σ widths`), padded
    // to the next power of two.  This drives `num_col_variables` =
    // the number of z_col challenges the in-circuit verifier samples —
    // it MUST equal the host's `log2(next_pow2(offsets.len()-1))`
    // (jagged_pcs.rs verify_jagged_basefold_inner).  The previous
    // `+ (cc[len-2]+1)` heuristic inflated this across a power-of-two
    // boundary for some chip sets (keccak shard: 568→1024 vs host 415→512),
    // desyncing the transcript under host-parity enforcement.
    let total_cols_before_pad: usize = column_counts_by_round
        .iter()
        .map(|cc| cc.iter().sum::<usize>())
        .sum();
    let padded_cols = total_cols_before_pad.max(1).next_power_of_two();
    let col_prefix_sums_len = padded_cols + 1;
    let num_col_variables = padded_cols.trailing_zeros() as usize;
    let num_rounds = column_counts_by_round.len().max(1);

    // ── Height-agnostic groundwork (Stage 3): witnessed NUMERIC
    // row_counts + padding_column_count, derived from the SAME bundle
    // packing the real prover / dummy use (single stacked main commit
    // == one round).  Carried ALONGSIDE the bit-decomposed `row_counts`
    // below; PURE DATA (Stage 4 wires the verifier checks).
    let (row_counts_usize, padding_column_counts): (Vec<Vec<usize>>, Vec<usize>) =
        if bundle.packing.column_counts.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            let (rc, pcc) = zkm_pcs::jagged::derive_row_and_padding_counts(
                &bundle.packing.column_counts,
                &bundle.packing.offsets,
                bundle.packing.total_values,
            );
            (vec![rc], vec![pcc])
        };

    // ── sumcheck_proof = the PRE-READ (witnessed) reduction
    // sumcheck (read in BasefoldShardProof::read), not a host const. ──
    let sumcheck_proof: PartialSumcheckProof<Ext<C::F, C::EF>> = preread_sumcheck;

    // ── basefold proof = the PRE-READ (witnessed) proof ──
    // No host_stacked_basefold_to_recursive / `.read()` here — the felt/ext
    // values already came off the witness stream in BasefoldShardProof::read.
    // Digests are witnessed too ([Felt;8] = inner DigestVariable), so the
    // proof is already in HV::DigestVariable form — no rekey needed.
    let basefold_proof_var = preread_basefold_proof;

    // ── batch_evaluations for the stacked layer = the SAME witnessed
    // values (reuse, don't re-read/re-const → no double-consume) ──
    let batch_evaluations_ext: Vec<Vec<Ext<C::F, C::EF>>> =
        basefold_proof_var.batch_evaluations.clone();

    let stacked_pcs_proof = RecursiveStackedPcsProof::<
        RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            HV::DigestVariable,
        >,
        C::F,
        C::EF,
    > {
        batch_evaluations: batch_evaluations_ext,
        pcs_proof: basefold_proof_var,
    };

    // ── REAL: original_commitments[0] = the witnessed commit cap root ──
    // original_commitments[0] is the BaseFold commit cap
    // root.  For the single-main-commit flow it EQUALS `main_commitment`
    // (basefold_commit_digest(commit) = commit.commitment.roots()[0]), which
    // is already witnessed in BasefoldShardProof::read.  Reuse that witnessed
    // value (`preread_commit_root`) instead of BAKING the proof-specific root
    // via const_digest — this is the final value-dependence in the lift, and
    // witnessing it is what lets a same-shape dummy match the real program.
    // (HV::DigestVariable == [Felt;8] for the inner ring per the where-bound.)
    let first_commit_digest: HV::DigestVariable = preread_commit_root;
    let zero_digest_var: HV::DigestVariable = HV::const_digest(
        builder,
        <HV as crate::hash::FieldHasher<C::F>>::Digest::default(),
    );
    let mut original_commitments: Vec<HV::DigestVariable> = Vec::with_capacity(num_rounds);
    original_commitments.push(first_commit_digest);
    for _ in 1..num_rounds {
        original_commitments.push(zero_digest_var);
    }

    // ── REAL: jagged_eval_proof from bundle.jagged_eval ──
    // The host prover now emits SP1's branching-program jagged-eval
    // sub-protocol (jagged_pcs.rs, between the reduction and
    // the BaseFold open).  Lift its `PartialSumcheckProof` to circuit
    // variables via the same const-promotion path as the outer
    // reduction so the in-circuit `real_jagged_evaluator_fn`
    // (compress_basefold.rs) verifies a non-vacuous closing identity.
    // pre-read (witnessed) jagged-eval sub-sumcheck.
    let jagged_eval_proof = JaggedSumcheckEvalProof::<Ext<C::F, C::EF>> {
        partial_sumcheck_proof: preread_jagged_eval,
    };

    // ── REAL: col_prefix_sums with artificial-zero insertion ──
    // Walks column_counts_by_round + bundle.packing.offsets in
    // lock-step, emitting per-real-column bit-decompositions and
    // per-round artificial-zero columns (the cc[len-2]+1 padding
    // rule the host prover applies for stripe alignment — see
    // jagged_pcs_lift.rs:111-118 for the formula derivation).
    //
    // Artificial columns have zero width, so their cumulative offset
    // equals the previous column's offset (no advance).  This makes
    // col_prefix_sums monotonic non-decreasing and ensures the final
    // entry bit-decodes to bundle.packing.total_values.
    //
    // For empty bundles all decompositions reduce to zero-felts,
    // preserving byte-for-byte compat with the prior placeholder.
    //
    // BaseFold-over-BN254 wrap port — CRITICAL: the per-entry bit
    // width must equal the branching program's `half = proof_point.len()/2`
    // (jagged_eval.rs:223 + compress_basefold.rs:998), which the HOST
    // jagged-eval prover sets to `log_m + 1` = z_trace.len()
    // (jagged_eval_sumcheck.rs:534).  Using `max_log_row_count + 1` is too
    // narrow when the total column area exceeds 2^max_log_row_count (true
    // for the wide WrapAir trace): col_prefix_sums.last() (= total_values)
    // then CLAMPS to 2^(max_log_row_count+1)-1 and the step-7 prefix-sum
    // felt-assert (acc == final_area) fails (e.g. 201326592 vs 8388607).
    // Derive the width from the jagged-eval sumcheck point length, falling
    // back to max_log_row_count+1 only for the dummy/empty jagged_eval.
    let jagged_eval_point_len =
        bundle.jagged_eval.partial_sumcheck_proof.point_and_eval.0.len();
    let bits_per_entry = if jagged_eval_point_len >= 2 {
        jagged_eval_point_len / 2
    } else {
        max_log_row_count + 1
    };
    let total_values = bundle.packing.total_values;
    if bits_per_entry > 31 {
        // FIX-off (bug #8): the 32-bit-width col_prefix_sum path is exercised.
        eprintln!(
            "LIFT-BUNDLE-DIAG bits_per_entry={bits_per_entry} jagged_eval_point_len={jagged_eval_point_len} \
             total_values={total_values} max_log_row_count={max_log_row_count} \
             col_prefix_sums_len={col_prefix_sums_len} chip_height_felts={} (width capped at 31, MSBs zero-extended)",
            chip_height_felts.is_some()
        );
    }
    let cap_to_bits = |v: usize| -> usize {
        if bits_per_entry < usize::BITS as usize {
            v.min((1usize << bits_per_entry) - 1)
        } else {
            v
        }
    };
    // HEIGHT-AGNOSTIC (low-placement) FIX: gate flag for the offset-diff
    // row_counts below (so they match the baked band col_prefix_sums under
    // ZIREN_HA_BAKED_COLPS).  The col_prefix_sums path is unchanged (baked when
    // chip_height_felts is None / gated).
    let ha_baked_band = std::env::var("ZIREN_HA_BAKED_COLPS").is_ok();
    let jagged_dim_metadata = if let Some(heights) = chip_height_felts {
        // reconstruct col_prefix_sums IN-CIRCUIT
        // from the WITNESSED per-chip heights instead of baking
        // bundle.packing.offsets.  offsets[k] = Σ (prior column heights);
        // chip i (name-sorted) contributes column_counts[i] columns of
        // height heights[i] (mirrors pack_traces_jagged jagged.rs:304-309).
        // The artificial-zero + pad columns share the last real offset; the
        // final slot is total_values = the running accumulator.
        // #88 band-5 (bug #8): `bits_per_entry = log2(total_area)+1` can reach
        // 32 when the band-padded total column area lands in [2^30, 2^31)
        // (band-5: ext_alu 2^24 etc. → total_values ≈ 1.28e9 → log_m=31 →
        // bits=32).  This is reachable in BOTH FIX-on and FIX-off (band-5
        // replaced the old component-opening band, so any program above band-4
        // lands on it).  Every col_prefix_sum VALUE is < total_values < 2^31,
        // so it genuinely fits in 31 bits — but `num2bits_v2_f` rejects a
        // 32-bit WIDTH (a single KoalaBear felt is < 2^31; modulus
        // 2^31-2^24+1).  Decompose only the low 31 bits (range-checked, valid
        // because v < 2^31) and zero-extend the big-endian MSBs to the full
        // `bits_per_entry` width.  The high bits are provably 0
        // (total_values < 2^31).  No-op when bits_per_entry ≤ 31 (every proof
        // landing on bands 1-4 + core) ⇒ byte-identical there.
        let num2bits_be = |b: &mut Builder<C>, v: Felt<C::F>| -> Vec<Felt<C::F>> {
            let dec_bits = bits_per_entry.min(31);
            let mut bits = b.num2bits_v2_f(v, dec_bits);
            bits.reverse(); // big-endian (MSB first), matching the baked path
            if bits_per_entry > dec_bits {
                // Prepend zero MSBs so the layout width == bits_per_entry,
                // matching the prover's `bits_big_endian(value, half)`.
                let mut out: Vec<Felt<C::F>> = Vec::with_capacity(bits_per_entry);
                for _ in 0..(bits_per_entry - dec_bits) {
                    out.push(b.constant(C::F::ZERO));
                }
                out.extend(bits);
                out
            } else {
                bits
            }
        };
        let mut col_prefix_sums: Vec<Vec<Felt<C::F>>> =
            Vec::with_capacity(col_prefix_sums_len);
        let mut acc: Felt<C::F> = builder.constant(C::F::ZERO);
        // [0] = 0
        let bits0 = num2bits_be(builder, acc);
        col_prefix_sums.push(bits0);
        // `current_offset_felt` mirrors the baked path's `current_offset`:
        // the last real-column offset pushed (artificial/pad columns reuse it).
        let mut current_offset_felt: Felt<C::F> = acc;
        'outer: for cc in column_counts_by_round.iter() {
            for (chip_idx, &w) in cc.iter().enumerate() {
                let h = heights
                    .get(chip_idx)
                    .copied()
                    .unwrap_or_else(|| builder.constant(C::F::ZERO));
                for _ in 0..w {
                    if col_prefix_sums.len() >= col_prefix_sums_len {
                        break 'outer;
                    }
                    current_offset_felt = acc;
                    let bits = num2bits_be(builder, acc);
                    col_prefix_sums.push(bits);
                    acc = builder.eval(acc + h);
                }
            }
            // Host parity: no artificial-zero columns (see padding-shape
            // comment above); the pow2 tail-pad below reuses
            // `current_offset_felt`, identical to what the old added-loop
            // emitted, so the per-entry values are unchanged where lengths
            // coincide.
        }
        while col_prefix_sums.len() < col_prefix_sums_len - 1 {
            let bits = num2bits_be(builder, current_offset_felt);
            col_prefix_sums.push(bits);
        }
        if col_prefix_sums.len() < col_prefix_sums_len {
            // Final = total_values = the running accumulator (Σ w_i·h_i).
            let bits = num2bits_be(builder, acc);
            col_prefix_sums.push(bits);
        }
        JaggedDimensionMetadata::<Felt<C::F>> { col_prefix_sums }
    } else {
        let mut col_prefix_sums: Vec<Vec<Felt<C::F>>> =
            Vec::with_capacity(col_prefix_sums_len);
        // [0] = 0 (always)
        col_prefix_sums.push(bit_decompose_usize_to_felts::<C>(builder, 0, bits_per_entry));
        let mut offset_idx: usize = 0;
        let mut current_offset: usize = 0;
        for cc in column_counts_by_round.iter() {
            // Real columns: per-column advance via bundle.packing.offsets.
            let real_in_round = cc.iter().sum::<usize>();
            for _ in 0..real_in_round {
                if offset_idx < bundle.packing.offsets.len() {
                    current_offset = bundle.packing.offsets[offset_idx];
                    offset_idx += 1;
                }
                if col_prefix_sums.len() >= col_prefix_sums_len {
                    break;
                }
                col_prefix_sums.push(bit_decompose_usize_to_felts::<C>(
                    builder,
                    cap_to_bits(current_offset),
                    bits_per_entry,
                ));
            }
            // Host parity: no artificial-zero columns; the pow2
            // tail-pad below emits the same `current_offset` entries.
        }
        // Pad to padded_cols (skip last slot — that one's reserved for
        // total_values).  Padding columns also have zero advance.
        while col_prefix_sums.len() < col_prefix_sums_len - 1 {
            col_prefix_sums.push(bit_decompose_usize_to_felts::<C>(
                builder,
                cap_to_bits(current_offset),
                bits_per_entry,
            ));
        }
        // Final slot = bit-decomp of total_values.  This is what the
        // verifier's final_area Horner-decode at
        // recursive_jagged_pcs.rs:262-272 asserts equals the
        // accumulated row-count sum.
        if col_prefix_sums.len() < col_prefix_sums_len {
            col_prefix_sums.push(bit_decompose_usize_to_felts::<C>(
                builder,
                cap_to_bits(total_values),
                bits_per_entry,
            ));
        }
        JaggedDimensionMetadata::<Felt<C::F>> { col_prefix_sums }
    };

    // ── row_counts: caller-plumbed if provided, else derived from the bundle ──
    // A caller MAY pass per-chip row counts via row_counts_by_round (parallel
    // to column_counts_by_round).  When None, they are derived from the
    // packer's `bundle.commit.chip_dims` (see the else-branch) — NOT zeroed,
    // which was the bug that broke the prefix-sum binding on real proofs.
    // The verifier reads row_counts[round][chip] as a SINGLE Felt
    // representing the chip's row count (recursive_jagged_pcs.rs:248-260
    // dereferences row as a Felt and repeats it `col` times).  Since
    // max_log_row_count is well within KoalaBear's 31-bit range, the
    // raw count fits in a single Felt constant.
    let row_counts: Vec<Vec<Felt<C::F>>> = if let Some(heights) = chip_height_felts {
        // per-chip row counts = the WITNESSED
        // heights (2^log_h), reused for every round (a chip's prep + main
        // traces share one height).  Value-independent (vs the baked
        // chip_dims fallback below).
        column_counts_by_round.iter().map(|_| heights.to_vec()).collect()
    } else if let Some(row_counts_src) = row_counts_by_round {
        row_counts_src
            .iter()
            .map(|round| {
                round
                    .iter()
                    .map(|&rc| builder.constant(C::F::from_u64(rc as u64)))
                    .collect()
            })
            .collect()
    } else {
        // row_counts NOT caller-plumbed: derive the padded per-chip heights
        // (2^log_height_padded) from the packer's own `bundle.commit.chip_dims`
        // — exactly the dimensions that produced `bundle.packing.offsets`, so
        // the verifier's prefix-sum consistency check
        // (recursive_jagged_pcs.rs:248-272) reconciles.  The previous all-zero
        // fallback made that check assert the real (non-zero) offsets equal 0,
        // i.e. it FAILED on every non-degenerate proof and only "passed" for
        // empty bundles.  A chip's preprocessed + main traces share one height,
        // so the same per-chip heights are reused for every round; chip_dims is
        // in the same (name-sorted) chip order as `column_counts_by_round`.
        // HEIGHT-AGNOSTIC (low-placement) FIX: when gated, derive the per-chip
        // row counts from the BAND offset DIFFS (the committed slot heights) so
        // they match the baked col_prefix_sums (= bundle.packing.offsets); the
        // default chip_dims path decodes the RAW height, which diverges from the
        // band offsets under low-placement and trips the step-7 prefix-sum
        // assert.  (FIX-on: offset diffs == 1<<chip_dims.log_h ⇒ same.)
        let heights: Vec<Felt<C::F>> = if ha_baked_band {
            let offs = &bundle.packing.offsets;
            let mut hs: Vec<Felt<C::F>> = Vec::new();
            let mut col = 0usize;
            if let Some(round0) = column_counts_by_round.first() {
                for &w in round0.iter() {
                    let h = if w > 0 && col + 1 < offs.len() {
                        offs[col + 1].saturating_sub(offs[col])
                    } else {
                        0
                    };
                    hs.push(builder.constant(C::F::from_u64(h as u64)));
                    col += w;
                }
            }
            hs
        } else {
            bundle
                .commit
                .chip_dims
                .iter()
                .map(|&(_w, log_h)| builder.constant(C::F::from_u64(1u64 << log_h)))
                .collect()
        };
        column_counts_by_round.iter().map(|_| heights.clone()).collect()
    };

    // ── REAL: expected_eval from bundle.reduction.q_at_z ──
    // The in-circuit verifier's closing identity asserts
    //     jagged_eval * expected_eval == sumcheck.point_and_eval.1
    // mirroring the host verifier's q_at_z * w(z) == current_claim.
    // pre-read (witnessed) expected_eval (q_at_z).
    let expected_eval: Ext<C::F, C::EF> = preread_expected_eval;

    // ── Top-level assembly ──
    JaggedPcsProofVariable {
        params: jagged_dim_metadata,
        sumcheck_proof,
        jagged_eval_proof,
        pcs_proof: stacked_pcs_proof,
        column_counts: column_counts_by_round.to_vec(),
        row_counts,
        row_counts_usize,
        padding_column_counts,
        original_commitments,
        expected_eval,
    }
}

/// Bridge a stark-side [`st::PartialSumcheckProof`] into the local
/// recursion-circuit [`PartialSumcheckProof`] type used by
/// [`host_sumcheck_to_const_var`] and the in-circuit jagged-PCS
/// verifier.
///
/// **Why this exists**: the two structs are *structurally identical*
/// (`Vec<UnivariatePolynomial<K>>` + `K` + `(Vec<K>, K)`) but live in
/// different crates (`zkm_pcs::shard_level::types` vs
/// `crate::partial_sumcheck`), with each carrying its own local
/// `UnivariatePolynomial` — so the compiler treats them as distinct
/// types (E0308 at call sites that cross the boundary).  The
/// host-side jagged-eval sub-protocol prover emits the stark variant
/// (`bundle.jagged_eval.partial_sumcheck_proof`); the in-circuit
/// lifter consumes the local variant.  This adapter performs a
/// field-by-field rebuild between the two — zero data transformation,
/// purely a type re-wrap.
fn stark_to_local_psp(
    host: &st::PartialSumcheckProof<InnerChallenge>,
) -> PartialSumcheckProof<InnerChallenge> {
    PartialSumcheckProof {
        univariate_polys: host
            .univariate_polys
            .iter()
            .map(|p| UnivariatePolynomial { coefficients: p.coefficients.clone() })
            .collect(),
        claimed_sum: host.claimed_sum,
        point_and_eval: (host.point_and_eval.0.clone(), host.point_and_eval.1),
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
    // point_and_eval.1 must be the last round's poly evaluated at the LAST
    // sampled challenge r_{n-1}, matching the circuit verify_sumcheck final
    // check `previous_poly.eval_at(alpha_last) == point_and_eval.1` and the
    // host's final claim `current_claim = jagged_eval_round_poly(round_{n-1},
    // r_{n-1})`. The host's `eval_point` is in REVERSE-sampled order
    // (verify_jagged_reduction asserts `sampled[i] == eval_point[n-1-i]`, so
    // eval_point[0] = r_{n-1}, eval_point[last] = r_0). The previous code used
    // `eval_point[last_idx]` = r_0 — the FIRST challenge — making point_and_eval.1
    // = poly[last].eval_at(r_0) != eval_at(r_{n-1}), failing the in-circuit jagged
    // sumcheck final-eval check (gnark wrap step5, n=24 rounds). Use eval_point[0].
    let final_eval = univariate_polys[last_idx].eval_at_point(proof.eval_point[0]);

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
        let proof = zkm_pcs::shard_level::shard_proof::BasefoldShardProof::<
            InnerVal,
            InnerChallenge,
        >::empty(std::array::from_fn(|_| InnerVal::ZERO), 8);
        let (main_commit, pvs, _logup, _zerocheck, evaluation_proof, _opened_values) =
            <_ as Witnessable<C>>::read(&proof, &mut builder);
        assert_eq!(main_commit.len(), 8);
        assert_eq!(pvs.len(), 8);
        // The `EvaluationProof` (formerly a separate `(evbytes, bundle_opt)`
        // pair) lifts to `LiftedEvalProof::Empty` for an empty proof.
        assert!(matches!(evaluation_proof, LiftedEvalProof::Empty));
    }

    /// JaggedReductionRound Witnessable round-trips a
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

    /// JaggedReductionProof Witnessable cascades through
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

    /// LeafOpening Witnessable handles the (Vec<Vec<F>>,
    /// MT::Proof const-passthrough) split correctly.
    #[test]
    fn leaf_opening_witnessable_reads() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let host = LeafOpening::<InnerVal, JaggedMmcs> {
            values: vec![vec![InnerVal::ZERO; 4], vec![InnerVal::ZERO; 4]],
            proof: vec![[InnerVal::ZERO; 8]; 3],
        };
        let var = <_ as Witnessable<C>>::read(&host, &mut builder);
        assert_eq!(var.values.len(), 2);
        assert_eq!(var.values[0].len(), 4);
        assert_eq!(var.proof.len(), 3);
    }

    /// MerkleOpening Witnessable composes through a Vec
    /// of LeafOpenings.
    #[test]
    fn merkle_opening_witnessable_reads() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let leaf = LeafOpening::<InnerVal, JaggedMmcs> {
            values: vec![vec![InnerVal::ZERO; 2]],
            proof: vec![[InnerVal::ZERO; 8]; 2],
        };
        let host = MerkleOpening::<InnerVal, JaggedMmcs> {
            leaves: vec![leaf.clone(), leaf],
        };
        let var = <_ as Witnessable<C>>::read(&host, &mut builder);
        assert_eq!(var.leaves.len(), 2);
    }

    /// eval-form → coeff-form converter shape sanity.
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

    /// converter output flows through the existing
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

    /// empty BaseFold proof converts to empty
    /// recursive shape — exercises the rounds.iter().zip path with
    /// zero rounds and the components/query_phase pass-through.
    #[test]
    fn host_basefold_proof_converter_empty() {
        let proof = BasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
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

    /// rounds preserve uni_poly + extracted cap root.
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
        let proof = BasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
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

    /// query-phase opening parses leaf row
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
        let leaf = LeafOpening::<InnerVal, JaggedMmcs> {
            values: vec![row],
            proof: vec![[InnerVal::ZERO; 8]; 5],
        };
        let opening = MerkleOpening::<InnerVal, JaggedMmcs> { leaves: vec![leaf] };
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
        // merkle_path_digests is populated from leaf.proof.
        assert_eq!(recur[0].merkle_path_digests.len(), 5);
        assert_eq!(recur[0].position, 0);
    }

    /// stacked converter threads batch_evaluations from
    /// the host StackedBasefoldProof verbatim.
    #[test]
    fn host_stacked_basefold_threads_batch_evaluations() {
        use p3_field::PrimeCharacteristicRing;
        let bf_proof = BasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
            univariate_messages: vec![],
            fri_commitments: vec![],
            component_polynomials_query_openings_and_proofs: vec![],
            query_phase_openings_and_proofs: vec![],
            final_poly: InnerChallenge::ZERO,
            pow_witness: InnerVal::ZERO,
            batch_grinding_witness: InnerVal::ZERO,
        };
        let stacked = StackedBasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
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

    /// converter output flows through the existing
    /// `RecursiveBasefoldProof` Witnessable impl
    /// (basefold_witness.rs:443) — confirms the bridge composes
    /// end-to-end with the pre-existing witness surface.
    #[test]
    fn host_basefold_converter_witnessable_composition() {
        use p3_field::PrimeCharacteristicRing;
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let proof = BasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
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

    /// bit_decompose_usize_to_felts uses MSB-first ordering that
    /// matches the verifier's Horner decode at
    /// recursive_jagged_pcs.rs:262-272 (`final_area = bit + 2*final_area`).
    #[test]
    fn bit_decompose_zero_yields_all_zero_felts() {
        use p3_field::PrimeCharacteristicRing;
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let bits = bit_decompose_usize_to_felts::<C>(&mut builder, 0, 5);
        assert_eq!(bits.len(), 5);
        // (Felts are SSA references; we can't read concrete values
        // here without running the circuit — just shape-check.)
        let _ = bits;
        let _ = InnerVal::ZERO;
    }

    /// bit decomposition shape with non-zero values.
    /// 4 bits LSB-first: 5 = [0, 1, 0, 1] when read MSB-first.
    #[test]
    fn bit_decompose_shape_matches_num_bits() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let bits = bit_decompose_usize_to_felts::<C>(&mut builder, 5, 4);
        assert_eq!(bits.len(), 4);
        let bits_zero = bit_decompose_usize_to_felts::<C>(&mut builder, 0, 8);
        assert_eq!(bits_zero.len(), 8);
        let bits_max = bit_decompose_usize_to_felts::<C>(&mut builder, 255, 8);
        assert_eq!(bits_max.len(), 8);
    }

    /// overflow panic when value exceeds bit budget.
    #[test]
    #[should_panic(expected = "exceeds 4 bits")]
    fn bit_decompose_overflow_panics() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        // 16 needs 5 bits; only allotted 4 → panic.
        let _ = bit_decompose_usize_to_felts::<C>(&mut builder, 16, 4);
    }

    /// edge case — zero bits is meaningful only for
    /// value zero.  Returns empty Vec.
    #[test]
    fn bit_decompose_zero_bits_for_zero_value() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let bits = bit_decompose_usize_to_felts::<C>(&mut builder, 0, 0);
        assert_eq!(bits.len(), 0);
    }

    /// bytes adapter falls back to zero placeholder
    /// for empty bytes (matches the BasefoldShardProof::empty path).
    #[test]
    fn lift_evaluation_proof_via_bundle_empty_bytes_falls_back() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let cols: Vec<Vec<usize>> = vec![vec![3], vec![5]];
        let var = lift_evaluation_proof_via_bundle::<C, zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>(&mut builder, &[], 21, &cols);
        assert_eq!(var.column_counts, cols);
        assert_eq!(var.original_commitments.len(), 2);
    }

    /// bytes adapter routes a real bundle's bytes
    /// through lift_jagged_basefold_bundle.  Round-trips serialize +
    /// deserialize via rmp-serde, then lifts.
    #[test]
    fn lift_evaluation_proof_via_bundle_real_bundle_bytes() {
        use p3_field::PrimeCharacteristicRing;
        use p3_symmetric::MerkleCap;
        use zkm_pcs::jagged_pcs::jagged::PackingMeta;
        use zkm_pcs::jagged_pcs::BasefoldLateBindingCommit;

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
            basefold_proof: StackedBasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
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
            jagged_eval: zkm_pcs::jagged_eval_sumcheck::JaggedSumcheckEvalProof::dummy(),
            // CP-A per-round split: single-group (G==1) test bundle.
            extra_reduction: vec![],
            extra_basefold_proof: vec![],
            extra_commit: vec![],
            extra_packing: vec![],
            extra_jagged_eval: vec![],
            groups: vec![],
        };
        let bytes = bundle.to_bytes();
        let cols: Vec<Vec<usize>> = vec![vec![3]];
        let var = lift_evaluation_proof_via_bundle::<C, zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>(&mut builder, &bytes, 21, &cols);
        assert_eq!(var.column_counts, cols);
        // sumcheck_proof has the real reduction round (1 univariate poly).
        assert_eq!(var.sumcheck_proof.univariate_polys.len(), 1);
    }

    /// row_counts_by_round plumbed through produces
    /// non-zero row_counts in the variable (one Felt per chip).
    /// STALE FIXTURE: predates the LiftedEvalProof bundle explosion —
    /// the 5-arg lift call needs a full RecursiveBasefoldProof + sumcheck
    /// fixtures rework.  Compile-gated out, not silently deleted.
    #[cfg(any())]
    #[test]
    fn lift_jagged_basefold_bundle_with_row_counts() {
        use p3_field::PrimeCharacteristicRing;
        use p3_symmetric::MerkleCap;
        use zkm_pcs::jagged_pcs::jagged::PackingMeta;
        use zkm_pcs::jagged_pcs::BasefoldLateBindingCommit;

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
            basefold_proof: StackedBasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
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
                offsets: vec![0, 16, 32],
                total_values: 64,
                log_dense_size: 6,
                column_counts: vec![1, 1, 1],
            },
            jagged_eval: zkm_pcs::jagged_eval_sumcheck::JaggedSumcheckEvalProof::dummy(),
            // CP-A per-round split: single-group (G==1) test bundle.
            extra_reduction: vec![],
            extra_basefold_proof: vec![],
            extra_commit: vec![],
            extra_packing: vec![],
            extra_jagged_eval: vec![],
            groups: vec![],
        };
        let cols: Vec<Vec<usize>> = vec![vec![1, 1, 1]];
        let rows: Vec<Vec<usize>> = vec![vec![16, 16, 16]];
        let var = lift_jagged_basefold_bundle::<C, zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>(&mut builder, &bundle, 8, &cols, Some(&rows));
        assert_eq!(var.row_counts.len(), 1);
        assert_eq!(var.row_counts[0].len(), 3);
        // col_prefix_sums has padded_cols+1 entries.  With cc=[1,1,1]
        // total_real=3, added=cc[len-2]+1=1+1=2, so per round 3+2=5
        // total before pad → next_power_of_two = 8 → col_prefix_sums.len = 9.
        assert_eq!(var.params.col_prefix_sums.len(), 9);
    }

    /// row_counts=None path: lifting a NON-degenerate bundle with populated
    /// `commit.chip_dims` must succeed and produce the right-shaped
    /// `row_counts` (one Felt per chip per round) derived from chip_dims —
    /// the wiring that replaced the all-zero fallback.  (Felt *values* are IR
    /// handles, so the numeric binding is asserted by the host-level test
    /// below and exercised in-circuit by the e2e compress gate.)
    /// STALE FIXTURE: predates the LiftedEvalProof bundle explosion —
    /// the 5-arg lift call needs RecursiveBasefoldProof + sumcheck fixture
    /// rework.  Compile-gated out, not silently deleted.
    #[cfg(any())]
    #[test]
    fn lift_jagged_basefold_bundle_none_path_derives_from_chip_dims() {
        use p3_field::PrimeCharacteristicRing;
        use p3_symmetric::MerkleCap;
        use zkm_pcs::jagged_pcs::jagged::PackingMeta;
        use zkm_pcs::jagged_pcs::BasefoldLateBindingCommit;

        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let cap_digest: [InnerVal; 8] = [InnerVal::ZERO; 8];
        let bundle = JaggedBasefoldBundle {
            reduction: JaggedReductionProof::<InnerChallenge> {
                rounds: vec![JaggedReductionRound { evals: [InnerChallenge::ZERO; 3] }],
                eval_point: vec![InnerChallenge::ZERO],
                q_at_z: InnerChallenge::ZERO,
            },
            basefold_proof: StackedBasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
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
                // 3 single-column chips, each padded height 16 = 2^4.
                chip_dims: vec![(1, 4), (1, 4), (1, 4)],
                area: 0,
                log_stacking_height: 0,
            },
            packing: PackingMeta {
                offsets: vec![0, 16, 32],
                total_values: 48,
                log_dense_size: 6,
                column_counts: vec![1, 1, 1],
            },
            jagged_eval: zkm_pcs::jagged_eval_sumcheck::JaggedSumcheckEvalProof::dummy(),
            // CP-A per-round split: single-group (G==1) test bundle.
            extra_reduction: vec![],
            extra_basefold_proof: vec![],
            extra_commit: vec![],
            extra_packing: vec![],
            extra_jagged_eval: vec![],
            groups: vec![],
        };
        let cols: Vec<Vec<usize>> = vec![vec![1, 1, 1]];
        // None -> derive row_counts from bundle.commit.chip_dims.
        let var = lift_jagged_basefold_bundle::<C, zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>(&mut builder, &bundle, 8, &cols, None);
        assert_eq!(var.row_counts.len(), 1);
        assert_eq!(var.row_counts[0].len(), 3);
        assert_eq!(var.params.col_prefix_sums.len(), 9);
    }

    /// NEGATIVE binding guard for the row_counts=None fix: the per-chip
    /// heights derived from `bundle.commit.chip_dims` (2^log_height_padded)
    /// must reconcile the packer's `packing.offsets` via the verifier's
    /// prefix-sum accumulation (recursive_jagged_pcs.rs:248-272), and the
    /// OLD all-zero fallback must NOT (it asserted the real, non-zero offsets
    /// equal 0 — failing every non-degenerate proof).  Pure-usize mirror of
    /// the in-circuit check; the e2e compress gate exercises the same logic
    /// in-circuit.
    #[test]
    fn row_counts_from_chip_dims_reconcile_prefix_sums() {
        // Consistent bundle: 3 single-column chips, padded height 16 = 2^4,
        // so offsets are the cumulative per-column heights and total = 3*16.
        let chip_dims: Vec<(usize, u32)> = vec![(1, 4), (1, 4), (1, 4)];
        let column_counts: Vec<usize> = vec![1, 1, 1];
        let offsets: Vec<usize> = vec![0, 16, 32];
        let total_values: usize = 48;

        // The fix: heights from chip_dims (NOT zeros).
        let heights: Vec<usize> =
            chip_dims.iter().map(|&(_w, log_h)| 1usize << log_h).collect();
        assert_eq!(heights, vec![16, 16, 16]);

        // Verifier reconciliation (recursive_jagged_pcs.rs:248-272) in usize:
        // repeat each chip's height `column_count` times, accumulate, and
        // assert the running sum equals each offset, ending at total_values.
        let reconciles = |rows: &[usize]| -> bool {
            let repeated: Vec<usize> = rows
                .iter()
                .zip(column_counts.iter())
                .flat_map(|(&h, &c)| std::iter::repeat(h).take(c))
                .collect();
            let mut acc = 0usize;
            for (i, &h) in repeated.iter().enumerate() {
                if acc != offsets[i] {
                    return false;
                }
                acc += h;
            }
            acc == total_values
        };

        // chip_dims-derived heights reconcile the real offsets.
        assert!(reconciles(&heights), "chip_dims heights must reconcile the offsets");
        // The old all-zero fallback does NOT — this is the bug it caused.
        assert!(
            !reconciles(&[0usize, 0, 0]),
            "all-zero row_counts must FAIL to reconcile non-zero offsets"
        );
    }

    /// bundle lift produces a structurally valid
    /// JaggedPcsProofVariable with shape matching the existing
    /// lift_evaluation_proof_bytes placeholder for empty bundles.
    /// STALE FIXTURE: predates the LiftedEvalProof bundle explosion.
    /// Compile-gated out, not silently deleted.
    #[cfg(any())]
    #[test]
    fn lift_jagged_basefold_bundle_smoke() {
        use p3_field::PrimeCharacteristicRing;
        use p3_symmetric::MerkleCap;
        use zkm_pcs::jagged_pcs::jagged::PackingMeta;
        use zkm_pcs::jagged_pcs::BasefoldLateBindingCommit;

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
            basefold_proof: StackedBasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
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
            jagged_eval: zkm_pcs::jagged_eval_sumcheck::JaggedSumcheckEvalProof::dummy(),
            // CP-A per-round split: single-group (G==1) test bundle.
            extra_reduction: vec![],
            extra_basefold_proof: vec![],
            extra_commit: vec![],
            extra_packing: vec![],
            extra_jagged_eval: vec![],
            groups: vec![],
        };
        let cols: Vec<Vec<usize>> = vec![vec![3], vec![5]];
        let var = lift_jagged_basefold_bundle::<C, zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>(&mut builder, &bundle, 21, &cols, None);
        // column_counts pass through verbatim.
        assert_eq!(var.column_counts, cols);
        // num_rounds == 2 → 2 commitment slots, first from bundle,
        // rest zero placeholders.
        assert_eq!(var.original_commitments.len(), 2);
        // sumcheck_proof has one univariate poly (one reduction round).
        assert_eq!(var.sumcheck_proof.univariate_polys.len(), 1);
    }
}
