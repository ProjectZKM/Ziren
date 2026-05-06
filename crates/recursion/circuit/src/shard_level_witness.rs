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

use zkm_stark::basefold::proof::{LeafOpening, MerkleOpening};
use zkm_stark::basefold_late_binding::LbMmcs;
use zkm_stark::jagged_sumcheck::{JaggedReductionProof, JaggedReductionRound};

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
}
