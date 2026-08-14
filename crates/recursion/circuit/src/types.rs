use hashbrown::HashMap;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use p3_matrix::Dimensions;

use zkm_pcs::septic_digest::SepticDigest;
use zkm_recursion_compiler::ir::{Builder, Ext, Felt};
use zkm_recursion_core::DIGEST_SIZE;

use crate::{
    challenger::CanObserveVariable, hash::FieldHasherVariable, CircuitConfig,
    KoalaBearFriParametersVariable,
};

/// Reference: [zkm_core::stark::StarkVerifyingKey]
#[derive(Clone)]
pub struct VerifyingKeyVariable<
    C: CircuitConfig<F = SC::Val>,
    SC: KoalaBearFriParametersVariable<C>,
> {
    pub commitment: SC::DigestVariable,
    pub pc_start: Felt<C::F>,
    pub initial_global_cumulative_sum: SepticDigest<Felt<C::F>>,
    pub chip_information: Vec<(String, TwoAdicMultiplicativeCoset<C::F>, Dimensions)>,
    pub chip_ordering: HashMap<String, usize>,
    /// The per-preprocessed-chip
    /// `vk.hash` inputs `[name_digest, prep_width]`, WITNESSED (read in the
    /// `StarkVerifyingKey` Witnessable) rather than baked from the
    /// compile-time `chip_information`, in place of a per-prep-domain
    /// HEIGHT block (`[log_n, 2^log_n, shift, generator]`).  WITNESSING (not
    /// baking) is load-bearing for VALUE-INDEPENDENCE: the recursion program
    /// must emit a FIXED number of reads per prep chip (2 here) regardless of
    /// the verified core vk's per-chip heights / name lengths / sort order,
    /// so the recursion VK depends only on the chip SET — not on which
    /// program produced the core vk.  `name_digest = poseidon2_hash(name
    /// bytes as fields)[0]` (a single fixed-width felt), computed identically
    /// on the host (prover/src/types.rs) and host-verifier
    /// (verifier/src/stark/mod.rs).  Empty for vks constructed directly
    /// without witnessing.
    pub prep_name_width_hash_inputs: Vec<[Felt<C::F>; 2]>,
}

#[derive(Clone)]
pub struct FriProofVariable<C: CircuitConfig, H: FieldHasherVariable<C>> {
    pub commit_phase_commits: Vec<H::DigestVariable>,
    /// Per-round PoW witnesses (one per commit phase round).
    pub commit_pow_witnesses: Vec<Felt<C::F>>,
    pub query_proofs: Vec<FriQueryProofVariable<C, H>>,
    pub final_poly: Ext<C::F, C::EF>,
    /// Query-level PoW witness.
    pub pow_witness: Felt<C::F>,
}

/// Reference: https://github.com/ProjectZKM/Plonky3/blob/main/fri/src/proof.rs#L35
#[derive(Clone)]
pub struct FriCommitPhaseProofStepVariable<C: CircuitConfig, H: FieldHasherVariable<C>> {
    /// Per-round folding arity (log2).  Currently every commit
    /// phase round uses arity 2 (log_arity = 1) — binary folding —
    /// but the field is part of the proof so future variable-arity
    /// schedules don't break the wire format.
    pub log_arity: Felt<C::F>,
    pub sibling_value: Ext<C::F, C::EF>,
    pub opening_proof: Vec<H::DigestVariable>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/main/fri/src/proof.rs#L26
#[derive(Clone)]
pub struct FriQueryProofVariable<C: CircuitConfig, H: FieldHasherVariable<C>> {
    pub input_proof: Vec<BatchOpeningVariable<C, H>>,
    pub commit_phase_openings: Vec<FriCommitPhaseProofStepVariable<C, H>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L22
#[derive(Clone)]
pub struct FriChallenges<C: CircuitConfig> {
    pub query_indices: Vec<Vec<C::Bit>>,
    pub betas: Vec<Ext<C::F, C::EF>>,
    pub betas_squared: Vec<Ext<C::F, C::EF>>,
}

//#[derive(Clone)]
//pub struct TwoAdicPcsProofVariable<C: CircuitConfig, H: FieldHasherVariable<C>> {
//    pub fri_proof: FriProofVariable<C, H>,
//    pub query_openings: Vec<Vec<BatchOpeningVariable<C, H>>>,
//}

#[derive(Clone)]
pub struct BatchOpeningVariable<C: CircuitConfig, H: FieldHasherVariable<C>> {
    pub opened_values: Vec<Vec<Felt<C::F>>>,
    pub opening_proof: Vec<H::DigestVariable>,
}

#[derive(Clone)]
pub struct TwoAdicPcsRoundVariable<C: CircuitConfig, H: FieldHasherVariable<C>> {
    pub batch_commit: H::DigestVariable,
    pub domains_points_and_opens: Vec<TwoAdicPcsMatsVariable<C>>,
}

#[derive(Clone)]
pub struct TwoAdicPcsMatsVariable<C: CircuitConfig> {
    pub domain: TwoAdicMultiplicativeCoset<C::F>,
    pub points: Vec<Ext<C::F, C::EF>>,
    pub values: Vec<Vec<Ext<C::F, C::EF>>>,
}

impl<C: CircuitConfig<F = SC::Val>, SC: KoalaBearFriParametersVariable<C>>
    VerifyingKeyVariable<C, SC>
{
    pub fn observe_into<Challenger>(&self, builder: &mut Builder<C>, challenger: &mut Challenger)
    where
        Challenger: CanObserveVariable<C, Felt<C::F>> + CanObserveVariable<C, SC::DigestVariable>,
    {
        // Observe the commitment.
        challenger.observe(builder, self.commitment);
        // Observe the pc_start.
        challenger.observe(builder, self.pc_start);
        // Observe the initial global cumulative sum.
        challenger.observe_slice(builder, self.initial_global_cumulative_sum.0.x.0);
        challenger.observe_slice(builder, self.initial_global_cumulative_sum.0.y.0);
        // Observe the padding.
        let zero: Felt<_> = builder.eval(C::F::ZERO);
        challenger.observe(builder, zero);
    }

    /// Hash the verifying key into a single digest.
    /// poseidon2( commit[0..8] || pc_start || initial_global_cumulative_sum )
    ///
    /// SP1's inputs, in SP1's order
    /// (hypercube/src/verifier/hashable_key.rs:107).  Nothing about the chips
    /// is folded in: the preprocessed commitment is the HASH-BOUND digest
    /// `compress([root, hash(row_counts ++ column_counts)])`, so it already
    /// discriminates the committed geometry, and the chip set and its widths
    /// are a property of the MACHINE.  The per-prep-chip
    /// `[name_digest, width]` fold this replaces existed only because the
    /// commitment did not yet say what shape it committed -- and it is also
    /// what made the program's input length depend on the verified core vk.
    /// MUST stay byte-identical to the host (prover/src/types.rs) and
    /// host-verifier (verifier/src/stark/mod.rs) folds.
    pub fn hash(&self, builder: &mut Builder<C>) -> SC::DigestVariable
    where
        C::F: TwoAdicField,
        SC::DigestVariable: IntoIterator<Item = Felt<C::F>>,
    {
        let mut inputs: Vec<Felt<C::F>> = Vec::with_capacity(DIGEST_SIZE + 1 + 14);
        inputs.extend(self.commitment);
        inputs.push(self.pc_start);
        inputs.extend(self.initial_global_cumulative_sum.0.x.0);
        inputs.extend(self.initial_global_cumulative_sum.0.y.0);

        SC::hash(builder, &inputs)
    }
}
