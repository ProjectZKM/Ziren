use hashbrown::HashMap;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use p3_matrix::Dimensions;

use zkm_pcs::septic_digest::SepticDigest;
use zkm_recursion_compiler::ir::{Builder, Felt};
use zkm_recursion_core::DIGEST_SIZE;

use crate::{challenger::CanObserveVariable, CircuitConfig, KoalaBearFriParametersVariable};

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
