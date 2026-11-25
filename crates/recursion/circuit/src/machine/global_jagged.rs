//! The global-round program: verifies one global proof of a core execution.
//!
//! A core shard proves its local lookups only. The lookups that cross shards
//! are proven afterwards, once every shard has committed its global round:
//! the hash chain over those rounds ends at `h_star`, the cross-shard
//! challenge is derived from `h_star`, and a global proof reopens one shard's
//! global round under that challenge and proves the sum of its lookups.
//!
//! The compress tree holds the global proofs before the shards, in reverse
//! round order. Each one steps the chain backwards, from its value after the
//! round to its value before it, so the global proofs unwind the chain from
//! `h_star` to its origin and the shards wind it forward again. A complete
//! proof starts and ends the chain at `h_star`, which makes the rounds the
//! global proofs open exactly the rounds the shards committed.
//!
//! Only the global proofs know `h_star`: a shard is verified before the last
//! shard has committed. The public values of a shard carry a zero challenge
//! digest and a zero proof-of-work witness, a global proof carries the digest
//! and a witness that is not zero, and a compress node takes both from its
//! first child and accepts a child that carries either the same or zero.

use std::borrow::BorrowMut;

use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use zkm_pcs::{
    air::{GlobalView, MachineAir},
    shard_level::shard_proof::JaggedShardProof,
    InnerChallenge, InnerVal, StarkVerifyingKey,
};
use zkm_recursion_compiler::ir::{Builder, Felt};
use zkm_recursion_core::{
    air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS},
    DIGEST_SIZE,
};

use super::core_jagged::{verify_shard_tuple, ShardProofTuple};
use crate::{
    global_challenge::{
        global_chain_step_variable, GlobalChallengeVariable, GlobalRoundBindingVariable,
    },
    machine::recursion_public_values_digest,
    CircuitConfig, KoalaBearFriParametersVariable, VerifyingKeyVariable,
};

/// The input of a global-round program.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "StarkVerifyingKey<SC>: Serialize",
    deserialize = "StarkVerifyingKey<SC>: for<'d> Deserialize<'d>"
))]
pub struct ZKMGlobalRoundWitnessValues<SC: zkm_pcs::StarkGenericConfig> {
    pub vk: StarkVerifyingKey<SC>,
    /// The global proof.
    pub proof: JaggedShardProof<InnerVal, InnerChallenge>,
    pub vk_root: [SC::Val; DIGEST_SIZE],
    /// The global hash chain's value before the round the proof opens.
    pub global_chain_end: [SC::Val; DIGEST_SIZE],
    /// The chain end, over every shard of the execution, the global
    /// challenge is derived from.
    pub global_h_star: [SC::Val; DIGEST_SIZE],
    /// The global challenge's proof-of-work witness.
    pub global_pow_witness: SC::Val,
}

/// [`ZKMGlobalRoundWitnessValues`] in the circuit.
pub struct ZKMGlobalRoundWitnessVariable<
    C: CircuitConfig<F = p3_koala_bear::KoalaBear>,
    SC: KoalaBearFriParametersVariable<C>,
> {
    pub vk: VerifyingKeyVariable<C, SC>,
    pub proof: ShardProofTuple<C>,
    pub vk_root: [Felt<C::F>; DIGEST_SIZE],
    pub global_chain_end: [Felt<C::F>; DIGEST_SIZE],
    pub global_h_star: [Felt<C::F>; DIGEST_SIZE],
    pub global_pow_witness: Felt<C::F>,
}

/// Verifies a global proof of `machine` under the challenge derived from
/// `global_h_star`, and commits public values that step the global hash chain
/// backwards over the round the proof opens and carry the sum of its lookups.
///
/// Every other coordinate stands at the start of the execution — shard one,
/// the key's first program counter, no address initialized or finalized — so
/// the proof can only sit before the first shard.
pub fn verify_global_round_jagged<C, SC, A>(
    builder: &mut Builder<C>,
    input: ZKMGlobalRoundWitnessVariable<C, SC>,
    machine: &zkm_pcs::StarkMachine<SC, A>,
    max_log_row_count: usize,
) where
    SC: KoalaBearFriParametersVariable<
        C,
        FriChallengerVariable = crate::challenger::DuplexChallengerVariable<C>,
        DigestVariable = [Felt<p3_koala_bear::KoalaBear>; DIGEST_SIZE],
        Val = InnerVal,
    >,
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<p3_koala_bear::KoalaBear>>,
    A: MachineAir<SC::Val>,
{
    let ZKMGlobalRoundWitnessVariable {
        vk,
        proof,
        vk_root,
        global_chain_end,
        global_h_star,
        global_pow_witness,
    } = input;
    assert!(machine.defers_global(), "a global proof needs a machine that defers global lookups");
    let jagged_vk =
        crate::shard_proof_variable_lift::build_verifying_key_variable::<C, SC>(builder, &vk);

    builder.assert_felt_ne(global_pow_witness, C::F::ZERO);
    let global = GlobalChallengeVariable::derive(
        builder,
        machine.config(),
        global_h_star,
        global_pow_witness,
        machine.global_beta_seed_dim(),
    );
    let views = machine.global_views(0);
    let shard = verify_shard_tuple::<C, SC, GlobalView<A>>(
        builder,
        machine.config(),
        &vk,
        &jagged_vk,
        &views,
        None,
        0,
        false,
        Some(&global),
        proof,
        max_log_row_count,
    );
    assert!(shard.global_commitment.is_none(), "a global proof commits one round");

    let chips = shard
        .chip_heights
        .iter()
        .map(|(view, height)| (GlobalView::<A>::chip_name(view).to_string(), *height))
        .collect::<Vec<_>>();
    let global_chain_start = global_chain_step_variable(
        builder,
        machine.config(),
        global_chain_end,
        Some(&GlobalRoundBindingVariable { commitment: shard.main_commitment, chips: &chips }),
    );

    let zero: Felt<_> = builder.eval(C::F::ZERO);
    let one: Felt<_> = builder.eval(C::F::ONE);
    let mut stream = [zero; RECURSIVE_PROOF_NUM_PV_ELTS];
    let public_values: &mut RecursionPublicValues<_> = stream.as_mut_slice().borrow_mut();
    public_values.start_pc = vk.pc_start;
    public_values.next_pc = vk.pc_start;
    public_values.start_shard = one;
    public_values.next_shard = one;
    public_values.start_execution_shard = one;
    public_values.next_execution_shard = one;
    public_values.zkm_vk_digest = vk.hash(builder);
    public_values.global_chain_start = global_chain_start;
    public_values.global_chain_end = global_chain_end;
    public_values.global_h_star = global_h_star;
    public_values.global_pow_witness = global_pow_witness;
    public_values.global_sum = shard.global_sum;
    public_values.vk_root = vk_root;
    public_values.digest = recursion_public_values_digest::<C, SC>(builder, public_values);

    SC::commit_recursion_public_values(builder, *public_values);
}

/// Domain tag hashed first into [`ZKMGlobalRoundWitnessValues::shape_key`].
const GLOBAL_ROUND_SHAPE_KEY_DOMAIN: u64 = 0x676c_6f62_616c_5f72;

impl<SC: zkm_pcs::StarkGenericConfig> ZKMGlobalRoundWitnessValues<SC> {
    /// The key of the program this input runs: what the program's shape
    /// depends on, the proof's structure and the tables it names.
    pub fn shape_key(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();

        GLOBAL_ROUND_SHAPE_KEY_DOMAIN.hash(&mut h);
        self.vk.chip_information.len().hash(&mut h);
        self.vk.chip_ordering.len().hash(&mut h);
        crate::machine::shape_signature::hash_shard_proof_structure(&self.proof, &mut h);
        self.proof.chip_heights.len().hash(&mut h);
        for name in self.proof.chip_heights.keys() {
            name.hash(&mut h);
        }

        h.finish()
    }
}
