//! The global-round program: verifies one global proof of a core execution.
//!
//! A core shard proves its local lookups only. The lookups that cross shards
//! are proven afterwards, once every shard has committed its global round:
//! the hash chain over those rounds ends at `h_star`, the cross-shard
//! challenge is derived from `h_star`, and a global proof reopens one shard's
//! global round under that challenge and proves the sum of its lookups.
//!
//! The chain has several lanes, each a hash chain of its own, and its value
//! is the digest of the lane heads. A shard's round extends one lane, and
//! one program opens consecutive rounds of one lane.
//!
//! The compress tree holds the global proofs before the shards, each lane's
//! rounds in reverse order. Each program steps the chain backwards, from its
//! value after its rounds to its value before them, so the global proofs
//! unwind the chain from `h_star` to its origin and the shards wind it
//! forward again. A complete proof starts and ends the chain at `h_star`.
//! The digest is collision resistant, so a chain value fixes its lane heads:
//! on each lane, the rounds the global proofs open are exactly the rounds
//! the shards committed, in order.
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
        add_global_lookup_units, global_chain_step_variable, global_lanes_digest_variable,
        global_lookup_units_variable, GlobalChallengeVariable, GlobalLaneSelectorVariable,
        GlobalLanesVariable, GlobalRoundBindingVariable,
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
    /// The global proofs of consecutive global rounds of one lane, the
    /// earliest first.
    pub proofs: Vec<JaggedShardProof<InnerVal, InnerChallenge>>,
    pub vk_root: [SC::Val; DIGEST_SIZE],
    /// The lane heads of the global hash chain before the first round the
    /// proofs open.
    pub global_lanes: zkm_pcs::logup_gkr::GlobalLanes<SC::Val>,
    /// The lane of the rounds the proofs open.
    pub global_lane: u8,
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
    pub proofs: Vec<ShardProofTuple<C>>,
    pub vk_root: [Felt<C::F>; DIGEST_SIZE],
    pub global_lanes: GlobalLanesVariable<C>,
    /// One bit for each lane: the lane of the rounds the proofs open.
    /// [`verify_global_round_jagged`] constrains the bits.
    pub global_lane: [Felt<C::F>; zkm_pcs::logup_gkr::GLOBAL_CHAIN_LANES],
    pub global_h_star: [Felt<C::F>; DIGEST_SIZE],
    pub global_pow_witness: Felt<C::F>,
}

/// Verifies the global proofs of consecutive global rounds of one lane of
/// `machine` under the challenge derived from `global_h_star`, and commits
/// public values that step the global hash chain backwards over the rounds
/// the proofs open and carry the sum of their lookups and a count of them.
/// The chain ends at the digest of the witnessed lane heads and starts at
/// their digest once the rounds have extended the selected lane. A round
/// counts each table's height times the lookups of a row, in the direction
/// with more; the core chips constrain a global lookup's multiplicity to a
/// bit, so no direction of the round holds more lookups than that.
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
        proofs,
        vk_root,
        global_lanes,
        global_lane,
        global_h_star,
        global_pow_witness,
    } = input;
    assert!(
        machine.defers_global_lookups(),
        "a global proof needs a machine that defers global lookups"
    );
    assert!(
        <SC as crate::KoalaBearFriParameters>::WHIR_PROFILE.unique_decoding(),
        "a global proof reopens its shard's global round, which binds one table only under a \
         unique-decoding schedule",
    );
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
    assert!(!proofs.is_empty(), "a global-round program opens at least one round");
    let views = machine.global_views(0);
    let lookups_per_row: std::collections::BTreeMap<String, usize> =
        views.iter().map(|view| (view.name(), view.global_lookups_per_row())).collect();
    let round_lookups_bound =
        (lookups_per_row.values().sum::<usize>() as u64) << (max_log_row_count + 1);
    let round_lookup_bits = (u64::BITS - round_lookups_bound.leading_zeros()) as usize;
    assert!(
        round_lookup_bits < 31
            && zkm_pcs::logup_gkr::global_lookup_units(1 << round_lookup_bits)
                <= zkm_pcs::logup_gkr::max_global_lookup_units::<InnerVal>(),
        "one global round stays within the bound on a proof's global lookups",
    );
    let global_chain_end = global_lanes_digest_variable(builder, machine.config(), &global_lanes);
    let global_lane = GlobalLaneSelectorVariable::constrain(builder, global_lane);
    let mut chain = global_lane.head(builder, &global_lanes);
    let mut global_sum: [Felt<C::F>; zkm_recursion_core::air::GLOBAL_SUM_NUM_ELTS] =
        core::array::from_fn(|_| builder.eval(C::F::ZERO));
    let mut global_lookup_units: Felt<C::F> = builder.eval(C::F::ZERO);
    for proof in proofs {
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
        chain = global_chain_step_variable(
            builder,
            machine.config(),
            chain,
            Some(&GlobalRoundBindingVariable { commitment: shard.main_commitment, chips: &chips }),
        );
        for (sum, part) in global_sum.iter_mut().zip(shard.global_sum) {
            *sum = builder.eval(*sum + part);
        }
        let round_lookups: zkm_recursion_compiler::ir::SymbolicFelt<C::F> = shard
            .chip_heights
            .iter()
            .map(|(view, height)| *height * C::F::from_usize(lookups_per_row[view]))
            .sum();
        let round_lookups: Felt<C::F> = builder.eval(round_lookups);
        let round_units = global_lookup_units_variable(builder, round_lookups, round_lookup_bits);
        global_lookup_units = add_global_lookup_units(builder, global_lookup_units, round_units);
    }
    let global_lanes = global_lane.with_head(builder, &global_lanes, chain);
    let global_chain_start = global_lanes_digest_variable(builder, machine.config(), &global_lanes);

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
    public_values.global_sum = global_sum;
    public_values.global_lookup_units = global_lookup_units;
    public_values.vk_root = vk_root;
    public_values.digest = recursion_public_values_digest::<C, SC>(builder, public_values);

    SC::commit_recursion_public_values(builder, *public_values);
}

/// Domain tag hashed first into [`ZKMGlobalRoundWitnessValues::shape_key`].
const GLOBAL_ROUND_SHAPE_KEY_DOMAIN: u64 = 0x676c_6f62_616c_5f72;

/// The shape of one global proof as far as the program that verifies it
/// goes: proofs with the same key are verified by the same operations.
pub fn global_proof_shape_key(proof: &JaggedShardProof<InnerVal, InnerChallenge>) -> u64 {
    use std::hash::Hasher;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    hash_global_proof_shape(proof, &mut h);
    h.finish()
}

fn hash_global_proof_shape<H: std::hash::Hasher>(
    proof: &JaggedShardProof<InnerVal, InnerChallenge>,
    h: &mut H,
) {
    use std::hash::Hash;
    crate::machine::shape_signature::hash_shard_proof_structure(proof, h);
    proof.chip_heights.len().hash(h);
    for name in proof.chip_heights.keys() {
        name.hash(h);
    }
}

impl<SC: zkm_pcs::StarkGenericConfig> ZKMGlobalRoundWitnessValues<SC> {
    /// The key of the program that verifies this input: the number of
    /// proofs and the shape of each.
    pub fn shape_key(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();

        GLOBAL_ROUND_SHAPE_KEY_DOMAIN.hash(&mut h);
        self.vk.chip_information.len().hash(&mut h);
        self.vk.chip_ordering.len().hash(&mut h);
        self.proofs.len().hash(&mut h);
        for proof in &self.proofs {
            hash_global_proof_shape(proof, &mut h);
        }

        h.finish()
    }
}
