//! The global-round program: verifies global proofs of a core execution.
//!
//! A core shard proves its local lookups only. The lookups that cross shards
//! are proven afterwards, once every shard has committed its global round:
//! the hash chain over those rounds ends at `h_star`, the cross-shard
//! challenge is derived from `h_star`, and a global proof reopens the global
//! rounds of several shards under that challenge, each in a table slot of
//! its own, and proves the sum of their lookups.
//!
//! The chain has several lanes, each a hash chain of its own, and its value
//! is the digest of the lane heads. A shard's round extends one lane, and
//! one program opens consecutive rounds of one lane: the slots of a proof
//! hold them in the lane's order, the earliest first.
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
        add_global_lookup_units, extend_global_chain_head_variable,
        global_chain_heads_digest_variable, global_lookup_units_variable, GlobalChainHeadsVariable,
        GlobalChainLaneSelectorVariable, GlobalChallengeVariable, GlobalRoundBindingVariable,
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
    /// earliest first: the rounds of a proof in the order of its table slots,
    /// then the rounds of the next proof.
    pub proofs: Vec<JaggedShardProof<InnerVal, InnerChallenge>>,
    pub vk_root: [SC::Val; DIGEST_SIZE],
    /// The lane heads of the global hash chain before the first round the
    /// proofs open.
    pub global_chain_heads: zkm_pcs::logup_gkr::GlobalChainHeads<SC::Val>,
    /// The lane of the rounds the proofs open.
    pub global_chain_lane: u8,
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
    pub global_chain_heads: GlobalChainHeadsVariable<C>,
    /// One bit for each lane: the lane of the rounds the proofs open.
    /// [`verify_global_round_jagged`] constrains the bits.
    pub global_chain_lane: [Felt<C::F>; zkm_pcs::logup_gkr::GLOBAL_CHAIN_LANE_COUNT],
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
/// A proof opens one round in each of its table slots: the slot's views are
/// a trace round of the proof, the last slot its main round, and the round
/// the chain absorbs is that trace round's commitment with the heights of
/// the slot's tables under their chip names. The number of slots of each
/// proof and the chips of each slot are fixed by the program; the slots
/// extend the lane in order, the first slot first.
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
    assert_eq!(
        max_log_row_count,
        machine.max_log_row_count(),
        "a child proof is verified at the row cube of the machine that proved it"
    );
    let ZKMGlobalRoundWitnessVariable {
        vk,
        proofs,
        vk_root,
        global_chain_heads,
        global_chain_lane,
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
    let lookups_per_row: std::collections::BTreeMap<String, usize> = machine
        .global_views(0)
        .iter()
        .map(|view| {
            (GlobalView::<A>::chip_name(&view.name()).to_string(), view.global_lookups_per_row())
        })
        .collect();
    let round_lookups_bound =
        (lookups_per_row.values().sum::<usize>() as u64) << (max_log_row_count + 1);
    let round_lookup_bits = (u64::BITS - round_lookups_bound.leading_zeros()) as usize;
    assert!(
        round_lookup_bits < 31
            && zkm_pcs::logup_gkr::global_lookup_units(1 << round_lookup_bits)
                <= zkm_pcs::logup_gkr::max_global_lookup_units::<InnerVal>(),
        "one global round stays within the bound on a proof's global lookups",
    );
    let global_chain_end =
        global_chain_heads_digest_variable(builder, machine.config(), &global_chain_heads);
    let global_chain_lane = GlobalChainLaneSelectorVariable::constrain(builder, global_chain_lane);
    let mut chain = global_chain_lane.head(builder, &global_chain_heads);
    let mut global_sum: [Felt<C::F>; zkm_recursion_core::air::GLOBAL_SUM_NUM_ELTS] =
        core::array::from_fn(|_| builder.eval(C::F::ZERO));
    let mut global_lookup_units: Felt<C::F> = builder.eval(C::F::ZERO);
    for proof in proofs {
        let slots = proof.6.preceding.len() + 1;
        assert!(
            slots <= zkm_pcs::logup_gkr::MAX_GLOBAL_ROUNDS_PER_PROOF,
            "a global proof opens at most {} rounds, not {slots}",
            zkm_pcs::logup_gkr::MAX_GLOBAL_ROUNDS_PER_PROOF,
        );
        let views = (0..slots).flat_map(|slot| machine.global_views(slot)).collect::<Vec<_>>();
        let preceding_slots = (0..slots - 1)
            .map(|slot| {
                machine
                    .global_views(slot)
                    .iter()
                    .map(|view| view.name())
                    .collect::<std::collections::BTreeSet<_>>()
            })
            .collect::<Vec<_>>();
        let shard = verify_shard_tuple::<C, SC, GlobalView<A>>(
            builder,
            machine.config(),
            &vk,
            &jagged_vk,
            &views,
            &preceding_slots.iter().collect::<Vec<_>>(),
            0,
            false,
            Some(&global),
            proof,
            max_log_row_count,
        );
        assert!(
            shard.preceding_commitments.len() + 1 == slots
                && shard.round_chips.len() == slots
                && shard.round_chips.iter().all(|chips| !chips.is_empty()),
            "every table slot of a global proof holds a round with a chip",
        );
        assert!(
            shard.round_areas.iter().sum::<usize>() < 1usize << zkm_pcs::jagged::MAX_ROUND_LOG_AREA,
            "the rounds of a global proof commit fewer cells than the area a verifier accepts",
        );

        let commitments = shard.preceding_commitments.iter().chain([&shard.main_commitment]);
        for (commitment, round) in commitments.zip(shard.round_chips.iter()) {
            let chips = round
                .iter()
                .map(|(view, height)| (GlobalView::<A>::chip_name(view).to_string(), *height))
                .collect::<Vec<_>>();
            chain = extend_global_chain_head_variable(
                builder,
                machine.config(),
                chain,
                Some(&GlobalRoundBindingVariable { commitment: *commitment, chips: &chips }),
            );
            let round_lookups: zkm_recursion_compiler::ir::SymbolicFelt<C::F> = chips
                .iter()
                .map(|(chip, height)| *height * C::F::from_usize(lookups_per_row[chip]))
                .sum();
            let round_lookups: Felt<C::F> = builder.eval(round_lookups);
            let round_units =
                global_lookup_units_variable(builder, round_lookups, round_lookup_bits);
            global_lookup_units =
                add_global_lookup_units(builder, global_lookup_units, round_units);
        }
        for (sum, part) in global_sum.iter_mut().zip(shard.global_sum) {
            *sum = builder.eval(*sum + part);
        }
    }
    let global_chain_heads = global_chain_lane.with_head(builder, &global_chain_heads, chain);
    let global_chain_start =
        global_chain_heads_digest_variable(builder, machine.config(), &global_chain_heads);

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
/// goes: proofs with the same key are verified by the same operations. It
/// holds the number of rounds the proof commits and the names of its tables,
/// so the number of its table slots and the chips of each.
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

/// The shape of a global-round program over one global proof: the proof
/// opens `rounds` global rounds of one geometry, each the chips `chips`, a
/// family of the machine's global-round chips
/// ([`zkm_pcs::StarkMachine::global_family`]), at `blocks` stacking blocks,
/// a class of global rounds ([`zkm_pcs::jagged::global_round_class`]). The
/// program is a function of the shape.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ZKMGlobalRoundShape {
    pub chips: std::collections::BTreeSet<String>,
    pub blocks: usize,
    pub rounds: usize,
}

impl ZKMGlobalRoundShape {
    /// Row counts for the chips of one round that put the round in the
    /// shape's class: one row each, then the widest chips first, each up to
    /// the row cube, until the round's cells pass the class below. `None`
    /// when the chips cannot fill the class, or are not chips of `machine`.
    pub fn rows<SC, A>(
        &self,
        machine: &zkm_pcs::StarkMachine<SC, A>,
    ) -> Option<Vec<(String, usize)>>
    where
        SC: zkm_pcs::StarkGenericConfig,
        A: MachineAir<SC::Val>,
    {
        let log_stack = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
        let cube = 1usize << machine.max_log_row_count();
        let mut widths = self
            .chips
            .iter()
            .map(|name| {
                let chip = machine.chips().iter().find(|chip| chip.name() == *name)?;
                Some((name.clone(), p3_air::BaseAir::<SC::Val>::width(&chip.air)))
            })
            .collect::<Option<Vec<_>>>()?;
        widths.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let below = if self.blocks > zkm_pcs::jagged::GLOBAL_ROUND_PIN_BLOCKS {
            (self.blocks / 2) << log_stack
        } else {
            0
        };
        let mut cells: usize = widths.iter().map(|(_, width)| width).sum();
        let rows = widths
            .into_iter()
            .map(|(name, width)| {
                let more = (below + 1).saturating_sub(cells).div_ceil(width).min(cube - 1);
                cells += more * width;
                (name, 1 + more)
            })
            .collect();
        (zkm_pcs::jagged::global_round_class(cells, log_stack) == Some(self.blocks)).then_some(rows)
    }
}

impl ZKMGlobalRoundWitnessValues<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2> {
    /// A placeholder input with the shape of one global proof of `shape` on
    /// `machine`: the program built from it is the one that verifies a real
    /// global proof of that shape.
    ///
    /// # Panics
    /// When the shape's chips cannot fill its blocks
    /// ([`ZKMGlobalRoundShape::rows`]).
    pub fn dummy<A>(
        machine: &zkm_pcs::StarkMachine<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2, A>,
        shape: &ZKMGlobalRoundShape,
    ) -> Self
    where
        A: MachineAir<InnerVal>,
    {
        let rows = shape.rows(machine).expect("the chips of a global round shape fill its blocks");
        let views = (0..shape.rounds)
            .flat_map(|slot| machine.global_views(slot))
            .filter(|view| shape.chips.contains(GlobalView::<A>::chip_name(&view.name())))
            .collect::<Vec<_>>();
        let view_rows = views
            .iter()
            .map(|view| {
                let name = view.name();
                let chip = GlobalView::<A>::chip_name(&name);
                let rows = rows.iter().find(|(of, _)| of == chip).map_or(0, |(_, rows)| *rows);
                (name, rows)
            })
            .collect::<Vec<_>>();
        let slots = (0..shape.rounds)
            .map(|slot| {
                shape.chips.iter().map(|chip| GlobalView::<A>::name_in_slot(slot, chip)).collect()
            })
            .collect::<Vec<std::collections::BTreeSet<String>>>();
        let proof = crate::dummy::dummy_global_jagged_shard_proof::<
            InnerVal,
            InnerChallenge,
            GlobalView<A>,
        >(
            &views.iter().collect::<Vec<_>>(),
            &view_rows,
            machine.max_log_row_count(),
            <zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2 as zkm_pcs::WhirRing>::WHIR_PROFILE,
            &slots,
        );
        let mut chip_information = machine
            .chips()
            .iter()
            .filter_map(|chip| {
                let width = p3_air::BaseAir::<InnerVal>::preprocessed_width(chip);
                (width > 0).then(|| {
                    (
                        chip.name(),
                        zkm_pcs::SerializableDomain { shift: InnerVal::ONE, log_size: 0 },
                        (width, 1),
                    )
                })
            })
            .collect::<Vec<_>>();
        chip_information.sort_by(|a, b| a.0.cmp(&b.0));
        let chip_ordering = chip_information
            .iter()
            .enumerate()
            .map(|(i, (name, _, _))| (name.clone(), i))
            .collect::<hashbrown::HashMap<_, _>>();
        Self {
            vk: StarkVerifyingKey {
                commit: crate::fri::dummy_commit(),
                pc_start: InnerVal::ZERO,
                chip_information,
                chip_ordering,
            },
            proofs: vec![proof],
            vk_root: [InnerVal::ZERO; DIGEST_SIZE],
            global_chain_heads: [[InnerVal::ZERO; DIGEST_SIZE];
                zkm_pcs::logup_gkr::GLOBAL_CHAIN_LANE_COUNT],
            global_chain_lane: 0,
            global_h_star: [InnerVal::ZERO; DIGEST_SIZE],
            global_pow_witness: InnerVal::ONE,
        }
    }
}

impl<SC: zkm_pcs::StarkGenericConfig> ZKMGlobalRoundWitnessValues<SC> {
    /// The global rounds the proofs open: one for each table slot.
    pub fn rounds(&self) -> usize {
        self.proofs.iter().map(|proof| proof.preceding_rounds.len() + 1).sum()
    }

    /// The shape of the input's proof, read from the proof: the chips of its
    /// table slots, the stacking blocks its rounds commit and the number of
    /// its rounds. `None` unless the input holds one proof whose rounds all
    /// have the chips and the blocks of the first, as the rounds a prover
    /// groups do (`StarkMachine::global_chain_lane_proof_groups`).
    pub fn shape(&self) -> Option<ZKMGlobalRoundShape> {
        let [proof] = self.proofs.as_slice() else {
            return None;
        };
        let zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(bundle) =
            &proof.evaluation_proof
        else {
            return None;
        };
        let rounds = proof.preceding_rounds.len() + 1;
        let mut slots = vec![std::collections::BTreeSet::new(); rounds];
        for view in proof.chip_heights.keys() {
            let (slot, chip) = GlobalView::<()>::slot_and_chip(view)?;
            slots.get_mut(slot)?.insert(chip.to_string());
        }
        let blocks = bundle.whir_proof.batch_evaluations.iter().map(Vec::len).collect::<Vec<_>>();
        let shape =
            ZKMGlobalRoundShape { chips: slots.first()?.clone(), blocks: *blocks.first()?, rounds };
        (blocks.len() == rounds
            && blocks.iter().all(|blocks| *blocks == shape.blocks)
            && slots.iter().all(|chips| *chips == shape.chips))
        .then_some(shape)
    }

    /// The key of the program that verifies this input: the number of
    /// proofs and the shape of each, which holds the number of its table
    /// slots and the chips of each.
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
