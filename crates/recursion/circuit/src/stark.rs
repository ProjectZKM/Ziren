use hashbrown::HashMap;
use itertools::{izip, Itertools};

use num_traits::cast::ToPrimitive;

use p3_air::{WindowAccess, Air, BaseAir};
use p3_commit::{Mmcs, Pcs, PolynomialSpace};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_koala_bear::KoalaBear;

use zkm_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, DslIr, Ext, ExtConst, SymbolicExt},
    prelude::Felt,
};
use zkm_stark::septic_digest::SepticDigest;
use zkm_stark::{
    air::LookupScope, koala_bear_poseidon2::KoalaBearPoseidon2, shape::OrderedShape,
    AirOpenedValues, Challenger, Chip, ChipOpenedValues, InnerChallenge,
    ShardCommitment, ShardOpenedValues, ShardProof, Val, PROOF_MAX_NUM_PVS,
};
use zkm_stark::{air::MachineAir, StarkGenericConfig, StarkMachine, StarkVerifyingKey};

use crate::{
    challenger::CanObserveVariable,
    fri::{dummy_commit, dummy_pcs_proof, PolynomialBatchShape, PolynomialShape},
    hash::FieldHasherVariable,
    CircuitConfig, FriProofVariable, KoalaBearFriParameters, TwoAdicPcsMatsVariable,
};

use crate::{
    challenger::FieldChallengerVariable, constraints::RecursiveVerifierConstraintFolder,
    domain::PolynomialSpaceVariable, KoalaBearFriParametersVariable,
    TwoAdicPcsRoundVariable, VerifyingKeyVariable,
};

/// Reference: [zkm_core::stark::ShardProof]
#[derive(Clone)]
pub struct ShardProofVariable<C: CircuitConfig<F = SC::Val>, SC: KoalaBearFriParametersVariable<C>> {
    pub commitment: ShardCommitment<SC::DigestVariable>,
    #[allow(clippy::type_complexity)]
    pub opened_values: ShardOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
    pub opening_proof: FriProofVariable<C, SC>,
    pub chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<Felt<C::F>>,
    /// Fixed-size fingerprint of the jagged-PCS opening proof
    /// bytes (XOR-fold of the Vec<u8> into 8 Felts).  Always
    /// `[Felt; 8]` — unconditional presence simplifies witness
    /// synchronisation: real proofs contribute the fold of
    /// `late_binding_jagged_proof.unwrap_or(&[])` while legacy
    /// proofs contribute the all-zero fingerprint.
    ///
    /// Observed into the challenger transcript inside
    /// `verify_shard` so the prover can't equivocate on the bytes
    /// content.  Full BaseFold-PCS in-circuit verification of the
    /// bytes (deserialize → run sumcheck + FRI) is a separate
    /// task; this fingerprint binding is the prerequisite.
    pub basefold_jagged_fingerprint: [Felt<C::F>; 8],
}

/// Get a dummy duplex challenger for use in dummy proofs.
pub fn dummy_challenger(config: &KoalaBearPoseidon2) -> Challenger<KoalaBearPoseidon2> {
    let mut challenger = config.challenger();
    challenger.input_buffer = vec![];
    challenger.output_buffer = vec![KoalaBear::ZERO; challenger.sponge_state.len()];
    challenger
}

/// Step 5 Phase 3b basefold-shaped recursion shard dummy (May 19 2026).
///
/// Produces a `(StarkVerifyingKey, ShardProof)` pair whose
/// `ShardProof` carries:
///   - `commitment.auxiliary_commits = vec![]` (no perm + quotient commits)
///   - `opened_values` with empty `permutation`/`quotient` fields
///   - `opening_proof` from the basefold-mode FRI sub-proof (prep + main only)
///   - `basefold_shard_proof: Some(_)` populated with the dummy
///     basefold shard proof from `dummy_basefold_vk_and_shard_proof`.
///
/// This mirrors the real prover output shape at
/// `crates/stark/src/prover.rs:600-610` (the `use_basefold_path`
/// return branch).  RecursionAir-parameterised because the inner
/// `dummy_basefold_vk_and_shard_proof` already drives the
/// `prove_shard_to_basefold` host path with the chip set from
/// `machine`, so passing in a `StarkMachine<KBP2, RecursionAir<_,_>>`
/// produces a basefold proof shaped for recursion chips
/// (BaseAlu/ExtAlu/Poseidon2/FriFold/etc.) instead of MIPS chips.
///
/// # Status (scaffold)
///
/// The opening_proof + opened_values FRI placeholders are minimal
/// (empty perm/quotient, opening_proof from a small pcs.open call
/// mirroring the prover branch).  Cryptographic soundness of the
/// dummy isn't required — consumers (`program_from_shape`) only
/// care about the witness-stream shape, which is driven by
/// chip_ordering + chip_cumulative_sums in the basefold sub-proof.
///
/// Wraps the inner `BasefoldShardProof` in a `Box` per the
/// `ShardProof::basefold_shard_proof: Option<Box<_>>` definition.
///
/// # Trait bounds
///
/// Same `A: MachineAir + Air<VerifierConstraintFolder>` bounds as
/// `dummy_basefold_vk_and_shard_proof` — both `MipsAir` and
/// `RecursionAir<F, DEGREE>` satisfy these via the standard derive
/// macro at `crates/derive/src/lib.rs:218,321`.
pub fn dummy_recursion_basefold_vk_and_shard_proof<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    shape: &OrderedShape,
) -> (StarkVerifyingKey<KoalaBearPoseidon2>, ShardProof<KoalaBearPoseidon2>)
where
    A: MachineAir<KoalaBear>
        + for<'b> Air<zkm_stark::folder::VerifierConstraintFolder<'b, KoalaBearPoseidon2>>,
{
    // Produce the basefold shard proof + matching VK using the
    // existing infrastructure.  The chip set and per-chip shapes
    // come from the machine + shape pair.
    let (vk, basefold_proof) = dummy_basefold_vk_and_shard_proof::<A>(machine, shape);

    // Build the empty FRI placeholder fields matching the real
    // basefold-path prover output at `prover.rs:600-610`.  Empty
    // auxiliary_commits + empty perm/quotient opened values.  The
    // chip_ordering carries the name → index map needed by
    // recursion-side Witnessable::read to fix the witness-stream
    // order.
    let chip_ordering = shape
        .inner
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (name.clone(), i))
        .collect::<HashMap<_, _>>();

    // Per-chip ChipOpenedValues with empty permutation / quotient
    // arrays — matching the prover's basefold-path emission at
    // `prover.rs:559-568`.  Preprocessed + main keep their real
    // widths so the witness reader still walks the right number
    // of felts; perm + quotient are empty because the basefold
    // pipeline doesn't commit them.
    let shard_chips = machine.shard_chips_ordered(&chip_ordering).collect::<Vec<_>>();
    let opened_values = ShardOpenedValues {
        chips: shard_chips
            .iter()
            .zip_eq(shape.inner.iter())
            .map(|(chip, (_, log_degree))| {
                let preprocessed_width = chip.preprocessed_width();
                let main_width = chip.width();
                ChipOpenedValues {
                    preprocessed: AirOpenedValues {
                        local: vec![InnerChallenge::ZERO; preprocessed_width],
                        next: vec![InnerChallenge::ZERO; preprocessed_width],
                    },
                    main: AirOpenedValues {
                        local: vec![InnerChallenge::ZERO; main_width],
                        next: vec![InnerChallenge::ZERO; main_width],
                    },
                    permutation: AirOpenedValues { local: vec![], next: vec![] },
                    quotient: vec![],
                    global_cumulative_sum: SepticDigest::<KoalaBear>::zero(),
                    local_cumulative_sum: InnerChallenge::ZERO,
                    log_degree: *log_degree,
                }
            })
            .collect(),
    };

    // FRI opening_proof — minimal placeholder.  The basefold path
    // still calls `pcs.open` for prep + main (no perm/quotient),
    // producing a 2-batch FRI proof.  For the dummy we emit a
    // 2-batch shape via `dummy_pcs_proof` (preprocessed + main only).
    let mut preprocessed_batch_shape = vec![];
    let mut main_batch_shape = vec![];
    for chip_opening in opened_values.chips.iter() {
        if !chip_opening.preprocessed.local.is_empty() {
            preprocessed_batch_shape.push(PolynomialShape {
                width: chip_opening.preprocessed.local.len(),
                log_degree: chip_opening.log_degree,
            });
        }
        main_batch_shape.push(PolynomialShape {
            width: chip_opening.main.local.len(),
            log_degree: chip_opening.log_degree,
        });
    }
    let mut batch_shapes = Vec::with_capacity(2);
    if !preprocessed_batch_shape.is_empty() {
        batch_shapes.push(PolynomialBatchShape { shapes: preprocessed_batch_shape });
    }
    if !main_batch_shape.is_empty() {
        batch_shapes.push(PolynomialBatchShape { shapes: main_batch_shape });
    }
    let fri_queries = machine.config().fri_config().num_queries;
    let log_blowup = machine.config().fri_config().log_blowup;
    let opening_proof = dummy_pcs_proof(fri_queries, &batch_shapes, log_blowup);

    let public_values = (0..PROOF_MAX_NUM_PVS).map(|_| KoalaBear::ZERO).collect::<Vec<_>>();

    let shard_proof = ShardProof {
        commitment: ShardCommitment {
            main_commit: dummy_commit(),
            auxiliary_commits: Vec::new(),
        },
        opened_values,
        opening_proof,
        chip_ordering,
        public_values,
        basefold_shard_proof: Some(Box::new(basefold_proof)),
    };

    (vk, shard_proof)
}

/// Make a dummy basefold-pipeline shard proof for a given proof shape.
///
/// Drives the host-side `prove_shard_to_basefold` with zero-filled
/// traces for every chip in `shape`. The resulting proof is
/// structurally correct (all inner sumcheck/jagged-PCS shapes match
/// the prover's wire format and the recursion-circuit's shape
/// asserts) but does NOT satisfy AIR constraints — the zero traces
/// can't pass the chip's per-row constraints. That's adequate for
/// `program_from_shape`-style consumers that only care about the
/// program SHAPE (number of witness reads), not soundness.
///
/// Returned `chip_cumulative_sums` has one entry per chip in
/// `shape.inner` — matching real proofs, so the recursion program's
/// witness-stream `read()` count is shape-stable across dummy and
/// real proofs.
///
/// Phase 4 — unblocks `program_from_shape` basefold
/// dispatch and downstream `dummy()` constructors for
/// `ZKMCoreBasefoldWitnessValues` etc.
pub fn dummy_basefold_vk_and_shard_proof<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    shape: &OrderedShape,
) -> (
    StarkVerifyingKey<KoalaBearPoseidon2>,
    zkm_stark::shard_level::shard_proof::BasefoldShardProof<KoalaBear, InnerChallenge>,
)
where
    A: MachineAir<KoalaBear>
        + for<'b> Air<zkm_stark::folder::VerifierConstraintFolder<'b, KoalaBearPoseidon2>>,
{
    use zkm_stark::shard_level::verifier::BasefoldShardVerifier;

    // Build the dummy shard proof by directly zero-filling every
    // field (chip log heights, cumulative sums, logup-GKR round
    // proofs, openings, evaluation proof bytes) at the shapes
    // dictated by the input `shape`. This replaces a previous slow
    // path that drove `prove_shard_to_basefold` against zero traces
    // (~15s per call × REDUCE_BATCH_SIZE during pre-warm); the
    // zero-fill allocator runs in microseconds because no field
    // arithmetic happens.
    //
    // Mirrors SP1's `dummy_shard_proof` in
    // crates/recursion/circuit/src/dummy/shard_proof.rs.
    //
    // Resolve each chip in the shape to a concrete &Chip from the
    // machine, KEEPING ITS OWN log_height. Skip names that don't
    // exist (the legacy `allowed_shapes` still carry retired chips —
    // BatchFRI / ExpReverseBitsLen — that the basefold machine no
    // longer has).
    //
    // VERIFY_VK=true fix (task #24): the previous code filtered the
    // chip list but then `zip`'d it against the UNFILTERED
    // `shape.inner`, so for shapes containing retired names every
    // chip after the first dropped entry received the NEXT entry's
    // height (e.g. ExtAlu got BatchFRI's 21). Every Compress /
    // Deferred / Shrink vk enumerated into vk_map.bin was therefore
    // built against misaligned dummy input shapes no real proof can
    // produce. Localized by `zkm_prover::tests::vkroot_shrink_vkeq`
    // (EQUAL=true, real shape == allowed shape, vk ∉ map).
    let chips_and_heights: Vec<(&Chip<KoalaBear, A>, usize)> = shape
        .inner
        .iter()
        .filter_map(|(name, log_height)| {
            machine
                .chips()
                .iter()
                .find(|c| c.name() == name.as_str())
                .map(|c| (c, *log_height))
        })
        .collect();
    let chips: Vec<&Chip<KoalaBear, A>> =
        chips_and_heights.iter().map(|(c, _)| *c).collect();

    let chip_log_heights_pairs: Vec<(String, u8)> = chips_and_heights
        .iter()
        .map(|(chip, log_height)| {
            let name = MachineAir::<KoalaBear>::name(*chip);
            (name, *log_height as u8)
        })
        .collect();

    let max_log_row_count =
        BasefoldShardVerifier::production_default().max_log_row_count;

    let proof = crate::dummy::dummy_basefold_shard_proof::<KoalaBear, InnerChallenge, A>(
        &chips,
        &chip_log_heights_pairs,
        max_log_row_count,
    );

    // Build a minimal-but-shape-correct VK matching the legacy
    // dummy: empty chip_information (preprocessed-keyed), name-keyed
    // chip_ordering. Recursion-side reads chip_ordering when fixing
    // the witness-stream order; chip_information is only consumed
    // by the legacy FRI vk-commit path which the basefold pipeline
    // doesn't exercise on the dummy fixture.
    // Same filtering as above: the real vk's chip_ordering only
    // contains chips the machine actually has, so the dummy must
    // not leak retired shape names (BatchFRI / ExpReverseBitsLen)
    // into it either.
    let chip_ordering = chip_log_heights_pairs
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (name.to_owned(), i))
        .collect::<HashMap<_, _>>();
    // P2b: the vk hash (recursion/circuit/src/types.rs:hash) absorbs one
    // prep-domain record per `chip_information` entry — (log_n, 2^log_n, shift,
    // two_adic_generator(log_n)).  The dummy MUST carry the same preprocessed
    // domains as the real vk (else the recursion program's vk.hash bakes a
    // different number of inputs → the program diverges in assert_complete's
    // vk-hash region).  Real builds these from the PREPROCESSED traces
    // (machine.rs:457-464), sorted by (Reverse(height), name); the natural
    // domain has shift = ONE.  For the chips that carry a preprocessed trace
    // (preprocessed_width > 0), the prep height equals the chip height for the
    // program-keyed chips on the shapes we enumerate (Program / Byte etc.).
    let chip_information: Vec<(
        String,
        zkm_stark::SerializableDomain<KoalaBear>,
        (usize, usize),
    )> = {
        let mut prep: Vec<(String, usize, usize)> = chip_log_heights_pairs
            .iter()
            .filter_map(|(name, log_h)| {
                let chip = chips.iter().find(|c| c.name() == name.as_str())?;
                let pw = MachineAir::<KoalaBear>::preprocessed_width(*chip);
                if pw > 0 {
                    Some((name.clone(), pw, *log_h as usize))
                } else {
                    None
                }
            })
            .collect();
        // Sort by (Reverse(height), name) to match the prover's preprocessed
        // trace ordering (machine.rs:454).
        prep.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
        prep.into_iter()
            .map(|(name, pw, log_h)| {
                (
                    name,
                    zkm_stark::SerializableDomain {
                        shift: KoalaBear::ONE,
                        log_size: log_h,
                    },
                    (pw, 1usize << log_h),
                )
            })
            .collect()
    };
    let vk = StarkVerifyingKey {
        commit: dummy_commit(),
        pc_start: KoalaBear::ZERO,
        initial_global_cumulative_sum: SepticDigest::<KoalaBear>::zero(),
        chip_information,
        chip_ordering,
    };

    (vk, proof)
}

#[derive(Clone)]
pub struct MerkleProofVariable<C: CircuitConfig, HV: FieldHasherVariable<C>> {
    pub index: Vec<C::Bit>,
    pub path: Vec<HV::DigestVariable>,
}

pub const EMPTY: usize = 0x_1111_1111;

#[derive(Debug, Clone, Copy)]
pub struct StarkVerifier<C: Config, SC: StarkGenericConfig, A> {
    _phantom: std::marker::PhantomData<(C, SC, A)>,
}

pub struct VerifyingKeyHint<'a, SC: StarkGenericConfig, A> {
    pub machine: &'a StarkMachine<SC, A>,
    pub vk: &'a StarkVerifyingKey<SC>,
}

impl<'a, SC: StarkGenericConfig, A: MachineAir<SC::Val>> VerifyingKeyHint<'a, SC, A> {
    pub const fn new(machine: &'a StarkMachine<SC, A>, vk: &'a StarkVerifyingKey<SC>) -> Self {
        Self { machine, vk }
    }
}


impl<C: CircuitConfig<F = SC::Val>, SC: KoalaBearFriParametersVariable<C>> ShardProofVariable<C, SC> {
    pub fn contains_cpu(&self) -> bool {
        self.chip_ordering.contains_key("Cpu")
    }

    pub fn log_degree_cpu(&self) -> usize {
        let idx = self.chip_ordering.get("Cpu").expect("Cpu chip not found");
        self.opened_values.chips[*idx].log_degree
    }

    pub fn contains_memory_init(&self) -> bool {
        self.chip_ordering.contains_key("MemoryGlobalInit")
    }

    pub fn contains_memory_finalize(&self) -> bool {
        self.chip_ordering.contains_key("MemoryGlobalFinalize")
    }
}

#[allow(unused_imports)]
#[cfg(test)]
pub mod tests {
    use std::collections::VecDeque;
    use std::fmt::Debug;

    use crate::{
        challenger::{CanCopyChallenger, CanObserveVariable, DuplexChallengerVariable},
        utils::tests::run_test_recursion_with_prover,
        KoalaBearFriParameters,
    };

    use zkm_core_executor::Program;
    use zkm_core_machine::{
        io::ZKMStdin,
        mips::MipsAir,
        utils::{prove, setup_logger},
    };
    use zkm_recursion_compiler::{
        config::{InnerConfig, OuterConfig},
        ir::{Builder, DslIr, TracedVec},
    };

    use test_artifacts::FIBONACCI_ELF;
    use zkm_recursion_core::{air::Block, machine::RecursionAir, stark::KoalaBearPoseidon2Outer};
    use zkm_stark::{
        koala_bear_poseidon2::KoalaBearPoseidon2, CpuProver, InnerVal, MachineProver, ShardProof,
        ZKMCoreOpts,
    };

    use super::*;
    use crate::witness::*;

    type F = InnerVal;
    type A = MipsAir<F>;
    type SC = KoalaBearPoseidon2;

    /// Verifies `dummy_basefold_vk_and_shard_proof` produces a
    /// proof whose `chip_cumulative_sums` map cardinality matches
    /// the input shape's chip count — the shape-stability invariant
    /// the recursion-program builder depends on.
    #[test]
    fn dummy_basefold_vk_and_shard_proof_shape_stable() {
        let machine = MipsAir::<KoalaBear>::machine(KoalaBearPoseidon2::default());
        // Pick two real chips with deterministic widths.  AddSub +
        // Bitwise both exist in MipsAir and have small preprocessed
        // widths — keeps the dummy proof inexpensive.
        let shape = OrderedShape::from_log2_heights(&[
            ("AddSub".to_string(), 3),
            ("Bitwise".to_string(), 3),
        ]);
        let (vk, proof) = super::dummy_basefold_vk_and_shard_proof::<MipsAir<KoalaBear>>(
            &machine, &shape,
        );
        assert_eq!(
            vk.chip_ordering.len(),
            shape.inner.len(),
            "vk chip_ordering must match shape chip count",
        );
        assert_eq!(
            proof.chip_cumulative_sums.len(),
            shape.inner.len(),
            "chip_cumulative_sums must have one entry per chip in the shape \
             — this is the shape-stability invariant for program_from_shape",
        );
        assert_eq!(
            proof.chip_log_heights.len(),
            shape.inner.len(),
            "chip_log_heights must have one entry per chip in the shape",
        );
        // opened_values.chips is intentionally empty in the basefold
        // pipeline — the recursion verifier builds per-chip openings
        // from LogUp-GKR's chip_openings instead (see prover.rs:207
        // and shard_basefold.rs's BasefoldShardOpenedValuesVariable).
    }
}
