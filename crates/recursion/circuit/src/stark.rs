use hashbrown::HashMap;

use p3_air::Air;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;

use zkm_pcs::septic_digest::SepticDigest;
use zkm_pcs::{air::MachineAir, StarkMachine, StarkVerifyingKey};
use zkm_pcs::{
    koala_bear_poseidon2::KoalaBearPoseidon2, shape::OrderedShape, Chip, InnerChallenge,
};

use crate::{fri::dummy_commit, hash::FieldHasherVariable, CircuitConfig};

/// Make a dummy basefold-pipeline shard proof for a given proof shape.
///
/// Drives the host-side `prove_shard_with_data` with zero-filled
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
/// Unblocks `program_from_shape` basefold
/// dispatch and downstream `dummy()` constructors for
/// `ZKMCoreBasefoldWitnessValues` etc.
pub fn dummy_basefold_vk_and_shard_proof<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    shape: &OrderedShape,
    // The recursion-layer AREA PIN this dummy child must mirror.
    // `Some(RECURSION_LOG_TRACE_AREA)` when the child being built is a
    // RECURSION (compress) proof (pinned dense → constant `jagged_n` / stripes);
    // `None` when it is a CORE/normalize child (NATURAL, byte-identical).
    recursion_area_pin: Option<usize>,
) -> (
    StarkVerifyingKey<KoalaBearPoseidon2>,
    zkm_pcs::shard_level::shard_proof::BasefoldShardProof<KoalaBear, InnerChallenge>,
)
where
    A: MachineAir<KoalaBear>
        + for<'b> Air<zkm_pcs::folder::VerifierConstraintFolder<'b, KoalaBearPoseidon2>>,
{
    use zkm_pcs::shard_level::verifier::BasefoldShardVerifier;

    // Build the dummy shard proof by directly zero-filling every
    // field (chip log heights, cumulative sums, logup-GKR round
    // proofs, openings, evaluation proof bytes) at the shapes
    // dictated by the input `shape`. This replaces a previous slow
    // path that drove `prove_shard_with_data` against zero traces
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
    // VERIFY_VK=true fix: the previous code filtered the
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
            machine.chips().iter().find(|c| c.name() == name.as_str()).map(|c| (c, *log_height))
        })
        .collect();
    let chips: Vec<&Chip<KoalaBear, A>> = chips_and_heights.iter().map(|(c, _)| *c).collect();

    let chip_log_heights_pairs: Vec<(String, u8)> = chips_and_heights
        .iter()
        .map(|(chip, log_height)| {
            let name = MachineAir::<KoalaBear>::name(*chip);
            (name, *log_height as u8)
        })
        .collect();

    // The DUMMY shard proof's zerocheck dim must match what a REAL proof at
    // this `shape` produces: the fixed cube.  Every admitted shape fits it —
    // recursion bands are asserted `<= cube` at shape construction
    // (recursion/core shape.rs) — so an over-tall shape here is a bug;
    // assert rather than grow the dummy's cube.
    let max_log_row_count = BasefoldShardVerifier::production_default().max_log_row_count;
    let shape_max_log =
        chip_log_heights_pairs.iter().map(|(_n, lh)| *lh as usize).max().unwrap_or(0);
    assert!(
        shape_max_log <= max_log_row_count,
        "dummy[basefold_shard_proof]: shape max log-height {shape_max_log} exceeds the \
         fixed cube {max_log_row_count}",
    );

    let proof = crate::dummy::dummy_basefold_shard_proof::<KoalaBear, InnerChallenge, A>(
        &chips,
        &chip_log_heights_pairs,
        max_log_row_count,
        recursion_area_pin,
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
    // The vk hash (recursion/circuit/src/types.rs:hash) absorbs one
    // prep-domain record per `chip_information` entry — (log_n, 2^log_n, shift,
    // two_adic_generator(log_n)).  The dummy MUST carry the same preprocessed
    // domains as the real vk (else the recursion program's vk.hash bakes a
    // different number of inputs → the program diverges in assert_complete's
    // vk-hash region).  Real builds these from the PREPROCESSED traces
    // (machine.rs:457-464), sorted by (Reverse(height), name); the natural
    // domain has shift = ONE.  For the chips that carry a preprocessed trace
    // (preprocessed_width > 0), the prep height equals the chip height for the
    // program-keyed chips on the shapes we enumerate (Program / Byte etc.).
    let chip_information: Vec<(String, zkm_pcs::SerializableDomain<KoalaBear>, (usize, usize))> = {
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
                    zkm_pcs::SerializableDomain { shift: KoalaBear::ONE, log_size: log_h },
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
    use zkm_pcs::{
        koala_bear_poseidon2::KoalaBearPoseidon2, CpuProver, InnerVal, MachineProver, ShardProof,
        ZKMCoreOpts,
    };
    use zkm_recursion_core::{air::Block, machine::RecursionAir, stark::KoalaBearPoseidon2Outer};

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
        let (vk, proof) =
            super::dummy_basefold_vk_and_shard_proof::<MipsAir<KoalaBear>>(&machine, &shape, None);
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
            proof.chip_heights.len(),
            shape.inner.len(),
            "chip_heights must have one entry per chip in the shape",
        );
        // opened_values.chips is intentionally empty in the basefold
        // pipeline — the recursion verifier builds per-chip openings
        // from LogUp-GKR's chip_openings instead (see prover.rs:207
        // and shard_basefold.rs's BasefoldShardOpenedValuesVariable).
    }
}
