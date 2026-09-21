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
/// A dummy (vk, shard proof) for a CORE child at `shape`, whose values are
/// LOG2 heights (the core cluster shapes: every core trace in a cluster is
/// padded to a power of two).
pub fn dummy_basefold_vk_and_shard_proof<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    shape: &OrderedShape,
) -> (
    StarkVerifyingKey<KoalaBearPoseidon2>,
    zkm_pcs::shard_level::shard_proof::JaggedShardProof<KoalaBear, InnerChallenge>,
)
where
    A: MachineAir<KoalaBear>
        + for<'b> Air<zkm_pcs::folder::VerifierConstraintFolder<'b, KoalaBearPoseidon2>>,
{
    let rows: Vec<(String, usize)> =
        shape.inner.iter().map(|(name, log_h)| (name.clone(), 1usize << *log_h)).collect();
    dummy_basefold_vk_and_shard_proof_rows(machine, &rows)
}

/// A dummy (vk, shard proof) for a child whose chips sit at exactly `rows`
/// (name, row count) — the RECURSION children, whose one shape pins every
/// chip to a multiple-of-32 row count (`next_multiple_of_32_rows`), not a
/// power of two.  `ZKMCompressShape::proof_shapes` carries ROWS.
pub fn dummy_basefold_vk_and_shard_proof_rows<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    rows: &[(String, usize)],
) -> (
    StarkVerifyingKey<KoalaBearPoseidon2>,
    zkm_pcs::shard_level::shard_proof::JaggedShardProof<KoalaBear, InnerChallenge>,
)
where
    A: MachineAir<KoalaBear>
        + for<'b> Air<zkm_pcs::folder::VerifierConstraintFolder<'b, KoalaBearPoseidon2>>,
{
    use zkm_pcs::shard_level::ceil_log2;
    use zkm_pcs::shard_level::verifier::JaggedShardVerifier;

    let chips_and_heights: Vec<(&Chip<KoalaBear, A>, usize)> = rows
        .iter()
        .filter_map(|(name, rows)| {
            machine.chips().iter().find(|c| c.name() == name.as_str()).map(|c| (c, *rows))
        })
        .collect();
    let chips: Vec<&Chip<KoalaBear, A>> = chips_and_heights.iter().map(|(c, _)| *c).collect();

    let chip_heights_pairs: Vec<(String, usize)> = chips_and_heights
        .iter()
        .map(|(chip, rows)| {
            let name = MachineAir::<KoalaBear>::name(*chip);
            (name, *rows)
        })
        .collect();

    let max_log_row_count = JaggedShardVerifier::production_default().max_log_row_count;
    let shape_max_log =
        chip_heights_pairs.iter().map(|(_n, rows)| ceil_log2(*rows)).max().unwrap_or(0);
    assert!(
        shape_max_log <= max_log_row_count,
        "dummy[jagged_shard_proof]: shape max log-height {shape_max_log} exceeds the \
         fixed cube {max_log_row_count}",
    );

    let proof = crate::dummy::dummy_jagged_shard_proof::<KoalaBear, InnerChallenge, A>(
        &chips,
        &chip_heights_pairs,
        max_log_row_count,
        machine.pins_for_rows(&chip_heights_pairs),
    );

    let chip_ordering = chip_heights_pairs
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (name.to_owned(), i))
        .collect::<HashMap<_, _>>();
    let chip_information: Vec<(String, zkm_pcs::SerializableDomain<KoalaBear>, (usize, usize))> = {
        let mut prep: Vec<(String, usize, usize)> = chip_heights_pairs
            .iter()
            .filter_map(|(name, rows)| {
                let chip = chips.iter().find(|c| c.name() == name.as_str())?;
                let pw = MachineAir::<KoalaBear>::preprocessed_width(*chip);
                if pw > 0 {
                    Some((name.clone(), pw, *rows))
                } else {
                    None
                }
            })
            .collect();
        prep.sort_by(|a, b| a.0.cmp(&b.0));
        prep.into_iter()
            .map(|(name, pw, rows)| {
                (
                    name,
                    zkm_pcs::SerializableDomain {
                        shift: KoalaBear::ONE,
                        log_size: ceil_log2(rows),
                    },
                    (pw, rows),
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

    /// Verifies `dummy_basefold_vk_and_shard_proof` produces a
    /// proof whose `chip_cumulative_sums` map cardinality matches
    /// the input shape's chip count — the shape-stability invariant
    /// the recursion-program builder depends on.
    #[test]
    fn dummy_basefold_vk_and_shard_proof_shape_stable() {
        let machine = MipsAir::<KoalaBear>::machine(KoalaBearPoseidon2::default());
        let shape = OrderedShape::from_log2_heights(&[
            ("AddSub".to_string(), 3),
            ("Bitwise".to_string(), 3),
        ]);
        let (vk, proof) =
            super::dummy_basefold_vk_and_shard_proof::<MipsAir<KoalaBear>>(&machine, &shape);
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
    }
}
