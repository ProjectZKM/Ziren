/// The recorded profile must be THIS build's, so the mismatch is caught in
/// CI rather than at a prover's startup.
///
/// A failure here means one of two things. Either the transcript moved, in
/// which case `vk_map.bin` is stale and regenerating it is the fix and this
/// file records the new digest afterwards. Or only the profile's own
/// representation changed, in which case the map is still valid and this
/// file is simply restated. The two are not distinguishable from here,
/// which is why updating this file is a deliberate act and not a default.
#[test]
fn vk_map_profile_matches_this_build() {
    let recorded = include_str!("../vk_map_profile.txt").trim();
    let ours = zkm_pcs::profile::transcript_profile_digest_hex();
    assert_eq!(
        recorded, ours,
        "crates/prover/vk_map_profile.txt records {recorded}, but this build's \
         protocol profile is {ours}; see this test's documentation",
    );
}
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
};

use super::*;

use crate::build::try_build_plonk_bn254_artifacts_dev;
use anyhow::Result;

/// A cached key is the key `setup` would rebuild for the program: the same
/// verifying-key hash, one build, then hits on the same `Arc`.
#[test]
fn recursion_pk_cache_matches_a_fresh_setup() {
    use crate::components::DefaultProverComponents;
    use crate::shapes::{ZKMCompressProgramShape, ZKMProofShape};
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let rec = prover.compress_shape_config.as_ref().expect("recursion shape config");
    let shape = ZKMProofShape::generate(rec, REDUCE_BATCH_SIZE).next().expect("a shape");
    let program = prover.program_from_shape(ZKMCompressProgramShape::from_proof_shape(
        shape,
        VK_MERKLE_TREE_HEIGHT,
    ));
    let fresh = prover.compress_prover.setup(&program).1.hash_koalabear();
    let first = prover.recursion_pk_cached(&program, || {
        let (pk, vk) = prover.compress_prover.setup(&program);
        (prover.compress_prover.pk_to_host(&pk), vk)
    });
    let second = prover.recursion_pk_cached(&program, || panic!("the second lookup must hit"));
    assert_eq!(first.1.hash_koalabear(), fresh);
    assert!(Arc::ptr_eq(&first, &second));
    let g = prover.recursion_pks_cache.lock().unwrap();
    assert_eq!((g.hits, g.misses, g.builds, g.waits), (1, 1, 1, 0));
}

/// The wrap program cache key is stable for one shrink shape and changes
/// with the chip heights. Independently built programs for the same dummy
/// input shape are byte-identical.
#[test]
fn wrap_program_shape_key_follows_the_shrink_shape() {
    use crate::components::DefaultProverComponents;
    let prover = ZKMProver::<DefaultProverComponents>::uninitialized();
    let input = |rows: &[(String, usize)]| ZKMWrapWitnessValues::<ShrinkSC> {
        vks_and_proofs: vec![zkm_recursion_circuit::stark::dummy_vk_and_shard_proof_rows(
            prover.shrink_prover.machine(),
            rows,
        )],
        vk_merkle_data: ZKMMerkleProofWitnessValues::dummy(1, VK_MERKLE_TREE_HEIGHT),
    };
    let mut rows: Vec<(String, usize)> = ZKMProver::<DefaultProverComponents>::shrink_shape()
        .clone_into_hash_map()
        .into_iter()
        .collect();
    rows.sort();
    let (a, b) = (input(&rows), input(&rows));
    assert_eq!(a.shape_key(), b.shape_key());
    let mut taller = rows.clone();
    taller[0].1 *= 2;
    assert_ne!(a.shape_key(), input(&taller).shape_key());
    assert_eq!(
        bincode::serialize(&*prover.wrap_program(&a)).unwrap(),
        bincode::serialize(&*prover.wrap_program(&b)).unwrap(),
    );
}

/// After prewarming, another dummy input at the frozen shrink shape
/// hits the program cache.
#[test]
fn wrap_program_prewarm_populates_cache() {
    use crate::components::DefaultProverComponents;
    let prover = ZKMProver::<DefaultProverComponents>::uninitialized();
    prover.prewarm_wrap_program();
    let (program, digest) = prover.wrap_program_cached(&prover.dummy_wrap_input());
    assert_eq!(digest, zkm_recursion_core::setup_digest(&program));
    let cache = prover.wrap_programs_cache.lock().unwrap();
    assert_eq!((cache.hits, cache.misses), (1, 1));
}
use build::{build_constraints_and_witness, try_build_groth16_bn254_artifacts_dev};
use p3_field::PrimeField32;

use zkm_recursion_circuit::machine::ZKMRecursionShape;
use zkm_recursion_core::air::RecursionPublicValues;

#[cfg(test)]
use serial_test::serial;
use utils::zkm_vkey_digest_koalabear;
#[cfg(test)]
use zkm_core_machine::utils::setup_logger;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Test {
    Core,
    Compress,
    Shrink,
    Wrap,
    CircuitTest,
    All,
}

pub fn test_e2e_prover<C: ZKMProverComponents>(
    prover: &ZKMProver<C>,
    elf: &[u8],
    stdin: ZKMStdin,
    opts: ZKMProverOpts,
    test_kind: Test,
) -> Result<()> {
    run_e2e_prover_with_options(prover, elf, stdin, opts, test_kind, true)
}

/// The COMPOSE program-cache key
/// (`ZKMCompressWitnessValues::shape_key`) must satisfy exactly one
/// invariant — **equal `shape_key` implies a byte-identical compose
/// program** — because `compose_program` hands back the cached
/// program on a key hit.  This test pins both directions of that
/// invariant.
///
///   * Height bands do NOT split the key: the compose program is
///     height-agnostic — (1) the recursion-layer AREA PIN
///     (`RECURSION_LOG_TRACE_AREA` = 27) fixes every child bundle's
///     `log_dense_size` for any child whose natural area is under the
///     floor, so all bands commit at L=27 with identical stripe/round
///     counts; and (2) `chip_height_bits_from_opened_degrees`
///     DERIVES per-chip heights
///     from witnessed values instead of baking `builder.constant()`s.
///     MEASURED at bands 3/8/12/16: one shape_key, one 173,774,597-byte
///     program, byte-identical.
///
///   * `log_dense_size` MUST split the key: the area
///     pin is a FLOOR (`max(natural, 27)`), not a clamp, so a recursion
///     child
///     whose NATURAL jagged area exceeds 2^27 carries L > 27 (the
///     soundness compose band used by tendermint and goat lands at natural
///     L = 29; unpadded core shapes reach L = 31), and
///     L=27/28/29 build DIFFERENT programs
///     (measured 173.8 MB / 178.0 MB /
///     185.3 MB), so a key that collided across L would serve the wrong
///     cached program.
#[test]
#[serial]
fn compose_program_cache_key_implies_identical_program() {
    use zkm_pcs::air::MachineAir;
    use zkm_pcs::shape::OrderedShape;
    use zkm_recursion_circuit::machine::{
        ZKMCompressShape, ZKMCompressWithVkeyShape, ZKMCompressWitnessValues,
        ZKMMerkleProofWitnessValues,
    };

    let prover = ZKMProver::<DefaultProverComponents>::new();
    let compress_machine = prover.compress_prover.machine();

    let chip_names: Vec<String> =
        compress_machine.chips().iter().map(<_ as MachineAir<KoalaBear>>::name).collect();

    let arity = 4usize;
    let prog_bytes = |w: &ZKMCompressWitnessValues<InnerSC>| -> Vec<u8> {
        bincode::serialize(&*prover.build_compose_program_uncached(w))
            .expect("serialize compose program")
    };

    let shape_at_band = |log_h: usize| -> ZKMCompressWithVkeyShape {
        let proof_shape = || {
            OrderedShape::from_rows(
                &chip_names.iter().map(|n: &String| (n.clone(), 1usize << log_h)).collect::<Vec<(
                    String,
                    usize,
                )>>(
                ),
            )
        };
        let compress_shape =
            ZKMCompressShape::from((0..arity).map(|_| proof_shape()).collect::<Vec<_>>());
        ZKMCompressWithVkeyShape { compress_shape, merkle_tree_height: VK_MERKLE_TREE_HEIGHT }
    };

    let witness_low = ZKMCompressWitnessValues::<InnerSC>::dummy::<CompressAir<KoalaBear>>(
        compress_machine,
        &shape_at_band(3),
    );
    let witness_high = ZKMCompressWitnessValues::<InnerSC>::dummy::<CompressAir<KoalaBear>>(
        compress_machine,
        &shape_at_band(8),
    );

    let sk_low = witness_low.shape_key();
    let sk_high = witness_high.shape_key();
    assert_eq!(sk_low, sk_high, "expected shape_key to be height-INDEPENDENT within a pin class",);
    let bytes_low = prog_bytes(&witness_low);
    let bytes_high = prog_bytes(&witness_high);
    assert_eq!(
        bytes_low.len(),
        bytes_high.len(),
        "CACHE-KEY UNSOUND: equal shape_key ({sk_low:#018x}) but \
         different compose program LENGTH across bands — the compose \
         program stopped being height-agnostic; extend shape_key to cover \
         whichever field diverged",
    );
    assert!(
        bytes_low == bytes_high,
        "CACHE-KEY UNSOUND: equal shape_key ({sk_low:#018x}) and \
         equal length but different compose program BYTES across bands",
    );

    let at_rows = |rows: usize| -> ZKMCompressWitnessValues<InnerSC> {
        let proof_shape = OrderedShape::from_rows(
            &chip_names
                .iter()
                .map(|n: &String| (n.clone(), rows))
                .collect::<Vec<(String, usize)>>(),
        );
        let vks_and_proofs: Vec<_> = (0..arity)
            .map(|_| {
                zkm_recursion_circuit::stark::dummy_vk_and_shard_proof_rows::<
                    _,
                    CompressAir<KoalaBear>,
                >(compress_machine, &proof_shape.inner)
            })
            .collect();
        let vk_merkle_data =
            ZKMMerkleProofWitnessValues::dummy(vks_and_proofs.len(), VK_MERKLE_TREE_HEIGHT);
        ZKMCompressWitnessValues { vks_and_proofs, vk_merkle_data, is_complete: false }
    };

    let mut seen: std::collections::BTreeMap<u64, (usize, Vec<u8>)> =
        std::collections::BTreeMap::new();
    for rows in [32usize, 4_096, 65_536] {
        let w = at_rows(rows);
        let sk = w.shape_key();
        let bytes = prog_bytes(&w);
        if let Some((prev_rows, prev_bytes)) = seen.get(&sk) {
            assert!(
                *prev_bytes == bytes,
                "CACHE-KEY UNSOUND: children at {prev_rows} and {rows} rows \
                 share shape_key {sk:#018x} but build DIFFERENT compose programs \
                 ({} vs {} bytes).",
                prev_bytes.len(),
                bytes.len(),
            );
        }
        seen.insert(sk, (rows, bytes));
    }
    assert_eq!(
        seen.len(),
        1,
        "expected ONE shape_key for children at 32 / 4,096 / 65,536 rows \
         (the area pins make the compose program row-independent); got {} — a \
         field of the proof structure still follows the child's rows",
        seen.len(),
    );
    let w1 = at_rows(131_072);
    let sk1 = w1.shape_key();
    assert!(
        !seen.contains_key(&sk1),
        "a class-1 child shares the class-0 compose program key {sk1:#018x}",
    );
    let bytes1 = prog_bytes(&w1);
    assert!(
        seen.values().all(|(_, b)| *b != bytes1),
        "a class-1 child builds the class-0 compose program bytes",
    );
}

/// The NORMALIZE program-cache key
/// (`ZKMCoreWitnessValues::shape_key`) carries the same single
/// invariant as the compose one — **equal `shape_key` implies a
/// byte-identical normalize program** — since
/// `recursion_program` hands back the cached program on a hit.
///
/// The leaf layer is where this matters most: one node per core shard, and
/// core shards differ from one another only in their per-chip heights,
/// which the normalize circuit is deliberately agnostic to (heights are
/// Horner-recomposed from the WITNESSED per-chip `degree`, a fixed
/// `max_log_row_count + 1` felts wide).  So heights must NOT split the key
/// while the chip SET must.
#[test]
#[serial]
fn normalize_program_cache_key_implies_identical_program() {
    use zkm_recursion_circuit::machine::ZKMCoreWitnessValues;

    let prover = ZKMProver::<DefaultProverComponents>::new();
    let machine = prover.core_prover.machine();

    let prog_bytes = |w: &ZKMCoreWitnessValues<CoreSC>| -> Vec<u8> {
        bincode::serialize(&*prover.build_normalize_program_uncached(w))
            .expect("serialize normalize program")
    };

    let base: Vec<(String, usize)> = crate::shapes::ZKMProofShape::generate_normalize(machine)
        .into_iter()
        .find_map(|shape| match shape {
            crate::shapes::ZKMProofShape::Normalize(os) => Some(os.inner),
            _ => None,
        })
        .expect("the core machine admits at least one normalize shape");

    let witness_of = |rows: &[(String, usize)]| -> ZKMCoreWitnessValues<CoreSC> {
        ZKMCoreWitnessValues::dummy_rows(machine, rows, false)
    };

    let shrink_one = |idx: usize| -> Vec<(String, usize)> {
        let mut v = base.clone();
        v[idx].1 = (v[idx].1 / 2).max(1);
        v
    };
    let candidates: Vec<Vec<(String, usize)>> =
        std::iter::once(base.clone()).chain((0..base.len().min(4)).map(shrink_one)).collect();

    let mut by_key: std::collections::BTreeMap<u64, Vec<(usize, Vec<u8>)>> =
        std::collections::BTreeMap::new();
    for (n, hs) in candidates.iter().enumerate() {
        let w = witness_of(hs);
        by_key.entry(w.shape_key()).or_default().push((n, prog_bytes(&w)));
    }
    let collided: Vec<_> = by_key.iter().filter(|(_, v)| v.len() > 1).collect();
    assert!(
        !collided.is_empty(),
        "expected at least one shape_key collision across single-chip \
         height variants — without one the normalize cache can never hit",
    );
    for (k, members) in collided {
        let (first_idx, first) = &members[0];
        for (idx, bytes) in members.iter().skip(1) {
            assert_eq!(
                first.len(),
                bytes.len(),
                "NORMALIZE CACHE-KEY UNSOUND: variants {first_idx} and {idx} \
                 share shape_key {k:#018x} but build normalize programs of \
                 different LENGTH; extend shape_key to cover whichever \
                 field diverged",
            );
            assert!(
                first == bytes,
                "NORMALIZE CACHE-KEY UNSOUND: variants {first_idx} and {idx} \
                 share shape_key {k:#018x} and length but different BYTES",
            );
        }
    }

    let mut fewer = base.clone();
    fewer.pop();
    assert_ne!(
        witness_of(&fewer).shape_key(),
        witness_of(&base).shape_key(),
        "NORMALIZE CACHE-KEY UNSOUND: dropping a chip left the key \
         unchanged, so a shard missing that chip would be served the \
         wrong cached program",
    );
}

/// The normalize dummy core VK is faithful in its `chip_information`.
///
/// `StarkMachine::setup` records one entry per chip with a preprocessed
/// trace, in name order; the dummy (`dummy_vk_and_shard_proof`)
/// records the chips OF THE SHAPE that have one.  The two agree on every
/// reachable shape because every preprocessed chip of the core machine is
/// included in every shard, so its name is in every shard's chip set.
/// Both halves are asserted: unconditional inclusion, and equality on a
/// representative shape.
#[test]
#[serial]
fn normalize_dummy_core_vk_chip_information_is_faithful() {
    use zkm_core_executor::ExecutionRecord;
    use zkm_core_machine::mips::MipsAir;
    use zkm_pcs::air::MachineAir;
    use zkm_pcs::shape::OrderedShape;

    let prover = ZKMProver::<DefaultProverComponents>::new();
    let core_machine = prover.core_prover.machine();

    let empty = ExecutionRecord::default();
    let prep_chips: Vec<_> = core_machine
        .chips()
        .iter()
        .filter(|c| <_ as p3_air::BaseAir<KoalaBear>>::preprocessed_width(*c) > 0)
        .collect();
    assert!(!prep_chips.is_empty(), "the core machine has no preprocessed chip");
    for chip in &prep_chips {
        assert!(
            <_ as MachineAir<KoalaBear>>::included(*chip, &empty),
            "preprocessed chip {} is not in every shard, so a shape without it gives \
             the dummy VK fewer chip_information entries than the real one",
            <_ as MachineAir<KoalaBear>>::name(*chip)
        );
    }
    let expected: BTreeSet<String> =
        prep_chips.iter().map(|c| <_ as MachineAir<KoalaBear>>::name(*c)).collect();

    let mut inner: Vec<(String, usize)> =
        expected.iter().map(|name| (name.clone(), 16usize)).collect();
    inner.push(("AddSub".to_string(), 18));
    inner.push(("Branch".to_string(), 18));
    let shape = OrderedShape::from_log2_heights(&inner);
    let (dummy_vk, _proof) = zkm_recursion_circuit::stark::dummy_vk_and_shard_proof::<
        _,
        MipsAir<KoalaBear>,
    >(core_machine, &shape);
    let dummy_prep: BTreeSet<String> =
        dummy_vk.chip_information.iter().map(|(n, _, _)| n.clone()).collect();
    assert_eq!(
        dummy_prep, expected,
        "dummy core VK chip_information diverges from the machine's preprocessed set"
    );
}

/// With the allowlist on, a vk outside it is a `VkNotAllowed` error for
/// the proof being built, carrying the digest and the map size, not a
/// panic.  A core-machine vk is never a recursion allowlist key.
#[test]
#[serial]
fn disallowed_vk_is_an_error_not_a_panic() {
    use zkm_core_machine::mips::MipsAir;
    use zkm_pcs::air::MachineAir;
    use zkm_pcs::shape::OrderedShape;

    let mut prover = ZKMProver::<DefaultProverComponents>::new();
    prover.vk_verification = true;
    let core_machine = prover.core_prover.machine();
    let mut inner: Vec<(String, usize)> = core_machine
        .chips()
        .iter()
        .filter(|c| <_ as p3_air::BaseAir<KoalaBear>>::preprocessed_width(*c) > 0)
        .map(|c| (<_ as MachineAir<KoalaBear>>::name(c), 16usize))
        .collect();
    inner.push(("AddSub".to_string(), 18));
    let shape = OrderedShape::from_log2_heights(&inner);
    let (vk, _proof) = zkm_recursion_circuit::stark::dummy_vk_and_shard_proof::<
        _,
        MipsAir<KoalaBear>,
    >(core_machine, &shape);

    assert!(
        !prover.recursion_vk_map.contains_key(&vk.hash_koalabear()),
        "a core vk must not be in the recursion allowlist"
    );
}

/// The wrap proves ONE program — the verifier of the shrink proof at the
/// frozen shrink shape — so the stripes its two rounds commit are a
/// constant of the tree, and the soundness model's wrap batch
/// cardinality (the batching over both rounds) is pinned rather than
/// bounded. Wrap pins the legacy power-of-two table heights, and cells
/// stack at `2^21` per stripe:
/// under the compress schedule the shrink proof's verifier packs into
/// 8 preprocessed and 8 main stripes, batch 16.
#[test]
#[serial]
fn wrap_committed_stripes_are_pinned() {
    use p3_air::BaseAir;
    use p3_matrix::Matrix;
    use zkm_pcs::air::MachineAir;
    use zkm_pcs::shape::OrderedShape;
    use zkm_recursion_circuit::machine::{
        ZKMCompressShape, ZKMCompressWithVkeyShape, ZKMWrapWitnessValues,
    };

    let prover = ZKMProver::<DefaultProverComponents>::new();
    let shrink_rows: Vec<(String, usize)> = ZKMProver::<DefaultProverComponents>::shrink_shape()
        .clone_into_hash_map()
        .into_iter()
        .collect();
    let compress_shape = ZKMCompressShape::from(vec![OrderedShape::from_rows(&shrink_rows)]);
    let shape =
        ZKMCompressWithVkeyShape { compress_shape, merkle_tree_height: VK_MERKLE_TREE_HEIGHT };
    let input = ZKMWrapWitnessValues::<ShrinkSC>::dummy(prover.shrink_prover.machine(), &shape);
    let program = prover.wrap_program(&input);

    let wrap_machine = prover.wrap_prover.machine();
    let log_stack = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
    let (mut main, mut prep) = (0usize, 0usize);
    for chip in wrap_machine.chips() {
        let rows = program.fixed_rows(chip).expect("wrap must pin its legacy table heights");
        assert!(rows.is_power_of_two(), "wrap chip {} has {rows} rows", chip.name());
        let trace = chip.generate_preprocessed_trace(&program).unwrap();
        assert_eq!(trace.height(), rows, "wrap preprocessed height for {}", chip.name());
        main += rows * <_ as BaseAir<KoalaBear>>::width(chip);
        prep += rows * <_ as p3_air::BaseAir<KoalaBear>>::preprocessed_width(chip);
    }
    let stripes =
        |cells: usize| zkm_pcs::jagged::committed_dense_len(cells, log_stack) >> log_stack;
    let (prep_stripes, main_stripes) = (stripes(prep), stripes(main));
    tracing::info!(
        "[STRIPES] wrap prep {prep} cells -> {prep_stripes}, main {main} cells -> {main_stripes}, batch {}",
        prep_stripes + main_stripes
    );
    assert_eq!(
        (prep_stripes, main_stripes),
        (8, 8),
        "the wrap geometry moved to ({prep_stripes}, {main_stripes}); update the pin and the \
         soundness model's wrap batch cardinality to {}",
        prep_stripes + main_stripes
    );
}

#[test]
#[serial]
fn compose_program_emits_seqblock_parallel() {
    use zkm_pcs::air::MachineAir;
    use zkm_pcs::shape::OrderedShape;
    use zkm_recursion_circuit::machine::programs::build_compose_program;
    use zkm_recursion_circuit::machine::{
        PublicValuesOutputDigest, ZKMCompressShape, ZKMCompressWithVkeyShape,
        ZKMCompressWitnessValues,
    };

    let compress_machine = CompressAir::compress_machine(InnerSC::default());

    let chip_names: Vec<String> =
        compress_machine.chips().iter().map(<_ as MachineAir<KoalaBear>>::name).collect();
    let proof_shape = || {
        OrderedShape::from_rows(
            &chip_names
                .iter()
                .map(|n: &String| (n.clone(), 1usize << 3))
                .collect::<Vec<(String, usize)>>(),
        )
    };
    let n_inputs = 4;
    let compress_shape =
        ZKMCompressShape::from((0..n_inputs).map(|_| proof_shape()).collect::<Vec<_>>());
    let merkle_tree_height = 4;
    let shape = ZKMCompressWithVkeyShape { compress_shape, merkle_tree_height };

    let witness = ZKMCompressWitnessValues::<InnerSC>::dummy::<CompressAir<KoalaBear>>(
        &compress_machine,
        &shape,
    );
    assert_eq!(
        witness.vks_and_proofs.len(),
        n_inputs,
        "dummy witness should have {n_inputs} input proofs",
    );

    let max_log_row_count = compress_machine.max_log_row_count();
    let program = build_compose_program::<CompressAir<KoalaBear>>(
        &compress_machine,
        &witness,
        max_log_row_count,
        false,
        PublicValuesOutputDigest::Reduce,
    );

    let (n_par, n_subs, n_par_instrs) = program.seq_blocks.parallelism_summary();
    assert!(
        n_par >= 1,
        "compose program with {n_inputs} inputs should have ≥1 SeqBlock::Parallel block, got {n_par}",
    );
    let top_level_fanouts: Vec<usize> = program
        .seq_blocks
        .seq_blocks
        .iter()
        .filter_map(|b| match b {
            zkm_recursion_core::runtime::SeqBlock::Parallel(subs) => Some(subs.len()),
            zkm_recursion_core::runtime::SeqBlock::Basic(_) => None,
        })
        .collect();
    assert!(
        top_level_fanouts.contains(&n_inputs),
        "a top-level Parallel block should hold one sub-program per input \
         ({n_inputs}); top-level fan-outs were {top_level_fanouts:?}",
    );
    assert!(
        n_subs >= n_inputs,
        "the recursive sub-program total ({n_subs}) cannot be below the \
         top-level fan-out ({n_inputs})",
    );
    assert!(n_par_instrs > 0, "Parallel sub-programs should hold non-zero instructions",);

    let total_instrs = program.instruction_count();
    let pct = 100.0 * n_par_instrs as f64 / total_instrs as f64;
    tracing::info!(
        "[compose_emits_parallel] N={} parallel_blocks={} subs={} parallel_instrs={}/{} ({:.1}%)",
        n_inputs,
        n_par,
        n_subs,
        n_par_instrs,
        total_instrs,
        pct,
    );

    use zkm_recursion_core::runtime::{Instruction, SeqBlock};
    let mut hint_in_par: usize = 0;
    use zkm_recursion_core::runtime::AnalyzedInstruction;
    fn walk<F>(block: &SeqBlock<AnalyzedInstruction<F>>, hint: &mut usize, inside: bool) {
        match block {
            SeqBlock::Basic(b) => {
                if inside {
                    for instr in &b.instrs {
                        if let Instruction::Hint(h) = instr.inner() {
                            *hint += h.output_addrs_mults.len();
                        }
                    }
                }
            }
            SeqBlock::Parallel(subs) => {
                for sub in subs {
                    for sb in &sub.seq_blocks {
                        walk(sb, hint, true);
                    }
                }
            }
        }
    }
    for b in &program.seq_blocks.seq_blocks {
        walk(b, &mut hint_in_par, false);
    }
    tracing::info!("[compose_emits_parallel] hint_in_par={}", hint_in_par,);
}

pub fn bench_e2e_prover<C: ZKMProverComponents>(
    prover: &ZKMProver<C>,
    elf: &[u8],
    stdin: ZKMStdin,
    opts: ZKMProverOpts,
    test_kind: Test,
) -> Result<()> {
    run_e2e_prover_with_options(prover, elf, stdin, opts, test_kind, false)
}

pub fn run_e2e_prover_with_options<C: ZKMProverComponents>(
    prover: &ZKMProver<C>,
    elf: &[u8],
    stdin: ZKMStdin,
    opts: ZKMProverOpts,
    test_kind: Test,
    verify: bool,
) -> Result<()> {
    tracing::info!("initializing prover");
    let context = ZKMContext::default();

    tracing::info!("setup elf");
    let (_, pk_d, program, vk) = prover.setup(elf);

    tracing::info!("prove core");
    let core_proof = prover.prove_core(&pk_d, program, &stdin, opts, context)?;
    let public_values = core_proof.public_values.clone();

    if verify {
        tracing::info!("verify core");
        prover.verify(&core_proof.proof, &vk)?;
    }

    if test_kind == Test::Core {
        return Ok(());
    }

    let core_bytes = bincode::serialize(&core_proof.proof).unwrap();
    tracing::info!("core proof size: {} bytes", core_bytes.len());
    tracing::info!("compress");
    let compress_span = tracing::debug_span!("compress").entered();
    let compressed_proof = prover.compress(&vk, core_proof, vec![], opts)?;
    compress_span.exit();
    let compressed_bytes = bincode::serialize(&compressed_proof).unwrap();
    tracing::info!("compressed proof size: {} bytes", compressed_bytes.len());
    if let Ok(dir) = std::env::var("ZIREN_SAVE_PROOFS") {
        std::fs::create_dir_all(&dir)?;
        std::fs::write(format!("{dir}/compressed_proof.bin"), &compressed_bytes)?;
        std::fs::write(format!("{dir}/vk.bin"), bincode::serialize(&vk).unwrap())?;
        tracing::info!("compressed proof and vk saved under {dir}");
    }

    if verify {
        tracing::info!("verify compressed");
        prover.verify_compressed(&compressed_proof, &vk)?;
    }

    if test_kind == Test::Compress {
        return Ok(());
    }

    tracing::info!("shrink");
    let shrink_proof = prover.shrink(compressed_proof, opts)?;
    tracing::info!("shrink proof size: {} bytes", bincode::serialize(&shrink_proof).unwrap().len());

    if verify {
        tracing::info!("verify shrink");
        prover.verify_shrink(&shrink_proof, &vk)?;
    }

    if test_kind == Test::Shrink {
        return Ok(());
    }

    tracing::info!("wrap bn254");
    let wrapped_bn254_proof = prover.wrap_bn254(shrink_proof, opts)?;
    let bytes = bincode::serialize(&wrapped_bn254_proof).unwrap();
    tracing::info!("wrap_bn254 proof size: {} bytes", bytes.len());

    let mut file = File::create("proof-with-pis.bin").unwrap();
    file.write_all(bytes.as_slice()).unwrap();

    let mut file = File::open("proof-with-pis.bin").unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();

    let wrapped_bn254_proof = bincode::deserialize(&bytes).unwrap();

    if verify {
        tracing::info!("verify wrap bn254");
        prover.verify_wrap_bn254(&wrapped_bn254_proof, &vk).unwrap();
    }

    if test_kind == Test::Wrap {
        return Ok(());
    }

    tracing::info!("checking vkey hash koalabear");
    let vk_digest_koalabear = zkm_vkey_digest_koalabear(&wrapped_bn254_proof);
    assert_eq!(vk_digest_koalabear, vk.hash_koalabear());

    tracing::info!("checking vkey hash bn254");
    let vk_digest_bn254 = zkm_vkey_digest_bn254(&wrapped_bn254_proof);
    assert_eq!(vk_digest_bn254, vk.hash_bn254());

    tracing::info!("Test the outer circuit");
    let (constraints, witness) =
        build_constraints_and_witness(&wrapped_bn254_proof.vk, &wrapped_bn254_proof.proof);
    PlonkBn254Prover::test(constraints.clone(), witness.clone());
    tracing::info!("Circuit PLONK test succeeded");
    Groth16Bn254Prover::test(constraints, witness);
    tracing::info!("Circuit GROTH16 test succeeded");

    if test_kind == Test::CircuitTest {
        return Ok(());
    }

    tracing::info!("generate plonk bn254 proof");
    let artifacts_dir =
        try_build_plonk_bn254_artifacts_dev(&wrapped_bn254_proof.vk, &wrapped_bn254_proof.proof);
    let plonk_bn254_proof = prover.wrap_plonk_bn254(wrapped_bn254_proof.clone(), &artifacts_dir);
    println!("{plonk_bn254_proof:?}");

    prover.verify_plonk_bn254(&plonk_bn254_proof, &vk, &public_values, &artifacts_dir)?;

    tracing::info!("generate groth16 bn254 proof");
    let artifacts_dir =
        try_build_groth16_bn254_artifacts_dev(&wrapped_bn254_proof.vk, &wrapped_bn254_proof.proof);
    let groth16_bn254_proof = prover.wrap_groth16_bn254(wrapped_bn254_proof, &artifacts_dir);
    println!("{groth16_bn254_proof:?}");

    if verify {
        prover.verify_groth16_bn254(&groth16_bn254_proof, &vk, &public_values, &artifacts_dir)?;
    }

    Ok(())
}

pub fn test_e2e_with_deferred_proofs_prover<C: ZKMProverComponents>(
    opts: ZKMProverOpts,
) -> Result<()> {
    let keccak_elf = test_artifacts::KECCAK_SPONGE_ELF;

    let verify_elf = test_artifacts::VERIFY_PROOF_ELF;

    tracing::info!("initializing prover");
    let prover = ZKMProver::<C>::new();

    tracing::info!("setup keccak elf");
    let (_, keccak_pk_d, keccak_program, keccak_vk) = prover.setup(keccak_elf);

    tracing::info!("setup verify elf");
    let (_, verify_pk_d, verify_program, verify_vk) = prover.setup(verify_elf);

    tracing::info!("prove subproof 1");
    let mut stdin = ZKMStdin::new();
    stdin.write(&1usize);
    stdin.write(&vec![0u8, 0, 0]);
    let deferred_proof_1 = prover.prove_core(
        &keccak_pk_d,
        keccak_program.clone(),
        &stdin,
        opts,
        Default::default(),
    )?;
    let pv_1 = deferred_proof_1.public_values.as_slice().to_vec().clone();

    tracing::info!("prove subproof 2");
    let mut stdin = ZKMStdin::new();
    stdin.write(&3usize);
    stdin.write(&vec![0u8, 1, 2]);
    stdin.write(&vec![2, 3, 4]);
    stdin.write(&vec![5, 6, 7]);
    let deferred_proof_2 =
        prover.prove_core(&keccak_pk_d, keccak_program, &stdin, opts, Default::default())?;
    let pv_2 = deferred_proof_2.public_values.as_slice().to_vec().clone();

    tracing::info!("compress subproof 1");
    let deferred_reduce_1 = prover.compress(&keccak_vk, deferred_proof_1, vec![], opts)?;

    tracing::info!("compress subproof 2");
    let deferred_reduce_2 = prover.compress(&keccak_vk, deferred_proof_2, vec![], opts)?;

    let mut stdin = ZKMStdin::new();
    let vkey_digest = keccak_vk.hash_koalabear();
    let vkey_digest: [u32; 8] =
        vkey_digest.iter().map(|n| n.as_canonical_u32()).collect::<Vec<_>>().try_into().unwrap();
    stdin.write(&vkey_digest);
    stdin.write(&vec![pv_1.clone(), pv_2.clone(), pv_2.clone()]);
    stdin.write_proof(deferred_reduce_1.clone(), keccak_vk.vk.clone());
    stdin.write_proof(deferred_reduce_2.clone(), keccak_vk.vk.clone());
    stdin.write_proof(deferred_reduce_2.clone(), keccak_vk.vk.clone());

    tracing::info!("proving verify program (core)");
    let verify_proof =
        prover.prove_core(&verify_pk_d, verify_program, &stdin, opts, Default::default())?;

    tracing::info!("compress verify program");
    let verify_reduce = prover.compress(
        &verify_vk,
        verify_proof,
        vec![deferred_reduce_1, deferred_reduce_2.clone(), deferred_reduce_2],
        opts,
    )?;
    let reduce_pv: &RecursionPublicValues<_> =
        verify_reduce.proof.public_values.as_slice().borrow();
    println!("deferred_hash: {:?}", reduce_pv.deferred_proofs_digest);
    println!("complete: {:?}", reduce_pv.is_complete);

    tracing::info!("verify verify program");
    prover.verify_compressed(&verify_reduce, &verify_vk)?;

    let shrink_proof = prover.shrink(verify_reduce, opts)?;

    tracing::info!("verify shrink");
    prover.verify_shrink(&shrink_proof, &verify_vk)?;

    tracing::info!("wrap bn254");
    let wrapped_bn254_proof = prover.wrap_bn254(shrink_proof, opts)?;

    tracing::info!("verify wrap bn254");
    println!("verify wrap bn254 {:#?}", wrapped_bn254_proof.vk.commit);
    prover.verify_wrap_bn254(&wrapped_bn254_proof, &verify_vk).unwrap();

    Ok(())
}

/// The fibonacci test guest reads its `n` from standard input (as
/// `examples/fibonacci` does), so every caller has to supply one. Ten keeps
/// the cycle count the tests were tuned against.
fn fib_stdin(n: u32) -> ZKMStdin {
    let mut stdin = ZKMStdin::new();
    stdin.write(&n);
    stdin
}

/// Tests an end-to-end workflow of proving a program across the entire proof generation
/// pipeline.
///
/// Add `FRI_QUERIES`=1 to your environment for faster execution. This test always rebuilds
/// the plonk bn254 artifacts, so setting ZKM_DEV is not needed.
#[test]
#[serial]
#[ignore]
fn test_e2e() -> Result<()> {
    let elf = test_artifacts::FIBONACCI_ELF;
    setup_logger();
    let opts = ZKMProverOpts::default();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    test_e2e_prover::<DefaultProverComponents>(&prover, elf, fib_stdin(10), opts, Test::All)
}

/// Tests an end-to-end workflow of proving a program across the entire proof generation
/// pipeline.
///
/// Add `FRI_QUERIES`=1 to your environment for faster execution. This test always rebuilds
/// the plonk bn254 artifacts, so setting ZKM_DEV is not needed.
#[test]
#[serial]
#[ignore]
fn test_e2e_hello_world() -> Result<()> {
    let elf = test_artifacts::HELLO_WORLD_ELF;

    setup_logger();
    let opts = ZKMProverOpts::default();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    test_e2e_prover::<DefaultProverComponents>(&prover, elf, ZKMStdin::default(), opts, Test::All)
}

/// Core + recursion + compress only.
#[test]
#[serial]
#[ignore]
fn test_e2e_compress_fibonacci() -> Result<()> {
    let elf = test_artifacts::FIBONACCI_ELF;
    setup_logger();
    let opts = ZKMProverOpts::default();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    test_e2e_prover::<DefaultProverComponents>(&prover, elf, fib_stdin(10), opts, Test::Compress)
}

/// Core + compress of an execution cut into several shards, whose global
/// rounds are on several lanes of the global hash chain and share global
/// proofs.
#[test]
#[serial]
#[ignore]
fn test_e2e_compress_on_several_chain_lanes() -> Result<()> {
    setup_logger();
    let prover = ZKMProver::<DefaultProverComponents>::new_with_vk_verification(Some(false));
    let (_, pk_d, program, vk) = prover.setup(test_artifacts::FIBONACCI_ELF);
    let mut opts = ZKMProverOpts::default();
    opts.core_opts.shard_size = 1 << 10;
    let core = prover.prove_core(&pk_d, program, &fib_stdin(1000), opts, ZKMContext::default())?;
    let machine = prover.core_prover.machine();
    let lanes = core
        .proof
        .0
        .iter()
        .filter(|shard| machine.global_round_binding(shard).is_some())
        .map(|shard| shard.global_chain_lane)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(lanes.len() > 2, "the proof's global rounds are on the lanes {lanes:?}");
    let rounds_opened = core
        .proof
        .1
        .iter()
        .map(|proof| proof.jagged_shard_proof.preceding_rounds.len() + 1)
        .collect::<Vec<_>>();
    assert!(
        rounds_opened.iter().any(|rounds| *rounds > 1),
        "the global proofs open {rounds_opened:?} rounds"
    );
    prover.verify(&core.proof, &vk)?;
    let compressed = prover.compress(&vk, core, vec![], opts)?;
    prover.verify_compressed(&compressed, &vk)?;
    Ok(())
}

/// A prover runs the program on an initial memory other than its image
/// and proves against the image's verifying key: it sets up on the
/// altered image and replaces the proving key's preprocessed commitment
/// with the honest one, so the transcript matches the honest key while
/// the preprocessed tables it opens carry the altered image.  Returns the
/// forged core proof and the honest image's verifying key.
fn forge_core_proof_over_altered_image(
    prover: &ZKMProver<DefaultProverComponents>,
    opts: ZKMProverOpts,
) -> Result<(ZKMCoreProof, ZKMVerifyingKey)> {
    let elf = test_artifacts::FIBONACCI_ELF;
    let (_, _, program, vk) = prover.setup(elf);

    let text = program.pc_base..program.pc_base + 4 * program.instructions.len() as u32;
    let (&addr, &word) = program
        .image
        .iter()
        .rev()
        .find(|(addr, _)| !text.contains(addr))
        .expect("an image word outside the text segment");
    let mut altered = program.clone();
    altered.image.insert(addr, word ^ 1);

    let (altered_pk_d, altered_vk) = prover.core_prover.setup(&altered);
    assert_ne!(vk.vk.commit, altered_vk.commit, "the altered word must move the commitment");
    let mut pk = prover.core_prover.pk_to_host(&altered_pk_d);
    pk.commit = vk.vk.commit.clone();
    let pk_d = prover.core_prover.pk_to_device(&pk);

    let core = prover.prove_core(&pk_d, altered, &fib_stdin(10), opts, ZKMContext::default())?;
    tracing::info!("altered image word {addr:#x}: {word:#x} -> {:#x}", word ^ 1);
    Ok((core, vk))
}

/// The recursion verifier opens the preprocessed tables against the
/// verifying key's commitment, so the tree over the proof of
/// [`forge_core_proof_over_altered_image`] cannot close.
///
/// `cargo test -r -p zkm-prover compress_rejects_a_proof_over_a_different_initial_memory -- --ignored --nocapture`
#[test]
#[serial]
#[ignore]
fn compress_rejects_a_proof_over_a_different_initial_memory() -> Result<()> {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    setup_logger();
    let opts = ZKMProverOpts::default();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let (core, vk) = forge_core_proof_over_altered_image(&prover, opts)?;

    let outcome = catch_unwind(AssertUnwindSafe(|| -> Result<()> {
        let compressed = prover.compress(&vk, core, vec![], opts)?;
        prover.verify_compressed(&compressed, &vk)?;
        Ok(())
    }));
    tracing::info!(
        "outcome: {}",
        match &outcome {
            Ok(Ok(())) => "ACCEPTED".to_string(),
            Ok(Err(e)) => format!("rejected: {e}"),
            Err(_) => "rejected: the recursion program panicked".to_string(),
        }
    );
    assert!(
        !matches!(outcome, Ok(Ok(()))),
        "a proof over an altered initial memory verified against the image's key"
    );
    Ok(())
}

/// The core machine's verifier opens the preprocessed tables against the
/// verifying key's commitment, so it rejects the proof of
/// [`forge_core_proof_over_altered_image`] on its own, without recursion and
/// without any check outside `StarkMachine::verify`.
///
/// `cargo test -r -p zkm-prover core_verify_rejects_a_proof_over_a_different_initial_memory -- --ignored --nocapture`
#[test]
#[serial]
#[ignore]
fn core_verify_rejects_a_proof_over_a_different_initial_memory() -> Result<()> {
    use zkm_pcs::MachineProof;

    setup_logger();
    let opts = ZKMProverOpts::default();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let (core, vk) = forge_core_proof_over_altered_image(&prover, opts)?;

    let machine = prover.core_prover.machine();
    let mut challenger = machine.config().challenger();
    let machine_proof =
        MachineProof { shard_proofs: core.proof.0.clone(), global_proofs: core.proof.1.clone() };
    let machine_result = machine.verify(&vk.vk, &machine_proof, &mut challenger);
    tracing::info!("StarkMachine::verify: {machine_result:?}");
    assert!(
        machine_result.is_err(),
        "the core machine verifier must reject a proof over an altered initial memory"
    );

    let prover_result = prover.verify(&core.proof, &vk);
    tracing::info!("ZKMProver::verify: {prover_result:?}");
    assert!(
        prover_result.is_err(),
        "ZKMProver::verify must reject a proof over an altered initial memory"
    );
    Ok(())
}

/// Compress a keccak (precompile + multi-shard) workload with unpadded
/// core shapes: exercises non-core chips (KeccakPermute/precompile/memory)
/// and the multi-shard global cumulative-sum chain through the recursion
/// `assert_complete`, beyond single-shard pure-core fibonacci.
#[test]
#[serial]
#[ignore]
fn test_e2e_compress_keccak() -> Result<()> {
    let elf = test_artifacts::KECCAK_SPONGE_ELF;
    setup_logger();
    let opts = ZKMProverOpts::default();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    test_e2e_prover::<DefaultProverComponents>(
        &prover,
        elf,
        ZKMStdin::default(),
        opts,
        Test::Compress,
    )
}

/// Validates the wrap path end-to-end: compress + shrink +
/// wrap_bn254 + verify_wrap_bn254 — without the heavy PLONK
/// artifact build that follows.
/// Jagged-WHIR e2e: prove the core shards under the stacked-WHIR inner
/// PCS (the core-machine default), then run normalize + compose over
/// them — the LEAF program verifies the core proofs' WHIR openings
/// in-circuit (WhirBundle witness lift + RecursiveStackedWhirVerifier).
#[test]
#[serial]
#[ignore]
fn test_e2e_compress_whir_core() -> Result<()> {
    let elf = test_artifacts::FIBONACCI_ELF;
    setup_logger();
    std::env::set_var("VERIFY_VK", "false");
    let opts = ZKMProverOpts::default();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let result = test_e2e_prover::<DefaultProverComponents>(
        &prover,
        elf,
        fib_stdin(10),
        opts,
        Test::Compress,
    );
    std::env::remove_var("VERIFY_VK");
    result
}

#[test]
#[serial]
#[ignore]
fn test_e2e_wrap_fibonacci() -> Result<()> {
    let elf = test_artifacts::FIBONACCI_ELF;
    setup_logger();
    let opts = ZKMProverOpts::default();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    test_e2e_prover::<DefaultProverComponents>(&prover, elf, fib_stdin(10), opts, Test::Wrap)
}

/// Runs through Test::CircuitTest — wrap_bn254 + the in-circuit
/// PlonkBn254/Groth16Bn254 checks against gnark, but without the
/// multi-hour SRS regen + full proof artifact build.  Cheap gate
/// before committing to the full Test::All run.
#[test]
#[serial]
#[ignore]
fn test_e2e_circuit_fibonacci() -> Result<()> {
    let elf = test_artifacts::FIBONACCI_ELF;
    setup_logger();
    let opts = ZKMProverOpts::default();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    test_e2e_prover::<DefaultProverComponents>(&prover, elf, fib_stdin(10), opts, Test::CircuitTest)
}

/// The MIPS 2-pc state `(pc, next_pc)` rides the State bus, and the bus's
/// entry endpoint is the public-value pair `(start_pc, start_next_pc)`.
/// `start_pc` is chained across shards; `start_next_pc` must be pinned too,
/// or row 0 continues wherever the prover says.  No shard boundary falls
/// inside a delay slot, so an execution shard enters and exits with the
/// sequential lookahead `pc + 4`, the halting row included -- which the
/// honest proof here exercises as the positive control.
#[test]
#[serial]
fn two_pc_lookahead_is_pinned_per_shard() -> Result<()> {
    use std::borrow::BorrowMut;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    setup_logger();
    let elf = test_artifacts::FIBONACCI_ELF;
    let opts = ZKMProverOpts::default();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let (_, pk_d, program, vk) = prover.setup(elf);
    let core = prover.prove_core(&pk_d, program, &fib_stdin(10), opts, ZKMContext::default())?;
    let n = core.proof.0.len();

    prover.verify(&core.proof, &vk)?;

    let forge = |idx: usize, f: &dyn Fn(&mut PublicValues<Word<KoalaBear>, KoalaBear>)| {
        let mut p = core.proof.clone();
        let outer: &mut PublicValues<Word<KoalaBear>, KoalaBear> =
            p.0[idx].public_values.as_mut_slice().borrow_mut();
        f(outer);
        let inner: &mut PublicValues<Word<KoalaBear>, KoalaBear> =
            p.0[idx].jagged_shard_proof.public_values.as_mut_slice().borrow_mut();
        f(inner);
        p
    };
    let eight = KoalaBear::from_u32(8);

    let entry = forge(0, &|pv| pv.start_next_pc = pv.start_pc + eight);
    assert!(prover.verify(&entry, &vk).is_err(), "host verifier accepted a forged start_next_pc");
    let exit = forge(n - 1, &|pv| pv.next_next_pc = pv.next_pc + eight);
    assert!(prover.verify(&exit, &vk).is_err(), "host verifier accepted a forged next_next_pc");

    let outer_only = {
        let mut p = core.proof.clone();
        let pv: &mut PublicValues<Word<KoalaBear>, KoalaBear> =
            p.0[0].public_values.as_mut_slice().borrow_mut();
        pv.initial_timestamp += KoalaBear::ONE;
        p
    };
    let err = prover.verify(&outer_only, &vk).expect_err("divergent public-value copies accepted");
    assert!(
        format!("{err:?}").contains("public values mismatch"),
        "rejected for another reason: {err:?}"
    );

    let accepts = |proof: &ZKMCoreProofData| -> bool {
        let input = prover
            .get_recursion_core_inputs(&vk.vk, &proof.0[..1], 1, false)
            .into_iter()
            .next()
            .unwrap();
        let (program, _) = prover.recursion_program(&input);
        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            program,
            prover.compress_prover.machine().config().perm.clone(),
        );
        let mut ws = Vec::new();
        Witnessable::<InnerConfig>::write(&input, &mut ws);
        runtime.witness_stream = ws.into();
        matches!(catch_unwind(AssertUnwindSafe(|| runtime.run())), Ok(Ok(())))
    };
    assert!(accepts(&core.proof), "the normalize program rejected the honest first shard");
    assert!(!accepts(&entry), "the normalize program accepted a forged start_next_pc");
    Ok(())
}

/// The memory tables chain their addresses across shards through the
/// public values: a shard's previous address, 32 elements for each table,
/// is the last address of the shard before it, and zero for the first
/// shard. The tables read the elements as two sums of 16; the verifier
/// equates every element, which equates both sums, and rejects a proof
/// with one element moved, in either half, before it looks at a shard
/// proof. The execution is cut so that its memory events fill several
/// shards after the execution shard.
#[test]
#[serial]
fn previous_memory_addresses_are_chained_across_shards() -> Result<()> {
    use std::borrow::{Borrow, BorrowMut};
    setup_logger();
    let elf = test_artifacts::FIBONACCI_ELF;
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let (_, pk_d, program, vk) = prover.setup(elf);
    let mut opts = ZKMProverOpts::default();
    opts.core_opts.split_opts.memory = 1 << 12;
    opts.core_opts.split_opts.combine_memory_threshold = 0;
    let core = prover.prove_core(&pk_d, program, &fib_stdin(10), opts, ZKMContext::default())?;
    prover.verify(&core.proof, &vk)?;

    let last = core.proof.0.len() - 1;
    assert!(last >= 2, "the memory events are in {last} shards");
    let chained: &PublicValues<Word<KoalaBear>, KoalaBear> =
        core.proof.0[last].public_values.as_slice().borrow();
    assert!(chained.previous_finalize_addr_bits.contains(&KoalaBear::ONE));

    for (shard, element, finalize) in
        itertools::iproduct!([0, 1, last], [0, 15, 16, 31], [false, true])
    {
        let mut forged = core.proof.clone();
        let proof = &mut forged.0[shard];
        for values in [&mut proof.public_values, &mut proof.jagged_shard_proof.public_values] {
            let pv: &mut PublicValues<Word<KoalaBear>, KoalaBear> =
                values.as_mut_slice().borrow_mut();
            let previous = if finalize {
                &mut pv.previous_finalize_addr_bits
            } else {
                &mut pv.previous_init_addr_bits
            };
            previous[element] += KoalaBear::ONE;
        }
        let err = prover.verify(&forged, &vk).expect_err("a moved previous address accepted");
        assert!(
            matches!(err, zkm_pcs::MachineVerificationError::InvalidPublicValues(_)),
            "shard {shard}, element {element}, finalize {finalize}: rejected by {err:?}"
        );
    }
    Ok(())
}

/// The programs of the global proofs unwind the global hash chain from
/// its end to its origin, lane by lane, and the shards' programs wind it
/// forward again through the host's chain values. A program rejects a
/// proof under a challenge derived from another chain end and a round on
/// a lane that does not exist, and a round moved to another lane leaves
/// the chain elsewhere.
#[test]
#[serial]
#[ignore = "proves a core execution; run with --ignored"]
fn global_round_program_opens_the_committed_round() -> Result<()> {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    setup_logger();
    let elf = test_artifacts::FIBONACCI_ELF;
    let prover = ZKMProver::<DefaultProverComponents>::new_with_vk_verification(Some(false));
    let (_, pk_d, program, vk) = prover.setup(elf);
    let mut opts = ZKMProverOpts::default();
    opts.core_opts.shard_size = 1 << 10;
    let core = prover.prove_core(&pk_d, program, &fib_stdin(10), opts, ZKMContext::default())?;
    let machine = prover.core_prover.machine();
    let chain = prover.global_chain(&vk.vk, &core.proof.0);
    let h_star = *chain.last().unwrap();
    let inputs = prover.get_recursion_global_round_inputs(&vk.vk, &core.proof.0, &core.proof.1)?;
    let lanes_in_use = core
        .proof
        .0
        .iter()
        .filter(|shard| machine.global_round_binding(shard).is_some())
        .map(|shard| shard.global_chain_lane)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(lanes_in_use.len() > 1, "the proof's global rounds are on one lane");

    let execute = |program: Arc<RecursionProgram<KoalaBear>>, ws: Vec<_>| {
        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            program,
            prover.compress_prover.machine().config().perm.clone(),
        );
        runtime.witness_stream = ws.into();
        match catch_unwind(AssertUnwindSafe(|| runtime.run())) {
            Ok(Ok(())) => Some(runtime.record.public_values),
            _ => None,
        }
    };
    let run = |input: &zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues<CoreSC>| {
        let mut ws = Vec::new();
        Witnessable::<InnerConfig>::write(input, &mut ws);
        execute(prover.global_round_program(input).0, ws)
    };
    let run_shard = |input: &ZKMCoreWitnessValues<CoreSC>| {
        let mut ws = Vec::new();
        Witnessable::<InnerConfig>::write(input, &mut ws);
        execute(prover.recursion_program(input).0, ws)
    };

    let mut after = h_star;
    let mut units = 0u64;
    for input in inputs.iter() {
        let public_values = run(input).expect("the honest global proof is rejected");
        assert_eq!(public_values.global_chain_start, after, "the extended chain head differs");
        assert_eq!(
            public_values.global_chain_end,
            machine.global_chain_value(&input.global_chain_heads)
        );
        assert_eq!(public_values.global_h_star, h_star);
        after = public_values.global_chain_end;
        units += u64::from(public_values.global_lookup_units.as_canonical_u32());
    }
    assert_eq!(after, chain[0], "the global proofs do not unwind the chain to its origin");
    let host_units: u64 = core
        .proof
        .0
        .iter()
        .filter_map(|shard| machine.global_round_binding(shard))
        .map(|round| zkm_pcs::logup_gkr::global_lookup_units(machine.global_lookup_count(&round)))
        .sum();
    assert_eq!(units, host_units, "the leaves count other global lookups than the host");

    let shard_inputs = prover.get_recursion_core_inputs(&vk.vk, &core.proof.0, 1, false);
    for (shard, input) in shard_inputs.iter().enumerate() {
        let public_values = run_shard(input).expect("the honest shard is rejected");
        assert_eq!(public_values.global_chain_start, chain[shard], "shard {shard} starts");
        assert_eq!(public_values.global_chain_end, chain[shard + 1], "shard {shard} ends");
    }

    let mut forged = inputs[0].clone();
    forged.global_h_star[0] += KoalaBear::ONE;
    assert!(run(&forged).is_none(), "a global proof passed under another chain end");

    let mut no_lane = inputs[0].clone();
    no_lane.global_chain_lane = zkm_pcs::logup_gkr::GLOBAL_CHAIN_LANE_COUNT as u8;
    assert!(run(&no_lane).is_none(), "a global proof passed on a lane that does not exist");

    let mut other_lane = inputs[0].clone();
    other_lane.global_chain_lane = (other_lane.global_chain_lane + 1) % 8;
    assert_ne!(
        run(&other_lane).map(|public_values| public_values.global_chain_start),
        Some(h_star),
        "a global proof on another lane still starts at the chain end"
    );

    let committing = core
        .proof
        .0
        .iter()
        .position(|shard| machine.global_round_binding(shard).is_some())
        .expect("a shard commits a global round");
    let mut no_lane = shard_inputs[committing].clone();
    no_lane.global_round_lanes[0] = zkm_pcs::logup_gkr::GLOBAL_CHAIN_LANE_COUNT as u8;
    assert!(run_shard(&no_lane).is_none(), "a shard passed on a lane that does not exist");

    let mut other_lane = shard_inputs[committing].clone();
    other_lane.global_round_lanes[0] = (other_lane.global_round_lanes[0] + 1) % 8;
    assert_ne!(
        run_shard(&other_lane).map(|public_values| public_values.global_chain_end),
        Some(chain[committing + 1]),
        "a shard on another lane still ends at the host's chain value"
    );
    Ok(())
}

/// The shards of the fibonacci guest on the input `n`, cut small, each
/// proven on its own with its global round on the lane `lane_of` gives it
/// by its position among the global rounds: the shard proofs, each global
/// round with its lane and tables in shard order, the global challenge,
/// and the core machine's challenger after the verifying key.
#[allow(clippy::type_complexity)]
fn prove_shards_on_chain_lanes(
    prover: &ZKMProver<DefaultProverComponents>,
    pk: &DeviceProvingKey<DefaultProverComponents>,
    program: &Program,
    n: u32,
    lane_of: impl Fn(usize) -> u8,
) -> Result<(
    Vec<ShardProof<CoreSC>>,
    Vec<(u8, zkm_pcs::logup_gkr::GlobalRoundBinding<KoalaBear>, zkm_pcs::Traces<KoalaBear>)>,
    zkm_pcs::logup_gkr::GlobalChallenge<KoalaBear, Challenge<CoreSC>>,
    <CoreSC as StarkGenericConfig>::Challenger,
)> {
    let opts = ZKMCoreOpts { shard_size: 1 << 10, ..ZKMCoreOpts::default() };
    prove_records_on_chain_lanes(prover, pk, program, &fib_stdin(n), opts, |_| true, lane_of)
}

/// [`prove_shards_on_chain_lanes`] for any guest: the shards of `program` on
/// `stdin` under `opts` that `keep` takes, the global challenge drawn
/// over their global rounds alone.
#[allow(clippy::type_complexity)]
fn prove_records_on_chain_lanes(
    prover: &ZKMProver<DefaultProverComponents>,
    pk: &DeviceProvingKey<DefaultProverComponents>,
    program: &Program,
    stdin: &ZKMStdin,
    opts: ZKMCoreOpts,
    keep: impl Fn(&zkm_core_executor::ExecutionRecord) -> bool,
    lane_of: impl Fn(usize) -> u8,
) -> Result<(
    Vec<ShardProof<CoreSC>>,
    Vec<(u8, zkm_pcs::logup_gkr::GlobalRoundBinding<KoalaBear>, zkm_pcs::Traces<KoalaBear>)>,
    zkm_pcs::logup_gkr::GlobalChallenge<KoalaBear, Challenge<CoreSC>>,
    <CoreSC as StarkGenericConfig>::Challenger,
)> {
    let core = &prover.core_prover;
    let machine = core.machine();
    let records = zkm_core_machine::utils::shard_records::<CoreSC, _>(core, program, stdin, opts)?;
    let mut challenger = machine.config().challenger();
    pk.observe_into(&mut challenger);
    let mut shard_proofs = Vec::new();
    let mut committed = Vec::new();
    for record in records.iter().filter(|record| keep(record)) {
        let traces = core.generate_traces(record).expect("the shard's traces");
        let data = core.commit(record, traces, None);
        let tables = core.global_round_tables(&data);
        let mut proof = core.open(pk, data, &mut challenger.clone()).expect("the shard proof");
        if let (Some(round), Some(tables)) = (machine.global_round_binding(&proof), tables) {
            proof.global_chain_lane = lane_of(committed.len());
            committed.push((proof.global_chain_lane, round, tables));
        }
        shard_proofs.push(proof);
    }
    let rounds =
        shard_proofs.iter().map(|proof| machine.global_round_binding(proof)).collect::<Vec<_>>();
    let global = machine
        .global_challenge(
            &challenger,
            rounds.iter().map(Option::as_ref),
            shard_proofs.iter().map(|proof| proof.global_chain_lane),
        )
        .expect("the core machine has global lookups");
    Ok((shard_proofs, committed, global, challenger))
}

/// Runs the global-round program of `input`, proves the run with the
/// compress prover and verifies the proof.
fn prove_global_leaf(
    prover: &ZKMProver<DefaultProverComponents>,
    input: &zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues<CoreSC>,
) {
    let compress_machine = prover.compress_prover.machine();
    let (leaf_program, _) = prover.global_round_program(input);
    let mut ws = Vec::new();
    Witnessable::<InnerConfig>::write(input, &mut ws);
    let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
        leaf_program.clone(),
        compress_machine.config().perm.clone(),
    );
    runtime.witness_stream = ws.into();
    runtime.run().expect("the honest global proof is rejected");
    let mut records = vec![runtime.record];
    compress_machine
        .generate_dependencies(&mut records, &ZKMProverOpts::default().recursion_opts, None)
        .expect("the leaf's dependencies");
    let record = records.pop().unwrap();
    let traces = prover.compress_prover.generate_traces(&record).expect("the leaf's traces");
    let (leaf_pk, leaf_vk) = prover.compress_prover.setup(&leaf_program);
    let mut leaf_challenger = compress_machine.config().challenger();
    leaf_pk.observe_into(&mut leaf_challenger);
    let data = prover.compress_prover.commit(&record, traces, None);
    let leaf_proof = prover
        .compress_prover
        .open(&leaf_pk, data, &mut leaf_challenger)
        .expect("the proof of the leaf");
    compress_machine
        .verify(
            &leaf_vk,
            &zkm_pcs::MachineProof::from_shards(vec![leaf_proof]),
            &mut compress_machine.config().challenger(),
        )
        .expect("the proof of the leaf is rejected");
}

/// The shape of the global proof of `rounds`, rounds of one family at
/// one class.
fn global_round_shape(
    prover: &ZKMProver<DefaultProverComponents>,
    rounds: &[&zkm_pcs::logup_gkr::GlobalRoundBinding<KoalaBear>],
) -> zkm_recursion_circuit::machine::ZKMGlobalRoundShape {
    let machine = prover.core_prover.machine();
    let shape = |round: &zkm_pcs::logup_gkr::GlobalRoundBinding<KoalaBear>| {
        zkm_recursion_circuit::machine::ZKMGlobalRoundShape {
            chips: round.chips.iter().map(|(name, _)| name.clone()).collect(),
            blocks: machine.global_round_blocks(round),
            rounds: rounds.len(),
        }
    };
    let first = shape(rounds[0]);
    assert!(
        rounds.iter().all(|round| shape(round) == first),
        "the rounds of a global proof have one shape"
    );
    first
}

/// The program built from the placeholder of `shape` is the program of
/// the real input `real`: the two inputs have one cache key, and their
/// programs, each built on its own, one verifying key.
fn placeholder_builds_the_program_of(
    prover: &ZKMProver<DefaultProverComponents>,
    shape: &zkm_recursion_circuit::machine::ZKMGlobalRoundShape,
    real: &zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues<CoreSC>,
) {
    let machine = prover.core_prover.machine();
    let placeholder =
        zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues::dummy(machine, shape);
    assert_eq!(
        placeholder.shape_key(),
        real.shape_key(),
        "the placeholder of {shape:?} has another cache key than a proof of that shape"
    );
    let vk_of = |input: &zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues<CoreSC>| {
        let program = prover.build_global_round_program_uncached(input);
        prover.compress_prover.setup(&program).1.hash_koalabear()
    };
    assert_eq!(
        vk_of(&placeholder),
        vk_of(real),
        "the placeholder of {shape:?} builds another program than a proof of that shape"
    );
    assert!(
        crate::shapes::ZKMProofShape::generate_global_rounds(machine)
            .contains(&crate::shapes::ZKMProofShape::GlobalRound(shape.clone())),
        "{shape:?} is not among the enumerated global-round shapes"
    );
}

/// Runs the global-round program of `input`: its public values, or
/// `None` when the program rejects the input.
fn run_global_leaf(
    prover: &ZKMProver<DefaultProverComponents>,
    input: &zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues<CoreSC>,
) -> Option<RecursionPublicValues<KoalaBear>> {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let mut ws = Vec::new();
    Witnessable::<InnerConfig>::write(input, &mut ws);
    let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
        prover.global_round_program(input).0,
        prover.compress_prover.machine().config().perm.clone(),
    );
    runtime.witness_stream = ws.into();
    match catch_unwind(AssertUnwindSafe(|| runtime.run())) {
        Ok(Ok(())) => Some(runtime.record.public_values),
        _ => None,
    }
}

/// Every recursion program real proofs go through is one the vk map is
/// built from, with no vk map at hand: fibonacci and keccak through
/// compress, fibonacci on through shrink, and an execution cut into many
/// shards whose global rounds share global proofs.
///
/// Each shard and each global proof has an enumerated shape
/// (`ZKMProofShape::generate_all`), and a second prover, building the
/// shape's program as the map's builders do, builds the program the
/// proof's leaf ran. The compress stage then proves no program but those
/// leaves' and the enumerated compose programs, and the keys of the root
/// and of the shrink proof are keys of enumerated programs.
#[test]
#[serial]
#[ignore = "proves three executions through compress; run with --ignored"]
fn real_proofs_use_enumerated_programs() -> Result<()> {
    use crate::shapes::{ZKMCompressProgramShape, ZKMProofShape};
    setup_logger();
    let prover = ZKMProver::<DefaultProverComponents>::new_with_vk_verification(Some(false));
    let builder = ZKMProver::<DefaultProverComponents>::uninitialized_with(Some(false));
    let machine = prover.core_prover.machine();
    let config = prover.compress_shape_config.as_ref().expect("the recursion shape config");
    let enumerated =
        ZKMProofShape::generate_all(config, REDUCE_BATCH_SIZE, machine).collect::<BTreeSet<_>>();
    let program_of = |prover: &ZKMProver<DefaultProverComponents>, shape: &ZKMProofShape| {
        prover.program_from_shape(ZKMCompressProgramShape::from_proof_shape(
            shape.clone(),
            VK_MERKLE_TREE_HEIGHT,
        ))
    };
    let key_of = |program: &RecursionProgram<KoalaBear>| {
        ZKMProver::<DefaultProverComponents>::recursion_pk_cache_key(program)
    };
    let normalize = enumerated
        .iter()
        .filter_map(|shape| match shape {
            ZKMProofShape::Normalize(rows) => {
                Some((ZKMProofShape::normalize_class(machine, &rows.inner), shape))
            }
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let mut allowed = enumerated
        .iter()
        .filter(|shape| matches!(shape, ZKMProofShape::Compress(_)))
        .map(|shape| key_of(&program_of(&prover, shape)))
        .collect::<BTreeSet<_>>();
    let roots = enumerated
        .iter()
        .filter(|shape| matches!(shape, ZKMProofShape::CompressRoot(_)))
        .map(|shape| prover.root_prover.setup(&program_of(&prover, shape)).1.hash_koalabear())
        .collect::<BTreeSet<_>>();
    let shrinks = enumerated
        .iter()
        .filter(|shape| matches!(shape, ZKMProofShape::Shrink(_)))
        .map(|shape| prover.shrink_prover.setup(&program_of(&builder, shape)).1.hash_koalabear())
        .collect::<BTreeSet<_>>();

    let mut short_shards = ZKMProverOpts::default();
    short_shards.core_opts.shard_size = 1 << 10;
    let runs = [
        (test_artifacts::FIBONACCI_ELF, fib_stdin(10), ZKMProverOpts::default(), true),
        (test_artifacts::KECCAK_SPONGE_ELF, ZKMStdin::default(), ZKMProverOpts::default(), false),
        (test_artifacts::FIBONACCI_ELF, fib_stdin(1000), short_shards, false),
    ];
    let mut placeholders = BTreeMap::new();
    let mut leaves = BTreeSet::new();
    let mut chip_sets = BTreeSet::new();
    let mut most_rounds = 0;
    for (elf, stdin, opts, shrink) in runs {
        let (_, pk_d, program, vk) = prover.setup(elf);
        let core = prover.prove_core(&pk_d, program, &stdin, opts, ZKMContext::default())?;
        let inputs = prover.get_first_layer_inputs(&vk, &core.proof.0, &core.proof.1, &[], 1)?;
        let mut run_leaves = BTreeSet::new();
        for input in inputs.iter() {
            let (shape, used) = match input {
                ZKMCircuitWitness::CoreJagged(input) => {
                    let rows = input.shard_proofs[0]
                        .chip_heights
                        .iter()
                        .map(|(name, rows)| (name.clone(), *rows))
                        .collect::<Vec<_>>();
                    let class = ZKMProofShape::normalize_class(machine, &rows);
                    let shape = normalize
                        .get(&class)
                        .unwrap_or_else(|| panic!("no normalize shape of the class {class:?}"));
                    chip_sets.insert(class.0);
                    ((*shape).clone(), prover.recursion_program(input).1)
                }
                ZKMCircuitWitness::GlobalJagged(input) => {
                    let shape = input.shape().expect("a global proof of rounds of one shape");
                    most_rounds = shape.rounds.max(most_rounds);
                    let shape = ZKMProofShape::GlobalRound(shape);
                    assert!(enumerated.contains(&shape), "{shape:?} is not enumerated");
                    (shape, prover.global_round_program(input).1)
                }
                _ => panic!("a proof without deferred proofs has core and global leaves"),
            };
            let placeholder = *placeholders
                .entry(shape.clone())
                .or_insert_with(|| key_of(&program_of(&builder, &shape)));
            assert_eq!(
                placeholder, used,
                "the program built from {shape:?} is not the one the proof's leaf runs"
            );
            run_leaves.insert(used);
        }
        leaves.extend(run_leaves.iter().copied());
        allowed.extend(run_leaves.iter().copied());

        let compressed = prover.compress(&vk, core, vec![], opts)?;
        prover.verify_compressed(&compressed, &vk)?;
        let proved = prover
            .recursion_pks_cache
            .lock()
            .unwrap()
            .entries
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        assert!(run_leaves.is_subset(&proved), "the compress stage ran other leaf programs");
        assert!(
            proved.difference(&leaves).next().is_some(),
            "the compress stage proved no compose program"
        );
        assert!(
            proved.is_subset(&allowed),
            "the compress stage proved a program outside the enumeration"
        );
        assert!(
            roots.contains(&compressed.vk.hash_koalabear()),
            "the root's key is not the key of an enumerated root program"
        );
        if shrink {
            let shrunk = prover.shrink(compressed, opts)?;
            assert!(
                shrinks.contains(&shrunk.vk.hash_koalabear()),
                "the shrink proof's key is not the key of the enumerated shrink program"
            );
        }
    }

    let holds = |names: &[&str], lacks: &[&str]| {
        chip_sets.iter().any(|chips| {
            names.iter().all(|name| chips.contains(*name))
                && !lacks.iter().any(|name| chips.contains(*name))
        })
    };
    assert!(holds(&["MemoryImage", "MemoryGlobalInit"], &[]), "no execution of one shard");
    assert!(holds(&["MemoryImage"], &["MemoryGlobalInit"]), "no first shard of several");
    assert!(holds(&["AddSub"], &["MemoryImage"]), "no later execution shard");
    assert!(holds(&["KeccakSponge"], &["AddSub"]), "no precompile shard");
    assert!(holds(&["MemoryGlobalInit"], &["MemoryLocal"]), "no memory shard");
    assert!(most_rounds > 1, "no global proof of several rounds");
    Ok(())
}

/// The largest global proof the grouping makes of each family of
/// global-round chips at each class of stacking blocks has a program that
/// fits a recursion pin class, and the bound on a proof's rounds counts
/// the cells of that program's main round from above: by the estimate
/// alone while the rounds commit at most 256 stacking blocks together,
/// and with what a round adds past that otherwise. The programs are
/// built from the shapes' placeholders. Four families at six classes,
/// less the class of 256 blocks for the two memory tables, which the row
/// cube keeps below it. The tallest table of each program fits the row
/// cube of the recursion machines and is counted from above by the rows
/// estimate that bounds the rounds of a proof.
#[test]
#[ignore = "builds two dozen global-round programs; run with --ignored"]
fn global_round_shapes_fit_a_pin_class() {
    use rayon::prelude::*;
    use zkm_pcs::logup_gkr::{
        global_round_leaf_cells, global_round_leaf_rows, GLOBAL_LEAF_CELLS,
        GLOBAL_LEAF_FIXED_CELLS, GLOBAL_LEAF_FIXED_ROWS, GLOBAL_LEAF_WIDE_ROUND_CELLS,
    };
    let prover = ZKMProver::<DefaultProverComponents>::new_with_vk_verification(Some(false));
    let machine = prover.core_prover.machine();
    let widths = prover
        .compress_prover
        .machine()
        .chips()
        .iter()
        .map(|chip| {
            (
                <_ as zkm_pcs::air::MachineAir<KoalaBear>>::name(chip),
                <_ as p3_air::BaseAir<KoalaBear>>::width(chip),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut largest = BTreeMap::new();
    for shape in crate::shapes::ZKMProofShape::generate_global_rounds(machine) {
        let crate::shapes::ZKMProofShape::GlobalRound(shape) = shape else {
            panic!("not a global-round shape")
        };
        let rounds = largest.entry((shape.chips, shape.blocks)).or_insert(0);
        *rounds = shape.rounds.max(*rounds);
    }
    let shapes = largest
        .into_iter()
        .map(|((chips, blocks), rounds)| zkm_recursion_circuit::machine::ZKMGlobalRoundShape {
            chips,
            blocks,
            rounds,
        })
        .collect::<Vec<_>>();
    assert!(shapes.iter().any(|shape| shape.rounds > 24) && shapes.len() >= 23);
    shapes.par_iter().for_each(|shape| {
        let input =
            zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues::dummy(machine, shape);
        let program = zkm_recursion_circuit::machine::programs::build_global_round_program(
            machine,
            &input,
            machine.max_log_row_count(),
        );
        let rows = RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::organic_shape(
            &RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::program_heights(&program),
        );
        assert!(
            RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::class_for_rows(&rows)
                .is_some(),
            "the program of {shape:?} fits no pin class"
        );
        let tallest = rows.values().copied().max().unwrap_or(0);
        let rows_estimate =
            GLOBAL_LEAF_FIXED_ROWS + shape.rounds * global_round_leaf_rows(shape.blocks);
        assert!(
            tallest <= 1 << prover.compress_prover.machine().max_log_row_count()
                && tallest <= rows_estimate,
            "the program of {shape:?} has a table of {tallest} rows, counted as \
             {rows_estimate}"
        );
        let cells: usize = rows.iter().map(|(chip, rows)| rows * widths[chip]).sum();
        let columns: usize = shape
            .chips
            .iter()
            .map(|name| {
                let chip = machine
                    .chips()
                    .iter()
                    .find(|chip| <_ as zkm_pcs::air::MachineAir<KoalaBear>>::name(*chip) == *name)
                    .expect("a chip of the machine");
                <_ as p3_air::BaseAir<KoalaBear>>::width(chip)
            })
            .sum();
        let estimate = GLOBAL_LEAF_FIXED_CELLS
            + shape.rounds * global_round_leaf_cells(shape.blocks, shape.chips.len(), columns);
        assert!(
            shape.rounds == 1 || estimate <= GLOBAL_LEAF_CELLS,
            "the grouping makes a proof of {shape:?}, counted as {estimate} cells"
        );
        let wide = if shape.rounds * shape.blocks > 256 {
            shape.rounds * GLOBAL_LEAF_WIDE_ROUND_CELLS
        } else {
            0
        };
        assert!(
            cells <= estimate + wide,
            "the program of {shape:?} commits {cells} cells, counted as {}",
            estimate + wide
        );
    });
}

/// Shards that ran different things commit one family of tables in their
/// global rounds, the tables a shard lacks without rows, so their rounds
/// share a global proof. The keccak guest's execution shards hold local
/// memory and syscalls and its precompile shard local memory and
/// precompile syscalls: one global proof opens rounds of both, the host
/// verifies the execution, every program unwinds the chain and sums the
/// lookups as the host does, and the program of that proof is proven. A
/// table without rows adds nothing to a round's lookups, and a proof in
/// which it claims rows is rejected. The placeholder of the proof's
/// shape builds the same program.
#[test]
#[serial]
#[ignore = "proves a core execution; run with --ignored"]
fn global_round_program_opens_rounds_of_one_family() -> Result<()> {
    use p3_field::BasedVectorSpace;
    setup_logger();
    let prover = ZKMProver::<DefaultProverComponents>::new_with_vk_verification(Some(false));
    let (_, pk_d, program, vk) = prover.setup(test_artifacts::KECCAK_SPONGE_ELF);
    let machine = prover.core_prover.machine();
    let opts = ZKMCoreOpts { shard_size: 1 << 10, ..ZKMCoreOpts::default() };
    let (shard_proofs, committed, global, challenger) = prove_records_on_chain_lanes(
        &prover,
        &pk_d,
        &program,
        &ZKMStdin::default(),
        opts,
        |_| true,
        |_| 3,
    )?;
    let with_rows = |round: usize| {
        committed[round]
            .1
            .chips
            .iter()
            .filter(|(_, height)| *height > 0)
            .map(|(name, _)| name.as_str())
            .collect::<BTreeSet<_>>()
    };
    for (round, (_, binding, _)) in committed.iter().enumerate() {
        let family = machine.global_family(with_rows(round)).expect("the round's family");
        assert!(
            binding.chips.iter().map(|(name, _)| name).eq(family.iter()),
            "round {round} commits {:?}, its family is {family:?}",
            binding.chips
        );
    }
    let groups = machine
        .global_proof_groups_by_lane(
            committed.iter().enumerate().map(|(round, (lane, binding, _))| (*lane, binding, round)),
            zkm_pcs::global_rounds_per_proof(),
        )
        .into_iter()
        .map(|group| group.into_iter().map(|(_, round)| round).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let mixed = groups
        .iter()
        .position(|group| {
            group.iter().map(|&round| with_rows(round)).collect::<BTreeSet<_>>().len() > 1
        })
        .unwrap_or_else(|| {
            panic!(
                "no global proof opens rounds with different tables: {:?}",
                groups
                    .iter()
                    .map(|group| group.iter().map(|&round| with_rows(round)).collect())
                    .collect::<Vec<Vec<_>>>()
            )
        });
    let prove = |group: &[usize]| {
        let rounds = group
            .iter()
            .map(|&round| (&committed[round].1, committed[round].2.clone()))
            .collect::<Vec<_>>();
        prover
            .core_prover
            .prove_global_rounds(&pk_d, &rounds, &global, &challenger)
            .expect("the global proof")
    };
    let global_proofs = groups.iter().map(|group| prove(group)).collect::<Vec<_>>();
    let core_proof = zkm_pcs::MachineProof {
        shard_proofs: shard_proofs.clone(),
        global_proofs: global_proofs.clone(),
    };
    machine
        .verify(&vk.vk, &core_proof, &mut machine.config().challenger())
        .expect("the host rejects the execution");

    let chain = prover.global_chain(&vk.vk, &shard_proofs);
    let h_star = *chain.last().unwrap();
    let inputs = prover.get_recursion_global_round_inputs(&vk.vk, &shard_proofs, &global_proofs)?;
    let group_of = |input: &zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues<CoreSC>| {
        global_proofs
            .iter()
            .position(|proof| {
                proof.jagged_shard_proof.main_commitment == input.proofs[0].main_commitment
            })
            .expect("the input holds one of the global proofs")
    };
    let mut after = h_star;
    let mut units = 0u64;
    for input in inputs.iter() {
        let group = group_of(input);
        let rounds = groups[group].iter().map(|&round| &committed[round].1).collect::<Vec<_>>();
        let host_sum = machine
            .verify_global_proof(&vk.vk, &challenger, &rounds, &global_proofs[group], &global)
            .expect("the host rejects the global proof");
        let public_values =
            run_global_leaf(&prover, input).expect("the honest global proof is rejected");
        assert_eq!(public_values.global_chain_start, after, "the extended chain head differs");
        assert_eq!(
            public_values.global_sum.as_slice(),
            host_sum.as_basis_coefficients_slice(),
            "the leaf sums other lookups than the host"
        );
        after = public_values.global_chain_end;
        units += u64::from(public_values.global_lookup_units.as_canonical_u32());
    }
    assert_eq!(after, chain[0], "the global proofs do not unwind the chain to its origin");
    let host_units: u64 = committed
        .iter()
        .map(|(_, round, _)| {
            zkm_pcs::logup_gkr::global_lookup_units(machine.global_lookup_count(round))
        })
        .sum();
    assert_eq!(units, host_units, "the leaves count other global lookups than the host");

    let leaf = inputs
        .iter()
        .find(|input| group_of(input) == mixed)
        .expect("the proof of rounds with different tables has a leaf");
    prove_global_leaf(&prover, leaf);
    let rounds = groups[mixed].iter().map(|&round| &committed[round].1).collect::<Vec<_>>();
    placeholder_builds_the_program_of(&prover, &global_round_shape(&prover, &rounds), leaf);

    let empty = leaf.proofs[0]
        .chip_heights
        .values()
        .position(|height| *height == 0)
        .expect("a round of the proof holds a table without rows");
    let mut claimed = leaf.clone();
    let degree = &mut claimed.proofs[0].opened_values.chips[empty].quotient[0];
    *degree.last_mut().unwrap() = zkm_pcs::InnerChallenge::ONE;
    assert!(
        run_global_leaf(&prover, &claimed).is_none(),
        "a table without rows passed with a row claimed"
    );
    Ok(())
}

/// A global round past the smallest class commits the stacking blocks of
/// its class, the next power of two, and its global proof commits the
/// same: the memory shard of a guest that hashes 1.5 MiB commits a global
/// round whose cells fill 24 blocks at 32, the shard verifies, its global
/// proof opens the commitment the shard made and the host and the program
/// accept it. The placeholder of that shape builds the same program.
#[test]
#[serial]
#[ignore = "proves a memory shard; run with --ignored"]
fn global_round_commits_the_blocks_of_its_class() -> Result<()> {
    use p3_field::BasedVectorSpace;
    setup_logger();
    let prover = ZKMProver::<DefaultProverComponents>::new_with_vk_verification(Some(false));
    let (_, pk_d, program, vk) = prover.setup(test_artifacts::SHA2_RUST_ELF);
    let machine = prover.core_prover.machine();
    let input = vec![7u8; 3 << 19];
    let mut stdin = ZKMStdin::new();
    stdin.write(&ZKMPublicValues::from(input.as_slice()).hash().to_vec());
    stdin.write(&input);
    let (shard_proofs, committed, global, challenger) = prove_records_on_chain_lanes(
        &prover,
        &pk_d,
        &program,
        &stdin,
        ZKMCoreOpts::default(),
        |record| {
            !record.global_memory_initialize_events.is_empty()
                || !record.global_memory_finalize_events.is_empty()
        },
        |_| 0,
    )?;
    machine
        .verify_shard_proofs(
            &vk.vk,
            &zkm_pcs::MachineProof { shard_proofs: shard_proofs.clone(), global_proofs: vec![] },
            &mut machine.config().challenger(),
        )
        .expect("the host rejects the memory shards");

    let log_stack = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
    let blocks_of = |proof: &ShardProof<CoreSC>, before_main: usize| {
        let zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(bundle) =
            &proof.jagged_shard_proof.evaluation_proof
        else {
            panic!("the proof carries no opening")
        };
        let rounds = &bundle.whir_proof.batch_evaluations;
        rounds[rounds.len() - 1 - before_main].len()
    };
    let natural = |round: &zkm_pcs::logup_gkr::GlobalRoundBinding<KoalaBear>| {
        let cells: usize = round
            .chips
            .iter()
            .map(|(name, height)| {
                let chip = machine
                    .chips()
                    .iter()
                    .find(|chip| <_ as zkm_pcs::air::MachineAir<KoalaBear>>::name(*chip) == *name)
                    .unwrap();
                height * <_ as p3_air::BaseAir<KoalaBear>>::width(chip)
            })
            .sum();
        zkm_pcs::jagged::committed_dense_len(cells, log_stack) >> log_stack
    };
    let (shard, (_, round, tables)) = shard_proofs
        .iter()
        .zip(committed.iter())
        .find(|(_, (_, round, _))| !natural(round).is_power_of_two())
        .expect("a memory shard whose global round fills no power of two of blocks");
    let class = natural(round).next_power_of_two();
    assert!(
        class > zkm_pcs::jagged::GLOBAL_ROUND_PIN_BLOCKS,
        "the round fills {} blocks, within the smallest class",
        natural(round)
    );
    assert_eq!(blocks_of(shard, 1), class, "the shard commits its global round at its class");

    let global_proof = prover
        .core_prover
        .prove_global_rounds(&pk_d, &[(round, tables.clone())], &global, &challenger)
        .expect("the global proof");
    assert_eq!(blocks_of(&global_proof, 0), class, "the global proof commits the class");
    assert_eq!(
        global_proof.jagged_shard_proof.main_commitment,
        shard.jagged_shard_proof.global_round().expect("the shard's global round").commitment,
        "the global proof commits another round than its shard"
    );
    let host_sum = machine
        .verify_global_proof(&vk.vk, &challenger, &[round], &global_proof, &global)
        .expect("the host rejects the global proof");

    let mut global_proofs = vec![global_proof];
    for (_, other, tables) in committed.iter().filter(|(_, other, _)| other != round) {
        global_proofs.push(
            prover
                .core_prover
                .prove_global_rounds(&pk_d, &[(other, tables.clone())], &global, &challenger)
                .expect("the global proof"),
        );
    }
    let inputs = prover.get_recursion_global_round_inputs(&vk.vk, &shard_proofs, &global_proofs)?;
    let leaf = inputs
        .iter()
        .find(|input| {
            input.proofs[0].main_commitment == global_proofs[0].jagged_shard_proof.main_commitment
        })
        .expect("the global proof has a leaf");
    let public_values =
        run_global_leaf(&prover, leaf).expect("the honest global proof is rejected");
    assert_eq!(
        public_values.global_chain_end,
        machine.global_chain_value(&leaf.global_chain_heads),
        "the leaf ends the chain elsewhere than the host"
    );
    assert_eq!(
        public_values.global_sum.as_slice(),
        host_sum.as_basis_coefficients_slice(),
        "the leaf sums other lookups than the host"
    );
    placeholder_builds_the_program_of(&prover, &global_round_shape(&prover, &[round]), leaf);
    Ok(())
}

/// A global proof opens several rounds of one lane, one in each table
/// slot, and its program steps the lane over them in slot order: the
/// programs of a proof of three rounds and of one of as many rounds as a
/// proof opens unwind the chain as the host does and carry the host's
/// sums and lookup counts. Every program commits no more cells than the
/// bound on a proof's rounds counts for it, and the program of the
/// largest proof is proven. A proof whose slots hold the rounds in
/// another order verifies but leaves the chain elsewhere, and has no
/// place among the leaves; a slot whose commitment is replaced by another
/// round's is rejected.
#[test]
#[serial]
#[ignore = "proves a core execution; run with --ignored"]
fn global_round_program_opens_the_rounds_of_a_grouped_proof() -> Result<()> {
    use p3_field::BasedVectorSpace;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    setup_logger();
    let prover = ZKMProver::<DefaultProverComponents>::new_with_vk_verification(Some(false));
    let (_, pk_d, program, vk) = prover.setup(test_artifacts::FIBONACCI_ELF);
    let machine = prover.core_prover.machine();
    let (shard_proofs, committed, global, challenger) =
        prove_shards_on_chain_lanes(&prover, &pk_d, &program, 4200, |round| {
            if round % 8 == 7 {
                2
            } else {
                5
            }
        })?;
    let lane = (0..committed.len()).filter(|&round| committed[round].0 == 5).collect::<Vec<_>>();
    let most = zkm_pcs::logup_gkr::MAX_GLOBAL_ROUNDS_PER_PROOF.min(
        zkm_pcs::logup_gkr::global_rounds_within_the_row_cube(
            machine.global_round_blocks(&committed[lane[0]].1),
        ),
    );
    assert!(lane.len() >= 3 + most, "lane 5 holds {} of {} rounds", lane.len(), committed.len());

    let prove = |rounds: &[usize]| {
        let rounds = rounds
            .iter()
            .map(|&round| (&committed[round].1, committed[round].2.clone()))
            .collect::<Vec<_>>();
        prover
            .core_prover
            .prove_global_rounds(&pk_d, &rounds, &global, &challenger)
            .expect("the global proof")
    };
    let mut global_proofs = vec![prove(&lane[..3]), prove(&lane[3..3 + most])];
    let rest = machine.global_proof_groups_by_lane(
        committed
            .iter()
            .enumerate()
            .filter(|(round, _)| !lane[..3 + most].contains(round))
            .map(|(round, (lane, binding, _))| (*lane, binding, round)),
        zkm_pcs::global_rounds_per_proof(),
    );
    for group in rest {
        global_proofs.push(prove(&group.iter().map(|(_, round)| *round).collect::<Vec<_>>()));
    }
    let core_proof = zkm_pcs::MachineProof {
        shard_proofs: shard_proofs.clone(),
        global_proofs: global_proofs.clone(),
    };
    machine
        .verify(&vk.vk, &core_proof, &mut machine.config().challenger())
        .expect("the host rejects the grouped global proofs");

    let chain = prover.global_chain(&vk.vk, &shard_proofs);
    let h_star = *chain.last().unwrap();
    let inputs = prover.get_recursion_global_round_inputs(&vk.vk, &shard_proofs, &global_proofs)?;
    let run = |input: &zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues<CoreSC>| {
        let mut ws = Vec::new();
        Witnessable::<InnerConfig>::write(input, &mut ws);
        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            prover.global_round_program(input).0,
            prover.compress_prover.machine().config().perm.clone(),
        );
        runtime.witness_stream = ws.into();
        match catch_unwind(AssertUnwindSafe(|| runtime.run())) {
            Ok(Ok(())) => Some(runtime.record.public_values),
            _ => None,
        }
    };
    let opens = |input: &zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues<CoreSC>,
                 proof: &ShardProof<CoreSC>| {
        proof.jagged_shard_proof.main_commitment == input.proofs[0].main_commitment
    };
    let rounds_of =
        |input: &zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues<CoreSC>| {
            let proof = global_proofs
                .iter()
                .find(|proof| opens(input, proof))
                .expect("the input holds one of the global proofs");
            (proof, machine.global_proof_rounds(proof).expect("the proof's rounds"))
        };
    let host_sum = |input: &zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues<CoreSC>| {
        let (proof, rounds) = rounds_of(input);
        machine
            .verify_global_proof(
                &vk.vk,
                &challenger,
                &rounds.iter().collect::<Vec<_>>(),
                proof,
                &global,
            )
            .expect("the host rejects the global proof")
    };
    let compress_machine = prover.compress_prover.machine();
    let widths = compress_machine
        .chips()
        .iter()
        .map(|chip| {
            (
                <_ as zkm_pcs::air::MachineAir<KoalaBear>>::name(chip),
                <_ as p3_air::BaseAir<KoalaBear>>::width(chip),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let main_cells = |program: &RecursionProgram<KoalaBear>| -> usize {
        let heights =
            RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::program_heights(program);
        RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::organic_shape(&heights)
            .iter()
            .map(|(chip, rows)| rows * widths[chip])
            .sum()
    };

    let mut after = h_star;
    let mut units = 0u64;
    let mut three = None;
    let mut rounds_opened = Vec::new();
    for input in inputs.iter() {
        let public_values = run(input).expect("the honest global proof is rejected");
        assert_eq!(public_values.global_chain_start, after, "the extended chain head differs");
        assert_eq!(
            public_values.global_chain_end,
            machine.global_chain_value(&input.global_chain_heads)
        );
        assert_eq!(
            public_values.global_sum.as_slice(),
            host_sum(input).as_basis_coefficients_slice(),
            "the leaf sums other lookups than the host"
        );
        after = public_values.global_chain_end;
        units += u64::from(public_values.global_lookup_units.as_canonical_u32());
        rounds_opened.push(input.rounds());
        let counted = zkm_pcs::logup_gkr::GLOBAL_LEAF_FIXED_CELLS
            + rounds_of(input)
                .1
                .iter()
                .map(|round| machine.global_round_leaf_cells(round))
                .sum::<usize>();
        let cells = main_cells(&prover.global_round_program(input).0);
        assert!(
            cells <= counted,
            "the program of a proof of {} rounds commits {cells} cells, counted as {counted}",
            input.rounds()
        );
        if opens(input, &global_proofs[0]) {
            three = Some((input, public_values));
        }
    }
    assert_eq!(after, chain[0], "the global proofs do not unwind the chain to its origin");
    assert!(rounds_opened.contains(&most), "the proofs open {rounds_opened:?} rounds");
    let host_units: u64 = committed
        .iter()
        .map(|(_, round, _)| {
            zkm_pcs::logup_gkr::global_lookup_units(machine.global_lookup_count(round))
        })
        .sum();
    assert_eq!(units, host_units, "the leaves count other global lookups than the host");

    let widest = inputs
        .iter()
        .find(|input| opens(input, &global_proofs[1]))
        .expect("the proof of the most rounds has a leaf");
    prove_global_leaf(&prover, widest);

    let (honest, honest_values) = three.expect("a proof of three rounds of lane 5");
    let swapped = prove(&[lane[1], lane[0], lane[2]]);
    let mut swapped_proofs = global_proofs.clone();
    swapped_proofs[0] = swapped.clone();
    let swapped_core = zkm_pcs::MachineProof {
        shard_proofs: shard_proofs.clone(),
        global_proofs: swapped_proofs.clone(),
    };
    machine
        .verify(&vk.vk, &swapped_core, &mut machine.config().challenger())
        .expect("the host verifier takes the rounds of a global proof in any order");
    assert!(
        prover.get_recursion_global_round_inputs(&vk.vk, &shard_proofs, &swapped_proofs).is_err(),
        "a global proof that opens its rounds out of the lane's order was given a leaf"
    );
    let swapped_values = run(&prover.get_recursion_global_round_input(
        &vk.vk,
        &swapped,
        honest.global_chain_heads,
        honest.global_chain_lane,
        h_star,
    ))
    .expect("a valid global proof is rejected");
    assert_eq!(swapped_values.global_chain_end, honest_values.global_chain_end);
    assert_ne!(
        swapped_values.global_chain_start, honest_values.global_chain_start,
        "rounds opened out of the lane's order still link the chain"
    );

    let mut observed = honest.clone();
    let slots = &mut observed.proofs[0].preceding_rounds;
    slots[0].commitment = slots[1].commitment;
    assert!(run(&observed).is_none(), "a slot passed under another round's commitment");

    let mut replaced = honest.clone();
    let slots = &mut replaced.proofs[0].preceding_rounds;
    slots[0] = slots[1];
    assert!(run(&replaced).is_none(), "a slot passed as another round");

    let mut exchanged = honest.clone();
    exchanged.proofs[0].preceding_rounds.swap(0, 1);
    assert!(run(&exchanged).is_none(), "two slots passed with their commitments exchanged");

    let mut last = honest.clone();
    let proof = &mut last.proofs[0];
    core::mem::swap(&mut proof.preceding_rounds[1].commitment, &mut proof.main_commitment);
    assert!(run(&last).is_none(), "the last slot passed under another round's commitment");
    Ok(())
}

/// GROTH16-ONLY CIRCUIT GATE.
///
/// [`test_e2e_circuit_fibonacci`] runs the PLONK test engine first, and that
/// needs a KZG SRS sized to the outer circuit (2^26 for this workload); on a
/// host without the headroom the process is killed there, before either
/// circuit is actually checked.  Groth16's test engine needs no SRS, so this
/// gate reaches the satisfiability check on machines the PLONK one cannot.
///
/// It is the gate for anything that changes the outer circuit's shape --- a
/// new public input, a new constraint opcode --- because it is the only cheap
/// test that both emits the constraint stream and solves it.
#[test]
#[serial]
#[ignore]
fn test_circuit_groth16_only() -> Result<()> {
    setup_logger();
    let elf = test_artifacts::FIBONACCI_ELF;
    let opts = ZKMProverOpts::default();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let (_, pk_d, program, vk) = prover.setup(elf);

    let stdin = fib_stdin(10);
    let core = prover.prove_core(&pk_d, program, &stdin, opts, ZKMContext::default())?;
    let compressed = prover.compress(&vk, core, vec![], opts)?;
    let shrunk = prover.shrink(compressed, opts)?;
    let wrapped = prover.wrap_bn254(shrunk, opts)?;

    let (constraints, witness) = build_constraints_and_witness(&wrapped.vk, &wrapped.proof);
    Groth16Bn254Prover::test(constraints, witness);
    tracing::info!("Circuit GROTH16 test succeeded");
    Ok(())
}

/// [`test_circuit_groth16_only`] over a wrap proof proved elsewhere: the
/// `(vk, wrap proof)` pair at `ZIREN_WRAP_DUMP`, as the GPU harness writes
/// it under `ZIREN_WRAP_VK_OUT`.  The circuit is built from the wrap
/// schedule this process reads, so the `ZIREN_WRAP_*` variables must be the
/// ones the proof was made with.
#[test]
#[serial]
#[ignore]
fn test_circuit_groth16_from_dump() -> Result<()> {
    setup_logger();
    let path = std::env::var("ZIREN_WRAP_DUMP").expect("set ZIREN_WRAP_DUMP");
    let bytes = std::fs::read(&path)?;
    let (_, wrapped): (ZKMVerifyingKey, ZKMReduceProof<OuterSC>) = bincode::deserialize(&bytes)?;
    let (constraints, witness) = build_constraints_and_witness(&wrapped.vk, &wrapped.proof);
    Groth16Bn254Prover::test(constraints, witness);
    tracing::info!("Circuit GROTH16 test succeeded");
    Ok(())
}

/// VALUE-INDEPENDENCE GATE: build the gnark outer circuit (R1CS
/// constraints) from wrap proof A, then SOLVE it with the witness built
/// from a DIFFERENT fresh wrap proof B.  If the outer lift BAKED proof-A's
/// q_at_z / jagged-eval / sumcheck as `builder.constant`, B's witness would
/// trip `assertIsEqual`.  Those values are WITNESS inputs, so the A-shaped
/// circuit accepts B's witness — the gnark verifier verifies ANY fresh
/// proof.
///
/// Reuses the same shrink proof for both wraps (the grind `find_any` nonce
/// re-rolls per wrap, so the two wrap proofs carry DIFFERENT q_at_z /
/// sumcheck / whir values at the SAME shape — exactly the fresh-proof
/// scenario the on-chain verifier faces).
#[test]
#[serial]
#[ignore]
fn test_outer_value_independence() -> Result<()> {
    setup_logger();
    let elf = test_artifacts::FIBONACCI_ELF;
    let opts = ZKMProverOpts::default();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let (_, pk_d, program, vk) = prover.setup(elf);

    let wrap_for = |n: u32| -> Result<crate::ZKMReduceProof<OuterSC>> {
        let mut stdin = ZKMStdin::new();
        stdin.write(&n);
        let core =
            prover.prove_core(&pk_d, program.clone(), &stdin, opts, ZKMContext::default()).unwrap();
        let compressed = prover.compress(&vk, core, vec![], opts)?;
        let shrink = prover.shrink(compressed, opts)?;
        Ok(prover.wrap_bn254(shrink, opts)?)
    };

    tracing::info!("[VI] wrap A (fib n=100): core→compress→shrink→wrap");
    let wrap_a = wrap_for(100)?;
    tracing::info!("[VI] wrap B (fib n=200): core→compress→shrink→wrap");
    let wrap_b = wrap_for(200)?;

    let a_bytes = bincode::serialize(&wrap_a.proof.jagged_shard_proof).unwrap();
    let b_bytes = bincode::serialize(&wrap_b.proof.jagged_shard_proof).unwrap();
    tracing::info!(
        "[VI] wrap A bundle {} bytes, wrap B bundle {} bytes, identical={}",
        a_bytes.len(),
        b_bytes.len(),
        a_bytes == b_bytes
    );
    assert_ne!(
        a_bytes, b_bytes,
        "[VI] wrap A and B carry IDENTICAL proof bytes — test would be vacuous \
         (need two distinct fresh proofs of the same shape)"
    );

    tracing::info!("[VI] build outer circuit (R1CS) from proof A");
    let (constraints_a, _witness_a) = build_constraints_and_witness(&wrap_a.vk, &wrap_a.proof);
    tracing::info!("[VI] built {} constraints from A", constraints_a.len());

    tracing::info!("[VI] build circuit + witness from proof B");
    let (constraints_b, witness_b) = build_constraints_and_witness(&wrap_b.vk, &wrap_b.proof);
    tracing::info!("[VI] built {} constraints from B", constraints_b.len());

    assert_eq!(
        constraints_a.len(),
        constraints_b.len(),
        "[VI] constraint counts differ between two same-shape proofs \
         ({} vs {}) — circuit is NOT value-independent (still baking?)",
        constraints_a.len(),
        constraints_b.len(),
    );

    tracing::info!("[VI] SOLVE circuit_A with witness_B (the value-independence gate)");
    PlonkBn254Prover::test(constraints_a, witness_b);
    tracing::info!("[VI] PASS — circuit_A solved by witness_B: outer wrap is VALUE-INDEPENDENT");
    Ok(())
}

/// Tests an end-to-end workflow of proving a program across the entire proof generation
/// pipeline in addition to verifying deferred proofs.
#[test]
#[serial]
#[ignore]
fn test_e2e_with_deferred_proofs() -> Result<()> {
    setup_logger();
    test_e2e_with_deferred_proofs_prover::<DefaultProverComponents>(ZKMProverOpts::default())
}

/// Perf-comparison fixture: prove_core only (Test::Core) on
/// keccak-sponge ELF.  Multi-shard sha-cluster workload — exercises
/// the jagged shard prover in `prove_shard_with_data` without invoking
/// the compose tree.
/// Use to capture per-shard whir prove perf for keccak vs fib-1k.
#[test]
#[serial]
#[ignore]
fn test_e2e_core_keccak() -> Result<()> {
    let elf = test_artifacts::KECCAK_SPONGE_ELF;
    setup_logger();
    let opts = ZKMProverOpts::default();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    test_e2e_prover::<DefaultProverComponents>(&prover, elf, ZKMStdin::default(), opts, Test::Core)
}

/// Fast Test::Core fib (prove_core + host verify) — runs the host
/// verify (verify_jagged_inner) on the fib core shape without
/// the 40-min compress.
#[test]
#[serial]
#[ignore]
fn test_e2e_core_fib() -> Result<()> {
    let elf = test_artifacts::FIBONACCI_ELF;
    setup_logger();
    let opts = ZKMProverOpts::default();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    test_e2e_prover::<DefaultProverComponents>(&prover, elf, fib_stdin(10), opts, Test::Core)
}

/// ARITY-ENUM DECISIVE (fast, single fib core prove): for a real
/// core shard, the ENUMERATED REPRESENTATIVE arity-N normalize batch
/// (uniform `vec![enum_shape; N]` at the shard's (chip_set, log_dense)
/// class — exactly what `ZKMProofShape::generate` emits) must produce
/// the SAME VK as a REAL arity-N batch of that shard (replicated N
/// times).  This proves the enumeration covers the multishard
/// first-compose-layer normalize VKs WITHOUT needing an 18-shard
/// workload.  Faithful-dummy (59aa8eb3) makes real==dummy per shard,
/// so the dummy-built representative VK == the real arity-N VK.
#[test]
#[serial]
#[ignore]
fn arity_enum_representative_reproduces_real_vk() -> Result<()> {
    use crate::shapes::ZKMProofShape;
    use zkm_pcs::shape::OrderedShape;
    setup_logger();
    let elf = test_artifacts::FIBONACCI_ELF;
    let opts = ZKMProverOpts::default();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let context = ZKMContext::default();
    let (_, pk_d, program, vk) = prover.setup(elf);
    let core_proof = prover.prove_core(&pk_d, program, &fib_stdin(10), opts, context)?;
    let machine = prover.core_prover.machine();
    let rec_cfg_owned = RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::default();
    let rec_cfg = prover.compress_shape_config.as_ref().unwrap_or(&rec_cfg_owned);

    let enum_norm: std::collections::BTreeSet<OrderedShape> =
        ZKMProofShape::generate(rec_cfg, REDUCE_BATCH_SIZE)
            .filter_map(|s| match s {
                ZKMProofShape::Recursion(b) => Some(b),
                _ => None,
            })
            .flatten()
            .collect();
    let chips_by_name: std::collections::BTreeMap<String, _> = {
        use zkm_pcs::air::MachineAir;
        machine.chips().iter().map(|c| (<_ as MachineAir<KoalaBear>>::name(c), c)).collect()
    };
    let blocks_of = |os: &OrderedShape| -> (usize, usize) {
        let log_stack = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
        let cells = |prep: bool| -> usize {
            os.inner
                .iter()
                .map(|(name, log_h)| {
                    let w = chips_by_name
                        .get(name)
                        .map(|c| {
                            if prep {
                                p3_air::BaseAir::<KoalaBear>::preprocessed_width(*c)
                            } else {
                                p3_air::BaseAir::<KoalaBear>::width(*c).max(1)
                            }
                        })
                        .unwrap_or(0);
                    w * (1usize << *log_h)
                })
                .sum()
        };
        let blocks = |total: usize| -> usize {
            zkm_pcs::jagged::committed_dense_len(total, log_stack) >> log_stack
        };
        (blocks(cells(true)), blocks(cells(false)))
    };

    let real_sp = &core_proof.proof.0[0];
    let real_os = real_sp.shape();
    let mut real_names: Vec<String> = real_os.inner.iter().map(|(n, _)| n.clone()).collect();
    real_names.sort();
    let real_ld = blocks_of(&real_os);

    let real_jagged = (*real_sp.jagged_shard_proof).clone();

    {
        let dummy_at_real = ZKMCoreWitnessValues::dummy(
            machine,
            &ZKMRecursionShape { proof_shapes: vec![real_os.clone()], is_complete: true },
        );
        let vk_dummy_at_real = prover
            .compress_prover
            .setup(&prover.recursion_program(&dummy_at_real).0)
            .1
            .hash_koalabear()
            .map(|x| x.as_canonical_u32());
        let real_witness_1 = ZKMCoreWitnessValues {
            vk: vk.vk.clone(),
            shard_proofs: vec![real_jagged.clone()],
            is_complete: true,
            is_first_shard: true,
            vk_root: prover.recursion_vk_root,
            global_chain_heads: [[KoalaBear::ZERO; DIGEST_SIZE];
                zkm_pcs::logup_gkr::GLOBAL_CHAIN_LANE_COUNT],
            global_round_lanes: vec![0],
        };
        let vk_real_1 = prover
            .compress_prover
            .setup(&prover.recursion_program(&real_witness_1).0)
            .1
            .hash_koalabear()
            .map(|x| x.as_canonical_u32());
        tracing::info!(
            "[ARITY-REPR] FAITHFUL? dummy_at_real_shape == real: {} \
             (dummy={vk_dummy_at_real:?} real={vk_real_1:?})",
            vk_dummy_at_real == vk_real_1,
        );
        assert_eq!(
            vk_dummy_at_real, vk_real_1,
            "[ARITY-REPR] the dummy built at the REAL shard's own shape does not reproduce \
             the real normalize vk — the dummy shard proof is not shape-faithful, and no \
             enumeration can close that",
        );

        use zkm_pcs::shard_level::shard_proof::EvaluationProof as EP;
        use zkm_pcs::InnerChallenge;
        let describe = |jagged: &zkm_pcs::shard_level::shard_proof::JaggedShardProof<
            KoalaBear,
            InnerChallenge,
        >|
         -> Vec<(String, String)> {
            let mut v: Vec<(String, String)> = Vec::new();
            v.push(("public_values".into(), jagged.public_values.len().to_string()));
            v.push(("opened_values.chips".into(), jagged.opened_values.chips.len().to_string()));
            v.push(("chip_heights".into(), format!("{:?}", jagged.chip_heights)));
            v.push((
                "row_counts".into(),
                format!("{:?}", jagged.row_counts.iter().map(|r| r.len()).collect::<Vec<_>>()),
            ));
            v.push(("padding_column_counts".into(), format!("{:?}", jagged.padding_column_counts)));
            v.push((
                "preprocessed_row_counts".into(),
                jagged.preprocessed_row_counts.len().to_string(),
            ));
            v.push((
                "padding_row_heights".into(),
                format!(
                    "{:?}",
                    jagged.padding_row_heights.iter().map(|r| r.len()).collect::<Vec<_>>()
                ),
            ));
            v.push((
                "opened per-chip (prep,main)".into(),
                format!(
                    "{:?}",
                    jagged
                        .opened_values
                        .chips
                        .iter()
                        .map(|c| (c.preprocessed.local.len(), c.main.local.len(), c.log_degree,))
                        .collect::<Vec<_>>()
                ),
            ));
            if let EP::Bundle(b) = &jagged.evaluation_proof {
                v.push(("packing.offsets".into(), b.packing.offsets.len().to_string()));
                v.push(("packing.column_counts".into(), b.packing.column_counts.len().to_string()));
                v.push(("packing.total_values".into(), b.packing.total_values.to_string()));
                v.push(("packing.log_dense_size".into(), b.packing.log_dense_size.to_string()));
                v.push((
                    "packing.round_counts".into(),
                    format!(
                        "{:?}",
                        b.packing.round_counts.iter().map(|r| r.len()).collect::<Vec<_>>()
                    ),
                ));
                v.push((
                    "packing.padding_heights".into(),
                    format!(
                        "{:?}",
                        b.packing.padding_heights.iter().map(|r| r.len()).collect::<Vec<_>>()
                    ),
                ));
                v.push(("y_per_chip".into(), b.y_per_chip.len().to_string()));
                v.push((
                    "y_per_chip inner".into(),
                    format!("{:?}", b.y_per_chip.iter().map(|y| y.len()).collect::<Vec<_>>()),
                ));
                v.push((
                    "batch_evaluations".into(),
                    format!(
                        "{:?}",
                        b.whir_proof.batch_evaluations.iter().map(|r| r.len()).collect::<Vec<_>>()
                    ),
                ));
                let whir = &b.whir_proof.whir_proof;
                v.push(("whir.round_commitments".into(), whir.round_commitments.len().to_string()));
                v.push((
                    "whir.round_sumcheck_polys".into(),
                    whir.round_sumcheck_polys.len().to_string(),
                ));
                v.push((
                    "whir.query_openings".into(),
                    format!(
                        "rounds={} leaves={:?} paths={:?}",
                        whir.round_query_openings.len(),
                        whir.round_query_openings
                            .iter()
                            .map(|m| m.leaves.len())
                            .collect::<Vec<_>>(),
                        whir.round_query_openings
                            .iter()
                            .map(|m| m.leaves.first().map(|l| l.proof.len()).unwrap_or(0))
                            .collect::<Vec<_>>(),
                    ),
                ));
                v.push(("reduction.rounds".into(), format!("{:?}", b.reduction.rounds.len())));
                v.push((
                    "reduction.eval_point".into(),
                    format!("{:?}", b.reduction.eval_point.len()),
                ));
                v.push(("preceding_commits".into(), b.preceding_commits.len().to_string()));
                v.push(("commit.chip_dims".into(), format!("{:?}", b.commit.chip_dims)));
                v.push((
                    "commit.log_stacking_height".into(),
                    b.commit.log_stacking_height.to_string(),
                ));
                v.push((
                    "jagged_eval.univariate_polys".into(),
                    b.jagged_eval.partial_sumcheck_proof.univariate_polys.len().to_string(),
                ));
                v.push((
                    "packing.round_counts detail".into(),
                    format!("{:?}", b.packing.round_counts),
                ));
                v.push((
                    "packing.padding_heights detail".into(),
                    format!("{:?}", b.packing.padding_heights),
                ));
            } else {
                v.push(("evaluation_proof".into(), "NOT A BUNDLE".into()));
            }
            v
        };
        let dr = describe(&dummy_at_real.shard_proofs[0]);
        let rr = describe(&real_jagged);
        for ((k, dv), (_, rv)) in dr.iter().zip(rr.iter()) {
            if dv != rv {
                tracing::info!("[DIFF] {k}:\n    dummy = {dv}\n    real  = {rv}");
            }
        }
        tracing::info!("[DIFF] fields compared = {}", dr.len());
    }

    let enum_os = enum_norm
        .iter()
        .find(|e| {
            let mut en: Vec<String> = e.inner.iter().map(|(n, _)| n.clone()).collect();
            en.sort();
            en == real_names && blocks_of(e) == real_ld
        })
        .cloned();
    let enum_os = match enum_os {
        Some(e) => e,
        None => {
            panic!(
                "[ARITY-REPR] real shard (chip_set, blocks={real_ld:?}) class NOT enumerated \
                 — enumeration gap"
            );
        }
    };
    tracing::info!(
        "[ARITY-REPR] real_blocks={real_ld:?} real_chips={} enum_blocks={:?} enum_matched=true",
        real_names.len(),
        blocks_of(&enum_os),
    );
    {
        let r: std::collections::BTreeMap<&String, &usize> =
            real_os.inner.iter().map(|(n, h)| (n, h)).collect();
        let e: std::collections::BTreeMap<&String, &usize> =
            enum_os.inner.iter().map(|(n, h)| (n, h)).collect();
        tracing::info!("[ARITY-REPR] real heights = {r:?}");
        tracing::info!("[ARITY-REPR] enum heights = {e:?}");
        let diffs: Vec<String> = r
            .iter()
            .filter_map(|(n, h)| {
                let eh = e.get(*n).copied();
                (eh != Some(*h)).then(|| format!("{n}: real={h} enum={eh:?}"))
            })
            .collect();
        tracing::warn!("[ARITY-REPR] per-chip height MISMATCHES ({}): {diffs:?}", diffs.len());
    }

    for arity in 1..=1 {
        let real_witness = ZKMCoreWitnessValues {
            vk: vk.vk.clone(),
            shard_proofs: vec![real_jagged.clone(); arity],
            is_complete: true,
            is_first_shard: true,
            vk_root: prover.recursion_vk_root,
            global_chain_heads: [[KoalaBear::ZERO; DIGEST_SIZE];
                zkm_pcs::logup_gkr::GLOBAL_CHAIN_LANE_COUNT],
            global_round_lanes: vec![0; arity],
        };
        let prog_real = prover.recursion_program(&real_witness).0;
        let vk_real = prover.compress_prover.setup(&prog_real).1.hash_koalabear();

        let enum_shape =
            ZKMRecursionShape { proof_shapes: vec![enum_os.clone(); arity], is_complete: true };
        let enum_dummy = ZKMCoreWitnessValues::dummy(machine, &enum_shape);
        let prog_enum = prover.recursion_program(&enum_dummy).0;
        let vk_enum = prover.compress_prover.setup(&prog_enum).1.hash_koalabear();

        let eq = vk_real == vk_enum;
        tracing::info!(
            "[ARITY-REPR] arity={arity}: enum_repr_reproduces_real={eq} \
             vk_real={:?} vk_enum={:?}",
            vk_real.map(|x| {
                use p3_field::PrimeField32;
                x.as_canonical_u32()
            }),
            vk_enum.map(|x| {
                use p3_field::PrimeField32;
                x.as_canonical_u32()
            }),
        );
        assert!(
            eq,
            "[ARITY-REPR] arity={arity}: the enumerated representative normalize VK does NOT \
             reproduce the real arity-{arity} normalize VK — the arity enumeration is wrong \
             for this class (the failure mode: wrong-but-different enumerated VK)."
        );
    }
    Ok(())
}

/// What does the allowed-vk Merkle tree's HEIGHT cost the recursion
/// programs?  Every compose / deferred / shrink program verifies a vk
/// membership path in-circuit, so its length is `VK_MERKLE_TREE_HEIGHT`
/// Poseidon2 compressions plus the selects around them, per child.  This
/// reports the compiled instruction count so the cost of a height change is
/// a measured number rather than an argument.  Deterministic — no wall
/// clock, so it is immune to box contention.
#[test]
#[serial]
#[ignore]
fn compose_program_size_probe() {
    use zkm_pcs::shape::OrderedShape;
    use zkm_recursion_circuit::machine::{ZKMCompressShape, ZKMCompressWithVkeyShape};
    setup_logger();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let compress_machine = prover.compress_prover.machine();
    let child: Vec<(String, usize)> = vec![
        ("BaseAlu".into(), 1 << 18),
        ("ExtAlu".into(), 1 << 18),
        ("MemoryConst".into(), 1 << 17),
        ("MemoryVar".into(), 1 << 18),
        ("Poseidon2WideDeg3".into(), 1 << 18),
        ("PublicValues".into(), 1 << 4),
        ("Select".into(), 1 << 18),
    ];
    let os = OrderedShape::from_rows(&child);
    for arity in [1usize, REDUCE_BATCH_SIZE] {
        let with_vkey = ZKMCompressWithVkeyShape {
            compress_shape: ZKMCompressShape::from(vec![os.clone(); arity]),
            merkle_tree_height: VK_MERKLE_TREE_HEIGHT,
        };
        let d =
            ZKMCompressWitnessValues::dummy::<CompressAir<KoalaBear>>(compress_machine, &with_vkey);
        let p = prover.compose_program(&d).0;
        tracing::info!(
            "[PROGSIZE] merkle_height={} arity={arity} compose_instructions={}",
            VK_MERKLE_TREE_HEIGHT,
            p.instruction_count(),
        );
    }
}

/// How many keys does the enumeration emit, and does it fit the vk merkle
/// tree's FIXED capacity?  The tree height is baked into every enumerated
/// recursion program, so an over-large map is not a tuning problem — it
/// does not fit at all.
///
/// Runs by default (~6 s): each recursion band adds exactly six shapes to
/// the enumeration, and `fix_shape` scores bands by cost rather than list
/// order, so bands are meant to be added freely — this is the only thing
/// standing between that and an enumeration too large to build.
#[test]
#[serial]
fn enumeration_size_probe() {
    use crate::shapes::ZKMProofShape;
    setup_logger();
    let rec_cfg = RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::default();
    let all: Vec<ZKMProofShape> = ZKMProofShape::generate(&rec_cfg, REDUCE_BATCH_SIZE).collect();
    let normalize = all.iter().filter(|s| matches!(s, ZKMProofShape::Recursion(_))).count();
    tracing::info!(
        "[ENUMSIZE] total={} normalize={} other={} capacity=2^{}={}",
        all.len(),
        normalize,
        all.len() - normalize,
        VK_MERKLE_TREE_HEIGHT,
        1usize << VK_MERKLE_TREE_HEIGHT,
    );
    assert!(
        all.len() <= (1usize << VK_MERKLE_TREE_HEIGHT),
        "[ENUMSIZE] the enumeration ({}) exceeds the vk merkle capacity {}",
        all.len(),
        1usize << VK_MERKLE_TREE_HEIGHT,
    );
}

/// Reports how per-chip heights affect each committed round and the normalize VK.
/// Shapes in the same class must build identical programs; changes across
/// classes are reported without assuming one combined main-round area.
#[test]
#[serial]
#[ignore]
fn normalize_vk_round_geometry_probe() {
    use crate::shapes::ZKMProofShape;
    use zkm_pcs::shape::OrderedShape;

    setup_logger();
    // This diagnostic compares freshly built keys and needs no allowlist.
    let prover = ZKMProver::<DefaultProverComponents>::new_with_vk_verification(Some(false));
    let machine = prover.core_prover.machine();
    let base: Vec<(String, usize)> = [
        "AddSub",
        "Bitwise",
        "Branch",
        "Byte",
        "CloClz",
        "Cpu",
        "DivRem",
        "Jump",
        "Lt",
        "LoadNarrow",
        "LoadWord",
        "StoreNarrow",
        "StoreWord",
        "MemoryUnaligned",
        "MemoryLocal",
        "MemoryProgram",
        "MiscInstrs",
        "MovCond",
        "Mul",
        "Program",
        "ShiftLeft",
        "ShiftRight",
        "SyscallCore",
        "SyscallInstrs",
    ]
    .into_iter()
    .map(|chip| (chip.to_string(), if chip == "Byte" { 16 } else { 18 }))
    .collect();
    let mut variants = vec![("base".to_string(), base.clone())];
    for name in ["MemoryLocal", "Mul", "Program", "MemoryProgram"] {
        let mut heights = base.clone();
        let (_, height) = heights
            .iter_mut()
            .find(|(chip, _)| chip == name)
            .expect("the representative contains the diagnostic chip");
        *height = height.saturating_sub(1).max(1);
        variants.push((format!("halve {name}"), heights));
    }

    let mut programs_by_class = BTreeMap::new();
    for (label, heights) in variants {
        let rows: Vec<_> =
            heights.iter().map(|(name, log_rows)| (name.clone(), 1usize << log_rows)).collect();
        let class = ZKMProofShape::normalize_class(machine, &rows);
        let shape = ZKMRecursionShape {
            proof_shapes: vec![OrderedShape::from_log2_heights(&heights)],
            is_complete: false,
        };
        let witness = ZKMCoreWitnessValues::dummy(machine, &shape);
        let program = prover.build_normalize_program_uncached(&witness);
        let bytes = bincode::serialize(&*program).expect("serialize normalize program");
        let vk = prover.compress_prover.setup(&program).1.hash_koalabear();
        tracing::info!(
            "{label}: prep_blocks={} global_blocks={} main_blocks={} padding_columns={:?} vk={vk:?}",
            class.1, class.2, class.3, witness.shard_proofs[0].padding_column_counts,
        );
        if let Some(previous) = programs_by_class.insert(class, bytes.clone()) {
            assert!(
                previous == bytes,
                "{label}: equal round geometry must produce the same normalize program"
            );
        }
    }
}

/// PROBE: does a RECURSION proving key carry a PREPROCESSED opening round?
///
/// `prove_shard_with_data` builds the preprocessed round from
/// `preprocessed_commit_data.packing.chip_infos` and emits a single
/// (main-only) round when that list is empty, while the enumeration's dummy
/// child derives its own two-round geometry from the machine's chip set.
/// If the two disagree the hint streams differ and so does the compose vk.
/// Setup only — no proving.
#[test]
#[serial]
#[ignore]
fn recursion_pk_preprocessed_round_probe() {
    use zkm_pcs::air::MachineAir;
    use zkm_pcs::shape::OrderedShape;
    use zkm_recursion_circuit::machine::ZKMCoreWitnessValues;
    setup_logger();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let core_machine = prover.core_prover.machine();

    for c in prover.compress_prover.machine().chips().iter() {
        tracing::info!(
            "[PREPROBE] compress chip {} preprocessed_width={}",
            <_ as MachineAir<KoalaBear>>::name(c),
            p3_air::BaseAir::<KoalaBear>::preprocessed_width(c),
        );
    }

    let cluster: Vec<&str> = vec![
        "AddSub",
        "Bitwise",
        "Branch",
        "Byte",
        "CloClz",
        "Cpu",
        "DivRem",
        "MemoryProgram",
        "Jump",
        "Lt",
        "MemoryGlobalFinalize",
        "MemoryGlobalInit",
        "LoadNarrow",
        "LoadWord",
        "StoreNarrow",
        "StoreWord",
        "MemoryUnaligned",
        "MemoryLocal",
        "MiscInstrs",
        "MovCond",
        "Mul",
        "Program",
        "ShiftLeft",
        "ShiftRight",
        "SyscallCore",
        "SyscallInstrs",
    ];
    let hs: Vec<(String, usize)> =
        cluster.iter().map(|n| ((*n).to_string(), if *n == "Byte" { 16 } else { 18 })).collect();
    let os = OrderedShape::from_log2_heights(&hs);
    let shape = ZKMRecursionShape { proof_shapes: vec![os], is_complete: true };
    let dummy = ZKMCoreWitnessValues::dummy(core_machine, &shape);
    let prog = prover.recursion_program(&dummy).0;
    let (pk, _vk) = prover.compress_prover.setup(&prog);
    let infos = &pk.preprocessed_data().packing.chip_infos;
    tracing::info!(
        "[PREPROBE] normalize pk: prep_chip_infos={} pk.traces={} chip_ordering={}",
        infos.len(),
        pk.traces.len(),
        pk.chip_ordering.len(),
    );
    for i in infos.iter() {
        tracing::info!(
            "[PREPROBE]   committed prep chip {} rows={} cols={}",
            i.name,
            i.row_count,
            i.column_count,
        );
    }
    tracing::info!(
        "[PREPROBE] CONCLUSION: the recursion prove path opens {} round(s)",
        if infos.is_empty() { 1 } else { 2 },
    );

    let packing = &pk.preprocessed_data().packing;
    let cube = 1usize << prover.compress_prover.machine().max_log_row_count();
    let real_cells = packing.total_values;
    let real_area = packing.dense_len;
    let real_pads = real_area.saturating_sub(real_cells).div_ceil(cube).max(1);
    tracing::info!(
        "[PREPROBE] REAL prep round: cells={real_cells} area={real_area} \
         gap={} cube={cube} pad_columns={real_pads}",
        real_area.saturating_sub(real_cells),
    );

    let band = prog.shape.as_ref().map(|sh| sh.clone_into_hash_map()).unwrap_or_default();
    let mut band_sorted: Vec<_> = band.iter().collect();
    band_sorted.sort();
    tracing::info!("[PREPROBE] program band (main heights) = {band_sorted:?}");
    let dummy_cells: usize = prover
        .compress_prover
        .machine()
        .chips()
        .iter()
        .map(|c| {
            let name = <_ as MachineAir<KoalaBear>>::name(c);
            let rows = band.get(&name).copied().unwrap_or(0);
            p3_air::BaseAir::<KoalaBear>::preprocessed_width(c) * rows
        })
        .sum();
    let dummy_area = zkm_pcs::jagged::committed_dense_len(
        dummy_cells,
        zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize,
    );
    let dummy_pads = dummy_area.saturating_sub(dummy_cells).div_ceil(cube).max(1);
    tracing::info!(
        "[PREPROBE] DUMMY prep round: cells={dummy_cells} area={dummy_area} \
         gap={} pad_columns={dummy_pads}",
        dummy_area.saturating_sub(dummy_cells),
    );
    tracing::info!(
        "[PREPROBE] RESULT: real_pad_columns={real_pads} dummy_pad_columns={dummy_pads} \
         match={}",
        real_pads == dummy_pads,
    );
}

/// Compose VK height-sensitivity: does the COMPOSE vk depend on the
/// child recursion proof's EXACT per-chip heights, or only the chip-SET /
/// log_dense?  `generate()`'s `compress_child_classes` emits a UNIFORM
/// child (all recursion chips at one `h`), but a REAL compose child is the
/// NON-uniform natural recursion shape (BaseAlu:18, MemoryConst:17,
/// PublicValues:4, ...).  If the compose vk is height-sensitive, the
/// uniform enum child != the real compose vk (the compose analog of the
/// normalize CPU-shard gap).  No proving — dummy compose programs only.
#[test]
#[serial]
#[ignore]
fn compose_vk_height_sensitivity() {
    use zkm_pcs::shape::OrderedShape;
    use zkm_recursion_circuit::machine::{ZKMCompressShape, ZKMCompressWithVkeyShape};
    setup_logger();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let compress_machine = prover.compress_prover.machine();
    let vk_of = |child: &[(&str, usize)], arity: usize| -> [u32; 8] {
        let os = OrderedShape::from_rows(
            &child.iter().map(|(n, h)| (n.to_string(), 1usize << *h)).collect::<Vec<_>>(),
        );
        let cshape = ZKMCompressShape::from(vec![os; arity]);
        let with_vkey = ZKMCompressWithVkeyShape {
            compress_shape: cshape,
            merkle_tree_height: VK_MERKLE_TREE_HEIGHT,
        };
        let d =
            ZKMCompressWitnessValues::dummy::<CompressAir<KoalaBear>>(compress_machine, &with_vkey);
        let p = prover.compose_program(&d).0;
        use p3_field::PrimeField32;
        prover.compress_prover.setup(&p).1.hash_koalabear().map(|x| x.as_canonical_u32())
    };
    let natural: &[(&str, usize)] = &[
        ("BaseAlu", 18),
        ("ExtAlu", 18),
        ("MemoryConst", 17),
        ("MemoryVar", 18),
        ("Poseidon2WideDeg3", 18),
        ("PublicValues", 4),
        ("Select", 18),
    ];
    let uniform18: Vec<(&str, usize)> = natural.iter().map(|(n, _)| (*n, 18usize)).collect();
    for arity in [1usize, 4] {
        let vn = vk_of(natural, arity);
        let vu = vk_of(&uniform18, arity);
        tracing::info!(
            "[CSENS] arity={arity} natural_vk={vn:?} uniform18_vk={vu:?} eq={}",
            vn == vu
        );
    }
    tracing::info!(
        "[CSENS] CONCLUSION: a UNIFORM compose child see eq= above — reproduce the natural compose vk"
    );
}

// SHA2_RUST_ELF requires stdin input (ZKMStdin::default() → "insufficient
// input data" syscall error).  Removed; fib + keccak already
// characterize the per-cycle vs per-MLE-size cost.

/// Perf-comparison fixture: prove_core only on
/// sha2-test ELF (hashes "hello world" literal — needs no stdin).
/// Third workload to triangulate per-MLE-size cost.
#[test]
#[serial]
#[ignore]
fn test_e2e_core_sha2_lit() -> Result<()> {
    let elf = test_artifacts::SHA2_ELF;
    setup_logger();
    let opts = ZKMProverOpts::default();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    test_e2e_prover::<DefaultProverComponents>(&prover, elf, ZKMStdin::default(), opts, Test::Core)
}

/// VK-map membership counts.
///
/// Logs the DETERMINISTIC, no-prove counts behind recursion VK
/// membership:
///
///   * the height-specific recursion `vk_map` size and the
///     `dummy_vk_map` size;
///   * the enumerated per-shard NORMALIZE shape count and the
///     enumerated COMPOSE (Compress) shape count per arity — the
///     height-keyed enumeration cardinality.
///
/// Asserts that `vk_map` fits the VK Merkle tree.
///
/// CHEAP (no proving): just loads the baked `vk_map.bin` and runs the
/// shape enumeration.  Run:
///   CUDA_VISIBLE_DEVICES="" cargo test --release -p zkm-prover \
///     vk_map_membership_counts -- --ignored --nocapture
#[test]
#[serial]
#[ignore = "loads vk_map.bin + enumerates shapes; run with --ignored"]
fn vk_map_membership_counts() {
    use crate::shapes::ZKMProofShape;
    setup_logger();

    let real_vk_map: BTreeMap<[KoalaBear; DIGEST_SIZE], usize> =
        bincode::deserialize(include_bytes!("../vk_map.bin")).unwrap();
    let dummy_vk_map: BTreeMap<[KoalaBear; DIGEST_SIZE], usize> =
        bincode::deserialize(include_bytes!("../dummy_vk_map.bin")).unwrap();
    tracing::info!(
        "[membership] height-specific vk_map.bin = {} entries; \
         dummy_vk_map.bin = {} entries",
        real_vk_map.len(),
        dummy_vk_map.len()
    );

    let rec_cfg = RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::default();
    let all: Vec<ZKMProofShape> = ZKMProofShape::generate(&rec_cfg, REDUCE_BATCH_SIZE).collect();

    let mut norm_shapes: std::collections::BTreeSet<OrderedShape> =
        std::collections::BTreeSet::new();
    let mut compose_by_arity: BTreeMap<usize, usize> = BTreeMap::new();
    let mut deferred = 0usize;
    let mut shrink = 0usize;
    for s in &all {
        match s {
            ZKMProofShape::Recursion(b) => {
                for os in b {
                    norm_shapes.insert(os.clone());
                }
            }
            ZKMProofShape::Compress(b) | ZKMProofShape::CompressRoot(b) => {
                *compose_by_arity.entry(b.len()).or_default() += 1;
            }
            ZKMProofShape::Deferred(_) => deferred += 1,
            ZKMProofShape::Shrink(_) => shrink += 1,
            ZKMProofShape::Normalize(_) | ZKMProofShape::GlobalRound(_) => {}
        }
    }
    tracing::info!(
        "[membership] enum total shapes = {} | distinct NORMALIZE per-shard shapes = {} \
         | COMPOSE by arity = {:?} | Deferred = {} | Shrink = {}",
        all.len(),
        norm_shapes.len(),
        compose_by_arity,
        deferred,
        shrink
    );
    assert!(
        real_vk_map.len() <= (1 << VK_MERKLE_TREE_HEIGHT),
        "vk_map ({}) exceeds 2^{} capacity",
        real_vk_map.len(),
        VK_MERKLE_TREE_HEIGHT
    );
}
