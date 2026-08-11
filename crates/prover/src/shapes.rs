use eyre::Result;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::File,
    hash::Hash,
    panic::{catch_unwind, AssertUnwindSafe},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};
use thiserror::Error;

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use serde::{Deserialize, Serialize};
use zkm_core_machine::shape::CoreShapeConfig;
use zkm_recursion_circuit::machine::{
    ZKMCompressBasefoldWitnessValues, ZKMCompressWithVkeyShape,
    ZKMCoreBasefoldWitnessValues, ZKMDeferredBasefoldWitnessValues, ZKMDeferredShape, ZKMRecursionShape,
    ZKMWrapBasefoldWitnessValues,
};
use zkm_recursion_core::{
    shape::{RecursionShape, RecursionShapeConfig},
    RecursionProgram,
};
use zkm_pcs::{shape::OrderedShape, MachineProver, DIGEST_SIZE};

use crate::{components::ZKMProverComponents, CompressAir, HashableKey, ZKMProver};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ZKMProofShape {
    /// A single-shard normalize/recursion shape.  Carries exactly ONE
    /// per-shard shape: the production normalize is arity-1 (`compress` →
    /// `get_first_layer_inputs` with first_layer_batch_size=1 →
    /// `get_recursion_core_inputs_basefold` chunks(1) → one core shard per
    /// `ZKMCoreBasefoldWitnessValues`; SP1 core.rs:118 asserts
    /// shard_proofs.len()==1).  Arity≥2 Recursion shapes would be a PHANTOM
    /// VK class no real proof produces; cross-shard aggregation lives in
    /// COMPRESS.  The `Vec` is retained for wire-format/serde stability but
    /// the enumerator emits only `vec![one]` and the dummy/in-circuit
    /// verifier asserts len==1.
    Recursion(Vec<OrderedShape>),
    Compress(Vec<OrderedShape>),
    Deferred(OrderedShape),
    Shrink(OrderedShape),
}

#[derive(Debug, Clone, Hash)]
pub enum ZKMCompressProgramShape {
    Recursion(ZKMRecursionShape),
    Compress(ZKMCompressWithVkeyShape),
    Deferred(ZKMDeferredShape),
    Shrink(ZKMCompressWithVkeyShape),
}

impl ZKMCompressProgramShape {
}

#[derive(Debug, Error)]
pub enum VkBuildError {
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Bincode(#[from] bincode::Error),
}

pub fn check_shapes<C: ZKMProverComponents>(
    reduce_batch_size: usize,
    no_precompiles: bool,
    num_compiler_workers: usize,
    prover: &ZKMProver<C>,
) -> bool {
    let (shape_tx, shape_rx) =
        std::sync::mpsc::sync_channel::<ZKMCompressProgramShape>(num_compiler_workers);
    let (panic_tx, panic_rx) = std::sync::mpsc::channel();
    let core_shape_config = &CoreShapeConfig::default();
    let recursion_shape_config =
        prover.compress_shape_config.as_ref().expect("recursion shape config not found");

    let all_maximal_shapes = ZKMProofShape::generate_maximal_shapes(
        core_shape_config,
        recursion_shape_config,
        reduce_batch_size,
        no_precompiles,
    )
    .collect::<BTreeSet<ZKMProofShape>>();
    let num_shapes = all_maximal_shapes.len();
    tracing::info!("number of shapes: {}", num_shapes);

    // The Merkle tree height (fixed ceiling — see crate::VK_MERKLE_TREE_HEIGHT).
    let height = crate::VK_MERKLE_TREE_HEIGHT;
    assert!(num_shapes <= (1 << height));

    let shape_rx = Mutex::new(shape_rx);
    let compress_ok = std::thread::scope(|s| {
        // Initialize compiler workers.
        for _ in 0..num_compiler_workers {
            let shape_rx = &shape_rx;
            let prover = &prover;
            let panic_tx = panic_tx.clone();
            s.spawn(move || {
                while let Ok(shape) = shape_rx.lock().unwrap().recv() {
                    tracing::info!("shape is {:?}", shape);
                    let program = catch_unwind(AssertUnwindSafe(|| {
                        // Try to build the recursion program from the given shape.
                        prover.program_from_shape(shape.clone(), None)
                    }));
                    match program {
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(
                                "Program generation failed for shape {:?}, with error: {:?}",
                                shape,
                                e
                            );
                            panic_tx.send(true).unwrap();
                        }
                    }
                }
            });
        }

        // Generate shapes and send them to the compiler workers.
        all_maximal_shapes.into_iter().for_each(|program_shape| {
            shape_tx
                .send(ZKMCompressProgramShape::from_proof_shape(program_shape, height))
                .unwrap();
        });

        drop(shape_tx);
        drop(panic_tx);

        // If the panic receiver has no panics, then the shape is correct.
        panic_rx.iter().next().is_none()
    });

    compress_ok
}

pub fn build_vk_map<C: ZKMProverComponents>(
    reduce_batch_size: usize,
    dummy: bool,
    num_compiler_workers: usize,
    num_setup_workers: usize,
    indices: Option<Vec<usize>>,
) -> (BTreeSet<[KoalaBear; DIGEST_SIZE]>, Vec<usize>, usize) {
    let mut prover = ZKMProver::<C>::new();
    prover.vk_verification = !dummy;
    let core_shape_config = &CoreShapeConfig::default();
    let recursion_shape_config =
        prover.compress_shape_config.as_ref().expect("recursion shape config not found");

    tracing::info!("building compress vk map");
    let (vk_set, panic_indices, height) = if dummy {
        tracing::warn!("Making a dummy vk map");
        let dummy_set = ZKMProofShape::dummy_vk_map(
            core_shape_config,
            recursion_shape_config,
            reduce_batch_size,
        )
        .into_keys()
        .collect::<BTreeSet<_>>();
        let height = crate::VK_MERKLE_TREE_HEIGHT;
        assert!(dummy_set.len() <= (1 << height));
        (dummy_set, vec![], height)
    } else {
        let start_time = Instant::now();
        let (vk_tx, vk_rx) = std::sync::mpsc::channel();
        let (shape_tx, shape_rx) =
            std::sync::mpsc::sync_channel::<(usize, ZKMCompressProgramShape)>(num_compiler_workers);
        let (program_tx, program_rx) = std::sync::mpsc::sync_channel(num_setup_workers);
        let (panic_tx, panic_rx) = std::sync::mpsc::channel();

        let compile_total_ns = AtomicU64::new(0);
        let compile_count = AtomicUsize::new(0);
        let setup_total_ns = AtomicU64::new(0);
        let setup_count = AtomicUsize::new(0);

        let indices_set = indices.map(|indices| indices.into_iter().collect::<HashSet<_>>());
        let all_shapes =
            ZKMProofShape::generate(core_shape_config, recursion_shape_config, reduce_batch_size)
                .collect::<BTreeSet<_>>();
        let num_shapes = all_shapes.len();
        tracing::info!("number of shapes: {}", num_shapes);

        // Fixed-height ceiling (see crate::VK_MERKLE_TREE_HEIGHT): the
        // enumeration and the runtime tree must agree on the height
        // regardless of how many shapes/vks survive dedup.
        let height = crate::VK_MERKLE_TREE_HEIGHT;
        assert!(num_shapes <= (1 << height), "shape count {num_shapes} exceeds 2^{height}");
        let chunk_size = indices_set.as_ref().map(|indices| indices.len()).unwrap_or(num_shapes);

        let shape_rx = Mutex::new(shape_rx);
        let program_rx = Mutex::new(program_rx);
        std::thread::scope(|s| {
            // Initialize compiler workers.
            for _ in 0..num_compiler_workers {
                let program_tx = program_tx.clone();
                let shape_rx = &shape_rx;
                let prover = &prover;
                let panic_tx = panic_tx.clone();
                let compile_total_ns = &compile_total_ns;
                let compile_count = &compile_count;
                s.spawn(move || {
                    while let Ok((i, shape)) = shape_rx.lock().unwrap().recv() {
                        tracing::info!("shape {i} is {shape:?}");
                        let compile_start = Instant::now();
                        let program = catch_unwind(AssertUnwindSafe(|| {
                            prover.program_from_shape(shape.clone(), None)
                        }));
                        let compile_ns = compile_start.elapsed().as_nanos() as u64;
                        compile_total_ns.fetch_add(compile_ns, Ordering::Relaxed);
                        compile_count.fetch_add(1, Ordering::Relaxed);
                        let is_shrink = matches!(shape, ZKMCompressProgramShape::Shrink(_));
                        match program {
                            Ok(program) => program_tx.send((i, program, is_shrink)).unwrap(),
                            Err(e) => {
                                tracing::warn!(
                                    "Program generation failed for shape {} {:?}, with error: {:?}",
                                    i,
                                    shape,
                                    e
                                );
                                panic_tx.send(i).unwrap();
                            }
                        }
                    }
                });
            }

            // Initialize setup workers.
            for _ in 0..num_setup_workers {
                let vk_tx = vk_tx.clone();
                let program_rx = &program_rx;
                let prover = &prover;
                let setup_total_ns = &setup_total_ns;
                let setup_count = &setup_count;
                s.spawn(move || {
                    while let Ok((i, program, is_shrink)) = program_rx.lock().unwrap().recv() {
                        let setup_start = Instant::now();
                        let vk = tracing::debug_span!("setup for program {}", i).in_scope(|| {
                            if is_shrink {
                                prover.shrink_prover.setup(&program).1
                            } else {
                                prover.compress_prover.setup(&program).1
                            }
                        });
                        let setup_ns = setup_start.elapsed().as_nanos() as u64;
                        setup_total_ns.fetch_add(setup_ns, Ordering::Relaxed);
                        let done = setup_count.fetch_add(1, Ordering::Relaxed) + 1;

                        let vk_digest = vk.hash_koalabear();
                        tracing::info!(
                            "program {} = {:?}, {}% done",
                            i,
                            vk_digest,
                            done * 100 / chunk_size
                        );
                        vk_tx.send(vk_digest).unwrap();
                    }
                });
            }

            // Generate shapes and send them to the compiler workers.
            let subset_shapes = all_shapes
                .into_iter()
                .enumerate()
                .filter(|(i, _)| indices_set.as_ref().map(|set| set.contains(i)).unwrap_or(true))
                .collect::<Vec<_>>();

            subset_shapes
                .clone()
                .into_iter()
                .map(|(i, shape)| (i, ZKMCompressProgramShape::from_proof_shape(shape, height)))
                .for_each(|(i, program_shape)| {
                    shape_tx.send((i, program_shape)).unwrap();
                });

            drop(shape_tx);
            drop(program_tx);
            drop(vk_tx);
            drop(panic_tx);

            let vk_set = vk_rx.iter().collect::<BTreeSet<_>>();

            let panic_indices = panic_rx.iter().collect::<Vec<_>>();

            for (i, shape) in subset_shapes {
                if panic_indices.contains(&i) {
                    tracing::info!("panic shape {}: {:?}", i, shape);
                }
            }

            let total_ms = start_time.elapsed().as_millis();
            let compile_cnt = compile_count.load(Ordering::Relaxed).max(1);
            let setup_cnt = setup_count.load(Ordering::Relaxed).max(1);
            let compile_ms = compile_total_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
            let setup_ms = setup_total_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
            tracing::info!(
                "vk_map stats: total={}ms, compile: count={}, avg={:.2}ms, total={:.2}ms; setup: count={}, avg={:.2}ms, total={:.2}ms",
                total_ms,
                compile_cnt,
                compile_ms / compile_cnt as f64,
                compile_ms,
                setup_cnt,
                setup_ms / setup_cnt as f64,
                setup_ms
            );

            (vk_set, panic_indices, height)
        })
    };
    tracing::info!("compress vks generated, number of keys: {}", vk_set.len());
    (vk_set, panic_indices, height)
}

pub fn build_vk_map_to_file<C: ZKMProverComponents>(
    build_dir: PathBuf,
    reduce_batch_size: usize,
    dummy: bool,
    num_compiler_workers: usize,
    num_setup_workers: usize,
    range_start: Option<usize>,
    range_end: Option<usize>,
    indices: Option<Vec<usize>>,
) -> Result<(), VkBuildError> {
    std::fs::create_dir_all(&build_dir)?;

    tracing::info!("Building vk set");

    // `--indices` (sparse, arbitrary shape set) supersedes `--start/--end`
    // (contiguous range) when provided — mirrors ziren-gpu's build_compress_vks.
    let selected = indices
        .or_else(|| range_start.and_then(|start| range_end.map(|end| (start..end).collect())));

    let (vk_set, _, _) = build_vk_map::<C>(
        reduce_batch_size,
        dummy,
        num_compiler_workers,
        num_setup_workers,
        selected,
    );

    let vk_map = vk_set.into_iter().enumerate().map(|(i, vk)| (vk, i)).collect::<BTreeMap<_, _>>();

    tracing::info!("Save the vk set to file");
    let mut file = if dummy {
        File::create(build_dir.join("dummy_vk_map.bin"))?
    } else {
        File::create(build_dir.join("vk_map.bin"))?
    };
    Ok(bincode::serialize_into(&mut file, &vk_map)?)
}

impl ZKMProofShape {
    /// Generate all Recursion/Compose/Deferred/Shrink shapes that
    /// need VK setup.
    ///
    /// Recursion shapes come from the size-class quantized
    /// `zkm_pcs::stacked_shapes::create_all_input_shapes` — ≤ 5,000
    /// `CoreProofShape`s that, after `to_ordered_shape`'s
    /// uniform-area projection + dedup, collapse to a much smaller
    /// per-chip `OrderedShape` set (~13-30 unique).  This
    /// replaces the ~1.25M-shape per-chip cartesian
    /// (`CoreShapeConfig::all_shapes`); stacked_shapes is the sole
    /// Recursion-shape source.
    ///
    /// The `core_shape_config` argument is retained for API
    /// stability but is not consulted.
    pub fn generate<'a>(
        _core_shape_config: &'a CoreShapeConfig<KoalaBear>,
        recursion_shape_config: &'a RecursionShapeConfig<KoalaBear, CompressAir<KoalaBear>>,
        reduce_batch_size: usize,
    ) -> impl Iterator<Item = Self> + 'a {
        use zkm_core_machine::mips::MipsAir;
        use zkm_pcs::stacked_shapes::{build_mips_machine_shape, types::consts};
        use zkm_pcs::air::MachineAir;
        use crate::CoreSC;

        // Real chips from the live MIPS machine — needed for two
        // post-processing steps on each `to_ordered_shape()` output:
        //
        //   1. **Name filter**: drop chip names from
        //      `stacked_shapes/enumerate.rs` that don't match a real
        //      `MachineAir::name()` (the enumerate list has
        //      `Bls12381Add` etc., the machine has `Bls12381AddAssign`).
        //      Without this, `dummy_basefold_vk_and_shard_proof` panics
        //      in `zip_eq` when `shard_chips_ordered` returns fewer
        //      chips than the shape names.
        //
        //   2. **Byte-lookup overflow cap**: `to_ordered_shape` gives
        //      every chip a uniform `log_height` (e.g. 22).  But the
        //      recursion VK setup asserts
        //      `Σ chip.num_sent_byte_lookups() · 2^log_degree ≤ |F|` —
        //      with ~22 chips at uniform 2^22 the sum overflows
        //      KoalaBear's order.  Per-chip we cap log_height to
        //      `floor(log2(|F| / total_byte_lookups_per_row))` for the
        //      shape's chip set, so the assertion always holds.
        let core_machine = MipsAir::machine(CoreSC::default());
        let chips_by_name: BTreeMap<String, &_> =
            core_machine.chips().iter().map(|c| (c.name(), c)).collect();

        // KoalaBear order ≈ 2^31 - 2^24 + 1.  Use 2^30 as a safe upper
        // bound so we have headroom against rounding/per-chip variance.
        const SAFE_BYTE_LOOKUP_BUDGET: u64 = 1u64 << 30;

        let _ = SAFE_BYTE_LOOKUP_BUDGET; // retained for reference
        let machine_shape = build_mips_machine_shape();

        // Area enumeration (for VERIFY_VK=true): the normalize program is
        // (chip_set, log_dense)-determined, so the recursion vk_map must cover
        // each cluster's chip set at the log_dense (total-trace-area) bands real
        // proofs hit.  The prior `create_all_input_shapes -> to_ordered_shape
        // (uniform) + byte-lookup cap` collapsed every cluster to ONE tiny
        // log_dense (~13), missing real proofs (e.g. fib needs log_dense=27).
        //
        // Construction (validated in `tests::vkroot_site5_construct`): per
        // cluster, sweep a uniform height `h` on the byte-lookup-FREE chips
        // (`num_sent_byte_lookups == 0`, each <= 2^CORE_MAX_LOG_ROW_COUNT so no
        // single chip overflows the max-height); pin byte-lookup chips minimal
        // (h=1) so the VK-setup `Σ byte_lookups·2^h ≤ |F|` always holds; pin
        // Byte at its 2^16 lookup-table height.  Spreading area across the
        // free fillers makes total_values span log_dense ~20..30 as `h` sweeps.
        // Since the program is (chip_set, log_dense)-determined, any distribution
        // hitting a target log_dense yields the same vk — so these synthetic
        // shapes produce exactly the real proofs' normalize vks.  We over-emit;
        // `build_compress_vks` catch_unwinds the few overflow shapes
        // (log_dense>30) and the vk_set dedups equal-log_dense shapes.
        // Cheap log_dense (= jagged `JaggedPacking::log_dense_size`) for an
        // OrderedShape WITHOUT building a full dummy bundle.  The jagged
        // packing's total_values = Σ_chips width·2^log_h, the commitment rounds
        // that out to whole stacking blocks, and the hypercube is the enclosing
        // power of two — see `zkm_pcs::jagged::committed_dense_len`.
        // BaseAir::width(chip) gives the dense width the dummy bundle uses.
        let chip_width = |name: &str| -> usize {
            chips_by_name
                .get(name)
                .map(|c| p3_air::BaseAir::<KoalaBear>::width(*c).max(1))
                .unwrap_or(1)
        };
        let log_dense_of = |os: &OrderedShape| -> usize {
            let total: usize = os
                .inner
                .iter()
                .map(|(name, log_h)| chip_width(name) * (1usize << *log_h))
                .sum();
            // The commitment covers whole stacking blocks, and the sumcheck
            // hypercube is the power of two that encloses them — the same two
            // steps `JaggedPacking::log_dense_size` takes.
            let dense = zkm_pcs::jagged::committed_dense_len(
                total,
                zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize,
            );
            if dense == 0 {
                0
            } else {
                dense.next_power_of_two().trailing_zeros() as usize
            }
        };

        // Per-shard normalize shapes — FAITHFUL representatives.
        //
        // The normalize program's VK depends on the child core proof's exact
        // PER-CHIP heights (the jagged bundle's per-chip `(width, log_height)`
        // + the Program/Byte preprocessed-domain `log_size` that feed
        // `vk.hash`), NOT merely the total `log_dense`.  Under FIX_CORE_SHAPES
        // =false a real core shard's jagged commit is padded to EXACTLY
        // `CoreShapeConfig::find_canonical_cluster_shape(record)` — one
        // cluster's per-chip band-cap shape (present chips at the cluster cap,
        // canonicalize's missing chips at log-1, the fitting Program band).
        //
        // A plain uniform-height-by-`log_dense` sweep is NOT faithful: at
        // a matched `(chip_set, log_dense)` its per-chip heights differ from
        // the canonical-cluster shape, so its dummy VK differs from the real
        // VK (pinned by `tests::test_vk_equality_normalize_fib` EQUAL=false on
        // a uniform/raw dummy, and `tests::multishard_normalize_arity_faithful`
        // dummy_faithful=true ONLY at the canonical lift, enum_repr_eq=false at
        // the uniform representative).
        //
        // FAITHFUL construction (coverage is partial — see
        // CAVEAT): generate candidate RAW height profiles via the cheap
        // per-cluster uniform-height SWEEP, then LIFT each through
        // `find_canonical_cluster_shape_from_ordered` — the min-area
        // canonical-cluster shape a real FIX-off core commit pads to (the SAME
        // construction `multishard_normalize_arity_faithful`'s `lift_to_band_cap`
        // proved `dummy_faithful=true` — i.e. the dummy built at the canonical
        // lift reproduces the real normalize VK).  Dedup the lifted shapes →
        // a SMALL canonical set (13 here), cheap: ONE min-area search per swept
        // profile (a few hundred), not the O(clusters²) `enumerate_canonical_
        // cluster_shapes` (~28.5K searches, > 3 min, over-emits ~70K).
        //
        // ⚠️ CAVEAT: the UNIFORM-height sweep only spans
        // raw profiles where every filler chip shares one height, so the lifted
        // canonical shapes have uniform-ish caps.  A real shard's per-chip event
        // counts are NON-uniform (e.g. fib shard1 real canonical = Bitwise:12
        // DivRem:10 MiscInstrs:1 Mul:10 …, vs this sweep's nearest = Bitwise:11
        // DivRem:9 MiscInstrs:10 Mul:9 …), which lift to a DIFFERENT canonical
        // shape — so the swept set MISSES some real canonical shapes and the
        // captured real fib-1k normalize VKs are NOT yet members.  The lift is
        // faithful; the raw-profile SOURCE is too coarse.  The fix is a fast,
        // correctly-COLLAPSED canonical enumeration (reproduce the min-area
        // collapse over the real reachable per-chip profiles) — neither this
        // sweep (misses) nor `enumerate_canonical_cluster_shapes_fast`
        // (over-emits, no collapse) is the final answer.
        // Enumerate the per-shard normalize shape at EVERY integer log_dense
        // L in [L_min, L_max] per cluster, DIRECTLY.
        //
        // Because the recursion VK = f(cluster, arity, log_dense) is
        // height-INDEPENDENT given log_dense, the right key is L itself, not a
        // particular height profile.  A uniform-height SWEEP + LIFT
        // (find_canonical_cluster_shape_from_ordered) only dedups a SPARSE set
        // of band-quantized L values, so real NON-uniform FIX-off proofs whose
        // NATURAL log_dense falls between the swept L's are MISSING.  Emitting
        // ONE canonical shape per integer L means any real proof landing at
        // log_dense L hits the map regardless of how its heights are
        // distributed.
        //
        // Per-L construction (value-independent; the VK is height-independent
        // given L so the exact distribution is free): Byte at its 2^16
        // lookup-table height; Program canonical-minimal; every other
        // byte-lookup-EMITTING chip pinned minimal (so the VK-setup
        // `Σ byte_lookups·2^h ≤ |F|` always holds); the remaining area is
        // GREEDILY packed into the byte-lookup-FREE filler chips (each ≤ 2^cube)
        // until total_values reaches ~2^L.  `log_dense_of` (= jagged
        // `packing.log_dense_size`) then confirms the produced shape lands at L;
        // we dedup by the produced OrderedShape so identical chip-NAME-sets
        // (cluster duplicates) collapse, and cap L < 30 (the AreaOutOfBounds
        // guard) — `build_compress_vks` catch_unwinds any overflow.
        let cube = consts::CORE_MAX_LOG_ROW_COUNT;
        // Build the canonical shape for `cluster` at a target log_dense `target`.
        // Returns None when `target` is below the fixed-overhead floor or above
        // the all-chips-at-cube ceiling for this cluster.
        let shape_at_log_dense =
            |names: &[String], fillers: &std::collections::HashSet<&String>, target: usize| -> Option<OrderedShape> {
                // Fixed overhead: Byte (2^16), Program (minimal), other
                // byte-lookup chips (minimal).  The fillers absorb the rest.
                let mut heights: Vec<(String, usize)> = names
                    .iter()
                    .map(|n| {
                        let h = if n == "Byte" {
                            16
                        } else {
                            1
                        };
                        (n.clone(), h)
                    })
                    .collect();
                let area_of = |hs: &[(String, usize)]| -> u128 {
                    hs.iter().map(|(n, h)| (chip_width(n) as u128) * (1u128 << *h)).sum()
                };
                // Greedily raise filler heights to approach 2^target without
                // overshooting (so log_dense lands EXACTLY at `target`).
                let cap_area: u128 = 1u128 << target;
                // Iterate height levels high→low; for each filler, set the
                // largest height whose marginal area still fits under cap_area.
                let mut filler_idx: Vec<usize> = heights
                    .iter()
                    .enumerate()
                    .filter(|(_, (n, _))| fillers.contains(n))
                    .map(|(i, _)| i)
                    .collect();
                // Stable order so the produced shape is deterministic.
                filler_idx.sort_by(|&a, &b| heights[a].0.cmp(&heights[b].0));
                for &i in &filler_idx {
                    // Largest h ≤ cube with this chip's marginal area still
                    // fitting under cap_area.
                    let mut best = 1usize;
                    for h in 1..=cube {
                        let mut trial = heights.clone();
                        trial[i].1 = h;
                        if area_of(&trial) <= cap_area {
                            best = h;
                        } else {
                            break;
                        }
                    }
                    heights[i].1 = best;
                }
                let os = OrderedShape::from_log2_heights(&heights);
                if log_dense_of(&os) == target {
                    Some(os)
                } else {
                    None
                }
            };
        // FULL reachable per-cluster log_dense range — covers the enumeration
        // completeness requirement WITHOUT core-area padding.
        //
        // A cluster's MINIMAL feasible L (all fillers at 1, Byte at its fixed
        // 2^16 lookup-table height) is its natural floor; every real core shard
        // carries the Byte table, so no provable shard lands below L_min = 20.
        // The UPPER bound is the AreaOutOfBounds guard (shard_level/verifier.rs:
        // ~365): a proof is rejected unless `0 < total_values < 2^30`, so the
        // largest provable shard has `log_dense = ceil(log2(total_values)) <= 30`.
        // We therefore emit EVERY integer L in `[L_min, L_HARD_CAP]` the greedy
        // construction can hit, filtered to `total_values < 2^30` (the provable
        // set).  A narrower window would MISS real shards whose natural
        // log_dense is 29/30 ("Invalid verification key" / "vk not allowed").
        // The complete grid is small: 268 normalize (+ 6
        // compress/deferred/shrink) = 274 keys, well under the
        // VK_MERKLE_TREE_HEIGHT=11 (2048) ceiling — measured by
        // scripts/pathb_grid.rs; regen-only (vk_root witnessed, no re-ceremony).
        // L_WINDOW is kept generous so the AreaOutOfBounds cap binds for every
        // cluster (l_min + L_WINDOW >= L_HARD_CAP always).
        const L_WINDOW: usize = 64;
        const L_HARD_CAP: usize = 30;
        // AreaOutOfBounds: a real proof's total trace-cell count must be
        // strictly below 2^30 to verify (host hash-bind guard).  Skip any
        // greedy shape that would land at/above it so the map contains only
        // provable normalize VKs.
        const MAX_TOTAL_VALUES: u128 = 1u128 << 30;
        let total_values_of = |os: &OrderedShape| -> u128 {
            os.inner
                .iter()
                .map(|(name, log_h)| (chip_width(name) as u128) * (1u128 << *log_h))
                .sum()
        };
        let small_shapes: Vec<OrderedShape> = {
            let mut by_shape: BTreeMap<Vec<(String, usize)>, OrderedShape> = BTreeMap::new();
            for cluster in &machine_shape.chip_clusters {
                let names: Vec<String> = cluster
                    .iter()
                    .filter(|n| chips_by_name.contains_key(*n))
                    .cloned()
                    .collect();
                if names.is_empty() {
                    continue;
                }
                let fillers: std::collections::HashSet<&String> = names
                    .iter()
                    .filter(|n| {
                        n.as_str() != "Byte"
                            && chips_by_name[n.as_str()].num_sent_byte_lookups() == 0
                    })
                    .collect();
                // Find this cluster's L_min (first feasible target), then sweep
                // the realistic window above it.
                let mut l_min = None;
                for target in 1..=L_HARD_CAP {
                    if shape_at_log_dense(&names, &fillers, target).is_some() {
                        l_min = Some(target);
                        break;
                    }
                }
                let Some(l_min) = l_min else { continue };
                let l_max = (l_min + L_WINDOW).min(L_HARD_CAP);
                for target in l_min..=l_max {
                    if let Some(os) = shape_at_log_dense(&names, &fillers, target) {
                        // Keep only provable shapes (AreaOutOfBounds).
                        if total_values_of(&os) >= MAX_TOTAL_VALUES {
                            continue;
                        }
                        let mut inner = os.inner.clone();
                        inner.sort();
                        by_shape.entry(inner.clone()).or_insert(OrderedShape { inner });
                    }
                }
            }
            by_shape.into_values().collect()
        };
        let _ = &log_dense_of;

        // SINGLE-SHARD NORMALIZE: emit ONLY arity-1 normalize shapes.
        // The production normalize is single-shard (`compress` →
        // `get_first_layer_inputs` with first_layer_batch_size=1 →
        // `get_recursion_core_inputs_basefold` chunks(1) → one core shard per
        // `ZKMCoreBasefoldWitnessValues`; SP1 core.rs:118 asserts
        // shard_proofs.len()==1).  Arity≥2 Recursion shapes are a PHANTOM
        // VK class that NO real proof produces.  Cross-shard aggregation lives
        // in COMPRESS (arity-4 + arity-1 tail), which has the full SP1-parity
        // PV chain.  Emitting just arity-1 makes the enumerated normalize VK
        // set match the runtime exactly (every real single-shard normalize
        // lands in-map) and shrinks the map (4× fewer Recursion shapes).
        let arity_recursion_shapes: Vec<Self> = small_shapes
            .iter()
            .map(|os| Self::Recursion(vec![os.clone()]))
            .collect();

        // ───────────────────────────────────────────────────────────────
        // Compress / Deferred / Shrink key on
        // f(recursion-chip-set, arity, CHILD NATURAL log_dense L).
        //
        // A compose/deferred/shrink program verifies a BATCH of CHILD proofs,
        // each itself a RECURSION (normalize/compose) proof over the fixed
        // 7-chip recursion machine (uniform chip-set).  The compose VK depends
        // on each child's jagged-bundle geometry, which is fully determined by
        // the child's NATURAL log_dense `n` (= log2(np2(Σ width·2^h))):
        //
        //   log_dense (L) = max(n, RECURSION_LOG_TRACE_AREA)   [the AREA PIN]
        //   log_stacking  = pick_log_stacking_height() = DEFAULT_LOG_STACKING_
        //                   HEIGHT — a CONSTANT, never area-dependent
        //   num_stripes   = 2^(L - log_stacking)   -> batch_evaluations width
        //   reduction     = L rounds over an L-long eval_point
        //   jagged_n      = 2*(L + 1)              -> jagged-eval sub-sumcheck
        //   BaseFold      = log_stacking rounds / query paths
        //
        // ⚠️ THE AREA PIN IS A **FLOOR, NOT A CLAMP** — `precompute_jagged_
        // basefold_commit_generic` raises `packing.log_dense_size` to
        // `max(natural, RECURSION_LOG_TRACE_AREA)`.  A child whose natural area
        // ALREADY exceeds 2^27 keeps its own larger L.  The enumeration used to
        // emit a SINGLE representative at natural L ≤ pin, on the (wrong)
        // premise that the pin fixed every child at L = 27.  That covers only
        // the compose layer whose children are NORMALIZE proofs (measured
        // natural L = 26 for a real fib normalize, so the pin binds); the
        // DEEPER layers, whose children are COMPOSE proofs, are several times
        // larger and land at natural L > 27 — a VK class no shape in the map
        // could ever match, so `VERIFY_VK=true` panicked "vk not allowed" the
        // moment the reduce tree grew past one compose layer.
        //
        // We therefore emit ONE representative per reachable child natural L:
        //   * L = pin covers every child at or below the floor (all of which
        //     share L = 27 / log_stacking = 21 / num_stripes = 64).
        //   * L in (pin, L_MAX] covers the over-floor children, where
        //     L_MAX is the largest natural area the recursion machine can
        //     reach with every chip at the `CORE_MAX_LOG_ROW_COUNT` cube.
        // Per class we emit Compress at every arity plus one Deferred and one
        // Shrink.  Since the geometry is a function of L alone, ANY height
        // profile landing at a given L yields the same program — so a single
        // greedy representative per L is exact, not approximate.
        // The children a compose/deferred/shrink program can be built over are
        // EXACTLY the recursion bands, because every recursion program is
        // snapped onto one of them before it is proven
        // (`ZKMProver::fix_recursion_shape`).
        //
        // This used to be a synthetic sweep that emitted ONE representative per
        // log-dense class, on the premise that a compose vk is a function of the
        // chip set and arity alone.  MEASURED (`compose_vk_height_dependence`):
        // it is not — seven bands give seven DISTINCT compose vks at arity 1 and
        // again at arity 4.  So a representative whose per-chip heights differ
        // from a real child's produces a different key, which is why a freshly
        // regenerated allowlist still rejected every produced compress vk.
        let compress_child_classes: Vec<OrderedShape> = {
            let mut classes: Vec<OrderedShape> = recursion_shape_config
                .get_all_shape_combinations(1)
                .map(|mut v| v.pop().expect("one shape per combination"))
                .collect();
            for os in classes.iter_mut() {
                os.inner.sort();
            }
            classes
        };

        let arity_compress_shapes: Vec<Self> = {
            let mut out =
                Vec::with_capacity(compress_child_classes.len() * reduce_batch_size);
            for arity in 1..=reduce_batch_size {
                for os in &compress_child_classes {
                    out.push(Self::Compress(vec![os.clone(); arity]));
                }
            }
            out
        };
        let deferred_shapes: Vec<Self> = compress_child_classes
            .iter()
            .map(|os| Self::Deferred(os.clone()))
            .collect();
        let shrink_shapes: Vec<Self> = compress_child_classes
            .iter()
            .map(|os| Self::Shrink(os.clone()))
            .collect();

        // `recursion_shape_config` is not consulted for the
        // Compress/Deferred/Shrink tail; retained in the signature for API
        // stability and `generate_maximal_shapes`.
        let _ = recursion_shape_config;

        arity_recursion_shapes
            .into_iter()
            .chain(arity_compress_shapes)
            .chain(deferred_shapes)
            .chain(shrink_shapes)
    }

    pub fn generate_maximal_shapes<'a>(
        core_shape_config: &'a CoreShapeConfig<KoalaBear>,
        recursion_shape_config: &'a RecursionShapeConfig<KoalaBear, CompressAir<KoalaBear>>,
        reduce_batch_size: usize,
        no_precompiles: bool,
    ) -> impl Iterator<Item = Self> + 'a {
        let core_shape_iter = if no_precompiles {
            core_shape_config.maximal_core_shapes(21).into_iter()
        } else {
            core_shape_config.maximal_core_plus_precompile_shapes(21).into_iter()
        };
        // single-shard normalize: emit ONLY arity-1 normalize shapes per
        // maximal core shape (matches `generate`; production normalize is
        // single-shard, and arity>=2 normalize programs assert len==1).
        core_shape_iter
            .map(move |core_shape| {
                let os = OrderedShape {
                    inner: core_shape.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
                };
                Self::Recursion(vec![os])
            })
            .chain((1..=reduce_batch_size).flat_map(|batch_size| {
                recursion_shape_config.get_all_shape_combinations(batch_size).map(Self::Compress)
            }))
            .chain(
                recursion_shape_config
                    .get_all_shape_combinations(1)
                    .map(|mut x| Self::Deferred(x.pop().unwrap())),
            )
            .chain(
                recursion_shape_config
                    .get_all_shape_combinations(1)
                    .map(|mut x| Self::Shrink(x.pop().unwrap())),
            )
    }

    pub fn dummy_vk_map<'a>(
        core_shape_config: &'a CoreShapeConfig<KoalaBear>,
        recursion_shape_config: &'a RecursionShapeConfig<KoalaBear, CompressAir<KoalaBear>>,
        reduce_batch_size: usize,
    ) -> BTreeMap<[KoalaBear; DIGEST_SIZE], usize> {
        Self::generate(core_shape_config, recursion_shape_config, reduce_batch_size)
            .enumerate()
            .map(|(i, _)| ([KoalaBear::from_usize(i); DIGEST_SIZE], i))
            .collect()
    }
}

impl ZKMCompressProgramShape {
    pub fn from_proof_shape(shape: ZKMProofShape, height: usize) -> Self {
        match shape {
            ZKMProofShape::Recursion(proof_shapes) => {
                // Arity = proof_shapes.len(); the per-shard shapes become
                // the batch verified by build_normalize_basefold_program.
                Self::Recursion(ZKMRecursionShape { proof_shapes, is_complete: false })
            }
            ZKMProofShape::Deferred(proof_shape) => {
                Self::Deferred(ZKMDeferredShape::new(vec![proof_shape].into(), height))
            }
            ZKMProofShape::Compress(proof_shapes) => Self::Compress(ZKMCompressWithVkeyShape {
                compress_shape: proof_shapes.into(),
                merkle_tree_height: height,
            }),
            ZKMProofShape::Shrink(proof_shape) => Self::Shrink(ZKMCompressWithVkeyShape {
                compress_shape: vec![proof_shape].into(),
                merkle_tree_height: height,
            }),
        }
    }
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    pub fn program_from_shape(
        &self,
        shape: ZKMCompressProgramShape,
        shrink_shape: Option<RecursionShape>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        // Always dispatch to the basefold program builders.
        let _ = shrink_shape;
        self.program_from_shape_basefold(shape)
    }

    /// Basefold companion to [`Self::program_from_shape`]. Builds a
    /// recursion program from a cached shape using the basefold-pipeline
    /// program builders (`recursion_program_basefold`,
    /// `compose_program_basefold`, etc.).
    ///
    /// Used by `build_compress_vks` to regenerate `vk_map.bin` against the
    /// basefold compress programs.
    pub fn program_from_shape_basefold(
        &self,
        shape: ZKMCompressProgramShape,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        match shape {
            ZKMCompressProgramShape::Recursion(shape) => {
                let input = ZKMCoreBasefoldWitnessValues::dummy(
                    self.core_prover.machine(),
                    &shape,
                );
                self.recursion_program_basefold(&input)
            }
            ZKMCompressProgramShape::Deferred(shape) => {
                let input = ZKMDeferredBasefoldWitnessValues::dummy(
                    self.compress_prover.machine(),
                    &shape,
                );
                self.deferred_program_basefold(&input)
            }
            ZKMCompressProgramShape::Compress(shape) => {
                // dummy now consumes the full ZKMCompressWithVkeyShape so
                // its embedded merkle_tree_height sizes the vk-merkle witness.
                let input = ZKMCompressBasefoldWitnessValues::dummy(
                    self.compress_prover.machine(),
                    &shape,
                );
                self.compose_program_basefold(&input)
            }
            ZKMCompressProgramShape::Shrink(shape) => {
                // SP1 alignment: dummy now consumes the full
                // ZKMCompressWithVkeyShape so its embedded merkle_tree_height
                // sizes the vk-merkle witness for the wrap stage too.
                let input = ZKMWrapBasefoldWitnessValues::dummy(
                    self.compress_prover.machine(),
                    &shape,
                );
                self.shrink_program_basefold(&input)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Does a compose program — and with it its verifying key — depend on its
    /// children's PER-CHIP heights, or only on their committed-geometry class?
    ///
    /// `ZKMProofShape::generate` emits ONE synthetic representative per
    /// log-dense class (`compress_child_classes`), which is only sound if the
    /// answer is "only the class".  If the program moves with the heights, no
    /// synthetic representative can ever reproduce a real child's vk and the
    /// allowlist can never contain a produced key.
    #[test]
    #[ignore]
    fn compose_vk_height_dependence() {
        use crate::components::DefaultProverComponents;
        use zkm_recursion_circuit::machine::{ZKMCompressWithVkeyShape, ZKMCompressShape};

        let prover = ZKMProver::<DefaultProverComponents>::new();
        let rec_cfg = prover.compress_shape_config.as_ref().unwrap();
        let bands: Vec<OrderedShape> = rec_cfg
            .get_all_shape_combinations(1)
            .map(|mut v| v.pop().unwrap())
            .collect();
        eprintln!("[HDEP] bands = {}", bands.len());

        let vk_of = |os: &OrderedShape, arity: usize| -> String {
            let compress_shape: ZKMCompressShape = vec![os.clone(); arity].into();
            let shape = ZKMCompressWithVkeyShape {
                compress_shape,
                merkle_tree_height: crate::VK_MERKLE_TREE_HEIGHT,
            };
            let input = zkm_recursion_circuit::machine::ZKMCompressBasefoldWitnessValues::dummy(
                prover.compress_prover.machine(),
                &shape,
            );
            let program = prover.compose_program_basefold(&input);
            let (_pk, vk) = prover.compress_prover.setup(&program);
            format!("{:?}", vk.hash_koalabear())
        };

        for arity in [1usize, 4] {
            let mut seen: BTreeMap<String, Vec<usize>> = BTreeMap::new();
            for (i, os) in bands.iter().enumerate() {
                seen.entry(vk_of(os, arity)).or_default().push(i);
            }
            eprintln!("[HDEP] arity={arity}: {} distinct vks over {} bands", seen.len(), bands.len());
            for (d, idxs) in &seen {
                eprintln!("[HDEP]   {d} <- bands {idxs:?}");
            }
        }
    }

    /// TEMP analysis: measure the per-shard normalize band structure
    /// (distinct OrderedShapes per cluster) to size the arity
    /// enumeration against the 2^11 budget.
    #[test]
    #[ignore]
    fn analyze_recursion_band_structure() {
        use crate::CoreSC;
        use zkm_core_machine::mips::MipsAir;
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::stacked_shapes::{build_mips_machine_shape, types::consts};
        use std::collections::{BTreeMap, BTreeSet};

        let core_machine = MipsAir::machine(CoreSC::default());
        let chips_by_name: BTreeMap<String, _> =
            core_machine.chips().iter().map(|c| (c.name(), c)).collect();
        let machine_shape = build_mips_machine_shape();
        eprintln!("[BAND] clusters = {}", machine_shape.chip_clusters.len());

        let mut total_per_shard_shapes = 0usize;
        let mut per_cluster_shape_counts: Vec<usize> = Vec::new();
        for (ci, cluster) in machine_shape.chip_clusters.iter().enumerate() {
            let names: Vec<String> = cluster
                .iter()
                .filter(|n| chips_by_name.contains_key(*n))
                .cloned()
                .collect();
            if names.is_empty() {
                continue;
            }
            let fillers: std::collections::HashSet<&String> = names
                .iter()
                .filter(|n| {
                    n.as_str() != "Byte" && chips_by_name[n.as_str()].num_sent_byte_lookups() == 0
                })
                .collect();
            let mut set: BTreeSet<OrderedShape> = BTreeSet::new();
            for h in 1..=consts::CORE_MAX_LOG_ROW_COUNT {
                let inner: Vec<(String, usize)> = names
                    .iter()
                    .map(|n| {
                        let height = if fillers.contains(n) {
                            h
                        } else if n == "Byte" {
                            16
                        } else {
                            1
                        };
                        (n.clone(), height)
                    })
                    .collect();
                set.insert(OrderedShape::from_log2_heights(&inner));
            }
            total_per_shard_shapes += set.len();
            per_cluster_shape_counts.push(set.len());
            eprintln!(
                "[BAND] cluster {ci}: chips={} fillers={} distinct_OrderedShapes={}",
                names.len(),
                fillers.len(),
                set.len()
            );
        }
        eprintln!("[BAND] TOTAL per-shard OrderedShapes = {total_per_shard_shapes}");
        let s = total_per_shard_shapes;
        eprintln!(
            "[BAND] uniform-replication arity 1..=4: {} (= {} per-shard x 4)",
            s * 4,
            s
        );
        let per_cluster_uniform: usize = per_cluster_shape_counts.iter().map(|c| c * 4).sum();
        eprintln!("[BAND] per-cluster uniform arity 1..=4 = {per_cluster_uniform}");
        eprintln!("[BAND] nonempty clusters = {}", per_cluster_shape_counts.len());
    }

    /// TEMP analysis: dedup the per-shard OrderedShapes by their
    /// normalize equivalence class — (chip-set, log_dense) — by building
    /// the dummy bundle for each shape and reading packing.log_dense_size.
    /// Tells us the true distinct per-shard normalize class count, which
    /// bounds the arity-replication enumeration.
    #[test]
    #[ignore]
    #[serial_test::serial]
    fn analyze_recursion_logdense_classes() {
        use crate::components::DefaultProverComponents;
        use zkm_recursion_circuit::machine::ZKMCoreBasefoldWitnessValues;
        use zkm_pcs::shard_level::shard_proof::EvaluationProof;
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::stacked_shapes::{build_mips_machine_shape, types::consts};
        use std::collections::{BTreeMap, BTreeSet};

        let prover = ZKMProver::<DefaultProverComponents>::new();
        let machine = prover.core_prover.machine();
        let chips_by_name: BTreeMap<String, _> =
            machine.chips().iter().map(|c| (<_ as MachineAir<KoalaBear>>::name(c), c)).collect();
        let machine_shape = build_mips_machine_shape();

        // (cluster_chip_set, log_dense) classes across all per-shard shapes.
        let mut classes: BTreeSet<(Vec<String>, usize)> = BTreeSet::new();
        let mut total_built = 0usize;
        let mut total_failed = 0usize;
        for (ci, cluster) in machine_shape.chip_clusters.iter().enumerate() {
            let names: Vec<String> = cluster
                .iter()
                .filter(|n| chips_by_name.contains_key(*n))
                .cloned()
                .collect();
            if names.is_empty() {
                continue;
            }
            let chipset: Vec<String> = {
                let mut v = names.clone();
                v.sort();
                v
            };
            let fillers: std::collections::HashSet<&String> = names
                .iter()
                .filter(|n| {
                    n.as_str() != "Byte" && chips_by_name[n.as_str()].num_sent_byte_lookups() == 0
                })
                .collect();
            let mut cluster_classes: BTreeSet<usize> = BTreeSet::new();
            for h in 1..=consts::CORE_MAX_LOG_ROW_COUNT {
                let inner: Vec<(String, usize)> = names
                    .iter()
                    .map(|n| {
                        let height = if fillers.contains(n) {
                            h
                        } else if n == "Byte" {
                            16
                        } else {
                            1
                        };
                        (n.clone(), height)
                    })
                    .collect();
                let os = OrderedShape::from_log2_heights(&inner);
                let shape = zkm_recursion_circuit::machine::ZKMRecursionShape {
                    proof_shapes: vec![os],
                    is_complete: false,
                };
                let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let dummy = ZKMCoreBasefoldWitnessValues::dummy(machine, &shape);
                    match &dummy.shard_proofs[0].evaluation_proof {
                        EvaluationProof::Bundle(b) => b.packing.log_dense_size,
                        _ => 0usize,
                    }
                }));
                match built {
                    Ok(ld) => {
                        total_built += 1;
                        classes.insert((chipset.clone(), ld));
                        cluster_classes.insert(ld);
                    }
                    Err(_) => total_failed += 1,
                }
            }
            eprintln!(
                "[LD] cluster {ci}: chips={} distinct_log_dense={} bands={:?}",
                names.len(),
                cluster_classes.len(),
                cluster_classes
            );
        }
        eprintln!(
            "[LD] TOTAL distinct (chip_set, log_dense) classes = {} (built={total_built} failed={total_failed})",
            classes.len()
        );
        eprintln!(
            "[LD] uniform-replication arity 1..=4 on classes = {}",
            classes.len() * 4
        );
    }

    /// ARITY-ENUM no-regression: the deduped arity-1 Recursion shapes
    /// must cover EXACTLY the same (chip_set, log_dense) classes as the
    /// full un-deduped per-cluster height sweep.  Since the normalize VK
    /// is (chip_set, log_dense)-determined, equal class coverage ⇒ the
    /// arity-1 normalize VK SET is unchanged from the pre-arity sweep
    /// (only redundant equal-VK shapes were dropped). Cheap (no proving):
    /// uses the same log_dense formula generate() uses.
    #[test]
    fn arity1_classes_cover_full_sweep() {
        use crate::CoreSC;
        use zkm_core_machine::mips::MipsAir;
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::stacked_shapes::{build_mips_machine_shape, types::consts};
        use std::collections::{BTreeMap, BTreeSet};

        let core_machine = MipsAir::machine(CoreSC::default());
        let chips_by_name: BTreeMap<String, _> =
            core_machine.chips().iter().map(|c| (c.name(), c)).collect();
        let machine_shape = build_mips_machine_shape();
        let log_dense_of = |os: &OrderedShape| -> usize {
            let total: usize = os
                .inner
                .iter()
                .map(|(name, log_h)| {
                    let w = chips_by_name
                        .get(name)
                        .map(|c| p3_air::BaseAir::<KoalaBear>::width(*c).max(1))
                        .unwrap_or(1);
                    w * (1usize << *log_h)
                })
                .sum();
            if total == 0 { 0 } else { total.next_power_of_two().trailing_zeros() as usize }
        };

        // Full un-deduped sweep -> set of (chip_set, log_dense) classes.
        let mut full_classes: BTreeSet<(Vec<String>, usize)> = BTreeSet::new();
        for cluster in &machine_shape.chip_clusters {
            let names: Vec<String> = cluster
                .iter()
                .filter(|n| chips_by_name.contains_key(*n))
                .cloned()
                .collect();
            if names.is_empty() {
                continue;
            }
            let mut chipset = names.clone();
            chipset.sort();
            let fillers: std::collections::HashSet<&String> = names
                .iter()
                .filter(|n| {
                    n.as_str() != "Byte" && chips_by_name[n.as_str()].num_sent_byte_lookups() == 0
                })
                .collect();
            for h in 1..=consts::CORE_MAX_LOG_ROW_COUNT {
                let inner: Vec<(String, usize)> = names
                    .iter()
                    .map(|n| {
                        let height = if fillers.contains(n) {
                            h
                        } else if n == "Byte" {
                            16
                        } else {
                            1
                        };
                        (n.clone(), height)
                    })
                    .collect();
                let os = OrderedShape::from_log2_heights(&inner);
                full_classes.insert((chipset.clone(), log_dense_of(&os)));
            }
        }

        // generate()'s arity-1 Recursion shapes -> their classes.
        let core_shape_config = CoreShapeConfig::default();
        let recursion_shape_config = RecursionShapeConfig::default();
        let mut gen_classes: BTreeSet<(Vec<String>, usize)> = BTreeSet::new();
        let mut arity1_count = 0usize;
        for s in ZKMProofShape::generate(&core_shape_config, &recursion_shape_config, 4) {
            if let ZKMProofShape::Recursion(batch) = s {
                if batch.len() == 1 {
                    arity1_count += 1;
                    let os = &batch[0];
                    let mut names: Vec<String> =
                        os.inner.iter().map(|(n, _)| n.clone()).collect();
                    names.sort();
                    gen_classes.insert((names, log_dense_of(os)));
                }
            }
        }

        assert_eq!(
            gen_classes, full_classes,
            "arity-1 deduped class coverage diverges from the full sweep — \
             the dedup dropped or added a (chip_set, log_dense) class (would \
             change the arity-1 normalize VK set)"
        );
        // Each class appears exactly once after dedup.
        assert_eq!(
            arity1_count,
            gen_classes.len(),
            "arity-1 shape count must equal distinct class count (one shape per class)"
        );
        eprintln!(
            "[ARITY1] full_sweep_classes={} gen_arity1_classes={} (EQUAL) arity1_shapes={}",
            full_classes.len(),
            gen_classes.len(),
            arity1_count
        );
    }

    /// ARITY-ENUM coverage: generate() emits ONLY arity-1 normalize shapes —
    /// the production normalize is single-shard, so arity≥2 Recursion shapes
    /// would be a phantom VK class no real proof produces.  Every Recursion
    /// shape must be exactly one per-shard shape.
    #[test]
    fn generate_emits_arity_1_to_reduce_batch_size() {
        use crate::REDUCE_BATCH_SIZE;
        let core_shape_config = CoreShapeConfig::default();
        let recursion_shape_config = RecursionShapeConfig::default();
        let mut per_arity: BTreeMap<usize, usize> = BTreeMap::new();
        for s in
            ZKMProofShape::generate(&core_shape_config, &recursion_shape_config, REDUCE_BATCH_SIZE)
        {
            if let ZKMProofShape::Recursion(batch) = s {
                *per_arity.entry(batch.len()).or_default() += 1;
            }
        }
        let arities: BTreeSet<usize> = per_arity.keys().cloned().collect();
        let expected: BTreeSet<usize> = BTreeSet::from([1]);
        assert_eq!(
            arities, expected,
            "normalize is single-shard: must emit exactly arity {{1}}, got {arities:?}"
        );
        eprintln!("[ARITY] per_arity_recursion_counts = {per_arity:?}");
    }

    /// CHILD-AREA coverage: the recursion AREA PIN is a FLOOR
    /// (`log_dense_size = max(natural, RECURSION_LOG_TRACE_AREA)`), not a
    /// clamp, so a compose/deferred/shrink child whose NATURAL jagged area
    /// already exceeds `2^pin` keeps its own larger `L` — and `L` drives every
    /// witnessed length in the child's BaseFold bundle (`num_stripes`, the
    /// reduction rounds, `jagged_n`).  The enumeration must therefore emit one
    /// class per reachable child `L`, not a single pinned representative.
    ///
    /// Regression guard: emitting only the pinned class made `VERIFY_VK=true`
    /// panic "vk not allowed" as soon as the reduce tree grew a second compose
    /// layer (whose children are COMPOSE proofs, several times larger than the
    /// NORMALIZE proofs of layer 0 and so above the floor).
    #[test]
    fn generate_spans_child_log_dense_above_the_area_pin() {
        use crate::{CompressAir, REDUCE_BATCH_SIZE};
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::stacked_shapes::types::consts;

        let compress_machine =
            CompressAir::<KoalaBear>::compress_machine(crate::InnerSC::default());
        let widths: BTreeMap<String, usize> = compress_machine
            .chips()
            .iter()
            .map(|c| {
                (
                    <_ as MachineAir<KoalaBear>>::name(c),
                    p3_air::BaseAir::<KoalaBear>::width(c).max(1),
                )
            })
            .collect();
        let natural_l = |os: &OrderedShape| -> usize {
            let total: u128 = os
                .inner
                .iter()
                .map(|(n, h)| (widths.get(n).copied().unwrap_or(1) as u128) * (1u128 << *h))
                .sum();
            let mut l = 0usize;
            while (1u128 << l) < total {
                l += 1;
            }
            l
        };

        let pin = zkm_pcs::jagged_pcs::RECURSION_LOG_TRACE_AREA;
        let ceiling = {
            let total: u128 = widths
                .values()
                .map(|w| (*w as u128) * (1u128 << consts::CORE_MAX_LOG_ROW_COUNT))
                .sum();
            let mut l = 0usize;
            while (1u128 << l) < total {
                l += 1;
            }
            l
        };

        let core_shape_config = CoreShapeConfig::default();
        let recursion_shape_config = RecursionShapeConfig::default();
        let mut by_kind: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
        for s in
            ZKMProofShape::generate(&core_shape_config, &recursion_shape_config, REDUCE_BATCH_SIZE)
        {
            let (kind, child) = match &s {
                ZKMProofShape::Recursion(_) => continue,
                ZKMProofShape::Compress(v) => (format!("Compress({})", v.len()), v[0].clone()),
                ZKMProofShape::Deferred(o) => ("Deferred".to_string(), o.clone()),
                ZKMProofShape::Shrink(o) => ("Shrink".to_string(), o.clone()),
            };
            by_kind.entry(kind).or_default().insert(natural_l(&child));
        }

        let expected: BTreeSet<usize> = (pin..=ceiling).collect();
        assert!(
            expected.len() > 1,
            "the machine ceiling ({ceiling}) must sit above the area pin ({pin}); \
             otherwise there is nothing to sweep and this guard is vacuous"
        );
        let mut kinds: Vec<String> = (1..=REDUCE_BATCH_SIZE).map(|a| format!("Compress({a})")).collect();
        kinds.push("Deferred".to_string());
        kinds.push("Shrink".to_string());
        for kind in kinds {
            let got = by_kind.get(&kind).unwrap_or_else(|| panic!("no {kind} shapes emitted"));
            assert_eq!(
                *got, expected,
                "{kind}: child natural log_dense classes must span [{pin}, {ceiling}] — the area \
                 pin is a FLOOR, so an over-floor child carries its own larger L and needs its \
                 own class"
            );
        }
        eprintln!("[CHILD-L] pin={pin} ceiling={ceiling} classes_per_kind={}", expected.len());
    }

    /// ARITY-ENUM GAP PROBE: does a HETEROGENEOUS batch (two shards of the
    /// SAME cluster at DIFFERENT log_dense bands — e.g. a full shard + a
    /// partial tail shard) have a VK that the UNIFORM enumeration covers?
    /// Builds dummy VKs (faithful dummy ⇒ dummy VK == real VK), so this
    /// measures whether real heterogeneous tail batches are enumerated.
    /// Reports the count of MISSED heterogeneous batch VKs.  #[ignore]
    /// (builds VKs — slow; run manually to quantify the gap).
    #[test]
    #[ignore]
    #[serial_test::serial]
    fn arity_hetero_batch_coverage_probe() {
        use crate::components::DefaultProverComponents;
        use zkm_recursion_circuit::machine::{ZKMCoreBasefoldWitnessValues, ZKMRecursionShape};
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::stacked_shapes::{build_mips_machine_shape, types::consts};
        use std::collections::{BTreeMap, BTreeSet};

        let prover = ZKMProver::<DefaultProverComponents>::new();
        let machine = prover.core_prover.machine();
        let chips_by_name: BTreeMap<String, _> = machine
            .chips()
            .iter()
            .map(|c| (<_ as MachineAir<KoalaBear>>::name(c), c))
            .collect();
        let machine_shape = build_mips_machine_shape();
        let log_dense_of = |os: &OrderedShape| -> usize {
            let total: usize = os
                .inner
                .iter()
                .map(|(name, log_h)| {
                    let w = chips_by_name
                        .get(name)
                        .map(|c| p3_air::BaseAir::<KoalaBear>::width(*c).max(1))
                        .unwrap_or(1);
                    w * (1usize << *log_h)
                })
                .sum();
            if total == 0 { 0 } else { total.next_power_of_two().trailing_zeros() as usize }
        };

        // Pick the main_exec cluster (core chips + Global, NO precompiles,
        // NO MemoryGlobalInit/Finalize) — the realistic multishard sha2/fib
        // cluster.  Identified by: contains Cpu + Global, NOT a precompile
        // family chip, NOT MemoryGlobalInit.  Falls back to the cluster with
        // Cpu and the most core chips.
        let precompile_marker = |n: &str| -> bool {
            n.contains("Keccak")
                || n.contains("Sha")
                || n.contains("Bls")
                || n.contains("Bn254")
                || n.contains("Secp")
                || n.contains("EdAdd")
                || n.contains("EdDecompress")
                || n.contains("Uint")
                || n.contains("Poseidon2")
        };
        let is_main_exec = |c: &BTreeSet<String>| -> bool {
            c.contains("Cpu")
                && c.contains("Global")
                && !c.contains("MemoryGlobalInit")
                && !c.contains("MemoryGlobalFinalize")
                && c.iter().all(|n| !precompile_marker(n))
        };
        let cluster = machine_shape
            .chip_clusters
            .iter()
            .filter(|c| is_main_exec(c))
            .min_by_key(|c| c.iter().filter(|n| chips_by_name.contains_key(*n)).count())
            .or_else(|| {
                machine_shape
                    .chip_clusters
                    .iter()
                    .filter(|c| c.contains("Cpu"))
                    .min_by_key(|c| c.iter().filter(|n| chips_by_name.contains_key(*n)).count())
            })
            .expect("a Cpu-bearing cluster");
        let names: Vec<String> = cluster
            .iter()
            .filter(|n| chips_by_name.contains_key(*n))
            .cloned()
            .collect();
        let fillers: std::collections::HashSet<&String> = names
            .iter()
            .filter(|n| n.as_str() != "Byte" && chips_by_name[n.as_str()].num_sent_byte_lookups() == 0)
            .collect();
        let mut band_reps: BTreeMap<usize, OrderedShape> = BTreeMap::new();
        for h in 1..=consts::CORE_MAX_LOG_ROW_COUNT {
            let inner: Vec<(String, usize)> = names
                .iter()
                .map(|n| {
                    let height = if fillers.contains(n) { h } else if n == "Byte" { 16 } else { 1 };
                    (n.clone(), height)
                })
                .collect();
            let os = OrderedShape::from_log2_heights(&inner);
            band_reps.entry(log_dense_of(&os)).or_insert(os);
        }
        let bands: Vec<usize> = band_reps.keys().cloned().collect();
        eprintln!("[HETERO] cluster chips={} bands={:?}", names.len(), bands);

        // Build the UNIFORM enumerated VK set for this cluster (arity 2).
        let setup_vk = |shape: &ZKMRecursionShape| -> Option<[KoalaBear; DIGEST_SIZE]> {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let d = ZKMCoreBasefoldWitnessValues::dummy(machine, shape);
                let p = prover.recursion_program_basefold(&d);
                prover.compress_prover.setup(&p).1.hash_koalabear()
            }))
            .ok()
        };
        let mut uniform_vks: BTreeSet<[KoalaBear; DIGEST_SIZE]> = BTreeSet::new();
        for (b, os) in band_reps.iter() {
            if *b > 30 {
                continue; // log_dense>30 over-emit (caught by build_compress_vks)
            }
            if let Some(vk) = setup_vk(&ZKMRecursionShape {
                proof_shapes: vec![os.clone(); 2],
                is_complete: true,
            }) {
                uniform_vks.insert(vk);
            }
        }
        eprintln!("[HETERO] uniform arity-2 VKs (this cluster) = {}", uniform_vks.len());

        // Now build HETEROGENEOUS arity-2 batches: [band_i, band_j] for i<j
        // (full + partial tail). Check how many are NOT in the uniform set.
        let buildable: Vec<usize> = bands.iter().cloned().filter(|b| *b <= 30).collect();
        let mut hetero_total = 0usize;
        let mut hetero_missed = 0usize;
        for (a, &bi) in buildable.iter().enumerate() {
            for &bj in buildable.iter().skip(a + 1) {
                let shape = ZKMRecursionShape {
                    proof_shapes: vec![band_reps[&bi].clone(), band_reps[&bj].clone()],
                    is_complete: true,
                };
                if let Some(vk) = setup_vk(&shape) {
                    hetero_total += 1;
                    if !uniform_vks.contains(&vk) {
                        hetero_missed += 1;
                    }
                }
            }
        }
        eprintln!(
            "[HETERO] heterogeneous arity-2 batches built={hetero_total} MISSED_by_uniform_enum={hetero_missed}"
        );
        eprintln!(
            "[HETERO] VERDICT: {}",
            if hetero_missed == 0 {
                "uniform enum COVERS heterogeneous batches (order/mix-independent VK)"
            } else {
                "uniform enum MISSES heterogeneous batches => gap for partial-tail mixed batches"
            }
        );
    }

    #[test]
    #[ignore]
    fn test_generate_all_shapes() {
        let core_shape_config = CoreShapeConfig::default();
        let recursion_shape_config = RecursionShapeConfig::default();
        let reduce_batch_size = 2;
        let all_shapes =
            ZKMProofShape::generate(&core_shape_config, &recursion_shape_config, reduce_batch_size)
                .collect::<BTreeSet<_>>();

        println!("Number of compress shapes: {}", all_shapes.len());
    }

    /// VKROOT-CIRCULARITY measurement: print enumeration height
    /// (ceil(log2(num_shapes)) at production REDUCE_BATCH_SIZE) vs
    /// production height (ceil(log2(map_size)) from the embedded
    /// vk_map.bin).  If these differ, the entire vk_map was baked at a
    /// merkle_tree_height the production prover never reproduces, so
    /// `contains_key(compose_vk)` can never hit.
    #[test]
    #[ignore]
    fn measure_vkroot_heights() {
        use crate::REDUCE_BATCH_SIZE;
        let core_shape_config = CoreShapeConfig::default();
        let recursion_shape_config = RecursionShapeConfig::default();
        let all_shapes: BTreeSet<_> = ZKMProofShape::generate(
            &core_shape_config,
            &recursion_shape_config,
            REDUCE_BATCH_SIZE,
        )
        .collect();
        let num_shapes = all_shapes.len();
        let enum_height = num_shapes.next_power_of_two().ilog2() as usize;

        let recursion_count =
            all_shapes.iter().filter(|s| matches!(s, ZKMProofShape::Recursion(_))).count();
        let compress_count =
            all_shapes.iter().filter(|s| matches!(s, ZKMProofShape::Compress(_))).count();
        let deferred_count =
            all_shapes.iter().filter(|s| matches!(s, ZKMProofShape::Deferred(_))).count();
        let shrink_count =
            all_shapes.iter().filter(|s| matches!(s, ZKMProofShape::Shrink(_))).count();

        let map: std::collections::BTreeMap<[KoalaBear; DIGEST_SIZE], usize> =
            bincode::deserialize(include_bytes!("../vk_map.bin")).unwrap();
        let map_size = map.len();
        let prod_height = map_size.next_power_of_two().ilog2() as usize;

        eprintln!("[VKROOT] REDUCE_BATCH_SIZE={REDUCE_BATCH_SIZE}");
        eprintln!("[VKROOT] num_shapes={num_shapes} (recursion={recursion_count} compress={compress_count} deferred={deferred_count} shrink={shrink_count})");
        eprintln!("[VKROOT] enum_height = ceil(log2({num_shapes})) = {enum_height}");
        eprintln!("[VKROOT] map_size={map_size}  prod_height = ceil(log2({map_size})) = {prod_height}");
        eprintln!(
            "[VKROOT] HEIGHTS {}",
            if enum_height == prod_height { "MATCH ✓ (no height circularity)" } else { "MISMATCH ✗ (every key baked at wrong height)" }
        );
    }

    /// The Recursion shape count is bounded by the per-cluster
    /// (chip_set, log_dense) class dedup × the arity range
    /// (1..=reduce_batch_size).  Each arity contributes the same deduped
    /// per-shard class set (uniform batches), so the total recursion
    /// count = distinct_classes × reduce_batch_size, and is divisible by
    /// reduce_batch_size.
    #[test]
    fn generate_uses_stacked_shapes_for_recursion() {
        let core_shape_config = CoreShapeConfig::default();
        let recursion_shape_config = RecursionShapeConfig::default();
        let reduce_batch_size = 2;

        let all: BTreeSet<_> =
            ZKMProofShape::generate(&core_shape_config, &recursion_shape_config, reduce_batch_size)
                .collect();
        let recursion_count =
            all.iter().filter(|s| matches!(s, ZKMProofShape::Recursion(_))).count();

        // Recursion = distinct (chip_set, log_dense) classes × arities.
        // Deduped class count is in the few-hundreds (26 clusters × ~12
        // distinct log_dense each), so reduce_batch_size=2 stays well under
        // the 2^11 budget shared with Compress/Deferred/Shrink.
        assert!(
            recursion_count % reduce_batch_size == 0,
            "recursion_count {recursion_count} must be divisible by reduce_batch_size \
             {reduce_batch_size} (uniform arity replication of one class set)"
        );
        assert!(
            recursion_count >= reduce_batch_size,
            "generate should produce at least one class × every arity"
        );
        assert!(
            recursion_count <= 1024,
            "Recursion shape count {recursion_count} unexpectedly large for reduce_batch_size=2"
        );
    }
}
