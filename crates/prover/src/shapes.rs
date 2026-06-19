use eyre::Result;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::File,
    hash::{DefaultHasher, Hash, Hasher},
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
    ZKMCompressBasefoldWitnessValues, ZKMCompressWithVKeyWitnessValues, ZKMCompressWithVkeyShape,
    ZKMCoreBasefoldWitnessValues, ZKMDeferredBasefoldWitnessValues, ZKMDeferredShape,
    ZKMDeferredWitnessValues, ZKMRecursionShape, ZKMRecursionWitnessValues,
    ZKMWrapBasefoldWitnessValues,
};
use zkm_recursion_core::{
    shape::{RecursionShape, RecursionShapeConfig},
    RecursionProgram,
};
use zkm_pcs::{shape::OrderedShape, MachineProver, DIGEST_SIZE};

use crate::{components::ZKMProverComponents, CompressAir, HashableKey, ShrinkAir, ZKMProver};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ZKMProofShape {
    /// A normalize/recursion batch.  Carries the per-shard shapes for an
    /// arity-`proof_shapes.len()` first-compose-layer normalize program
    /// (`build_normalize_basefold_program` verifies a BATCH of shard
    /// proofs — arity = number of shards in the batch).  Real multishard
    /// proofs batch core shards in `chunks(REDUCE_BATCH_SIZE)`
    /// (`get_recursion_core_inputs_basefold`), so the enumeration emits
    /// arity 1..=REDUCE_BATCH_SIZE.  Arity-1 (`vec![one]`) is the legacy
    /// single-shard shape, byte-identical to the prior `Recursion(OrderedShape)`.
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
    pub fn hash_u64(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        Hash::hash(&self, &mut hasher);
        hasher.finish()
    }
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
    let core_shape_config = prover.core_shape_config.as_ref().expect("core shape config not found");
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
    let core_shape_config = prover.core_shape_config.as_ref().expect("core shape config not found");
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
) -> Result<(), VkBuildError> {
    std::fs::create_dir_all(&build_dir)?;

    tracing::info!("Building vk set");

    let (vk_set, _, _) = build_vk_map::<C>(
        reduce_batch_size,
        dummy,
        num_compiler_workers,
        num_setup_workers,
        range_start.and_then(|start| range_end.map(|end| (start..end).collect())),
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
    /// replaces Ziren's legacy ~1.25M-shape per-chip cartesian
    /// (`CoreShapeConfig::all_shapes`); the task commits to
    /// stacked_shapes as the sole Recursion-shape source.
    ///
    /// The `core_shape_config` argument is retained for API
    /// stability but is no longer consulted.
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
        // Cheap log_dense (= jagged `packing.log_dense_size`) for an
        // OrderedShape WITHOUT building a full dummy bundle.  The jagged
        // packing's total_values = Σ_chips width·2^log_h and
        // log_dense_size = log2(np2(total_values)) — see
        // `zkm_pcs::jagged::pack_traces_jagged` (uses only height/width).
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
            if total == 0 {
                0
            } else {
                total.next_power_of_two().trailing_zeros() as usize
            }
        };

        // Per-shard normalize shapes (one representative per
        // (chip_set, log_dense) class).  The normalize program — hence
        // its VK — is (chip_set, log_dense)-determined (validated in
        // `tests::vkroot_normalize_vk_equivalence_class`), so collapsing
        // equal-log_dense shapes keeps the produced VK set IDENTICAL while
        // shrinking the shape count.  This is what lets arity replication
        // (below) fit the fixed VK_MERKLE_TREE_HEIGHT budget.
        let small_shapes: Vec<OrderedShape> = {
            // Keyed by (sorted chip names, log_dense) so we emit exactly
            // one shape per distinct normalize equivalence class.
            let mut by_class: BTreeMap<(Vec<String>, usize), OrderedShape> = BTreeMap::new();
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
                        n.as_str() != "Byte"
                            && chips_by_name[n.as_str()].num_sent_byte_lookups() == 0
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
                    let ld = log_dense_of(&os);
                    // Keep the FIRST shape seen for each class (smallest
                    // sweep height h that reaches this log_dense) — its
                    // distribution is irrelevant to the VK, only the class
                    // matters.
                    by_class.entry((chipset.clone(), ld)).or_insert(os);
                }
            }
            by_class.into_values().collect()
        };

        // Emit arity 1..=reduce_batch_size normalize batches.  Real
        // multishard proofs batch core shards in chunks(REDUCE_BATCH_SIZE)
        // (`get_recursion_core_inputs_basefold`); within a chunk every
        // shard shares the program's chip cluster, so the dominant batch
        // is UNIFORM (all shards at the same band).  We emit the uniform
        // arity-N batch (`vec![shape; arity]`) per per-shard class.
        // Arity-1 reproduces today's single-shard normalize VK set
        // exactly (same distinct (chip_set, log_dense) classes).
        let arity_recursion_shapes: Vec<Self> = {
            let mut out = Vec::with_capacity(small_shapes.len() * reduce_batch_size);
            for arity in 1..=reduce_batch_size {
                for os in &small_shapes {
                    out.push(Self::Recursion(vec![os.clone(); arity]));
                }
            }
            out
        };

        arity_recursion_shapes
            .into_iter()
            .chain((1..=reduce_batch_size).flat_map(move |batch_size| {
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
        // Emit arity 1..=reduce_batch_size uniform normalize batches per
        // maximal core shape (so the program-build check exercises the
        // multishard normalize program too — matches `generate`).
        core_shape_iter
            .flat_map(move |core_shape| {
                let os = OrderedShape {
                    inner: core_shape.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
                };
                (1..=reduce_batch_size).map(move |arity| Self::Recursion(vec![os.clone(); arity]))
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
        // Legacy FRI path removed (May 2026); always dispatch to the
        // basefold program builders.
        let _ = shrink_shape;
        self.program_from_shape_basefold(shape)
    }

    /// Basefold companion to [`Self::program_from_shape`]. Builds a
    /// recursion program from a cached shape using the basefold-pipeline
    /// program builders (`recursion_program_basefold`,
    /// `compose_program_basefold`, etc.) instead of the legacy FRI ones.
    ///
    /// step 4. Used by `build_compress_vks` to regenerate
    /// `vk_map.bin` against the basefold compress programs.
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

    /// ARITY-ENUM coverage: generate() emits arity 1..=REDUCE_BATCH_SIZE
    /// uniform normalize batches, and the per-arity counts are equal
    /// (uniform replication of the deduped per-shard class set).
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
                // Uniform batch: all shards identical.
                assert!(
                    batch.windows(2).all(|w| w[0] == w[1]),
                    "generate() should emit UNIFORM arity batches"
                );
            }
        }
        let arities: BTreeSet<usize> = per_arity.keys().cloned().collect();
        let expected: BTreeSet<usize> = (1..=REDUCE_BATCH_SIZE).collect();
        assert_eq!(arities, expected, "must emit exactly arities 1..=REDUCE_BATCH_SIZE");
        // Each arity has the same count (uniform replication of one class set).
        let counts: BTreeSet<usize> = per_arity.values().cloned().collect();
        assert_eq!(
            counts.len(),
            1,
            "per-arity counts should be equal (uniform replication): {per_arity:?}"
        );
        eprintln!("[ARITY] per_arity_recursion_counts = {per_arity:?}");
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
