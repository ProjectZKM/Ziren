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
use zkm_pcs::{shape::OrderedShape, MachineProver, DIGEST_SIZE};
use zkm_recursion_circuit::machine::{
    ZKMCompressBasefoldWitnessValues, ZKMCompressWithVkeyShape, ZKMCoreBasefoldWitnessValues,
    ZKMDeferredBasefoldWitnessValues, ZKMDeferredShape, ZKMRecursionShape,
    ZKMWrapBasefoldWitnessValues,
};
use zkm_recursion_core::{
    shape::{RecursionShape, RecursionShapeConfig},
    RecursionProgram,
};

use crate::{components::ZKMProverComponents, CompressAir, HashableKey, ZKMProver};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ZKMProofShape {
    /// A single-shard normalize/recursion shape.  Carries exactly ONE
    /// per-shard shape: the production normalize is arity-1 (`compress` →
    /// `get_first_layer_inputs` with first_layer_batch_size=1 →
    /// `get_recursion_core_inputs_basefold` chunks(1) → one core shard per
    /// `ZKMCoreBasefoldWitnessValues`, hard-asserted
    /// there).  Arity≥2 Recursion shapes would be a PHANTOM
    /// VK class no real proof produces; cross-shard aggregation lives in
    /// COMPRESS.  The `Vec` is retained for wire-format/serde stability but
    /// the enumerator emits only `vec![one]` and the dummy/in-circuit
    /// verifier asserts len==1.
    Recursion(Vec<OrderedShape>),
    Compress(Vec<OrderedShape>),
    /// Deferred proofs are batched `REDUCE_BATCH_SIZE` at a time
    /// (`get_recursion_deferred_inputs_basefold` chunks by the reduce batch
    /// size), so the deferred program — and its VK — is a function of the
    /// BATCH ARITY exactly like `Compress`.  Enumerating only arity 1 left
    /// every multi-proof deferred node out of the allowlist ("vk not allowed"
    /// in `test_e2e_with_deferred_proofs`).
    Deferred(Vec<OrderedShape>),
    Shrink(OrderedShape),
    /// The compose that closes the tree: the same children as `Compress`
    /// with `is_complete = 1`.  The flag is a witness, so the instructions
    /// are those of the open compose; what moves is the snapping
    /// (`compose-root`), and with it the rows and the key.  At arity
    /// `REDUCE_BATCH_SIZE` both snap to the same rows and the two keys
    /// coincide (measured: all 8 arity-3 tuples); below it they differ, so
    /// the enumeration carries both and the distinct-key count is smaller
    /// than the shape count.
    CompressRoot(Vec<OrderedShape>),
    /// A normalize (leaf) class representative: one core shard whose chips sit
    /// at exactly these (name, row count) pairs — rows, not log heights, so a
    /// representative can land on any committed-block bucket.
    Normalize(OrderedShape),
}

/// The witness shape of an enumerated normalize class: exact rows per chip.
#[derive(Debug, Clone, Hash)]
pub struct ZKMNormalizeShape {
    pub rows: Vec<(String, usize)>,
}

#[derive(Debug, Clone, Hash)]
pub enum ZKMCompressProgramShape {
    Recursion(ZKMRecursionShape),
    Compress(ZKMCompressWithVkeyShape),
    Deferred(ZKMDeferredShape),
    Shrink(ZKMCompressWithVkeyShape),
    CompressRoot(ZKMCompressWithVkeyShape),
    Normalize(ZKMNormalizeShape),
}

impl ZKMCompressProgramShape {}

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
    let recursion_shape_config =
        prover.compress_shape_config.as_ref().expect("recursion shape config not found");
    let core_shape_config = &CoreShapeConfig::default();

    let all_maximal_shapes = ZKMProofShape::generate_maximal_shapes(
        core_shape_config,
        recursion_shape_config,
        reduce_batch_size,
        no_precompiles,
    )
    .collect::<BTreeSet<ZKMProofShape>>();
    let num_shapes = all_maximal_shapes.len();
    tracing::info!("number of shapes: {}", num_shapes);

    let height = crate::VK_MERKLE_TREE_HEIGHT;
    assert!(num_shapes <= (1 << height));

    let shape_rx = Mutex::new(shape_rx);
    let compress_ok = std::thread::scope(|s| {
        for _ in 0..num_compiler_workers {
            let shape_rx = &shape_rx;
            let prover = &prover;
            let panic_tx = panic_tx.clone();
            s.spawn(move || {
                while let Ok(shape) = shape_rx.lock().unwrap().recv() {
                    tracing::info!("shape is {:?}", shape);
                    let program = catch_unwind(AssertUnwindSafe(|| {
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

        all_maximal_shapes.into_iter().for_each(|program_shape| {
            shape_tx
                .send(ZKMCompressProgramShape::from_proof_shape(program_shape, height))
                .unwrap();
        });

        drop(shape_tx);
        drop(panic_tx);

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
    let prover = ZKMProver::<C>::new_with_vk_verification(Some(!dummy));
    let recursion_shape_config =
        prover.compress_shape_config.as_ref().expect("recursion shape config not found");

    tracing::info!("building compress vk map");
    let (vk_set, panic_indices, height) = if dummy {
        tracing::warn!("Making a dummy vk map");
        let dummy_set = ZKMProofShape::dummy_vk_map(recursion_shape_config, reduce_batch_size)
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
        let all_shapes = ZKMProofShape::generate_all(
            recursion_shape_config,
            reduce_batch_size,
            prover.core_prover.machine(),
        )
        .collect::<BTreeSet<_>>();
        let num_shapes = all_shapes.len();
        tracing::info!("number of shapes: {}", num_shapes);

        let height = crate::VK_MERKLE_TREE_HEIGHT;
        assert!(num_shapes <= (1 << height), "shape count {num_shapes} exceeds 2^{height}");
        let chunk_size = indices_set.as_ref().map(|indices| indices.len()).unwrap_or(num_shapes);

        let shape_rx = Mutex::new(shape_rx);
        let program_rx = Mutex::new(program_rx);
        std::thread::scope(|s| {
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

/// The core (MIPS) machine the normalize shapes are enumerated over.
pub type CoreMachine = zkm_pcs::StarkMachine<
    zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
    zkm_core_machine::mips::MipsAir<KoalaBear>,
>;

const LOG_STACK: usize = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;

/// The `Program` table sizes enumerated: `2^10` rows up to the row cube.
/// Every program below `2^10` instructions shares the smallest bucket's class.
const PROGRAM_LOG_ROWS: std::ops::RangeInclusive<usize> =
    10..=zkm_pcs::stacked_shapes::consts::CORE_MAX_LOG_ROW_COUNT;

/// Cells a core shard's main round may carry past `ELEMENT_THRESHOLD`: the
/// executor closes a shard once its accounted area reaches the threshold, so
/// the last instruction's rows, and the chips the accounting leaves out, land
/// on top of it.  `2^26` cells is the allowance; the buckets stop there.
const CORE_MAIN_OVERSHOOT_CELLS: usize = 1 << 26;

/// A core chip's name and its two round widths.
struct CoreChipDims {
    name: String,
    main_width: usize,
    prep_width: usize,
}

fn core_chip_dims(machine: &CoreMachine) -> Vec<CoreChipDims> {
    use p3_air::BaseAir;
    use zkm_pcs::air::MachineAir;
    machine
        .chips()
        .iter()
        .map(|c| CoreChipDims {
            name: <_ as MachineAir<KoalaBear>>::name(c),
            main_width: <_ as BaseAir<KoalaBear>>::width(&c.air),
            prep_width: <_ as MachineAir<KoalaBear>>::preprocessed_width(c),
        })
        .collect()
}

/// The fixed table height of a preprocessed chip: `Byte` is the full `2^16`
/// byte-pair table, `Range` the `2^11` range table, and `Program` the program
/// padded to `2^program_log_rows`.  Every other chip is event-driven.
fn table_log_rows(name: &str, program_log_rows: usize) -> Option<usize> {
    match name {
        "Program" => Some(program_log_rows),
        "Byte" => Some(16),
        "Range" => Some(11),
        _ => None,
    }
}

/// The committed-block buckets of `zkm_pcs::jagged::committed_dense_len` up
/// to the one holding `max_blocks`: `1, 2, 3, 4, 8, 16, 24, …`.
fn main_buckets(max_blocks: usize) -> Vec<usize> {
    let top = zkm_pcs::jagged::committed_dense_len(max_blocks << LOG_STACK, LOG_STACK) >> LOG_STACK;
    let mut out: Vec<usize> = (1..=4).filter(|b| *b <= top).collect();
    let mut b = 8;
    while b <= top {
        out.push(b);
        b += 8;
    }
    out
}

impl ZKMProofShape {
    /// The enumerable shapes that need VK setup: compose, deferred and shrink.
    ///
    /// These key on the children's PIN CLASSES, which the machine fixes.  No
    /// core shape configuration is taken because none is consulted: the
    /// normalize shapes that WOULD have depended on core workload data are not
    /// enumerated at all, being collected from real proofs instead, for the
    /// reason the body records.
    pub fn generate<'a>(
        recursion_shape_config: &'a RecursionShapeConfig<KoalaBear, CompressAir<KoalaBear>>,
        reduce_batch_size: usize,
    ) -> impl Iterator<Item = Self> + 'a {
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

        let tuples = |arity: usize| -> Vec<Vec<OrderedShape>> {
            recursion_shape_config
                .get_all_shape_combinations(arity)
                .map(|mut t| {
                    for os in t.iter_mut() {
                        os.inner.sort();
                    }
                    t
                })
                .collect()
        };
        let arity_compress_shapes: Vec<Self> = {
            let mut out = Vec::new();
            for arity in 1..=reduce_batch_size {
                for t in tuples(arity) {
                    out.push(Self::Compress(t.clone()));
                    out.push(Self::CompressRoot(t));
                }
            }
            out
        };
        let deferred_shapes: Vec<Self> = {
            let mut out = Vec::new();
            for arity in 1..=reduce_batch_size {
                for t in tuples(arity) {
                    out.push(Self::Deferred(t));
                }
            }
            out
        };
        let shrink_shapes: Vec<Self> =
            compress_child_classes.last().map(|os| Self::Shrink(os.clone())).into_iter().collect();

        arity_compress_shapes.into_iter().chain(deferred_shapes).chain(shrink_shapes)
    }

    /// Every shape the vk map is built from: the compose/deferred/shrink
    /// classes of [`Self::generate`] and the normalize classes of
    /// [`Self::generate_normalize`].  The map's index space is this
    /// iterator's order, so every tool that addresses shapes by index runs
    /// over it.
    pub fn generate_all<'a>(
        recursion_shape_config: &'a RecursionShapeConfig<KoalaBear, CompressAir<KoalaBear>>,
        reduce_batch_size: usize,
        machine: &CoreMachine,
    ) -> impl Iterator<Item = Self> + 'a {
        Self::generate(recursion_shape_config, reduce_batch_size)
            .chain(Self::generate_normalize(machine))
    }

    /// The normalize (leaf) shapes: one representative per
    /// `(chip cluster, preprocessed bucket, main bucket)` of the core machine —
    /// the three quantities a core shard's proof geometry, hence the normalize
    /// program verifying it, hence its verifying key, are a function of.
    ///
    /// A shard's chip set is one of the machine's clusters
    /// (`zkm_pcs::stacked_shapes::build_mips_machine_shape`); each of its two
    /// committed rounds lands on a block bucket of
    /// `zkm_pcs::jagged::committed_dense_len`; and under
    /// `zkm_pcs::jagged::unpinned_pad_columns` the padding-column count is a
    /// function of the bucket.  Heights themselves are witnessed, so every
    /// height vector inside one class yields the same program.  The
    /// representative keeps the preprocessed chips at their table sizes
    /// (`Program` at `2^k` rows, `Byte` at `2^16`, `Range` at `2^11`) and fills
    /// the rest of the bucket with the cluster's other chips, widest first,
    /// each up to the row cube; a bucket the cluster cannot fill (or cannot
    /// stay under) has no shard and is skipped.
    pub fn generate_normalize(machine: &CoreMachine) -> Vec<Self> {
        let dims = core_chip_dims(machine);
        let block = 1usize << zkm_pcs::stacked_shapes::consts::LOG_STACKING_HEIGHT;
        let max_log_rows = zkm_pcs::stacked_shapes::consts::CORE_MAX_LOG_ROW_COUNT;
        let machine_names: BTreeSet<String> = dims.iter().map(|d| d.name.clone()).collect();
        let clusters: BTreeSet<BTreeSet<String>> =
            zkm_pcs::stacked_shapes::build_mips_machine_shape()
                .chip_clusters
                .into_iter()
                .map(|c| c.intersection(&machine_names).cloned().collect())
                .collect();
        let mut out = Vec::new();
        for cluster in clusters.iter() {
            let mut seen_prep: BTreeSet<usize> = BTreeSet::new();
            for program_log_rows in PROGRAM_LOG_ROWS {
                let table_rows = |name: &str| table_log_rows(name, program_log_rows);
                let fixed: Vec<(&CoreChipDims, usize)> = dims
                    .iter()
                    .filter(|d| cluster.contains(&d.name))
                    .filter_map(|d| table_rows(&d.name).map(|log_h| (d, 1usize << log_h)))
                    .collect();
                let prep_total: usize = fixed.iter().map(|(d, h)| d.prep_width * h).sum();
                let prep_blocks =
                    zkm_pcs::jagged::committed_dense_len(prep_total, LOG_STACK) / block;
                if !seen_prep.insert(prep_blocks) {
                    continue;
                }
                let fixed_main: usize = fixed.iter().map(|(d, h)| d.main_width * h).sum();
                let mut fill: Vec<&CoreChipDims> = dims
                    .iter()
                    .filter(|d| cluster.contains(&d.name) && table_rows(&d.name).is_none())
                    .collect();
                fill.sort_by(|a, b| b.main_width.cmp(&a.main_width).then(a.name.cmp(&b.name)));
                let one_row_each: usize = fill.iter().map(|d| d.main_width).sum();
                let max_main = zkm_pcs::ELEMENT_THRESHOLD + fixed_main + CORE_MAIN_OVERSHOOT_CELLS;
                for blocks in main_buckets(max_main.div_ceil(block)) {
                    let hi = blocks * block;
                    let lo = zkm_pcs::jagged::previous_bucket_blocks(blocks) * block;
                    if fixed_main + one_row_each > hi {
                        continue;
                    }
                    let mut remaining = hi - fixed_main - one_row_each;
                    let mut rows: Vec<(String, usize)> =
                        fixed.iter().map(|(d, h)| (d.name.clone(), *h)).collect();
                    for d in fill.iter() {
                        let extra = (remaining / d.main_width).min((1usize << max_log_rows) - 1);
                        remaining -= d.main_width * extra;
                        rows.push((d.name.clone(), 1 + extra));
                    }
                    let total = hi - remaining;
                    if total <= lo || zkm_pcs::jagged::committed_dense_len(total, LOG_STACK) != hi {
                        continue;
                    }
                    out.push(Self::Normalize(OrderedShape { inner: rows }));
                }
            }
        }
        out
    }

    /// The class of a real core shard at `rows` (name, row count): its chip
    /// set and the committed block counts of its preprocessed and main
    /// rounds — the key [`Self::generate_normalize`] enumerates on.
    pub fn normalize_class(
        machine: &CoreMachine,
        rows: &[(String, usize)],
    ) -> (BTreeSet<String>, usize, usize) {
        let dims = core_chip_dims(machine);
        let block = 1usize << zkm_pcs::stacked_shapes::consts::LOG_STACKING_HEIGHT;
        let (mut prep, mut main) = (0usize, 0usize);
        for (name, h) in rows {
            if let Some(d) = dims.iter().find(|d| d.name == *name) {
                prep += d.prep_width * h;
                main += d.main_width * h;
            }
        }
        (
            rows.iter().map(|(n, _)| n.clone()).collect(),
            zkm_pcs::jagged::committed_dense_len(prep, LOG_STACK) / block,
            zkm_pcs::jagged::committed_dense_len(main, LOG_STACK) / block,
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
            .chain((1..=reduce_batch_size).flat_map(|batch_size| {
                recursion_shape_config.get_all_shape_combinations(batch_size).map(Self::Deferred)
            }))
            .chain(
                recursion_shape_config
                    .get_all_shape_combinations(1)
                    .map(|mut x| Self::Shrink(x.pop().unwrap())),
            )
    }

    pub fn dummy_vk_map(
        recursion_shape_config: &RecursionShapeConfig<KoalaBear, CompressAir<KoalaBear>>,
        reduce_batch_size: usize,
    ) -> BTreeMap<[KoalaBear; DIGEST_SIZE], usize> {
        Self::generate(recursion_shape_config, reduce_batch_size)
            .enumerate()
            .map(|(i, _)| ([KoalaBear::from_usize(i); DIGEST_SIZE], i))
            .collect()
    }
}

impl ZKMCompressProgramShape {
    pub fn from_proof_shape(shape: ZKMProofShape, height: usize) -> Self {
        match shape {
            ZKMProofShape::Recursion(proof_shapes) => {
                Self::Recursion(ZKMRecursionShape { proof_shapes, is_complete: false })
            }
            ZKMProofShape::Deferred(proof_shapes) => {
                Self::Deferred(ZKMDeferredShape::new(proof_shapes.into(), height))
            }
            ZKMProofShape::Compress(proof_shapes) => Self::Compress(ZKMCompressWithVkeyShape {
                compress_shape: proof_shapes.into(),
                merkle_tree_height: height,
            }),
            ZKMProofShape::Shrink(proof_shape) => Self::Shrink(ZKMCompressWithVkeyShape {
                compress_shape: vec![proof_shape].into(),
                merkle_tree_height: height,
            }),
            ZKMProofShape::CompressRoot(proof_shapes) => {
                Self::CompressRoot(ZKMCompressWithVkeyShape {
                    compress_shape: proof_shapes.into(),
                    merkle_tree_height: height,
                })
            }
            ZKMProofShape::Normalize(shape) => {
                Self::Normalize(ZKMNormalizeShape { rows: shape.inner })
            }
        }
    }
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    pub fn program_from_shape(
        &self,
        shape: ZKMCompressProgramShape,
        shrink_shape: Option<RecursionShape>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
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
                let input = ZKMCoreBasefoldWitnessValues::dummy(self.core_prover.machine(), &shape);
                self.recursion_program_basefold(&input).0
            }
            ZKMCompressProgramShape::Deferred(shape) => {
                let input =
                    ZKMDeferredBasefoldWitnessValues::dummy(self.compress_prover.machine(), &shape);
                self.deferred_program_basefold(&input)
            }
            ZKMCompressProgramShape::Compress(shape) => {
                let input =
                    ZKMCompressBasefoldWitnessValues::dummy(self.compress_prover.machine(), &shape);
                self.compose_program_basefold(&input).0
            }
            ZKMCompressProgramShape::Shrink(shape) => {
                let input =
                    ZKMWrapBasefoldWitnessValues::dummy(self.compress_prover.machine(), &shape);
                self.shrink_program_basefold(&input)
            }
            ZKMCompressProgramShape::CompressRoot(shape) => {
                let mut input =
                    ZKMCompressBasefoldWitnessValues::dummy(self.compress_prover.machine(), &shape);
                input.is_complete = true;
                self.compose_program_basefold(&input).0
            }
            ZKMCompressProgramShape::Normalize(shape) => {
                let input = ZKMCoreBasefoldWitnessValues::dummy_rows(
                    self.core_prover.machine(),
                    &shape.rows,
                    false,
                );
                self.recursion_program_basefold(&input).0
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
    /// THE FIXED POINT of the single recursion shape (`RecursionShapeConfig::
    /// default`): every compose and deferred program at arities
    /// `1..=REDUCE_BATCH_SIZE`, built over children padded to the shape,
    /// must itself fit the shape.  Prints the organic rows per chip against
    /// the caps, plus committed cells, so the caps can be re-sized from
    /// measurement (the leaf side is surveyed in production with
    /// `ZIREN_FIXSHAPE_DIAG=1`; see the shape's comment).
    ///
    /// `cargo test -r -p zkm-prover single_shape_fixed_point -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn single_shape_fixed_point() {
        use crate::components::DefaultProverComponents;
        use crate::REDUCE_BATCH_SIZE;
        use p3_air::BaseAir;
        use zkm_pcs::air::MachineAir;
        use zkm_recursion_circuit::machine::{
            build_compose_basefold_recursion_program, build_deferred_basefold_recursion_program,
            PublicValuesOutputDigest, ZKMCompressBasefoldWitnessValues, ZKMCompressShape,
            ZKMCompressWithVkeyShape, ZKMDeferredBasefoldWitnessValues, ZKMDeferredShape,
        };
        use zkm_recursion_core::shape::RecursionShapeConfig;

        let prover = ZKMProver::<DefaultProverComponents>::new();
        let rec_cfg = prover.compress_shape_config.as_ref().expect("compress shape config");
        let shapes = rec_cfg.all_shapes();
        assert_eq!(
            shapes.len(),
            zkm_pcs::jagged::RECURSION_PIN_CLASSES.len(),
            "one dummy shape per pin class, got {}",
            shapes.len()
        );
        let top = shapes.last().expect("a shape per class");
        let os = RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::as_ordered_shape(top);
        let caps: std::collections::BTreeMap<String, usize> =
            top.iter().map(|(n, r)| (n.clone(), *r)).collect();
        let caps = &caps;
        let widths = {
            let mut w = std::collections::BTreeMap::new();
            for c in prover.compress_prover.machine().chips() {
                let name = <_ as MachineAir<KoalaBear>>::name(c);
                let main = <_ as BaseAir<KoalaBear>>::width(&c.air);
                w.insert(name, main + <_ as MachineAir<KoalaBear>>::preprocessed_width(c));
            }
            w
        };
        let cells = |shape: &[(String, usize)]| -> u128 {
            shape.iter().map(|(n, r)| (*widths.get(n).unwrap_or(&1) as u128) * (*r as u128)).sum()
        };
        let mut caps_sorted: Vec<(String, usize)> =
            caps.iter().map(|(n, r)| (n.clone(), *r)).collect();
        caps_sorted.sort();
        tracing::info!("[FIXPOINT] shape = {caps_sorted:?} cells={}", cells(&caps_sorted));

        let max_log_row_count = ZKMProver::<DefaultProverComponents>::pcs_max_log_row_count();
        let machine = prover.compress_prover.machine();
        let mut worst: std::collections::BTreeMap<String, (usize, String)> =
            std::collections::BTreeMap::new();
        let mut overflow = Vec::new();
        for arity in 1..=REDUCE_BATCH_SIZE {
            let compress_shape = ZKMCompressShape::from(vec![os.clone(); arity]);
            for is_complete in [false, true] {
                let shape = ZKMCompressWithVkeyShape {
                    compress_shape: compress_shape.clone(),
                    merkle_tree_height: crate::VK_MERKLE_TREE_HEIGHT,
                };
                let mut witness = ZKMCompressBasefoldWitnessValues::<
                    zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
                >::dummy(machine, &shape);
                witness.is_complete = is_complete;
                let program = build_compose_basefold_recursion_program(
                    machine,
                    &witness,
                    max_log_row_count,
                    prover.vk_verification,
                    PublicValuesOutputDigest::Reduce,
                );
                let heights = CompressAir::<KoalaBear>::heights(&program);
                let tag = format!("compose arity={arity} complete={is_complete}");
                report(&tag, &heights, caps, &mut worst, &mut overflow, &cells);
            }
            let dshape =
                ZKMDeferredShape::new(compress_shape.clone(), crate::VK_MERKLE_TREE_HEIGHT);
            let witness = ZKMDeferredBasefoldWitnessValues::<
                zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
            >::dummy(machine, &dshape);
            let program = build_deferred_basefold_recursion_program(
                machine,
                &witness,
                max_log_row_count,
                prover.vk_verification,
            );
            let heights = CompressAir::<KoalaBear>::heights(&program);
            report(
                &format!("deferred arity={arity}"),
                &heights,
                caps,
                &mut worst,
                &mut overflow,
                &cells,
            );
        }
        for (chip, (rows, tag)) in worst.iter() {
            let cap = caps.get(chip).copied().unwrap_or(0);
            tracing::info!(
                "[FIXPOINT] worst {chip:18} rows={rows:>9} cap={cap:>9} fill={:5.1}%  ({tag})",
                100.0 * *rows as f64 / cap.max(1) as f64
            );
        }
        assert!(overflow.is_empty(), "[FIXPOINT] programs overflow the shape: {overflow:?}");

        fn report(
            tag: &str,
            heights: &[(String, usize)],
            caps: &std::collections::BTreeMap<String, usize>,
            worst: &mut std::collections::BTreeMap<String, (usize, String)>,
            overflow: &mut Vec<String>,
            cells: &dyn Fn(&[(String, usize)]) -> u128,
        ) {
            let mut hs: Vec<(String, usize)> = heights.to_vec();
            hs.sort();
            tracing::info!("[FIXPOINT] {tag}: organic={hs:?} cells={}", cells(&hs));
            for (chip, rows) in hs.iter() {
                let cap = caps.get(chip).copied().unwrap_or(0);
                if *rows > cap {
                    overflow.push(format!("{tag}: {chip} {rows} > {cap}"));
                }
                let e = worst.entry(chip.clone()).or_insert((0, String::new()));
                if *rows > e.0 {
                    *e = (*rows, tag.to_string());
                }
            }
        }
    }

    #[test]
    #[ignore]
    fn compose_vk_height_dependence() {
        use crate::components::DefaultProverComponents;
        use zkm_recursion_circuit::machine::{ZKMCompressShape, ZKMCompressWithVkeyShape};

        let prover = ZKMProver::<DefaultProverComponents>::new();
        let rec_cfg = prover.compress_shape_config.as_ref().unwrap();
        let bands: Vec<OrderedShape> =
            rec_cfg.get_all_shape_combinations(1).map(|mut v| v.pop().unwrap()).collect();
        tracing::info!("[HDEP] bands = {}", bands.len());

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
            let (_pk, vk) = prover.compress_prover.setup(&program.0);
            format!("{:?}", vk.hash_koalabear())
        };

        for arity in [1usize, 4] {
            let mut seen: BTreeMap<String, Vec<usize>> = BTreeMap::new();
            for (i, os) in bands.iter().enumerate() {
                seen.entry(vk_of(os, arity)).or_default().push(i);
            }
            tracing::info!(
                "[HDEP] arity={arity}: {} distinct vks over {} bands",
                seen.len(),
                bands.len()
            );
            for (d, idxs) in &seen {
                tracing::info!("[HDEP]   {d} <- bands {idxs:?}");
            }
        }
    }

    /// Analysis: measure the per-shard normalize band structure
    /// (distinct OrderedShapes per cluster) to size the arity
    /// enumeration against the 2^11 budget.
    #[test]
    #[ignore]
    fn analyze_recursion_band_structure() {
        use crate::CoreSC;
        use std::collections::{BTreeMap, BTreeSet};
        use zkm_core_machine::mips::MipsAir;
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::stacked_shapes::{build_mips_machine_shape, types::consts};

        let core_machine = MipsAir::machine(CoreSC::default());
        let chips_by_name: BTreeMap<String, _> =
            core_machine.chips().iter().map(|c| (c.name(), c)).collect();
        let machine_shape = build_mips_machine_shape();
        tracing::info!("[BAND] clusters = {}", machine_shape.chip_clusters.len());

        let mut total_per_shard_shapes = 0usize;
        let mut per_cluster_shape_counts: Vec<usize> = Vec::new();
        for (ci, cluster) in machine_shape.chip_clusters.iter().enumerate() {
            let names: Vec<String> =
                cluster.iter().filter(|n| chips_by_name.contains_key(*n)).cloned().collect();
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
            tracing::info!(
                "[BAND] cluster {ci}: chips={} fillers={} distinct_OrderedShapes={}",
                names.len(),
                fillers.len(),
                set.len()
            );
        }
        tracing::info!("[BAND] TOTAL per-shard OrderedShapes = {total_per_shard_shapes}");
        let s = total_per_shard_shapes;
        tracing::info!("[BAND] uniform-replication arity 1..=4: {} (= {} per-shard x 4)", s * 4, s);
        let per_cluster_uniform: usize = per_cluster_shape_counts.iter().map(|c| c * 4).sum();
        tracing::info!("[BAND] per-cluster uniform arity 1..=4 = {per_cluster_uniform}");
        tracing::info!("[BAND] nonempty clusters = {}", per_cluster_shape_counts.len());
    }

    /// Analysis: dedup the per-shard OrderedShapes by their
    /// normalize equivalence class — (chip-set, log_dense) — by building
    /// the dummy bundle for each shape and reading packing.log_dense_size.
    /// Tells us the true distinct per-shard normalize class count, which
    /// bounds the arity-replication enumeration.
    #[test]
    #[ignore]
    #[serial_test::serial]
    fn analyze_recursion_logdense_classes() {
        use crate::components::DefaultProverComponents;
        use std::collections::{BTreeMap, BTreeSet};
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::shard_level::shard_proof::EvaluationProof;
        use zkm_pcs::stacked_shapes::{build_mips_machine_shape, types::consts};
        use zkm_recursion_circuit::machine::ZKMCoreBasefoldWitnessValues;

        let prover = ZKMProver::<DefaultProverComponents>::new();
        let machine = prover.core_prover.machine();
        let chips_by_name: BTreeMap<String, _> =
            machine.chips().iter().map(|c| (<_ as MachineAir<KoalaBear>>::name(c), c)).collect();
        let machine_shape = build_mips_machine_shape();

        let mut classes: BTreeSet<(Vec<String>, usize)> = BTreeSet::new();
        let mut total_built = 0usize;
        let mut total_failed = 0usize;
        for (ci, cluster) in machine_shape.chip_clusters.iter().enumerate() {
            let names: Vec<String> =
                cluster.iter().filter(|n| chips_by_name.contains_key(*n)).cloned().collect();
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
            tracing::info!(
                "[LD] cluster {ci}: chips={} distinct_log_dense={} bands={:?}",
                names.len(),
                cluster_classes.len(),
                cluster_classes
            );
        }
        tracing::warn!(
            "[LD] TOTAL distinct (chip_set, log_dense) classes = {} (built={total_built} failed={total_failed})",
            classes.len()
        );
        tracing::info!("[LD] uniform-replication arity 1..=4 on classes = {}", classes.len() * 4);
    }

    /// `generate` emits NO normalize shapes, and every shape it does emit is
    /// one the machine determines rather than the block.
    ///
    /// A normalize program is selected by its core shard's chip NAME SET, and
    /// which chips a shard carries is a property of the block it executed, so
    /// enumerating over the machine's chips cannot predict them: doing so
    /// produced 7,834 keys covering 9 of the 57 one real block needed. Those
    /// keys are collected (`ZIREN_VK_COLLECT`), not enumerated.
    ///
    /// Compose, deferred and shrink stay enumerable because they key on the
    /// children's PIN CLASSES, which `RECURSION_PIN_CLASSES` fixes — rows and
    /// chip sets do not enter.
    #[test]
    fn generate_emits_no_normalize_shapes() {
        use crate::REDUCE_BATCH_SIZE;
        let recursion_shape_config = RecursionShapeConfig::default();
        let all: Vec<ZKMProofShape> =
            ZKMProofShape::generate(&recursion_shape_config, REDUCE_BATCH_SIZE).collect();

        let normalize = all.iter().filter(|s| matches!(s, ZKMProofShape::Recursion(_))).count();
        assert_eq!(
            normalize, 0,
            "normalize keys are collected from real proofs, not enumerated; \
             emitting {normalize} of them is weight without coverage",
        );

        let compress = all.iter().filter(|s| matches!(s, ZKMProofShape::Compress(_))).count();
        let deferred = all.iter().filter(|s| matches!(s, ZKMProofShape::Deferred(_))).count();
        let shrink = all.iter().filter(|s| matches!(s, ZKMProofShape::Shrink(_))).count();
        let root = all.iter().filter(|s| matches!(s, ZKMProofShape::CompressRoot(_))).count();
        assert!(compress > 0 && deferred > 0 && shrink > 0, "the enumerable tail must remain");
        assert_eq!(root, compress, "every compose tuple has its closing variant");
        assert_eq!(all.len(), compress + root + deferred + shrink, "no other variant is emitted");
        tracing::info!(
            "[ENUM] compress={compress} root={root} deferred={deferred} shrink={shrink}"
        );
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
        use std::collections::{BTreeMap, BTreeSet};
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::stacked_shapes::{build_mips_machine_shape, types::consts};
        use zkm_recursion_circuit::machine::{ZKMCoreBasefoldWitnessValues, ZKMRecursionShape};

        let prover = ZKMProver::<DefaultProverComponents>::new();
        let machine = prover.core_prover.machine();
        let chips_by_name: BTreeMap<String, _> =
            machine.chips().iter().map(|c| (<_ as MachineAir<KoalaBear>>::name(c), c)).collect();
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
            if total == 0 {
                0
            } else {
                total.next_power_of_two().trailing_zeros() as usize
            }
        };

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
        let names: Vec<String> =
            cluster.iter().filter(|n| chips_by_name.contains_key(*n)).cloned().collect();
        let fillers: std::collections::HashSet<&String> = names
            .iter()
            .filter(|n| {
                n.as_str() != "Byte" && chips_by_name[n.as_str()].num_sent_byte_lookups() == 0
            })
            .collect();
        let mut band_reps: BTreeMap<usize, OrderedShape> = BTreeMap::new();
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
            band_reps.entry(log_dense_of(&os)).or_insert(os);
        }
        let bands: Vec<usize> = band_reps.keys().cloned().collect();
        tracing::info!("[HETERO] cluster chips={} bands={:?}", names.len(), bands);

        let setup_vk = |shape: &ZKMRecursionShape| -> Option<[KoalaBear; DIGEST_SIZE]> {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let d = ZKMCoreBasefoldWitnessValues::dummy(machine, shape);
                let p = prover.recursion_program_basefold(&d);
                prover.compress_prover.setup(&p.0).1.hash_koalabear()
            }))
            .ok()
        };
        let mut uniform_vks: BTreeSet<[KoalaBear; DIGEST_SIZE]> = BTreeSet::new();
        for (b, os) in band_reps.iter() {
            if *b > 30 {
                continue;
            }
            if let Some(vk) = setup_vk(&ZKMRecursionShape {
                proof_shapes: vec![os.clone(); 2],
                is_complete: true,
            }) {
                uniform_vks.insert(vk);
            }
        }
        tracing::info!("[HETERO] uniform arity-2 VKs (this cluster) = {}", uniform_vks.len());

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
        tracing::info!(
            "[HETERO] heterogeneous arity-2 batches built={hetero_total} MISSED_by_uniform_enum={hetero_missed}"
        );
        tracing::info!(
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
        let recursion_shape_config = RecursionShapeConfig::default();
        let reduce_batch_size = 2;
        let all_shapes = ZKMProofShape::generate(&recursion_shape_config, reduce_batch_size)
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
        let recursion_shape_config = RecursionShapeConfig::default();
        let all_shapes: BTreeSet<_> =
            ZKMProofShape::generate(&recursion_shape_config, REDUCE_BATCH_SIZE).collect();
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

        tracing::info!("[VKROOT] REDUCE_BATCH_SIZE={REDUCE_BATCH_SIZE}");
        tracing::info!("[VKROOT] num_shapes={num_shapes} (recursion={recursion_count} compress={compress_count} deferred={deferred_count} shrink={shrink_count})");
        tracing::info!("[VKROOT] enum_height = ceil(log2({num_shapes})) = {enum_height}");
        tracing::info!(
            "[VKROOT] map_size={map_size}  prod_height = ceil(log2({map_size})) = {prod_height}"
        );
        tracing::info!(
            "[VKROOT] HEIGHTS {}",
            if enum_height == prod_height {
                "MATCH ✓ (no height circularity)"
            } else {
                "MISMATCH ✗ (every key baked at wrong height)"
            }
        );
    }
}

#[cfg(test)]
mod normalize_enumeration_tests {
    use super::*;
    use crate::components::DefaultProverComponents;
    use crate::REDUCE_BATCH_SIZE;

    /// One real leaf of the production census: whether it was the first shard
    /// and its per-chip row counts.
    struct CensusLeaf {
        first: bool,
        rows: Vec<(String, usize)>,
    }

    fn parse_census(path: &str) -> Vec<CensusLeaf> {
        let text = std::fs::read_to_string(path).expect("census file");
        let mut seen: BTreeSet<(bool, String)> = BTreeSet::new();
        let mut out = Vec::new();
        for line in text.lines() {
            let field = |key: &str| -> Option<&str> {
                line.split_whitespace().find_map(|w| w.strip_prefix(key))
            };
            let (Some(first), Some(heights)) = (field("first="), field("heights=")) else {
                continue;
            };
            let first = first == "true";
            if !seen.insert((first, heights.to_string())) {
                continue;
            }
            let rows: Vec<(String, usize)> = heights
                .split(',')
                .filter_map(|kv| kv.split_once(':'))
                .map(|(n, h)| (n.to_string(), h.parse().expect("row count")))
                .collect();
            out.push(CensusLeaf { first, rows });
        }
        out
    }

    fn shape_rows(shape: &ZKMProofShape) -> Vec<(String, usize)> {
        let ZKMProofShape::Normalize(os) = shape else { panic!("not a normalize shape") };
        os.inner.clone()
    }

    /// The enumeration is one shape per class and stays inside the tree.
    #[test]
    fn normalize_enumeration_is_one_per_class() {
        zkm_core_machine::utils::setup_logger();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let machine = prover.core_prover.machine();
        let shapes = ZKMProofShape::generate_normalize(machine);
        let mut classes = BTreeSet::new();
        for shape in shapes.iter() {
            let class = ZKMProofShape::normalize_class(machine, &shape_rows(shape));
            assert!(classes.insert(class.clone()), "class enumerated twice: {class:?}");
        }
        let compose =
            ZKMProofShape::generate(&RecursionShapeConfig::default(), REDUCE_BATCH_SIZE).count();
        tracing::info!(
            "normalize shapes {} + compose/deferred/shrink {} of 2^{}",
            shapes.len(),
            compose,
            crate::VK_MERKLE_TREE_HEIGHT
        );
        assert!(shapes.len() + compose <= 1 << crate::VK_MERKLE_TREE_HEIGHT);
    }

    /// Every leaf the production census recorded (`ZIREN_CENSUS_FILE`, lines
    /// with `first=` and `heights=`) falls in an enumerated class, and its
    /// normalize program is byte-identical to the class representative's; the
    /// first-shard flag, being a witness, does not move the program either.
    ///
    /// `ZIREN_CENSUS_FILE=census.txt cargo test -r -p zkm-prover
    ///  normalize_enumeration_covers_census -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn normalize_enumeration_covers_census() {
        zkm_core_machine::utils::setup_logger();
        let path = std::env::var("ZIREN_CENSUS_FILE").expect("ZIREN_CENSUS_FILE");
        let per_class: usize =
            std::env::var("ZIREN_CENSUS_PER_CLASS").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
        let threads: usize =
            std::env::var("ZIREN_CENSUS_THREADS").ok().and_then(|s| s.parse().ok()).unwrap_or(8);
        let leaves = parse_census(&path);
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let machine = prover.core_prover.machine();
        let representatives: BTreeMap<_, ZKMProofShape> =
            ZKMProofShape::generate_normalize(machine)
                .into_iter()
                .map(|s| (ZKMProofShape::normalize_class(machine, &shape_rows(&s)), s))
                .collect();

        let mut by_class: BTreeMap<_, Vec<&CensusLeaf>> = BTreeMap::new();
        for leaf in leaves.iter() {
            by_class
                .entry(ZKMProofShape::normalize_class(machine, &leaf.rows))
                .or_default()
                .push(leaf);
        }
        let missing: Vec<_> =
            by_class.keys().filter(|c| !representatives.contains_key(*c)).cloned().collect();
        for class in missing.iter() {
            tracing::error!(
                "class not enumerated: chips {} prep {} main {}",
                class.0.len(),
                class.1,
                class.2
            );
        }

        let jobs: Vec<(&CensusLeaf, &ZKMProofShape)> = by_class
            .iter()
            .filter_map(|(class, ls)| representatives.get(class).map(|rep| (ls, rep)))
            .flat_map(|(ls, rep)| ls.iter().take(per_class).map(move |l| (*l, rep)))
            .collect();
        let mismatched = std::sync::atomic::AtomicUsize::new(0);
        let first_moved = std::sync::atomic::AtomicUsize::new(0);
        let next = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((leaf, rep)) = jobs.get(i) else { break };
                    let mut real =
                        ZKMCoreBasefoldWitnessValues::dummy_rows(machine, &leaf.rows, false);
                    real.is_first_shard = leaf.first;
                    let (_, real_digest) = prover.recursion_program_basefold(&real);
                    real.is_first_shard = !leaf.first;
                    let (_, flipped_digest) = prover.recursion_program_basefold(&real);
                    let rep_input =
                        ZKMCoreBasefoldWitnessValues::dummy_rows(machine, &shape_rows(rep), false);
                    let (_, rep_digest) = prover.recursion_program_basefold(&rep_input);
                    if real_digest != rep_digest {
                        mismatched.fetch_add(1, Ordering::Relaxed);
                        tracing::error!(
                            "program differs from its class representative: {:?}",
                            leaf.rows
                        );
                    }
                    if real_digest != flipped_digest {
                        first_moved.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        let mismatched = mismatched.load(Ordering::Relaxed);
        let first_moved = first_moved.load(Ordering::Relaxed);
        tracing::info!(
            "census leaves {} in {} classes; representatives {}; checked {}; missing classes {}; \
             mismatched {}; first-flag moved {}",
            leaves.len(),
            by_class.len(),
            representatives.len(),
            jobs.len(),
            missing.len(),
            mismatched,
            first_moved
        );
        assert!(missing.is_empty() && mismatched == 0 && first_moved == 0);
    }
}

#[cfg(test)]
mod shape_program_dump {
    use super::*;
    use crate::components::DefaultProverComponents;
    use crate::REDUCE_BATCH_SIZE;

    /// Build the programs of a range of enumerated shapes in one process and
    /// record what each verifying key is a function of — program bytes
    /// (digested), organic heights, vk digest — so two processes, or two
    /// build orders, can be compared shape by shape.  `ZIREN_SHAPE_RANGE`
    /// (`start..end`) selects the shapes, `ZIREN_DUMP_DIR` receives the
    /// serialized programs.
    #[test]
    #[ignore]
    fn dump_shape_program() {
        zkm_core_machine::utils::setup_logger();
        let range = std::env::var("ZIREN_SHAPE_RANGE").expect("ZIREN_SHAPE_RANGE");
        let (lo, hi) = range.split_once("..").expect("start..end");
        let (lo, hi): (usize, usize) = (lo.parse().unwrap(), hi.parse().unwrap());
        let dir = std::env::var("ZIREN_DUMP_DIR").expect("ZIREN_DUMP_DIR");
        let prover = ZKMProver::<DefaultProverComponents>::new_with_vk_verification(Some(true));
        let rec = prover.compress_shape_config.as_ref().expect("recursion shape config");
        let all: Vec<ZKMProofShape> =
            ZKMProofShape::generate_all(rec, REDUCE_BATCH_SIZE, prover.core_prover.machine())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
        for (index, shape) in all.iter().enumerate().skip(lo).take(hi - lo) {
            let shape = shape.clone();
            let program_shape =
                ZKMCompressProgramShape::from_proof_shape(shape, crate::VK_MERKLE_TREE_HEIGHT);
            let program = prover.program_from_shape(program_shape, None);
            let heights =
                RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::program_heights(
                    &program,
                );
            let bytes = bincode::serialize(&*program).expect("serialize program");
            let program_digest = {
                use std::hash::{Hash, Hasher};
                let mut h = std::collections::hash_map::DefaultHasher::new();
                bytes.hash(&mut h);
                h.finish()
            };
            std::fs::write(format!("{dir}/p{index}.bin"), &bytes).expect("write dump");
            let (_, vk) = prover.compress_prover.setup(&program);
            let digest = vk.hash_koalabear();
            tracing::info!(
                "DUMP shape={index} program={program_digest:016x} bytes={} vk={digest:?} heights={heights:?}",
                bytes.len()
            );
        }
    }
}

#[cfg(test)]
mod dumped_program_diff {
    /// Compare two serialized recursion programs (`ZIREN_DUMP_A`,
    /// `ZIREN_DUMP_B`) block by block and report the first instruction that
    /// differs, so a program that is not reproducible across processes can be
    /// traced to the construction step that varies.
    #[test]
    #[ignore]
    fn diff_dumped_programs() {
        use p3_koala_bear::KoalaBear;
        use zkm_recursion_core::RecursionProgram;
        zkm_core_machine::utils::setup_logger();
        let load = |k: &str| -> RecursionProgram<KoalaBear> {
            let bytes = std::fs::read(std::env::var(k).expect(k)).expect("read dump");
            bincode::deserialize(&bytes).expect("program")
        };
        let (a, b) = (load("ZIREN_DUMP_A"), load("ZIREN_DUMP_B"));
        tracing::info!(
            "memory {} vs {}; blocks {} vs {}",
            a.total_memory,
            b.total_memory,
            a.seq_blocks.seq_blocks.len(),
            b.seq_blocks.seq_blocks.len()
        );
        let (da, db) = (format!("{:?}", a.seq_blocks), format!("{:?}", b.seq_blocks));
        let first =
            da.bytes().zip(db.bytes()).position(|(x, y)| x != y).unwrap_or(da.len().min(db.len()));
        let lo = first.saturating_sub(600);
        tracing::info!(
            "debug lengths {} vs {}; first difference at byte {first}",
            da.len(),
            db.len()
        );
        tracing::info!("A: …{}…", &da[lo..(first + 400).min(da.len())]);
        tracing::info!("B: …{}…", &db[lo..(first + 400).min(db.len())]);
        if let Ok(addr) = std::env::var("ZIREN_DIFF_ADDR") {
            let needle = format!("Address({addr})");
            for (tag, d) in [("A", &da), ("B", &db)] {
                let hits: Vec<usize> = d.match_indices(&needle).map(|(i, _)| i).collect();
                tracing::info!("{tag}: {} occurrences of {needle}", hits.len());
                for i in hits {
                    let lo = i.saturating_sub(260);
                    tracing::info!("{tag}@{i}: …{}…", &d[lo..(i + 120).min(d.len())]);
                }
            }
        }
    }
}
