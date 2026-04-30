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
use zkm_stark::{shape::OrderedShape, MachineProver, DIGEST_SIZE};

use crate::{components::ZKMProverComponents, CompressAir, HashableKey, ShrinkAir, ZKMProver};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ZKMProofShape {
    Recursion(OrderedShape),
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

    // The Merkle tree height.
    let height = num_shapes.next_power_of_two().ilog2() as usize;

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
        let height = dummy_set.len().next_power_of_two().ilog2() as usize;
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

        let height = num_shapes.next_power_of_two().ilog2() as usize;
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
    /// `zkm_stark::stacked_shapes::create_all_input_shapes` — ≤ 5,000
    /// `CoreProofShape`s that, after `to_ordered_shape`'s
    /// uniform-area projection + dedup, collapse to a much smaller
    /// per-chip `OrderedShape` set (~13-30 unique).  This
    /// replaces Ziren's legacy ~1.25M-shape per-chip cartesian
    /// (`CoreShapeConfig::all_shapes`); task #32 commits to
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
        use zkm_stark::stacked_shapes::{build_mips_machine_shape, create_all_input_shapes};
        use zkm_stark::air::MachineAir;
        use crate::CoreSC;

        // Real chips from the live MIPS machine — needed for two
        // post-processing steps on each `to_ordered_shape()` output:
        //
        //   1. **Name filter**: drop chip names from
        //      `stacked_shapes/enumerate.rs` that don't match a real
        //      `MachineAir::name()` (the enumerate list has
        //      `Bls12381Add` etc., the machine has `Bls12381AddAssign`).
        //      Without this, `dummy_vk_and_shard_proof` panics in
        //      `zip_eq` when `shard_chips_ordered` returns fewer chips
        //      than the shape names.
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

        let machine_shape = build_mips_machine_shape();
        let small_shapes: Vec<OrderedShape> = create_all_input_shapes(&machine_shape)
            .into_iter()
            .map(|cps| {
                let mut shape = cps.to_ordered_shape();
                shape.inner.retain(|(name, _)| chips_by_name.contains_key(name));

                // Apply per-shape byte-lookup cap.
                let total_byte_lookups: u64 = shape
                    .inner
                    .iter()
                    .map(|(name, _)| chips_by_name[name].num_sent_byte_lookups() as u64)
                    .sum();
                if total_byte_lookups > 0 {
                    let max_log_height: u32 =
                        (SAFE_BYTE_LOOKUP_BUDGET / total_byte_lookups.max(1)).trailing_zeros();
                    for entry in &mut shape.inner {
                        entry.1 = entry.1.min(max_log_height as usize);
                    }
                }

                shape
            })
            .filter(|shape| !shape.inner.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        small_shapes
            .into_iter()
            .map(Self::Recursion)
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

    pub fn generate_compress_shapes(
        recursion_shape_config: &'_ RecursionShapeConfig<KoalaBear, CompressAir<KoalaBear>>,
        reduce_batch_size: usize,
    ) -> impl Iterator<Item = Vec<OrderedShape>> + '_ {
        recursion_shape_config.get_all_shape_combinations(reduce_batch_size)
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
            .map(|core_shape| {
                Self::Recursion(OrderedShape {
                    inner: core_shape.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
                })
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
            ZKMProofShape::Recursion(proof_shape) => Self::Recursion(proof_shape.into()),
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
        // META #59 (#52): when ZIREN_USE_BASEFOLD=1, dispatch to the
        // basefold program builders so cached shapes regenerate against
        // the basefold pipeline. The basefold dummys produce structurally
        // matching witnesses (chip_cumulative_sums.len() == chips.len()
        // per shard) — see `dummy_basefold_vk_and_shard_proof` in
        // crates/recursion/circuit/src/stark.rs.
        let use_basefold = std::env::var("ZIREN_USE_BASEFOLD")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if use_basefold {
            return self.program_from_shape_basefold(shape);
        }
        match shape {
            ZKMCompressProgramShape::Recursion(shape) => {
                let input = ZKMRecursionWitnessValues::dummy(self.core_prover.machine(), &shape);
                self.recursion_program(&input)
            }
            ZKMCompressProgramShape::Deferred(shape) => {
                let input = ZKMDeferredWitnessValues::dummy(self.compress_prover.machine(), &shape);
                self.deferred_program(&input)
            }
            ZKMCompressProgramShape::Compress(shape) => {
                let input =
                    ZKMCompressWithVKeyWitnessValues::dummy(self.compress_prover.machine(), &shape);
                self.compress_program(&input)
            }
            ZKMCompressProgramShape::Shrink(shape) => {
                let input =
                    ZKMCompressWithVKeyWitnessValues::dummy(self.compress_prover.machine(), &shape);
                self.shrink_program(
                    shrink_shape.unwrap_or_else(ShrinkAir::<KoalaBear>::shrink_shape),
                    &input,
                )
            }
        }
    }

    /// Basefold companion to [`Self::program_from_shape`]. Builds a
    /// recursion program from a cached shape using the basefold-pipeline
    /// program builders (`recursion_program_basefold`,
    /// `compose_program_basefold`, etc.) instead of the legacy FRI ones.
    ///
    /// META #59 step 4 (#52). Used by `build_compress_vks` to regenerate
    /// `vk_map.bin` against basefold programs when `ZIREN_USE_BASEFOLD=1`.
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
                let input = ZKMCompressBasefoldWitnessValues::dummy(
                    self.compress_prover.machine(),
                    &shape.compress_shape,
                );
                self.compose_program_basefold(&input)
            }
            ZKMCompressProgramShape::Shrink(shape) => {
                let input = ZKMWrapBasefoldWitnessValues::dummy(
                    self.compress_prover.machine(),
                    &shape.compress_shape,
                );
                self.shrink_program_basefold(&input)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Task #32: the Recursion shape count is now strictly bounded
    /// by stacked_shapes' size-class quantization.  Before this change,
    /// `ZKMProofShape::generate` sourced ~1.25M shapes from the
    /// per-chip cartesian `CoreShapeConfig::all_shapes`; now it
    /// sources from `create_all_input_shapes` followed by
    /// `to_ordered_shape` dedup, yielding a much smaller set.
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

        // stacked_shapes → to_ordered_shape with uniform-area projection
        // and dedup collapses to ≤ ~30 unique OrderedShapes (one per
        // chip cluster × band that maps to a distinct log_height).
        assert!(
            recursion_count <= 100,
            "Recursion shape count {} should be ≤ 100 (stacked_shapes path)",
            recursion_count
        );
        assert!(
            recursion_count >= 1,
            "generate should produce at least 1 Recursion shape"
        );
    }
}
