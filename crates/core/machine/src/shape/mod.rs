use std::collections::BTreeMap;
use std::str::FromStr;

use hashbrown::HashMap;
use itertools::Itertools;
use num::Integer;
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use p3_util::log2_ceil_usize;
use thiserror::Error;

use zkm_core_executor::{ExecutionRecord, MipsAirId, Program};
use zkm_stark::{
    air::MachineAir,
    shape::{OrderedShape, Shape, ShapeCluster},
    MachineRecord,
};

use super::mips::mips_chips::{ByteChip, ProgramChip, SyscallChip};
use crate::{
    global::GlobalChip,
    memory::{MemoryLocalChip, NUM_LOCAL_MEMORY_ENTRIES_PER_ROW},
    mips::MipsAir,
};

/// The set of maximal shapes.
///
/// These shapes define the "worst-case" shapes for typical shards that are proving `mips`
/// execution. We use a variant of a cartesian product of the allowed log heights to generate
/// smaller shapes from these ones.
const MAXIMAL_SHAPES: &[u8] = include_bytes!("maximal_shapes.json");

/// The set of tiny shapes.
///
/// These shapes are used to optimize performance for smaller programs.
const SMALL_SHAPES: &[u8] = include_bytes!("small_shapes.json");

/// A configuration for what shapes are allowed to be used by the prover.
#[derive(Debug)]
pub struct CoreShapeConfig<F: PrimeField32> {
    partial_preprocessed_shapes: ShapeCluster<MipsAirId>,
    partial_core_shapes: BTreeMap<usize, Vec<ShapeCluster<MipsAirId>>>,
    partial_memory_shapes: ShapeCluster<MipsAirId>,
    partial_precompile_shapes: HashMap<MipsAir<F>, (usize, Vec<usize>)>,
    partial_small_shapes: Vec<ShapeCluster<MipsAirId>>,
    costs: HashMap<MipsAirId, usize>,
}

impl<F: PrimeField32> CoreShapeConfig<F> {
    /// Fix the preprocessed shape of the proof.
    pub fn fix_preprocessed_shape(&self, program: &mut Program) -> Result<(), CoreShapeError> {
        // If the preprocessed shape is already fixed, return an error.
        if program.preprocessed_shape.is_some() {
            return Err(CoreShapeError::PreprocessedShapeAlreadyFixed);
        }

        // Get the heights of the preprocessed chips and find a shape that fits.
        let preprocessed_heights = MipsAir::<F>::preprocessed_heights(program);
        let preprocessed_shape = self
            .partial_preprocessed_shapes
            .find_shape(&preprocessed_heights)
            .ok_or(CoreShapeError::PreprocessedShapeError)?;

        // Set the preprocessed shape.
        program.preprocessed_shape = Some(preprocessed_shape);

        Ok(())
    }

    /// Fix the shape of the proof.
    pub fn fix_shape(&self, record: &mut ExecutionRecord) -> Result<(), CoreShapeError> {
        if record.program.preprocessed_shape.is_none() {
            return Err(CoreShapeError::PreprocessedShapeMissing);
        }
        if record.shape.is_some() {
            return Err(CoreShapeError::ShapeAlreadyFixed);
        }

        // Set the shape of the chips with prepcoded shapes to match the preprocessed shape from the
        // program.
        record.shape.clone_from(&record.program.preprocessed_shape);

        // If this is a packed "core" record where the cpu events are alongside the memory init and
        // finalize events, try to fix the shape using the tiny shapes.
        if record.contains_cpu()
            && (!record.global_memory_finalize_events.is_empty()
                || !record.global_memory_initialize_events.is_empty())
        {
            // Get the heights of the core airs in the record.
            let mut heights = MipsAir::<F>::core_heights(record);
            heights.extend(MipsAir::<F>::memory_heights(record));

            // Try to find a shape fitting within at least one of the candidate shapes.
            let mut minimal_shape = None;
            let mut minimal_area = usize::MAX;
            let mut minimal_cluster = None;
            for (i, cluster) in self.partial_small_shapes.iter().enumerate() {
                if let Some(shape) = cluster.find_shape(&heights) {
                    if self.estimate_lde_size(&shape) < minimal_area {
                        minimal_area = self.estimate_lde_size(&shape);
                        minimal_shape = Some(shape);
                        minimal_cluster = Some(i);
                    }
                }
            }

            if let Some(shape) = minimal_shape {
                let shard = record.public_values.shard;
                tracing::info!(
                    "Shard Lifted: Index={}, Cluster={}",
                    shard,
                    minimal_cluster.unwrap()
                );
                for (air, height) in heights.iter() {
                    if shape.contains(air) {
                        tracing::info!(
                            "Chip {:<20}: {:<3} -> {:<3}",
                            air,
                            log2_ceil_usize(*height),
                            shape.log2_height(air).unwrap(),
                        );
                    }
                }
                record.shape.as_mut().unwrap().extend(shape);
                return Ok(());
            }

            // Fallback: generate a dynamic shape from the actual heights.
            let dynamic_shape = Self::dynamic_shape_from_heights(&heights);
            tracing::warn!(
                "No small shape fits shard {}. Using dynamic shape (VK may not be in vk_map.bin).",
                record.public_values.shard
            );
            record.shape.as_mut().unwrap().extend(dynamic_shape);
            return Ok(());
        }

        // If this is a normal "core" record, try to fix the shape as such.
        if record.contains_cpu() {
            // Get the heights of the core airs in the record.
            let heights = MipsAir::<F>::core_heights(record);

            // Try to find the smallest shape fitting within at least one of the candidate shapes.
            let log2_shard_size = record.cpu_events.len().next_power_of_two().ilog2() as usize;
            let mut minimal_shape = None;
            let mut minimal_area = usize::MAX;
            let mut minimal_cluster = None;
            for (_, clusters) in self.partial_core_shapes.range(log2_shard_size..) {
                for (i, cluster) in clusters.iter().enumerate() {
                    if let Some(shape) = cluster.find_shape(&heights) {
                        if self.estimate_lde_size(&shape) < minimal_area {
                            minimal_area = self.estimate_lde_size(&shape);
                            minimal_shape = Some(shape.clone());
                            minimal_cluster = Some(i);
                        }
                    }
                }
            }

            if let Some(shape) = minimal_shape {
                let shard = record.public_values.shard;
                let cluster = minimal_cluster.unwrap();
                tracing::info!("Shard Lifted: Index={}, Cluster={}", shard, cluster);

                for (air, height) in heights.iter() {
                    if shape.contains(air) {
                        tracing::info!(
                            "Chip {:<20}: {:<3} -> {:<3}",
                            air,
                            log2_ceil_usize(*height),
                            shape.log2_height(air).unwrap(),
                        );
                    }
                }
                record.shape.as_mut().unwrap().extend(shape);
                return Ok(());
            }

            // Fallback: generate a dynamic shape from the actual heights.
            tracing::warn!(
                "No core shape found for shard {}. Using dynamic shape (VK may not be in vk_map.bin).",
                record.public_values.shard
            );
            let dynamic_shape = Self::dynamic_shape_from_heights(&heights);
            record.shape.as_mut().unwrap().extend(dynamic_shape);
            return Ok(());
        }

        // If the record is a does not have the CPU chip and is a global memory init/finalize
        // record, try to fix the shape as such.
        if !record.global_memory_initialize_events.is_empty()
            || !record.global_memory_finalize_events.is_empty()
        {
            let heights = MipsAir::<F>::memory_heights(record);
            if let Some(shape) = self.partial_memory_shapes.find_shape(&heights) {
                record.shape.as_mut().unwrap().extend(shape);
                return Ok(());
            }

            // Fallback: generate a dynamic shape from the actual heights.
            tracing::warn!(
                "No memory shape found for shard {}. Using dynamic shape (VK may not be in vk_map.bin).",
                record.public_values.shard
            );
            let dynamic_shape = Self::dynamic_shape_from_heights(&heights);
            record.shape.as_mut().unwrap().extend(dynamic_shape);
            return Ok(());
        }

        // Try to fix the shape as a precompile record.
        for (air, (memory_events_per_row, allowed_log2_heights)) in
            self.partial_precompile_shapes.iter()
        {
            if let Some((height, num_memory_local_events, num_global_events)) =
                air.precompile_heights(record)
            {
                for allowed_log2_height in allowed_log2_heights {
                    let allowed_height = 1 << allowed_log2_height;
                    if height <= allowed_height {
                        for shape in self.get_precompile_shapes(
                            air,
                            *memory_events_per_row,
                            *allowed_log2_height,
                        ) {
                            let mem_events_height = shape[2].1;
                            let global_events_height = shape[3].1;
                            if num_memory_local_events.div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
                                <= (1 << mem_events_height)
                                && num_global_events <= (1 << global_events_height)
                            {
                                record.shape.as_mut().unwrap().extend(
                                    shape.iter().map(|x| (MipsAirId::from_str(&x.0).unwrap(), x.1)),
                                );
                                return Ok(());
                            }
                        }
                    }
                }

                // Fallback: generate a dynamic precompile shape.
                tracing::warn!(
                    "No precompile shape found for {:?}. Using dynamic shape (VK may not be in vk_map.bin).",
                    air.name()
                );
                let log2_height = log2_ceil_usize(height);
                let log2_mem = log2_ceil_usize(
                    num_memory_local_events.div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW),
                );
                let log2_global = log2_ceil_usize(num_global_events);
                let precompile_shape = self.get_precompile_shapes(
                    air,
                    *memory_events_per_row,
                    log2_height,
                );
                if let Some(shape) = precompile_shape.into_iter().find(|shape| {
                    let mem_h = shape[2].1;
                    let global_h = shape[3].1;
                    log2_mem <= mem_h && log2_global <= global_h
                }) {
                    record.shape.as_mut().unwrap().extend(
                        shape.iter().map(|x| (MipsAirId::from_str(&x.0).unwrap(), x.1)),
                    );
                    return Ok(());
                }

                return Err(CoreShapeError::ShapeError(record.stats()));
            }
        }

        Err(CoreShapeError::PrecompileNotIncluded(record.stats()))
    }

    /// Generate a dynamic shape by rounding each chip height up to the next power of 2.
    /// This is used as a fallback when no pre-defined shape fits the execution record.
    fn dynamic_shape_from_heights(heights: &[(MipsAirId, usize)]) -> Shape<MipsAirId> {
        heights
            .iter()
            .filter(|(_, height)| *height > 0)
            .map(|(air, height)| (*air, log2_ceil_usize(*height)))
            .collect()
    }

    fn get_precompile_shapes(
        &self,
        air: &MipsAir<F>,
        memory_events_per_row: usize,
        allowed_log2_height: usize,
    ) -> Vec<[(String, usize); 4]> {
        // TODO: This is a temporary fix to the shape, concretely fix this
        (1..=4 * air.rows_per_event())
            .rev()
            .map(|rows_per_event| {
                let num_local_mem_events =
                    ((1 << allowed_log2_height) * memory_events_per_row).div_ceil(rows_per_event);
                [
                    (air.name(), allowed_log2_height),
                    (
                        MipsAir::<F>::SyscallPrecompile(SyscallChip::precompile()).name(),
                        ((1 << allowed_log2_height)
                            .div_ceil(&air.rows_per_event())
                            .next_power_of_two()
                            .ilog2() as usize)
                            .max(4),
                    ),
                    (
                        MipsAir::<F>::MemoryLocal(MemoryLocalChip::new()).name(),
                        (num_local_mem_events
                            .div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
                            .next_power_of_two()
                            .ilog2() as usize)
                            .max(4),
                    ),
                    (
                        MipsAir::<F>::Global(GlobalChip).name(),
                        ((2 * num_local_mem_events
                            + (1 << allowed_log2_height).div_ceil(&air.rows_per_event()))
                        .next_power_of_two()
                        .ilog2() as usize)
                            .max(4),
                    ),
                ]
            })
            .filter(|shape| shape[3].1 <= 22)
            .collect::<Vec<_>>()
    }

    fn generate_all_shapes_from_allowed_log_heights(
        allowed_log_heights: impl IntoIterator<Item = (String, Vec<Option<usize>>)>,
    ) -> impl Iterator<Item = OrderedShape> {
        allowed_log_heights
            .into_iter()
            .map(|(name, heights)| heights.into_iter().map(move |height| (name.clone(), height)))
            .multi_cartesian_product()
            .map(|iter| {
                iter.into_iter()
                    .filter_map(|(name, maybe_height)| {
                        maybe_height.map(|log_height| (name, log_height))
                    })
                    .collect::<OrderedShape>()
            })
    }

    pub fn all_shapes(&self) -> impl Iterator<Item = OrderedShape> + '_ {
        let preprocessed_heights = self
            .partial_preprocessed_shapes
            .iter()
            .map(|(air, heights)| (air.to_string(), heights.clone()))
            .collect::<HashMap<_, _>>();

        let mut memory_heights = self
            .partial_memory_shapes
            .iter()
            .map(|(air, heights)| (air.to_string(), heights.clone()))
            .collect::<HashMap<_, _>>();
        memory_heights.extend(preprocessed_heights.clone());

        let precompile_only_shapes = self.partial_precompile_shapes.iter().flat_map(
            move |(air, (mem_events_per_row, allowed_log_heights))| {
                allowed_log_heights.iter().flat_map(move |allowed_log_height| {
                    self.get_precompile_shapes(air, *mem_events_per_row, *allowed_log_height)
                })
            },
        );

        let precompile_shapes =
            Self::generate_all_shapes_from_allowed_log_heights(preprocessed_heights.clone())
                .flat_map(move |preprocessed_shape| {
                    precompile_only_shapes.clone().map(move |precompile_shape| {
                        preprocessed_shape
                            .clone()
                            .into_iter()
                            .chain(precompile_shape)
                            .collect::<OrderedShape>()
                    })
                });

        self.partial_core_shapes
            .values()
            .flatten()
            .chain(self.partial_small_shapes.iter())
            .flat_map(move |allowed_log_heights| {
                Self::generate_all_shapes_from_allowed_log_heights({
                    let mut log_heights = allowed_log_heights
                        .iter()
                        .map(|(air, heights)| (air.to_string(), heights.clone()))
                        .collect::<HashMap<_, _>>();
                    log_heights.extend(preprocessed_heights.clone());
                    log_heights
                })
            })
            .chain(Self::generate_all_shapes_from_allowed_log_heights(memory_heights))
            .chain(precompile_shapes)
    }

    pub fn maximal_core_shapes(&self, max_log_shard_size: usize) -> Vec<Shape<MipsAirId>> {
        let max_shard_size: usize = core::cmp::max(
            1 << max_log_shard_size,
            1 << self.partial_core_shapes.keys().min().unwrap(),
        );

        let log_shard_size = max_shard_size.ilog2() as usize;
        debug_assert_eq!(1 << log_shard_size, max_shard_size);
        let max_preprocessed = self
            .partial_preprocessed_shapes
            .iter()
            .map(|(air, allowed_heights)| {
                (air.to_string(), allowed_heights.last().unwrap().unwrap())
            })
            .collect::<HashMap<_, _>>();

        let max_core_shapes =
            self.partial_core_shapes[&log_shard_size].iter().map(|allowed_log_heights| {
                max_preprocessed
                    .clone()
                    .into_iter()
                    .chain(allowed_log_heights.iter().flat_map(|(air, allowed_heights)| {
                        allowed_heights
                            .last()
                            .unwrap()
                            .map(|log_height| (air.to_string(), log_height))
                    }))
                    .map(|(air, log_height)| (MipsAirId::from_str(&air).unwrap(), log_height))
                    .collect::<Shape<MipsAirId>>()
            });

        max_core_shapes.collect()
    }

    pub fn maximal_core_plus_precompile_shapes(
        &self,
        max_log_shard_size: usize,
    ) -> Vec<Shape<MipsAirId>> {
        let max_preprocessed = self
            .partial_preprocessed_shapes
            .iter()
            .map(|(air, allowed_heights)| {
                (air.to_string(), allowed_heights.last().unwrap().unwrap())
            })
            .collect::<HashMap<_, _>>();

        let precompile_only_shapes = self.partial_precompile_shapes.iter().flat_map(
            move |(air, (mem_events_per_row, allowed_log_heights))| {
                self.get_precompile_shapes(
                    air,
                    *mem_events_per_row,
                    *allowed_log_heights.last().unwrap(),
                )
            },
        );

        let precompile_shapes: Vec<Shape<MipsAirId>> = precompile_only_shapes
            .map(|x| {
                max_preprocessed
                    .clone()
                    .into_iter()
                    .chain(x)
                    .map(|(air, log_height)| (MipsAirId::from_str(&air).unwrap(), log_height))
                    .collect::<Shape<MipsAirId>>()
            })
            .filter(|shape| shape.log2_height(&MipsAirId::Global).unwrap() < 21)
            .collect();

        self.maximal_core_shapes(max_log_shard_size).into_iter().chain(precompile_shapes).collect()
    }

    fn estimate_lde_size(&self, shape: &Shape<MipsAirId>) -> usize {
        shape.iter().map(|(air, height)| self.costs[air] * (1 << height)).sum()
    }

    pub fn small_program_shapes(&self) -> Vec<OrderedShape> {
        self.partial_small_shapes
            .iter()
            .map(|log_heights| {
                OrderedShape::from_log2_heights(
                    &log_heights
                        .iter()
                        .filter(|(_, v)| v[0].is_some())
                        .map(|(k, v)| (k.to_string(), v.last().unwrap().unwrap()))
                        .chain(vec![
                            (MachineAir::<KoalaBear>::name(&ProgramChip), 19),
                            (MachineAir::<KoalaBear>::name(&ByteChip::default()), 16),
                        ])
                        .collect::<Vec<_>>(),
                )
            })
            .collect()
    }
}

impl<F: PrimeField32> Default for CoreShapeConfig<F> {
    fn default() -> Self {
        // Load the maximal shapes.
        let maximal_shapes = std::env::var("MAXIMAL_SHAPES_FILE")
            .ok()
            .map(|file| std::fs::read(file).expect("Failed to read MAXIMAL_SHAPES_FILE"))
            .unwrap_or_else(|| MAXIMAL_SHAPES.to_vec());
        let maximal_shapes: BTreeMap<usize, Vec<Shape<MipsAirId>>> =
            serde_json::from_slice(&maximal_shapes).unwrap();

        let small_shapes = std::env::var("SMALL_SHAPES_FILE")
            .ok()
            .map(|file| std::fs::read(file).expect("Failed to read SMALL_SHAPES_FILE"))
            .unwrap_or_else(|| SMALL_SHAPES.to_vec());
        let small_shapes: Vec<Shape<MipsAirId>> = serde_json::from_slice(&small_shapes).unwrap();

        // Set the allowed preprocessed log2 heights.
        let allowed_preprocessed_log2_heights = HashMap::from([
            (MipsAirId::Program, vec![Some(19), Some(20), Some(21), Some(22)]),
            (MipsAirId::Byte, vec![Some(16)]),
        ]);

        // OpenVM-style: merge all maximal shapes per shard size into a single envelope shape.
        // This produces 1 fixed shape per shard size instead of thousands of clusters.
        let mut core_allowed_log2_heights = BTreeMap::new();
        for (log2_shard_size, shard_shapes) in maximal_shapes {
            // Take the max log2_height per chip across all maximal shapes for this shard size.
            let mut envelope: HashMap<MipsAirId, usize> = HashMap::new();
            for shape in shard_shapes.iter() {
                for (air, log_height) in shape.iter() {
                    let entry = envelope.entry(*air).or_insert(0);
                    *entry = (*entry).max(*log_height);
                }
            }
            // Convert to a single-shape cluster (1 height option per chip).
            let cluster = ShapeCluster::new(
                envelope
                    .into_iter()
                    .map(|(air, h)| (air, vec![Some(h)]))
                    .collect(),
            );
            core_allowed_log2_heights.insert(log2_shard_size, vec![cluster]);
        }

        // Merge small shapes into a single envelope small shape.
        let merged_small_shapes = if small_shapes.is_empty() {
            vec![]
        } else {
            let mut envelope: HashMap<MipsAirId, usize> = HashMap::new();
            for shape in small_shapes.iter() {
                for (air, log_height) in shape.iter() {
                    let entry = envelope.entry(*air).or_insert(0);
                    *entry = (*entry).max(*log_height);
                }
            }
            vec![ShapeCluster::new(
                envelope
                    .into_iter()
                    .map(|(air, h)| (air, vec![Some(h)]))
                    .collect(),
            )]
        };

        // Set the memory init and finalize heights — single maximal combination.
        let memory_allowed_log2_heights = HashMap::from(
            [
                (MipsAirId::MemoryGlobalInit, vec![None, Some(21)]),
                (MipsAirId::MemoryGlobalFinalize, vec![None, Some(21)]),
                (MipsAirId::Global, vec![None, Some(22)]),
            ]
            .map(|(air, log_heights)| (air, log_heights)),
        );

        // Set the precompile heights — single maximal height.
        let mut precompile_allowed_log2_heights = HashMap::new();
        let precompile_heights = vec![20];
        for (air, memory_events_per_row) in
            MipsAir::<F>::precompile_airs_with_memory_events_per_row()
        {
            precompile_allowed_log2_heights
                .insert(air, (memory_events_per_row, precompile_heights.clone()));
        }

        Self {
            partial_preprocessed_shapes: ShapeCluster::new(allowed_preprocessed_log2_heights),
            partial_core_shapes: core_allowed_log2_heights,
            partial_memory_shapes: ShapeCluster::new(memory_allowed_log2_heights),
            partial_precompile_shapes: precompile_allowed_log2_heights,
            partial_small_shapes: merged_small_shapes,
            costs: serde_json::from_str(include_str!(
                "../../../executor/src/artifacts/mips_costs.json"
            ))
            .unwrap(),
        }
    }
}

#[derive(Debug, Error)]
pub enum CoreShapeError {
    #[error("no preprocessed shape found")]
    PreprocessedShapeError,
    #[error("Preprocessed shape already fixed")]
    PreprocessedShapeAlreadyFixed,
    #[error("no shape found {0:?}")]
    ShapeError(HashMap<String, usize>),
    #[error("Preprocessed shape missing")]
    PreprocessedShapeMissing,
    #[error("Shape already fixed")]
    ShapeAlreadyFixed,
    #[error("Precompile not included in allowed shapes {0:?}")]
    PrecompileNotIncluded(HashMap<String, usize>),
}

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use hashbrown::HashSet;
    use zkm_stark::{Dom, MachineProver, StarkGenericConfig};

    use super::*;

    fn create_dummy_program(shape: &Shape<MipsAirId>) -> Program {
        let mut program = Program::new(vec![], 1 << 5, 1 << 5);
        program.preprocessed_shape = Some(shape.clone());
        program
    }

    fn create_dummy_record(shape: &Shape<MipsAirId>) -> ExecutionRecord {
        let program = Arc::new(create_dummy_program(shape));
        let mut record = ExecutionRecord::new(program);
        record.shape = Some(shape.clone());
        record
    }

    fn try_generate_dummy_proof<SC: StarkGenericConfig, P: MachineProver<SC, MipsAir<SC::Val>>>(
        prover: &P,
        shape: &Shape<MipsAirId>,
    ) where
        SC::Val: PrimeField32,
        Dom<SC>: core::fmt::Debug,
    {
        let program = create_dummy_program(shape);
        let record = create_dummy_record(shape);

        // Try doing setup.
        let (pk, _) = prover.setup(&program);

        // Try to generate traces.
        let main_traces = prover.generate_traces(&record).unwrap();

        // Try to commit the traces.
        let main_data = prover.commit(&record, main_traces);

        let mut challenger = prover.machine().config().challenger();

        // Try to "open".
        prover.open(&pk, main_data, &mut challenger).unwrap();
    }

    #[test]
    #[ignore]
    fn test_making_shapes() {
        use p3_koala_bear::KoalaBear;
        let shape_config = CoreShapeConfig::<KoalaBear>::default();
        let num_shapes = shape_config.all_shapes().collect::<HashSet<_>>().len();
        assert!(num_shapes < 1 << 24);
        for shape in shape_config.all_shapes() {
            println!("{shape:?}");
        }
        println!("There are {num_shapes} core shapes");
    }

    #[test]
    fn test_dummy_record() {
        use crate::utils::setup_logger;
        use p3_koala_bear::KoalaBear;
        use zkm_stark::{koala_bear_poseidon2::KoalaBearPoseidon2, CpuProver};

        type SC = KoalaBearPoseidon2;
        type A = MipsAir<KoalaBear>;

        setup_logger();

        let preprocessed_log_heights = [(MipsAirId::Program, 10), (MipsAirId::Byte, 16)];

        let core_log_heights = [
            (MipsAirId::Cpu, 11),
            (MipsAirId::DivRem, 11),
            (MipsAirId::AddSub, 10),
            (MipsAirId::Bitwise, 10),
            (MipsAirId::Mul, 10),
            (MipsAirId::ShiftRight, 10),
            (MipsAirId::ShiftLeft, 10),
            (MipsAirId::Lt, 10),
            (MipsAirId::CloClz, 10),
            (MipsAirId::MemoryLocal, 10),
            (MipsAirId::SyscallCore, 10),
            (MipsAirId::Global, 10),
        ];

        let height_map =
            preprocessed_log_heights.into_iter().chain(core_log_heights).collect::<HashMap<_, _>>();

        let shape = Shape::new(height_map);

        // Try generating preprocessed traces.
        let config = SC::default();
        let machine = A::machine(config);
        let prover = CpuProver::new(machine);

        try_generate_dummy_proof(&prover, &shape);
    }
}
