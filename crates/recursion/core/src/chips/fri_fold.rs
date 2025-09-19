#![allow(clippy::needless_range_loop)]

use core::borrow::Borrow;
use itertools::Itertools;
use p3_koala_bear::KoalaBear;
use std::borrow::BorrowMut;
use tracing::instrument;
use zkm_core_machine::utils::{next_power_of_two, pad_rows_fixed};
use zkm_stark::air::{BinomialExtension, MachineAir};

use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_field::{FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use zkm_stark::air::{BaseAirBuilder, ExtensionAirBuilder};

use zkm_derive::AlignedBorrow;

use crate::{
    air::Block, builder::ZKMRecursionAirBuilder, runtime::{Instruction, RecursionProgram}, ExecutionRecord, FriFoldEvent, FriFoldInstr
};

use super::mem::MemoryAccessColsChips;

pub const NUM_FRI_FOLD_COLS: usize = core::mem::size_of::<FriFoldCols<u8>>();
pub const NUM_FRI_FOLD_PREPROCESSED_COLS: usize =
    core::mem::size_of::<FriFoldPreprocessedCols<u8>>();

pub struct FriFoldChip<const DEGREE: usize> {
    pub fixed_log2_rows: Option<usize>,
    pub pad: bool,
}

impl<const DEGREE: usize> Default for FriFoldChip<DEGREE> {
    fn default() -> Self {
        Self { fixed_log2_rows: None, pad: true }
    }
}

/// The preprocessed columns for a FRI fold invocation.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct FriFoldPreprocessedCols<T: Copy> {
    pub is_first: T,

    // Memory accesses for the single fields.
    pub z_mem: MemoryAccessColsChips<T>,
    pub alpha_mem: MemoryAccessColsChips<T>,
    pub x_mem: MemoryAccessColsChips<T>,

    // Memory accesses for the vector field inputs.
    pub alpha_pow_input_mem: MemoryAccessColsChips<T>,
    pub ro_input_mem: MemoryAccessColsChips<T>,
    pub p_at_x_mem: MemoryAccessColsChips<T>,
    pub p_at_z_mem: MemoryAccessColsChips<T>,

    // Memory accesses for the vector field outputs.
    pub ro_output_mem: MemoryAccessColsChips<T>,
    pub alpha_pow_output_mem: MemoryAccessColsChips<T>,

    pub is_real: T,
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct FriFoldCols<T: Copy> {
    pub z: Block<T>,
    pub alpha: Block<T>,
    pub x: T,

    pub p_at_x: Block<T>,
    pub p_at_z: Block<T>,
    pub alpha_pow_input: Block<T>,
    pub ro_input: Block<T>,

    pub alpha_pow_output: Block<T>,
    pub ro_output: Block<T>,
}

impl<F, const DEGREE: usize> BaseAir<F> for FriFoldChip<DEGREE> {
    fn width(&self) -> usize {
        NUM_FRI_FOLD_COLS
    }
}

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for FriFoldChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "FriFold".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn preprocessed_width(&self) -> usize {
        NUM_FRI_FOLD_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<KoalaBear>(),
            "generate_trace only supports KoalaBear field"
        );

        let mut rows: Vec<[KoalaBear; NUM_FRI_FOLD_PREPROCESSED_COLS]> = Vec::new();
        program
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::FriFold(instr) => Some(unsafe {
                    std::mem::transmute::<&Box<FriFoldInstr<F>>, &Box<FriFoldInstr<KoalaBear>>>(
                        instr,
                    )
                }),
                _ => None,
            })
            .for_each(|instruction| {
                let mut row_add = vec![
                    [KoalaBear::ZERO; NUM_FRI_FOLD_PREPROCESSED_COLS];
                    instruction.ext_vec_addrs.ps_at_z.len()
                ];

                row_add.iter_mut().enumerate().for_each(|(row_idx, row)| {
                    let cols: &mut FriFoldPreprocessedCols<KoalaBear> =
                        row.as_mut_slice().borrow_mut();
                    unsafe {
                        crate::sys::fri_fold_instr_to_row_koalabear(
                            &instruction.into(),
                            row_idx,
                            cols,
                        );
                    }
                });
                rows.extend(row_add);
            });

        // Pad the trace to a power of two.
        if self.pad {
            pad_rows_fixed(
                &mut rows,
                || [KoalaBear::ZERO; NUM_FRI_FOLD_PREPROCESSED_COLS],
                self.fixed_log2_rows,
            );
        }

        let trace = RowMajorMatrix::new(
            unsafe {
                std::mem::transmute::<Vec<KoalaBear>, Vec<F>>(
                    rows.into_iter().flatten().collect::<Vec<KoalaBear>>(),
                )
            },
            NUM_FRI_FOLD_PREPROCESSED_COLS,
        );
        Some(trace)
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let events = &input.fri_fold_events;
        Some(next_power_of_two(events.len(), input.fixed_log2_rows(self)))
    }

    #[instrument(name = "generate fri fold trace", level = "debug", skip_all, fields(rows = input.fri_fold_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<KoalaBear>(),
            "generate_trace only supports KoalaBear field"
        );

        let events = unsafe {
            std::mem::transmute::<&Vec<FriFoldEvent<F>>, &Vec<FriFoldEvent<KoalaBear>>>(
                &input.fri_fold_events,
            )
        };

        let mut rows = events
            .iter()
            .map(|event| {
                let mut row = [KoalaBear::ZERO; NUM_FRI_FOLD_COLS];
                let cols: &mut FriFoldCols<KoalaBear> = row.as_mut_slice().borrow_mut();
                unsafe {
                    crate::sys::fri_fold_event_to_row_koalabear(event, cols);
                }
                row
            })
            .collect_vec();

        // Pad the trace to a power of two.
        if self.pad {
            rows.resize(self.num_rows(input).unwrap(), [KoalaBear::ZERO; NUM_FRI_FOLD_COLS]);
        }

        // Convert the trace to a row major matrix.
        let trace = RowMajorMatrix::new(
            unsafe {
                std::mem::transmute::<Vec<KoalaBear>, Vec<F>>(
                    rows.into_iter().flatten().collect::<Vec<KoalaBear>>(),
                )
            },
            NUM_FRI_FOLD_COLS,
        );

        #[cfg(debug_assertions)]
        println!("fri fold trace dims is width: {:?}, height: {:?}", trace.width(), trace.height());

        trace
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<const DEGREE: usize> FriFoldChip<DEGREE> {
    pub fn eval_fri_fold<AB: ZKMRecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local: &FriFoldCols<AB::Var>,
        next: &FriFoldCols<AB::Var>,
        local_prepr: &FriFoldPreprocessedCols<AB::Var>,
        next_prepr: &FriFoldPreprocessedCols<AB::Var>,
    ) {
        // Constrain mem read for x.  Read at the first fri fold row.
        builder.send_single(local_prepr.x_mem.addr, local.x, local_prepr.x_mem.mult);

        // Ensure that the x value is the same for all rows within a fri fold invocation.
        builder
            .when_transition()
            .when(next_prepr.is_real)
            .when_not(next_prepr.is_first)
            .assert_eq(local.x, next.x);

        // Constrain mem read for z.  Read at the first fri fold row.
        builder.send_block(local_prepr.z_mem.addr, local.z, local_prepr.z_mem.mult);

        // Ensure that the z value is the same for all rows within a fri fold invocation.
        builder
            .when_transition()
            .when(next_prepr.is_real)
            .when_not(next_prepr.is_first)
            .assert_ext_eq(local.z.as_extension::<AB>(), next.z.as_extension::<AB>());

        // Constrain mem read for alpha.  Read at the first fri fold row.
        builder.send_block(local_prepr.alpha_mem.addr, local.alpha, local_prepr.alpha_mem.mult);

        // Ensure that the alpha value is the same for all rows within a fri fold invocation.
        builder
            .when_transition()
            .when(next_prepr.is_real)
            .when_not(next_prepr.is_first)
            .assert_ext_eq(local.alpha.as_extension::<AB>(), next.alpha.as_extension::<AB>());

        // Constrain read for alpha_pow_input.
        builder.send_block(
            local_prepr.alpha_pow_input_mem.addr,
            local.alpha_pow_input,
            local_prepr.alpha_pow_input_mem.mult,
        );

        // Constrain read for ro_input.
        builder.send_block(
            local_prepr.ro_input_mem.addr,
            local.ro_input,
            local_prepr.ro_input_mem.mult,
        );

        // Constrain read for p_at_z.
        builder.send_block(local_prepr.p_at_z_mem.addr, local.p_at_z, local_prepr.p_at_z_mem.mult);

        // Constrain read for p_at_x.
        builder.send_block(local_prepr.p_at_x_mem.addr, local.p_at_x, local_prepr.p_at_x_mem.mult);

        // Constrain write for alpha_pow_output.
        builder.send_block(
            local_prepr.alpha_pow_output_mem.addr,
            local.alpha_pow_output,
            local_prepr.alpha_pow_output_mem.mult,
        );

        // Constrain write for ro_output.
        builder.send_block(
            local_prepr.ro_output_mem.addr,
            local.ro_output,
            local_prepr.ro_output_mem.mult,
        );

        // 1. Constrain new_value = old_value * alpha.
        let alpha = local.alpha.as_extension::<AB>();
        let old_alpha_pow = local.alpha_pow_input.as_extension::<AB>();
        let new_alpha_pow = local.alpha_pow_output.as_extension::<AB>();
        builder.assert_ext_eq(old_alpha_pow.clone() * alpha, new_alpha_pow.clone());

        // 2. Constrain new_value = old_alpha_pow * quotient + old_ro,
        // where quotient = (p_at_x - p_at_z) / (x - z)
        // <=> (new_ro - old_ro) * (z - x) = old_alpha_pow * (p_at_x - p_at_z)
        let p_at_z = local.p_at_z.as_extension::<AB>();
        let p_at_x = local.p_at_x.as_extension::<AB>();
        let z = local.z.as_extension::<AB>();
        let x = local.x.into();
        let old_ro = local.ro_input.as_extension::<AB>();
        let new_ro = local.ro_output.as_extension::<AB>();
        builder.assert_ext_eq(
            (new_ro.clone() - old_ro) * (BinomialExtension::from_base(x) - z),
            (p_at_x - p_at_z) * old_alpha_pow,
        );
    }

    pub const fn do_memory_access<T: Copy>(local: &FriFoldPreprocessedCols<T>) -> T {
        local.is_real
    }
}

impl<AB, const DEGREE: usize> Air<AB> for FriFoldChip<DEGREE>
where
    AB: ZKMRecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &FriFoldCols<AB::Var> = (*local).borrow();
        let next: &FriFoldCols<AB::Var> = (*next).borrow();
        let prepr = builder.preprocessed();
        let (prepr_local, prepr_next) = (prepr.row_slice(0), prepr.row_slice(1));
        let prepr_local: &FriFoldPreprocessedCols<AB::Var> = (*prepr_local).borrow();
        let prepr_next: &FriFoldPreprocessedCols<AB::Var> = (*prepr_next).borrow();

        // Dummy constraints to normalize to DEGREE.
        let lhs = (0..DEGREE).map(|_| prepr_local.is_real.into()).product::<AB::Expr>();
        let rhs = (0..DEGREE).map(|_| prepr_local.is_real.into()).product::<AB::Expr>();
        builder.assert_eq(lhs, rhs);

        self.eval_fri_fold::<AB>(builder, local, next, prepr_local, prepr_next);
    }
}

#[cfg(test)]
mod tests {
    use p3_field::FieldExtensionAlgebra;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::mem::size_of;
    use zkm_core_machine::utils::setup_logger;
    use zkm_stark::{air::MachineAir, StarkGenericConfig};

    use p3_field::FieldAlgebra;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;

    use crate::{
        air::Block,
        chips::fri_fold::FriFoldChip,
        machine::tests::run_recursion_test_machines,
        runtime::{instruction as instr, ExecutionRecord},
        stark::KoalaBearPoseidon2Outer,
        FriFoldBaseIo, FriFoldEvent, FriFoldExtSingleIo, FriFoldExtVecIo, Instruction,
        MemAccessKind, RecursionProgram,
    };

    #[test]
    fn prove_koalabear_circuit_fri_fold() {
        setup_logger();
        type SC = KoalaBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_felt = move || -> F { F::from_canonical_u32(rng.gen_range(0..1 << 16)) };
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_block =
            move || Block::from([F::from_canonical_u32(rng.gen_range(0..1 << 16)); 4]);
        let mut addr = 0;

        let num_ext_vecs: u32 = size_of::<FriFoldExtVecIo<u8>>() as u32;
        let num_singles: u32 =
            size_of::<FriFoldBaseIo<u8>>() as u32 + size_of::<FriFoldExtSingleIo<u8>>() as u32;

        let instructions = (2..17)
            .flat_map(|i: u32| {
                let alloc_size = i * (num_ext_vecs + 2) + num_singles;

                // Allocate the memory for a FRI fold instruction. Here, i is the lengths
                // of the vectors for the vector fields of the instruction.
                let mat_opening_a = (0..i).map(|x| x + addr).collect::<Vec<_>>();
                let ps_at_z_a = (0..i).map(|x| x + i + addr).collect::<Vec<_>>();

                let alpha_pow_input_a = (0..i).map(|x: u32| x + addr + 2 * i).collect::<Vec<_>>();
                let ro_input_a = (0..i).map(|x: u32| x + addr + 3 * i).collect::<Vec<_>>();

                let alpha_pow_output_a = (0..i).map(|x: u32| x + addr + 4 * i).collect::<Vec<_>>();
                let ro_output_a = (0..i).map(|x: u32| x + addr + 5 * i).collect::<Vec<_>>();

                let x_a = addr + 6 * i;
                let z_a = addr + 6 * i + 1;
                let alpha_a = addr + 6 * i + 2;

                addr += alloc_size;

                // Generate random values for the inputs.
                let x = random_felt();
                let z = random_block();
                let alpha = random_block();

                let alpha_pow_input = (0..i).map(|_| random_block()).collect::<Vec<_>>();
                let ro_input = (0..i).map(|_| random_block()).collect::<Vec<_>>();

                let ps_at_z = (0..i).map(|_| random_block()).collect::<Vec<_>>();
                let mat_opening = (0..i).map(|_| random_block()).collect::<Vec<_>>();

                // Compute the outputs from the inputs.
                let alpha_pow_output = (0..i)
                    .map(|i| alpha_pow_input[i as usize].ext::<EF>() * alpha.ext::<EF>())
                    .collect::<Vec<EF>>();
                let ro_output = (0..i)
                    .map(|i| {
                        let i = i as usize;
                        ro_input[i].ext::<EF>()
                            + alpha_pow_input[i].ext::<EF>()
                                * (-ps_at_z[i].ext::<EF>() + mat_opening[i].ext::<EF>())
                                / (-z.ext::<EF>() + x)
                    })
                    .collect::<Vec<EF>>();

                // Write the inputs to memory.
                let mut instructions = vec![instr::mem_single(MemAccessKind::Write, 1, x_a, x)];

                instructions.push(instr::mem_block(MemAccessKind::Write, 1, z_a, z));

                instructions.push(instr::mem_block(MemAccessKind::Write, 1, alpha_a, alpha));

                (0..i).for_each(|j_32| {
                    let j = j_32 as usize;
                    instructions.push(instr::mem_block(
                        MemAccessKind::Write,
                        1,
                        mat_opening_a[j],
                        mat_opening[j],
                    ));
                    instructions.push(instr::mem_block(
                        MemAccessKind::Write,
                        1,
                        ps_at_z_a[j],
                        ps_at_z[j],
                    ));

                    instructions.push(instr::mem_block(
                        MemAccessKind::Write,
                        1,
                        alpha_pow_input_a[j],
                        alpha_pow_input[j],
                    ));
                    instructions.push(instr::mem_block(
                        MemAccessKind::Write,
                        1,
                        ro_input_a[j],
                        ro_input[j],
                    ));
                });

                // Generate the FRI fold instruction.
                instructions.push(instr::fri_fold(
                    z_a,
                    alpha_a,
                    x_a,
                    mat_opening_a.clone(),
                    ps_at_z_a.clone(),
                    alpha_pow_input_a.clone(),
                    ro_input_a.clone(),
                    alpha_pow_output_a.clone(),
                    ro_output_a.clone(),
                    vec![1; i as usize],
                    vec![1; i as usize],
                ));

                // Read all the outputs.
                (0..i).for_each(|j| {
                    let j = j as usize;
                    instructions.push(instr::mem_block(
                        MemAccessKind::Read,
                        1,
                        alpha_pow_output_a[j],
                        Block::from(alpha_pow_output[j].as_base_slice()),
                    ));
                    instructions.push(instr::mem_block(
                        MemAccessKind::Read,
                        1,
                        ro_output_a[j],
                        Block::from(ro_output[j].as_base_slice()),
                    ));
                });

                instructions
            })
            .collect::<Vec<Instruction<F>>>();

        let program = RecursionProgram { instructions, ..Default::default() };

        run_recursion_test_machines(program);
    }

    #[test]
    fn generate_fri_fold_circuit_trace() {
        type F = KoalaBear;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut rng2 = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_felt = move || -> F { F::from_canonical_u32(rng.gen_range(0..1 << 16)) };
        let mut random_block = move || Block::from([random_felt(); 4]);

        let shard = ExecutionRecord {
            fri_fold_events: (0..17)
                .map(|_| FriFoldEvent {
                    base_single: FriFoldBaseIo {
                        x: F::from_canonical_u32(rng2.gen_range(0..1 << 16)),
                    },
                    ext_single: FriFoldExtSingleIo { z: random_block(), alpha: random_block() },
                    ext_vec: crate::FriFoldExtVecIo {
                        mat_opening: random_block(),
                        ps_at_z: random_block(),
                        alpha_pow_input: random_block(),
                        ro_input: random_block(),
                        alpha_pow_output: random_block(),
                        ro_output: random_block(),
                    },
                })
                .collect(),
            ..Default::default()
        };
        let chip = FriFoldChip::<3>::default();
        let trace: RowMajorMatrix<F> = chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }
}
