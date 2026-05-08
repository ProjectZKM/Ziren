use core::borrow::Borrow;
use std::{borrow::BorrowMut, iter::zip};

use p3_air::{WindowAccess, Air, BaseAir};
#[cfg(feature = "sys")]
use p3_field::PrimeCharacteristicRing;
use p3_field::{extension::BinomiallyExtendable, Field, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use zkm_core_machine::utils::next_power_of_two;
use zkm_derive::AlignedBorrow;
use zkm_stark::air::{ExtensionAirBuilder, MachineAir};

use crate::{builder::ZKMRecursionAirBuilder, gpu_hooks, *};

/// Try the GPU device-tracegen hook for `ExtAluChip`.
///
/// Returns `Some(matrix)` when ALL of the following hold:
///   * `ZIREN_GPU_TRACEGEN_DEVICE=1` is set in the environment.
///   * `F == KoalaBear` (the production reth path).
///   * A hook is registered via
///     [`gpu_hooks::register_ext_alu_device_trace_hook`] (called from
///     `compress_multi_gpu` startup in `ziren-gpu`).
///   * The hook itself returns `Some` (it can decline; the caller
///     then falls back to host).
///
/// The returned matrix is byte-identical to the host `generate_trace`
/// output: same per-row entry layout (4 entries × `(out, in1, in2)`
/// of `Block<F>` = EF4-degree blocks), same `padded_nb_rows`,
/// zero-padded tail.  See
/// `cuda/tracegen/recursion.cuh::recursion_ext_alu_generate_trace_kernel`
/// + `core/src/tracegen/recursion.rs::ExtAluChip::generate_trace_device`
/// in the `ziren-gpu` repo.
#[inline]
fn try_device_trace<F: PrimeField32>(
    events: &[ExtAluIo<crate::air::Block<F>>],
    padded_nb_rows: usize,
) -> Option<RowMajorMatrix<F>> {
    // Cheap env check (called once per chip per shard — perf is fine).
    if std::env::var("ZIREN_GPU_TRACEGEN_DEVICE")
        .map(|v| v == "1")
        .unwrap_or(false)
        == false
    {
        return None;
    }
    // Debug instrumentation: one-shot per-arm warns (#7 ExtAlu).
    use std::sync::OnceLock;
    static MISMATCH_ONCE: OnceLock<()> = OnceLock::new();
    static NOHOOK_ONCE: OnceLock<()> = OnceLock::new();
    static FIRED_ONCE: OnceLock<()> = OnceLock::new();
    static REJECT_ONCE: OnceLock<()> = OnceLock::new();
    if std::any::TypeId::of::<F>() != std::any::TypeId::of::<KoalaBear>() {
        MISMATCH_ONCE.get_or_init(|| tracing::warn!("#7 ExtAlu hook FELL THROUGH (TypeId: F != KoalaBear)"));
        return None;
    }
    let hook = match gpu_hooks::get_ext_alu_device_trace_hook() {
        Some(h) => h,
        None => {
            NOHOOK_ONCE.get_or_init(|| tracing::warn!("#7 ExtAlu hook FELL THROUGH (env=set, hook=None)"));
            return None;
        }
    };
    let events_kb: &[ExtAluEvent<KoalaBear>] = unsafe {
        std::mem::transmute::<&[ExtAluIo<crate::air::Block<F>>], &[ExtAluEvent<KoalaBear>]>(events)
    };
    let mat_kb = match hook(events_kb, padded_nb_rows) {
        Some(m) => {
            FIRED_ONCE.get_or_init(|| tracing::warn!("#7 ExtAlu hook FIRED (ZIREN_GPU_TRACEGEN_DEVICE=1, dispatched)"));
            m
        }
        None => {
            REJECT_ONCE.get_or_init(|| tracing::warn!("#7 ExtAlu hook FELL THROUGH (hook returned None)"));
            return None;
        }
    };
    let width = <RowMajorMatrix<KoalaBear> as p3_matrix::Matrix<KoalaBear>>::width(&mat_kb);
    let values_f: Vec<F> =
        unsafe { std::mem::transmute::<Vec<KoalaBear>, Vec<F>>(mat_kb.values) };
    Some(RowMajorMatrix::new(values_f, width))
}

pub const NUM_EXT_ALU_ENTRIES_PER_ROW: usize = 4;

#[derive(Default)]
pub struct ExtAluChip;

pub const NUM_EXT_ALU_COLS: usize = core::mem::size_of::<ExtAluCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtAluCols<F: Copy> {
    pub values: [ExtAluValueCols<F>; NUM_EXT_ALU_ENTRIES_PER_ROW],
}
const NUM_EXT_ALU_VALUE_COLS: usize = core::mem::size_of::<ExtAluValueCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtAluValueCols<F: Copy> {
    pub vals: ExtAluIo<Block<F>>,
}

pub const NUM_EXT_ALU_PREPROCESSED_COLS: usize = core::mem::size_of::<ExtAluPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtAluPreprocessedCols<F: Copy> {
    pub accesses: [ExtAluAccessCols<F>; NUM_EXT_ALU_ENTRIES_PER_ROW],
}

pub const NUM_EXT_ALU_ACCESS_COLS: usize = core::mem::size_of::<ExtAluAccessCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtAluAccessCols<F: Copy> {
    pub addrs: ExtAluIo<Address<F>>,
    pub is_add: F,
    pub is_sub: F,
    pub is_mul: F,
    pub is_div: F,
    /// is_div AND mult≠0. Skips division constraint for dead instructions.
    pub is_div_active: F,
    /// is_div AND opcode == DivEAssert.  Mirrors `is_div_soundness`
    /// on `BaseAluAccessCols`.
    pub is_div_soundness: F,
    pub mult: F,
}

impl<F: Field> BaseAir<F> for ExtAluChip {
    fn width(&self) -> usize {
        NUM_EXT_ALU_COLS
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<D>> MachineAir<F> for ExtAluChip {
    type Record = ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    type Error = crate::RecursionChipError;

    fn name(&self) -> String {
        "ExtAlu".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_EXT_ALU_PREPROCESSED_COLS
    }

    fn preprocessed_num_rows(&self, program: &Self::Program, instrs_len: usize) -> Option<usize> {
        let nb_rows = instrs_len.div_ceil(NUM_EXT_ALU_ENTRIES_PER_ROW);
        let fixed_log2_rows = program.fixed_log2_rows(self);
        Some(match fixed_log2_rows {
            Some(log2_rows) => 1 << log2_rows,
            None => {
                next_power_of_two(nb_rows, None, <ExtAluChip as MachineAir<F>>::name(self).as_str())
            }
        })
    }

    #[cfg(not(feature = "sys"))]
    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        // Allocating an intermediate `Vec` is faster.
        let instrs = program
            .iter_instructions() // Faster than using `rayon` for some reason. Maybe vectorization?
            .filter_map(|instruction| match instruction {
                Instruction::ExtAlu(x) => Some(x),
                _ => None,
            })
            .collect::<Vec<_>>();

        let padded_nb_rows = self.preprocessed_num_rows(program, instrs.len()).unwrap();
        let mut values = vec![F::ZERO; padded_nb_rows * NUM_EXT_ALU_PREPROCESSED_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = instrs.len() * NUM_EXT_ALU_ACCESS_COLS;
        values[..populate_len].par_chunks_mut(NUM_EXT_ALU_ACCESS_COLS).zip_eq(instrs).for_each(
            |(row, instr)| {
                let ExtAluInstr { opcode, mult, addrs } = instr;
                let access: &mut ExtAluAccessCols<_> = row.borrow_mut();
                let is_div_op = opcode.is_div();
                let is_div_assert = opcode.is_div_assert();
                *access = ExtAluAccessCols {
                    addrs: addrs.to_owned(),
                    is_add: F::from_bool(false),
                    is_sub: F::from_bool(false),
                    is_mul: F::from_bool(false),
                    is_div: F::from_bool(false),
                    is_div_active: F::from_bool(is_div_op && !mult.is_zero()),
                    is_div_soundness: F::from_bool(is_div_assert),
                    mult: mult.to_owned(),
                };
                let target_flag = match opcode {
                    ExtAluOpcode::AddE => &mut access.is_add,
                    ExtAluOpcode::SubE => &mut access.is_sub,
                    ExtAluOpcode::MulE => &mut access.is_mul,
                    ExtAluOpcode::DivE | ExtAluOpcode::DivEAssert => &mut access.is_div,
                };
                *target_flag = F::from_bool(true);
            },
        );

        // Convert the trace to a row major matrix.
        Some(RowMajorMatrix::new(values, NUM_EXT_ALU_PREPROCESSED_COLS))
    }

    #[cfg(feature = "sys")]
    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<KoalaBear>(),
            "generate_trace only supports KoalaBear field"
        );

        // Allocating an intermediate `Vec` is faster.
        let instrs = unsafe {
            std::mem::transmute::<Vec<&ExtAluInstr<F>>, Vec<&ExtAluInstr<KoalaBear>>>(
                program
                    .iter_instructions()
                    .filter_map(|instruction| match instruction {
                        Instruction::ExtAlu(x) => Some(x),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            )
        };

        let padded_nb_rows = self.preprocessed_num_rows(program, instrs.len()).unwrap();
        let mut values = vec![KoalaBear::ZERO; padded_nb_rows * NUM_EXT_ALU_PREPROCESSED_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = instrs.len() * NUM_EXT_ALU_ACCESS_COLS;
        values[..populate_len].par_chunks_mut(NUM_EXT_ALU_ACCESS_COLS).zip_eq(instrs).for_each(
            |(row, instr)| {
                let access: &mut ExtAluAccessCols<_> = row.borrow_mut();
                unsafe {
                    crate::sys::alu_ext_instr_to_row_koalabear(instr, access);
                }
            },
        );

        // Convert the trace to a row major matrix.
        Some(RowMajorMatrix::new(
            unsafe { std::mem::transmute::<Vec<KoalaBear>, Vec<F>>(values) },
            NUM_EXT_ALU_PREPROCESSED_COLS,
        ))
    }

    fn generate_dependencies(
        &self,
        _: &Self::Record,
        _: &mut Self::Record,
    ) -> Result<(), Self::Error> {
        // This is a no-op.
        Ok(())
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let events = &input.ext_alu_events;
        let nb_rows = events.len().div_ceil(NUM_EXT_ALU_ENTRIES_PER_ROW);
        let fixed_log2_rows = input.fixed_log2_rows(self);
        Some(match fixed_log2_rows {
            Some(log2_rows) => 1 << log2_rows,
            None => {
                next_power_of_two(nb_rows, None, <ExtAluChip as MachineAir<F>>::name(self).as_str())
            }
        })
    }

    #[cfg(not(feature = "sys"))]
    fn generate_trace(
        &self,
        input: &Self::Record,
        _: &mut Self::Record,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let events = &input.ext_alu_events;
        let padded_nb_rows = self.num_rows(input).unwrap();

        // Integration #4: try the GPU device-tracegen hook first.
        // Returns `None` when the env flag is unset, F != KoalaBear,
        // no hook is registered, or the hook itself declines.
        if let Some(mat) = try_device_trace(events, padded_nb_rows) {
            return Ok(mat);
        }

        let mut values = vec![F::ZERO; padded_nb_rows * NUM_EXT_ALU_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = events.len() * NUM_EXT_ALU_VALUE_COLS;
        values[..populate_len].par_chunks_mut(NUM_EXT_ALU_VALUE_COLS).zip_eq(events).for_each(
            |(row, &vals)| {
                let cols: &mut ExtAluValueCols<_> = row.borrow_mut();
                *cols = ExtAluValueCols { vals };
            },
        );

        // Convert the trace to a row major matrix.
        Ok(RowMajorMatrix::new(values, NUM_EXT_ALU_COLS))
    }

    #[cfg(feature = "sys")]
    fn generate_trace(
        &self,
        input: &Self::Record,
        _: &mut Self::Record,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<KoalaBear>(),
            "generate_trace only supports KoalaBear field"
        );

        let padded_nb_rows = self.num_rows(input).unwrap();

        // Integration #4: try the GPU device-tracegen hook first.
        // (`F` is enforced KoalaBear by the assert above, so the
        // TypeId guard inside `try_device_trace` always matches.)
        if let Some(mat) = try_device_trace(&input.ext_alu_events, padded_nb_rows) {
            return Ok(mat);
        }

        let events = unsafe {
            std::mem::transmute::<&Vec<ExtAluIo<Block<F>>>, &Vec<ExtAluIo<Block<KoalaBear>>>>(
                &input.ext_alu_events,
            )
        };
        let mut values = vec![KoalaBear::ZERO; padded_nb_rows * NUM_EXT_ALU_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = events.len() * NUM_EXT_ALU_VALUE_COLS;
        values[..populate_len].par_chunks_mut(NUM_EXT_ALU_VALUE_COLS).zip_eq(events).for_each(
            |(row, &vals)| {
                let cols: &mut ExtAluValueCols<_> = row.borrow_mut();
                unsafe {
                    crate::sys::alu_ext_event_to_row_koalabear(&vals, cols);
                }
            },
        );

        // Convert the trace to a row major matrix.
        Ok(RowMajorMatrix::new(
            unsafe { std::mem::transmute::<Vec<KoalaBear>, Vec<F>>(values) },
            NUM_EXT_ALU_COLS,
        ))
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<AB> Air<AB> for ExtAluChip
where
    AB: ZKMRecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &ExtAluCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();
        let prep_local: &ExtAluPreprocessedCols<AB::Var> = (*prep_local).borrow();

        for (
            ExtAluValueCols { vals },
            ExtAluAccessCols { addrs, is_add, is_sub, is_mul, is_div, is_div_active, is_div_soundness, mult },
        ) in zip(local.values, prep_local.accesses)
        {
            let in1 = vals.in1.as_extension::<AB>();
            let in2 = vals.in2.as_extension::<AB>();
            let out = vals.out.as_extension::<AB>();

            // Check exactly one flag is enabled.
            let is_real = is_add + is_sub + is_mul + is_div;
            builder.assert_bool(is_real.clone());

            builder.when(is_add).assert_ext_eq(in1.clone() + in2.clone(), out.clone());
            builder.when(is_sub).assert_ext_eq(in1.clone(), in2.clone() + out.clone());
            builder.when(is_mul).assert_ext_eq(in1.clone() * in2.clone(), out.clone());
            // Enforce DivE constraint when EITHER is_div_active (regular,
            // mult>0) OR is_div_soundness (assertion-DivE; mult is 0
            // but soundness must trip).  Mutually exclusive in
            // construction.
            builder.when(is_div_active + is_div_soundness).assert_ext_eq(in1, in2 * out);

            // Read the inputs from memory.
            builder.receive_block(addrs.in1, vals.in1, is_real.clone());

            builder.receive_block(addrs.in2, vals.in2, is_real);

            // Write the output to memory.
            builder.send_block(addrs.out, vals.out, mult);
        }
    }
}

#[cfg(test)]
mod tests {
    use machine::tests::run_recursion_test_machines;
    use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing, ExtensionField, BasedVectorSpace};
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;

    use rand::{rngs::StdRng, Rng, SeedableRng};
    use stark::KoalaBearPoseidon2Outer;
    use zkm_stark::StarkGenericConfig;

    use super::*;

    use crate::runtime::instruction as instr;

    #[test]
    fn generate_trace() {
        type F = KoalaBear;

        let shard = ExecutionRecord {
            ext_alu_events: vec![ExtAluIo {
                out: F::ONE.into(),
                in1: F::ONE.into(),
                in2: F::ONE.into(),
            }],
            ..Default::default()
        };
        let chip = ExtAluChip;
        let trace: RowMajorMatrix<F> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default()).unwrap();
        println!("{:?}", trace.values)
    }

    #[test]
    pub fn four_ops() {
        type SC = KoalaBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_extfelt = move || {
            let inner: [F; 4] = core::array::from_fn(|_| F::from_u64(rng.gen::<u64>()));
            BinomialExtensionField::<F, D>::from_basis_coefficients_slice(&inner).unwrap()
        };
        let mut addr = 0;

        let instructions = (0..1000)
            .flat_map(|_| {
                let quot = random_extfelt();
                let in2 = random_extfelt();
                let in1 = in2 * quot;
                let alloc_size = 6;
                let a = (0..alloc_size).map(|x| x + addr).collect::<Vec<_>>();
                addr += alloc_size;
                [
                    instr::mem_ext(MemAccessKind::Write, 4, a[0], in1),
                    instr::mem_ext(MemAccessKind::Write, 4, a[1], in2),
                    instr::ext_alu(ExtAluOpcode::AddE, 1, a[2], a[0], a[1]),
                    instr::mem_ext(MemAccessKind::Read, 1, a[2], in1 + in2),
                    instr::ext_alu(ExtAluOpcode::SubE, 1, a[3], a[0], a[1]),
                    instr::mem_ext(MemAccessKind::Read, 1, a[3], in1 - in2),
                    instr::ext_alu(ExtAluOpcode::MulE, 1, a[4], a[0], a[1]),
                    instr::mem_ext(MemAccessKind::Read, 1, a[4], in1 * in2),
                    instr::ext_alu(ExtAluOpcode::DivE, 1, a[5], a[0], a[1]),
                    instr::mem_ext(MemAccessKind::Read, 1, a[5], quot),
                ]
            })
            .collect::<Vec<Instruction<F>>>();

        let program = RecursionProgram {
            seq_blocks: crate::RawProgram::from_linear(instructions),
            ..Default::default()
        };

        run_recursion_test_machines(program);
    }
}
