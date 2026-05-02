#[cfg(not(feature = "sys"))]
use std::array;
use std::{borrow::BorrowMut, mem::size_of};

use itertools::Itertools;
#[cfg(feature = "sys")]
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use tracing::instrument;
use zkm_core_machine::utils::next_power_of_two;
#[cfg(not(feature = "sys"))]
use zkm_primitives::RC_16_30_U32;
use zkm_stark::air::MachineAir;

#[cfg(not(feature = "sys"))]
use crate::chips::mem::MemoryAccessColsChips;
#[cfg(not(feature = "sys"))]
use crate::chips::poseidon2_skinny::external_linear_layer;
#[cfg(not(feature = "sys"))]
use crate::chips::poseidon2_skinny::internal_linear_layer;
#[cfg(not(feature = "sys"))]
use crate::chips::poseidon2_skinny::NUM_INTERNAL_ROUNDS;
#[cfg(not(feature = "sys"))]
use crate::chips::poseidon2_skinny::WIDTH;
use crate::{
    chips::poseidon2_skinny::{
        columns::{Poseidon2 as Poseidon2Cols, NUM_POSEIDON2_COLS},
        Poseidon2SkinnyChip, NUM_EXTERNAL_ROUNDS,
    },
    gpu_hooks,
    instruction::Instruction::Poseidon2,
    ExecutionRecord, Poseidon2Event, RecursionProgram,
};
#[cfg(feature = "sys")]
use crate::{Poseidon2Io, Poseidon2SkinnyInstr};

/// Try the GPU device-tracegen hook for `Poseidon2SkinnyChip`
/// (integration #5 — sister of `try_device_trace` in
/// `chips/poseidon2_wide/trace.rs`).
///
/// Returns `Some(matrix)` when ALL of the following hold:
///   * `ZIREN_GPU_TRACEGEN_DEVICE=1` is set in the environment.
///   * `F == KoalaBear` (the production reth path; generic-EF callers
///     fall back to host even when the env flag is set).
///   * A hook is registered via
///     [`gpu_hooks::register_poseidon2_skinny_device_trace_hook`].
///   * The hook itself returns `Some` (it can decline to run, e.g.
///     when the GPU is unhealthy; the caller then falls back to host).
///
/// The returned matrix is byte-identical to the host `generate_trace`
/// output — same fixed `NUM_POSEIDON2_COLS` width, same
/// `padded_nb_rows`, and the trailing rows beyond
/// `events.len() * (OUTPUT_ROUND_IDX + 1)` are zero-padded by the
/// kernel's leading `cudaMemsetAsync` (matching the host
/// `rows.resize(num_rows, [F::ZERO; NUM_POSEIDON2_COLS])`).
#[inline]
fn try_device_trace<F: PrimeField32>(
    events: &[Poseidon2Event<F>],
    padded_nb_rows: usize,
) -> Option<RowMajorMatrix<F>> {
    if std::env::var("ZIREN_GPU_TRACEGEN_DEVICE").map(|v| v == "1").unwrap_or(false) == false {
        return None;
    }
    if std::any::TypeId::of::<F>() != std::any::TypeId::of::<KoalaBear>() {
        return None;
    }
    let hook = gpu_hooks::get_poseidon2_skinny_device_trace_hook()?;

    // SAFETY: TypeId guard above proves F == KoalaBear, so the slice
    // and result transmutes are layout-compatible.  `Poseidon2Io<F>`
    // is `#[repr(C)]` with `[F; WIDTH]` fields; `RowMajorMatrix<F>`
    // is `Vec<F>` + width.
    let events_kb: &[Poseidon2Event<KoalaBear>] = unsafe {
        std::mem::transmute::<&[Poseidon2Event<F>], &[Poseidon2Event<KoalaBear>]>(events)
    };
    let mat_kb = hook(events_kb, padded_nb_rows)?;
    let w = <RowMajorMatrix<KoalaBear> as p3_matrix::Matrix<KoalaBear>>::width(&mat_kb);
    debug_assert_eq!(w, NUM_POSEIDON2_COLS, "device hook returned matrix with unexpected width");
    let values_f: Vec<F> = unsafe { std::mem::transmute::<Vec<KoalaBear>, Vec<F>>(mat_kb.values) };
    Some(RowMajorMatrix::new(values_f, w))
}

use super::columns::preprocessed::Poseidon2PreprocessedCols;

const PREPROCESSED_POSEIDON2_WIDTH: usize = size_of::<Poseidon2PreprocessedCols<u8>>();

#[cfg(not(feature = "sys"))]
const INTERNAL_ROUND_IDX: usize = NUM_EXTERNAL_ROUNDS / 2 + 1;
#[cfg(not(feature = "sys"))]
const INPUT_ROUND_IDX: usize = 0;
pub const OUTPUT_ROUND_IDX: usize = NUM_EXTERNAL_ROUNDS + 2;

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for Poseidon2SkinnyChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    type Error = crate::RecursionChipError;

    fn name(&self) -> String {
        format!("Poseidon2SkinnyDeg{DEGREE}")
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
        let events = &input.poseidon2_events;
        Some(next_power_of_two(
            events.len() * (OUTPUT_ROUND_IDX + 1),
            input.fixed_log2_rows(self),
            <Poseidon2SkinnyChip<DEGREE> as MachineAir<F>>::name(self).as_str(),
        ))
    }

    #[cfg(not(feature = "sys"))]
    #[instrument(name = "generate poseidon2 skinny trace", level = "debug", skip_all, fields(rows = input.poseidon2_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _output: &mut ExecutionRecord<F>,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        // Integration #5: try the GPU device-tracegen hook first.
        // Returns `None` when the env flag is unset, F != KoalaBear,
        // no hook is registered, or the hook itself declines.
        let padded_nb_rows = self.num_rows(input).unwrap();
        if let Some(mat) = try_device_trace(&input.poseidon2_events, padded_nb_rows) {
            return Ok(mat);
        }

        let mut rows = Vec::new();

        for event in &input.poseidon2_events {
            // We have one row for input, one row for output, NUM_EXTERNAL_ROUNDS rows for the
            // external rounds, and one row for all internal rounds.
            let mut row_add = [[F::ZERO; NUM_POSEIDON2_COLS]; NUM_EXTERNAL_ROUNDS + 3];

            // The first row should have event.input and [event.input[0].clone();
            // NUM_INTERNAL_ROUNDS-1] in its state columns. The sbox_state will be
            // modified in the computation of the first row.
            {
                use crate::chips::poseidon2_skinny::external_linear_layer;

                let (first_row, second_row) = &mut row_add[0..2].split_at_mut(1);
                let input_cols: &mut Poseidon2Cols<F> = first_row[0].as_mut_slice().borrow_mut();
                input_cols.state_var = event.input;

                let next_cols: &mut Poseidon2Cols<F> = second_row[0].as_mut_slice().borrow_mut();
                next_cols.state_var = event.input;
                external_linear_layer(&mut next_cols.state_var);
            }

            // For each external round, and once for all the internal rounds at the same time, apply
            // the corresponding operation. This will change the state and internal_rounds_s0
            // variable in row r+1.
            for i in 1..OUTPUT_ROUND_IDX {
                let next_state_var = {
                    let cols: &mut Poseidon2Cols<F> = row_add[i].as_mut_slice().borrow_mut();
                    let state = cols.state_var;

                    if i != INTERNAL_ROUND_IDX {
                        self.populate_external_round(&state, i - 1)
                    } else {
                        // Populate the internal rounds.
                        self.populate_internal_rounds(&state, &mut cols.internal_rounds_s0)
                    }
                };
                let next_row_cols: &mut Poseidon2Cols<F> =
                    row_add[i + 1].as_mut_slice().borrow_mut();
                next_row_cols.state_var = next_state_var;
            }

            // Check that the permutation is computed correctly.
            {
                use std::borrow::Borrow;

                let last_row_cols: &Poseidon2Cols<F> =
                    row_add[OUTPUT_ROUND_IDX].as_slice().borrow();
                debug_assert_eq!(last_row_cols.state_var, event.output);
            }
            rows.extend(row_add.into_iter());
        }

        // Pad the trace to a power of two.
        // This will need to be adjusted when the AIR constraints are implemented.
        rows.resize(self.num_rows(input).unwrap(), [F::ZERO; NUM_POSEIDON2_COLS]);

        // Convert the trace to a row major matrix.
        Ok(RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_POSEIDON2_COLS))
    }

    #[cfg(feature = "sys")]
    #[instrument(name = "generate poseidon2 skinny trace", level = "debug", skip_all, fields(rows = input.poseidon2_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _output: &mut ExecutionRecord<F>,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<KoalaBear>(),
            "generate_trace only supports KoalaBear field"
        );

        // Integration #5: try the GPU device-tracegen hook first.
        // (`F` is enforced KoalaBear by the assert above, so the
        // TypeId guard inside `try_device_trace` always matches.)
        let padded_nb_rows = self.num_rows(input).unwrap();
        if let Some(mat) = try_device_trace(&input.poseidon2_events, padded_nb_rows) {
            return Ok(mat);
        }

        let mut rows = Vec::new();

        let events = unsafe {
            std::mem::transmute::<&Vec<Poseidon2Io<F>>, &Vec<Poseidon2Io<KoalaBear>>>(
                &input.poseidon2_events,
            )
        };

        for event in events {
            let mut row_add = [[KoalaBear::ZERO; NUM_POSEIDON2_COLS]; NUM_EXTERNAL_ROUNDS + 3];
            unsafe {
                crate::sys::poseidon2_skinny_event_to_row_koalabear(
                    event,
                    row_add.as_mut_ptr() as *mut Poseidon2Cols<KoalaBear>,
                );
            }
            rows.extend(row_add.into_iter());
        }

        // Pad the trace to a power of two.
        // This will need to be adjusted when the AIR constraints are implemented.
        rows.resize(self.num_rows(input).unwrap(), [KoalaBear::ZERO; NUM_POSEIDON2_COLS]);

        Ok(RowMajorMatrix::new(
            unsafe {
                std::mem::transmute::<Vec<KoalaBear>, Vec<F>>(
                    rows.into_iter().flatten().collect::<Vec<KoalaBear>>(),
                )
            },
            NUM_POSEIDON2_COLS,
        ))
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }

    fn preprocessed_width(&self) -> usize {
        PREPROCESSED_POSEIDON2_WIDTH
    }

    fn preprocessed_num_rows(&self, program: &Self::Program, instrs_len: usize) -> Option<usize> {
        Some(next_power_of_two(
            instrs_len,
            program.fixed_log2_rows(self),
            <Poseidon2SkinnyChip<DEGREE> as MachineAir<F>>::name(self).as_str(),
        ))
    }

    #[cfg(not(feature = "sys"))]
    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instructions =
            program.instructions.iter().filter_map(|instruction| match instruction {
                Poseidon2(instr) => Some(instr),
                _ => None,
            });

        let num_instructions = instructions.clone().count();

        let mut rows = vec![
            [F::ZERO; PREPROCESSED_POSEIDON2_WIDTH];
            num_instructions * (NUM_EXTERNAL_ROUNDS + 3)
        ];

        // Iterate over the instructions and take NUM_EXTERNAL_ROUNDS + 3 rows for each instruction.
        // We have one extra round for the internal rounds, one extra round for the input,
        // and one extra round for the output.
        instructions.zip_eq(&rows.iter_mut().chunks(NUM_EXTERNAL_ROUNDS + 3)).for_each(
            |(instruction, row_add)| {
                row_add.into_iter().enumerate().for_each(|(i, row)| {
                    let cols: &mut Poseidon2PreprocessedCols<_> =
                        (*row).as_mut_slice().borrow_mut();

                    // Set the round-counter columns.
                    cols.round_counters_preprocessed.is_input_round =
                        F::from_bool(i == INPUT_ROUND_IDX);
                    let is_external_round =
                        i != INPUT_ROUND_IDX && i != INTERNAL_ROUND_IDX && i != OUTPUT_ROUND_IDX;
                    cols.round_counters_preprocessed.is_external_round =
                        F::from_bool(is_external_round);
                    cols.round_counters_preprocessed.is_internal_round =
                        F::from_bool(i == INTERNAL_ROUND_IDX);

                    (0..WIDTH).for_each(|j| {
                        cols.round_counters_preprocessed.round_constants[j] = if is_external_round {
                            let r = i - 1;
                            let round = if i < INTERNAL_ROUND_IDX {
                                r
                            } else {
                                r + NUM_INTERNAL_ROUNDS - 1
                            };

                            F::from_u32(RC_16_30_U32[round][j])
                        } else if i == INTERNAL_ROUND_IDX {
                            F::from_u32(RC_16_30_U32[NUM_EXTERNAL_ROUNDS / 2 + j][0])
                        } else {
                            F::ZERO
                        };
                    });

                    // Set the memory columns. We read once, at the first iteration,
                    // and write once, at the last iteration.
                    if i == INPUT_ROUND_IDX {
                        cols.memory_preprocessed = instruction
                            .addrs
                            .input
                            .map(|addr| MemoryAccessColsChips { addr, mult: F::NEG_ONE });
                    } else if i == OUTPUT_ROUND_IDX {
                        cols.memory_preprocessed = array::from_fn(|i| MemoryAccessColsChips {
                            addr: instruction.addrs.output[i],
                            mult: instruction.mults[i],
                        });
                    }
                });
            },
        );

        // Pad the trace to a power of two.
        // This may need to be adjusted when the AIR constraints are implemented.
        rows.resize(
            self.preprocessed_num_rows(program, rows.len()).unwrap(),
            [F::ZERO; PREPROCESSED_POSEIDON2_WIDTH],
        );
        let trace_rows = rows.into_iter().flatten().collect::<Vec<_>>();
        Some(RowMajorMatrix::new(trace_rows, PREPROCESSED_POSEIDON2_WIDTH))
    }

    #[cfg(feature = "sys")]
    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<KoalaBear>(),
            "generate_trace only supports KoalaBear field"
        );

        let instructions =
            program.instructions.iter().filter_map(|instruction| match instruction {
                Poseidon2(instr) => Some(unsafe {
                    std::mem::transmute::<
                        &Box<Poseidon2SkinnyInstr<F>>,
                        &Box<Poseidon2SkinnyInstr<KoalaBear>>,
                    >(instr)
                }),
                _ => None,
            });

        let num_instructions =
            program.instructions.iter().filter(|instr| matches!(instr, Poseidon2(_))).count();

        let mut rows = vec![
            [KoalaBear::ZERO; PREPROCESSED_POSEIDON2_WIDTH];
            num_instructions * (NUM_EXTERNAL_ROUNDS + 3)
        ];

        // Iterate over the instructions and take NUM_EXTERNAL_ROUNDS + 3 rows for each instruction.
        // We have one extra round for the internal rounds, one extra round for the input,
        // and one extra round for the output.
        instructions.zip_eq(&rows.iter_mut().chunks(NUM_EXTERNAL_ROUNDS + 3)).for_each(
            |(instruction, row_add)| {
                row_add.into_iter().enumerate().for_each(|(i, row)| {
                    let cols: &mut Poseidon2PreprocessedCols<_> =
                        (*row).as_mut_slice().borrow_mut();
                    unsafe {
                        crate::sys::poseidon2_skinny_instr_to_row_koalabear(instruction, i, cols);
                    }
                });
            },
        );

        // Pad the trace to a power of two.
        // This may need to be adjusted when the AIR constraints are implemented.
        rows.resize(
            self.preprocessed_num_rows(program, rows.len()).unwrap(),
            [KoalaBear::ZERO; PREPROCESSED_POSEIDON2_WIDTH],
        );

        Some(RowMajorMatrix::new(
            unsafe {
                std::mem::transmute::<Vec<KoalaBear>, Vec<F>>(
                    rows.into_iter().flatten().collect::<Vec<KoalaBear>>(),
                )
            },
            PREPROCESSED_POSEIDON2_WIDTH,
        ))
    }
}

#[cfg(not(feature = "sys"))]
impl<const DEGREE: usize> Poseidon2SkinnyChip<DEGREE> {
    fn populate_external_round<F: PrimeField32>(
        &self,
        round_state: &[F; WIDTH],
        r: usize,
    ) -> [F; WIDTH] {
        let mut state = {
            // Add round constants.

            // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
            // columns for it, and instead include it in the constraint for the x^3 part of the
            // sbox.
            let round = if r < NUM_EXTERNAL_ROUNDS / 2 { r } else { r + NUM_INTERNAL_ROUNDS - 1 };
            let mut add_rc = *round_state;
            (0..WIDTH).for_each(|i| add_rc[i] += F::from_u32(RC_16_30_U32[round][i]));

            // Apply the sboxes.
            // Optimization: since the linear layer that comes after the sbox is degree 1, we can
            // avoid adding columns for the result of the sbox, and instead include the x^3 -> x^7
            // part of the sbox in the constraint for the linear layer
            let mut sbox_deg_3: [F; 16] = [F::ZERO; WIDTH];
            for i in 0..WIDTH {
                sbox_deg_3[i] = add_rc[i] * add_rc[i] * add_rc[i];
                // sbox_deg_7[i] = sbox_deg_3 * sbox_deg_3 * add_rc[i];
            }

            sbox_deg_3
        };
        // Apply the linear layer.
        external_linear_layer(&mut state);
        state
    }

    fn populate_internal_rounds<F: PrimeField32>(
        &self,
        state: &[F; WIDTH],
        internal_rounds_s0: &mut [F; NUM_INTERNAL_ROUNDS - 1],
    ) -> [F; WIDTH] {
        let mut new_state = *state;
        (0..NUM_INTERNAL_ROUNDS).for_each(|r| {
            // Add the round constant to the 0th state element.
            // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
            // columns for it, just like for external rounds.
            let round = r + NUM_EXTERNAL_ROUNDS / 2;
            let add_rc = new_state[0] + F::from_u32(RC_16_30_U32[round][0]);

            // Apply the sboxes.
            // Optimization: since the linear layer that comes after the sbox is degree 1, we can
            // avoid adding columns for the result of the sbox, just like for external rounds.
            let sbox_deg_3 = add_rc * add_rc * add_rc;
            // let sbox_deg_7 = sbox_deg_3 * sbox_deg_3 * add_rc;

            // Apply the linear layer.
            new_state[0] = sbox_deg_3;
            internal_linear_layer(&mut new_state);

            // Optimization: since we're only applying the sbox to the 0th state element, we only
            // need to have columns for the 0th state element at every step. This is because the
            // linear layer is degree 1, so all state elements at the end can be expressed as a
            // degree-3 polynomial of the state at the beginning of the internal rounds and the 0th
            // state element at rounds prior to the current round
            if r < NUM_INTERNAL_ROUNDS - 1 {
                internal_rounds_s0[r] = new_state[0];
            }
        });

        new_state
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_symmetric::Permutation;
    use rand::Rng;
    use zkhash::ark_ff::UniformRand;
    use zkm_stark::{air::MachineAir, inner_perm};

    use crate::{
        chips::poseidon2_skinny::{Poseidon2SkinnyChip, WIDTH},
        ExecutionRecord, Poseidon2Event,
    };

    #[test]
    fn generate_trace() {
        type F = KoalaBear;
        let input_0 = [F::ONE; WIDTH];
        let permuter = inner_perm();
        let output_0 = permuter.permute(input_0);
        let mut rng = rand::thread_rng();

        let input_1: [F; WIDTH] = core::array::from_fn(|_| F::from_u64(rng.gen::<u64>()));
        let output_1 = permuter.permute(input_1);
        let shard = ExecutionRecord {
            poseidon2_events: vec![
                Poseidon2Event { input: input_0, output: output_0 },
                Poseidon2Event { input: input_1, output: output_1 },
            ],
            ..Default::default()
        };
        let chip_9 = Poseidon2SkinnyChip::<9>::default();
        let _: RowMajorMatrix<F> =
            chip_9.generate_trace(&shard, &mut ExecutionRecord::default()).unwrap();
    }
}
