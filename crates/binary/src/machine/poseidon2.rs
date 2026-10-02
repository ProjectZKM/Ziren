//! The Poseidon2 tables: one row per permutation for its input and output,
//! one row per external round and one per internal round, the state
//! travelling from row to row on the [`POSEIDON2`] channel.
//!
//! The input row applies the first linear layer and pushes the state at
//! round zero; each round row pulls the state at its round, pushes it at
//! the next, and holds the round's witness; the input row pulls the state
//! after the last round as the output.  The round constants are
//! preprocessed, a word per lane per row.

use core::borrow::{Borrow, BorrowMut};
use std::sync::Arc;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::{Field, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_derive::AlignedBorrow;
use zkm_recursion_core::{ExecutionRecord, Instruction, Poseidon2Io, RecursionProgram};

use super::bits::{
    cell_tuple, dense, log_height_for, single_block, state_tuple, BitRows, Cell, ADDRESS_BITS,
    MEMORY, PERMUTATION_ID_BITS, POSEIDON2, ROUND_BITS, WRITE,
};
use crate::machine_builder::MachineBuilder;
use crate::poseidon2::{
    eval_external_round, eval_internal_round, eval_mds, fill_mds, fill_permutation_states,
    ExternalRoundCols, InternalRoundCols, MdsCols, PermutationCols, RoundConstants, State,
    StateExprs, HALF_EXTERNAL_ROUNDS, INTERNAL_ROUNDS, NUM_PERMUTATION_COLS, ROUNDS, WIDTH,
};
use crate::word::{bits_le, constant_bits, exprs, Word, KB_BITS};
use crate::F;

/// Products a permutation asks the multiply table for: two per cube.
pub const MUL_REQUESTS_PER_PERMUTATION: usize =
    2 * (WIDTH * 2 * HALF_EXTERNAL_ROUNDS + INTERNAL_ROUNDS);

/// The program's part of an input row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2IoPrep<T> {
    /// The permutation's identity on the channel.
    pub id: [T; PERMUTATION_ID_BITS],
    /// Where each input lane is read.
    pub addr_in: [[T; ADDRESS_BITS]; WIDTH],
    /// Where each output lane is written.
    pub addr_out: [[T; ADDRESS_BITS]; WIDTH],
    /// The row holds an instruction.
    pub is_real: T,
    /// Each output lane is read at least once.
    pub has_out: [T; WIDTH],
}

/// The witness part of an input row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2IoCols<T> {
    /// The input state.
    pub input: State<T>,
    /// The first linear layer on it.
    pub initial: MdsCols<T>,
    /// The output state.
    pub output: State<T>,
}

/// The program's part of a round row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RoundPrep<T> {
    /// The permutation's identity on the channel.
    pub id: [T; PERMUTATION_ID_BITS],
    /// The round the row pulls its state at.
    pub round: [T; ROUND_BITS],
    /// The round the row pushes its state at.
    pub next_round: [T; ROUND_BITS],
    /// The row holds a round.
    pub is_real: T,
    /// The round's constants, a word per lane.
    pub constants: State<T>,
}

/// The witness part of an external round row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct ExternalCols<T> {
    /// The state entering the round.
    pub state: State<T>,
    /// The round.
    pub round: ExternalRoundCols<T>,
}

/// The witness part of an internal round row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct InternalCols<T> {
    /// The state entering the round.
    pub state: State<T>,
    /// The round.
    pub round: InternalRoundCols<T>,
}

/// Columns of [`Poseidon2IoPrep`].
pub const NUM_POSEIDON2_IO_PREP_COLS: usize = core::mem::size_of::<Poseidon2IoPrep<u8>>();

/// Columns of [`Poseidon2IoCols`].
pub const NUM_POSEIDON2_IO_COLS: usize = core::mem::size_of::<Poseidon2IoCols<u8>>();

/// Columns of [`RoundPrep`].
pub const NUM_ROUND_PREP_COLS: usize = core::mem::size_of::<RoundPrep<u8>>();

/// Columns of [`ExternalCols`].
pub const NUM_EXTERNAL_COLS: usize = core::mem::size_of::<ExternalCols<u8>>();

/// Columns of [`InternalCols`].
pub const NUM_INTERNAL_COLS: usize = core::mem::size_of::<InternalCols<u8>>();

/// A word of a state as bits.
#[must_use]
pub fn word(value: u32) -> Word<u8> {
    bits_le::<KB_BITS>(u64::from(value))
}

/// The permutations of one program, shared by the three tables.
pub struct Permutations {
    constants: RoundConstants,
    /// `(address, reads)` of each permutation's output lanes, in order.
    outputs: Vec<[(u32, u32); WIDTH]>,
    /// Addresses of each permutation's input lanes, in order.
    inputs: Vec<[u32; WIDTH]>,
}

/// One permutation's witness and the state entering each round.
type Filled = (Vec<u8>, [[u32; WIDTH]; ROUNDS + 1]);

impl Permutations {
    /// The permutations of `program`.
    #[must_use]
    pub fn new(program: &RecursionProgram<KoalaBear>) -> Self {
        let mut outputs = Vec::new();
        let mut inputs = Vec::new();
        for instruction in program.iter_instructions() {
            let Instruction::Poseidon2(instr) = instruction else { continue };
            let Poseidon2Io { input, output } = &instr.addrs;
            inputs.push(input.map(|a| a.0.as_canonical_u32()));
            outputs.push(core::array::from_fn(|lane| {
                (output[lane].0.as_canonical_u32(), instr.mults[lane].as_canonical_u32())
            }));
        }
        Self { constants: RoundConstants::vm(), outputs, inputs }
    }

    /// The number of permutations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inputs.len()
    }

    /// Whether the program permutes at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }

    /// Every permutation's witness and states, in order, with the products
    /// asked for.
    fn fill_all(
        &self,
        record: &ExecutionRecord<KoalaBear>,
        requests: &mut Vec<(u32, u32)>,
    ) -> Vec<Filled> {
        assert_eq!(record.poseidon2_events.len(), self.len(), "one event per instruction");
        record
            .poseidon2_events
            .iter()
            .map(|event| {
                let mut row = vec![0u8; NUM_PERMUTATION_COLS];
                let cols: &mut PermutationCols<u8> = row.as_mut_slice().borrow_mut();
                let input = event.input.map(|x| x.as_canonical_u32());
                let states = fill_permutation_states(&input, &self.constants, cols, requests);
                let expected = event.output.map(|x| x.as_canonical_u32());
                assert_eq!(
                    states[ROUNDS], expected,
                    "the permutation over bits agrees with the VM"
                );
                (row, states)
            })
            .collect()
    }

    /// The witness of a permutation of zeros under zero constants, for the
    /// rows past the program.
    fn padding() -> Vec<u8> {
        let mut scratch = vec![0u8; NUM_PERMUTATION_COLS];
        let cols: &mut PermutationCols<u8> = scratch.as_mut_slice().borrow_mut();
        let zero = RoundConstants {
            external_initial: [[0; WIDTH]; HALF_EXTERNAL_ROUNDS],
            internal: [0; INTERNAL_ROUNDS],
            external_final: [[0; WIDTH]; HALF_EXTERNAL_ROUNDS],
        };
        fill_permutation_states(&[0; WIDTH], &zero, cols, &mut Vec::new());
        scratch
    }
}

/// The input and output table.
pub struct Poseidon2IoAir {
    log_height: usize,
    preprocessed: Vec<u8>,
    permutations: Arc<Permutations>,
}

impl Poseidon2IoAir {
    /// The table of `permutations`.
    #[must_use]
    pub fn new(permutations: Arc<Permutations>) -> Self {
        let log_height = log_height_for(permutations.len());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_POSEIDON2_IO_PREP_COLS];
        for (row, (inputs, outputs)) in
            permutations.inputs.iter().zip(&permutations.outputs).enumerate()
        {
            let prep: &mut Poseidon2IoPrep<u8> = preprocessed
                [row * NUM_POSEIDON2_IO_PREP_COLS..(row + 1) * NUM_POSEIDON2_IO_PREP_COLS]
                .borrow_mut();
            prep.id = bits_le::<PERMUTATION_ID_BITS>(row as u64);
            for lane in 0..WIDTH {
                prep.addr_in[lane] = bits_le::<ADDRESS_BITS>(u64::from(inputs[lane]));
                prep.addr_out[lane] = bits_le::<ADDRESS_BITS>(u64::from(outputs[lane].0));
                prep.has_out[lane] = u8::from(outputs[lane].1 > 0);
            }
            prep.is_real = 1;
        }
        Self { log_height, preprocessed, permutations }
    }

    /// The log height of the table.
    #[must_use]
    pub fn log_height(&self) -> usize {
        self.log_height
    }

    /// The products the permutations ask for, fixed by the program.
    #[must_use]
    pub fn mul_request_count(&self) -> usize {
        MUL_REQUESTS_PER_PERMUTATION * self.permutations.len()
    }

    /// The products the permutations ask for.
    #[must_use]
    pub fn mul_requests(&self, record: &ExecutionRecord<KoalaBear>) -> Vec<(u32, u32)> {
        let mut requests = Vec::with_capacity(self.mul_request_count());
        self.permutations.fill_all(record, &mut requests);
        requests
    }

    /// The writes `(address, reads)` of the table that are read, in order.
    #[must_use]
    pub fn writes(&self) -> Vec<(u32, u32)> {
        self.permutations
            .outputs
            .iter()
            .flatten()
            .copied()
            .filter(|&(_, reads)| reads > 0)
            .collect()
    }

    /// The values of [`Self::writes`], in order.
    #[must_use]
    pub fn written_values(&self, record: &ExecutionRecord<KoalaBear>) -> Vec<Cell> {
        assert_eq!(record.poseidon2_events.len(), self.permutations.len());
        record
            .poseidon2_events
            .iter()
            .zip(&self.permutations.outputs)
            .flat_map(|(event, outputs)| {
                event
                    .output
                    .iter()
                    .zip(outputs)
                    .filter(|(_, &(_, reads))| reads > 0)
                    .map(|(value, _)| [value.as_canonical_u32(), 0, 0, 0])
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// The witness: every permutation's input, first layer and output; the
    /// rows past the program carry the first layer on zeros.
    #[must_use]
    pub fn main_table(&self, record: &ExecutionRecord<KoalaBear>) -> Table<F> {
        let mut requests = Vec::new();
        let filled = self.permutations.fill_all(record, &mut requests);
        let mut rows = BitRows::new(NUM_POSEIDON2_IO_COLS, self.log_height);
        let mut row = vec![0u8; NUM_POSEIDON2_IO_COLS];
        for r in 0..1usize << self.log_height {
            row.fill(0);
            let cols: &mut Poseidon2IoCols<u8> = row.as_mut_slice().borrow_mut();
            match filled.get(r).zip(record.poseidon2_events.get(r)) {
                Some(((perm, states), event)) => {
                    let perm: &PermutationCols<u8> = perm.as_slice().borrow();
                    cols.input = event.input.map(|x| word(x.as_canonical_u32()));
                    cols.initial = perm.initial;
                    cols.output = states[ROUNDS].map(word);
                }
                None => {
                    fill_mds(&[0; WIDTH], &mut cols.initial);
                }
            }
            rows.set_row(r, &row);
        }
        rows.into_table()
    }
}

impl<X: Field> BaseAir<X> for Poseidon2IoAir {
    fn width(&self) -> usize {
        NUM_POSEIDON2_IO_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_POSEIDON2_IO_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_POSEIDON2_IO_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F = F>> Air<AB> for Poseidon2IoAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Poseidon2IoCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: Poseidon2IoPrep<AB::Var> = *prep.current_slice().borrow();

        for bit in local.input.iter().chain(local.output.iter()).flatten() {
            builder.assert_bool(*bit);
        }
        let input: StateExprs<AB> = core::array::from_fn(|i| exprs::<AB, KB_BITS>(&local.input[i]));
        let output: StateExprs<AB> =
            core::array::from_fn(|i| exprs::<AB, KB_BITS>(&local.output[i]));
        let id = exprs::<AB, PERMUTATION_ID_BITS>(&prep_local.id);
        let first = eval_mds(builder, &input, &local.initial);
        builder.declare_bus(
            POSEIDON2,
            BusDirection::Push,
            state_tuple::<AB>(&id, &constant_bits::<AB, ROUND_BITS>(0), &first),
            BusActivation::Boolean(prep_local.is_real.into()),
        );
        builder.declare_bus(
            POSEIDON2,
            BusDirection::Pull,
            state_tuple::<AB>(&id, &constant_bits::<AB, ROUND_BITS>(ROUNDS as u64), &output),
            BusActivation::Boolean(prep_local.is_real.into()),
        );
        for lane in 0..WIDTH {
            builder.declare_bus(
                MEMORY,
                BusDirection::Pull,
                cell_tuple::<AB>(
                    &exprs::<AB, ADDRESS_BITS>(&prep_local.addr_in[lane]),
                    &single_block::<AB>(&input[lane]),
                ),
                BusActivation::Boolean(prep_local.is_real.into()),
            );
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell_tuple::<AB>(
                    &exprs::<AB, ADDRESS_BITS>(&prep_local.addr_out[lane]),
                    &single_block::<AB>(&output[lane]),
                ),
                BusActivation::Boolean(prep_local.has_out[lane].into()),
            );
        }
    }
}

/// The preprocessed rows of a round table: `(permutation, round)` for every
/// round `select` accepts, in permutation order.
fn round_preprocessed(
    permutations: &Permutations,
    select: fn(usize) -> bool,
) -> (usize, Vec<u8>, Vec<(usize, usize)>) {
    let rounds: Vec<(usize, usize)> = (0..permutations.len())
        .flat_map(|perm| (0..ROUNDS).filter(|&round| select(round)).map(move |round| (perm, round)))
        .collect();
    let log_height = log_height_for(rounds.len());
    let mut preprocessed = vec![0u8; (1 << log_height) * NUM_ROUND_PREP_COLS];
    for (row, &(perm, round)) in rounds.iter().enumerate() {
        let prep: &mut RoundPrep<u8> =
            preprocessed[row * NUM_ROUND_PREP_COLS..(row + 1) * NUM_ROUND_PREP_COLS].borrow_mut();
        prep.id = bits_le::<PERMUTATION_ID_BITS>(perm as u64);
        prep.round = bits_le::<ROUND_BITS>(round as u64);
        prep.next_round = bits_le::<ROUND_BITS>(round as u64 + 1);
        prep.is_real = 1;
        prep.constants = permutations.constants.of_round(round).map(word);
    }
    (log_height, preprocessed, rounds)
}

/// Pull the state at the row's round and push `output` at the next.
fn carry_state<AB: MachineBuilder<F = F>>(
    builder: &mut AB,
    prep: &RoundPrep<AB::Var>,
    state: &StateExprs<AB>,
    output: &StateExprs<AB>,
) {
    let id = exprs::<AB, PERMUTATION_ID_BITS>(&prep.id);
    builder.declare_bus(
        POSEIDON2,
        BusDirection::Pull,
        state_tuple::<AB>(&id, &exprs::<AB, ROUND_BITS>(&prep.round), state),
        BusActivation::Boolean(prep.is_real.into()),
    );
    builder.declare_bus(
        POSEIDON2,
        BusDirection::Push,
        state_tuple::<AB>(&id, &exprs::<AB, ROUND_BITS>(&prep.next_round), output),
        BusActivation::Boolean(prep.is_real.into()),
    );
}

/// The external round table.
pub struct Poseidon2ExternalAir {
    log_height: usize,
    preprocessed: Vec<u8>,
    rounds: Vec<(usize, usize)>,
    permutations: Arc<Permutations>,
}

impl Poseidon2ExternalAir {
    /// The table of `permutations`' external rounds.
    #[must_use]
    pub fn new(permutations: Arc<Permutations>) -> Self {
        let (log_height, preprocessed, rounds) =
            round_preprocessed(&permutations, RoundConstants::is_external);
        Self { log_height, preprocessed, rounds, permutations }
    }

    /// The log height of the table.
    #[must_use]
    pub fn log_height(&self) -> usize {
        self.log_height
    }

    /// The witness: every external round's entering state and witness; the
    /// rows past the program hold a round of zeros under zero constants.
    #[must_use]
    pub fn main_table(&self, record: &ExecutionRecord<KoalaBear>) -> Table<F> {
        let mut requests = Vec::new();
        let filled = self.permutations.fill_all(record, &mut requests);
        let padding = Permutations::padding();
        let padding: &PermutationCols<u8> = padding.as_slice().borrow();
        let mut rows = BitRows::new(NUM_EXTERNAL_COLS, self.log_height);
        let mut row = vec![0u8; NUM_EXTERNAL_COLS];
        for r in 0..1usize << self.log_height {
            row.fill(0);
            let cols: &mut ExternalCols<u8> = row.as_mut_slice().borrow_mut();
            match self.rounds.get(r) {
                Some(&(perm, round)) => {
                    let (perm_row, states) = &filled[perm];
                    let perm_cols: &PermutationCols<u8> = perm_row.as_slice().borrow();
                    cols.state = states[round].map(word);
                    cols.round = if round < HALF_EXTERNAL_ROUNDS {
                        perm_cols.external_initial[round]
                    } else {
                        perm_cols.external_final[round - HALF_EXTERNAL_ROUNDS - INTERNAL_ROUNDS]
                    };
                }
                None => cols.round = padding.external_initial[0],
            }
            rows.set_row(r, &row);
        }
        rows.into_table()
    }
}

impl<X: Field> BaseAir<X> for Poseidon2ExternalAir {
    fn width(&self) -> usize {
        NUM_EXTERNAL_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_ROUND_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_ROUND_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F = F>> Air<AB> for Poseidon2ExternalAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ExternalCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: RoundPrep<AB::Var> = *prep.current_slice().borrow();

        for bit in local.state.iter().flatten() {
            builder.assert_bool(*bit);
        }
        let state: StateExprs<AB> = core::array::from_fn(|i| exprs::<AB, KB_BITS>(&local.state[i]));
        let constants: StateExprs<AB> =
            core::array::from_fn(|i| exprs::<AB, KB_BITS>(&prep_local.constants[i]));
        let output = eval_external_round(
            builder,
            &state,
            &constants,
            &local.round,
            prep_local.is_real.into(),
        );
        carry_state(builder, &prep_local, &state, &output);
    }
}

/// The internal round table.
pub struct Poseidon2InternalAir {
    log_height: usize,
    preprocessed: Vec<u8>,
    rounds: Vec<(usize, usize)>,
    permutations: Arc<Permutations>,
}

impl Poseidon2InternalAir {
    /// The table of `permutations`' internal rounds.
    #[must_use]
    pub fn new(permutations: Arc<Permutations>) -> Self {
        let (log_height, preprocessed, rounds) =
            round_preprocessed(&permutations, |round| !RoundConstants::is_external(round));
        Self { log_height, preprocessed, rounds, permutations }
    }

    /// The log height of the table.
    #[must_use]
    pub fn log_height(&self) -> usize {
        self.log_height
    }

    /// The witness: every internal round's entering state and witness; the
    /// rows past the program hold a round of zeros under a zero constant.
    #[must_use]
    pub fn main_table(&self, record: &ExecutionRecord<KoalaBear>) -> Table<F> {
        let mut requests = Vec::new();
        let filled = self.permutations.fill_all(record, &mut requests);
        let padding = Permutations::padding();
        let padding: &PermutationCols<u8> = padding.as_slice().borrow();
        let mut rows = BitRows::new(NUM_INTERNAL_COLS, self.log_height);
        let mut row = vec![0u8; NUM_INTERNAL_COLS];
        for r in 0..1usize << self.log_height {
            row.fill(0);
            let cols: &mut InternalCols<u8> = row.as_mut_slice().borrow_mut();
            match self.rounds.get(r) {
                Some(&(perm, round)) => {
                    let (perm_row, states) = &filled[perm];
                    let perm_cols: &PermutationCols<u8> = perm_row.as_slice().borrow();
                    cols.state = states[round].map(word);
                    cols.round = perm_cols.internal[round - HALF_EXTERNAL_ROUNDS];
                }
                None => cols.round = padding.internal[0],
            }
            rows.set_row(r, &row);
        }
        rows.into_table()
    }
}

impl<X: Field> BaseAir<X> for Poseidon2InternalAir {
    fn width(&self) -> usize {
        NUM_INTERNAL_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_ROUND_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_ROUND_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F = F>> Air<AB> for Poseidon2InternalAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &InternalCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: RoundPrep<AB::Var> = *prep.current_slice().borrow();

        for bit in local.state.iter().flatten() {
            builder.assert_bool(*bit);
        }
        let state: StateExprs<AB> = core::array::from_fn(|i| exprs::<AB, KB_BITS>(&local.state[i]));
        let constant = exprs::<AB, KB_BITS>(&prep_local.constants[0]);
        let output = eval_internal_round(
            builder,
            &state,
            &constant,
            &local.round,
            prep_local.is_real.into(),
        );
        carry_state(builder, &prep_local, &state, &output);
    }
}
