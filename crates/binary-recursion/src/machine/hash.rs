//! The Blake3 input and output table: one row per compression.
//!
//! A row assembles the state a compression starts from and its block,
//! hands both to the round table on [`BLAKE3`], takes the state after the
//! last round back, and sends the chaining value on:
//!
//! - **The chaining value** is the initial value for the first block of a
//!   chunk and for a parent, and otherwise the output of the compression
//!   before, pulled on [`CHAIN`].
//! - **The block** is four cells of sixteen bytes pulled from [`MEMORY`],
//!   or a parent's two children's chaining values pulled on [`CHAIN`].  A
//!   Merkle node pulls its digest and its sibling as the four cells and
//!   swaps the halves when its path bit is one: `block = x + bit (x + x')`,
//!   `x'` the cells with the halves swapped, one packed constraint per
//!   cell.
//! - **The output** of a root is the digest, its two halves pushed on
//!   [`WRITE`]; any other output is pushed on [`CHAIN`] for the one
//!   compression that continues from it.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_binary_stark::machine::bits::{
    blake3_tuple, dense, log_height_for, pack_field, BitRows, BLAKE3, BLAKE3_ROUND_BITS, MEMORY,
    PERMUTATION_ID_BITS, WRITE,
};
use zkm_binary_stark::machine::blake3::{permute, ROUNDS, STATE_WORDS, WORD_BITS};
use zkm_binary_stark::machine_builder::MachineBuilder;
use zkm_binary_stark::word::{bits_le, constant_bits, exprs};
use zkm_binary_stark::BinaryBase;
use zkm_derive::AlignedBorrow;
use zkm_recursion_core::runtime::blake3::IV;

use super::cells::{addr_bits, cell, constant, pack, CHAIN, VALUE_BITS};
use super::program::{BlockSource, CompressionState, CvSource, Output, Program, ADDR_BITS};
use crate::tape::F;
use p3_binary_field::TowerLevel;

/// Cells of a block.
const SLOTS: usize = 4;

/// The program's part of a compression row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct HashPrep<T> {
    pub id: [T; PERMUTATION_ID_BITS],
    /// The compression whose chaining value this one continues from.
    pub previous: [T; PERMUTATION_ID_BITS],
    pub left: [T; PERMUTATION_ID_BITS],
    pub right: [T; PERMUTATION_ID_BITS],
    pub slots: [[T; ADDR_BITS]; SLOTS],
    pub bit_addr: [T; ADDR_BITS],
    pub out_base: [T; ADDR_BITS],
    pub is_real: T,
    /// The chaining value is the initial value.
    pub starts: T,
    /// The chaining value is pulled on the chain.
    pub chained: T,
    /// The block's cells are pulled from memory.
    pub reads_slots: T,
    /// The block is two children's chaining values.
    pub is_parent: T,
    /// The row is a Merkle node, and pulls its bit.
    pub is_merkle: T,
    /// The output is pushed on the chain.
    pub links: T,
    /// The digest's halves are pushed, each where it is read.
    pub writes: [T; 2],
    pub counter: [T; WORD_BITS],
    pub block_len: [T; WORD_BITS],
    pub flags: [T; WORD_BITS],
    /// Zeros, which make the width a power of two.
    pub pad: [T; 512 - 4 * PERMUTATION_ID_BITS - (SLOTS + 2) * ADDR_BITS - 9 - 3 * WORD_BITS],
}

/// The witness part of a compression row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct HashCols<T> {
    /// The four cells pulled, before a Merkle node's swap.
    pub cells: [[T; VALUE_BITS]; SLOTS],
    pub bit: T,
    pub cv: [[T; WORD_BITS]; 8],
    pub block: [[T; WORD_BITS]; STATE_WORDS],
    pub final_state: [[T; WORD_BITS]; STATE_WORDS],
    /// Zeros, which make the width a power of two.
    pub pad: [T; 2048 - SLOTS * VALUE_BITS - 1 - 8 * WORD_BITS - 2 * STATE_WORDS * WORD_BITS],
}

pub const NUM_HASH_PREP_COLS: usize = core::mem::size_of::<HashPrep<u8>>();
pub const NUM_HASH_COLS: usize = core::mem::size_of::<HashCols<u8>>();

/// The compression table of one program.
pub struct HashAir {
    log_height: usize,
    preprocessed: Vec<u8>,
}

/// The bits of a word.
fn word(value: u32) -> [u8; WORD_BITS] {
    bits_le::<WORD_BITS>(u64::from(value))
}

impl HashAir {
    #[must_use]
    pub fn new(program: &Program) -> Self {
        let log_height = log_height_for(program.compressions.len());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_HASH_PREP_COLS];
        for (row, c) in program.compressions.iter().enumerate() {
            let prep: &mut HashPrep<u8> =
                preprocessed[row * NUM_HASH_PREP_COLS..(row + 1) * NUM_HASH_PREP_COLS].borrow_mut();
            let id = |i: usize| bits_le::<PERMUTATION_ID_BITS>(i as u64);
            prep.id = id(row);
            prep.is_real = 1;
            match c.cv {
                CvSource::Iv => prep.starts = 1,
                CvSource::Chained(previous) => {
                    prep.chained = 1;
                    prep.previous = id(previous);
                }
            }
            match c.block {
                BlockSource::Slots(reads) => {
                    prep.reads_slots = 1;
                    prep.slots = reads.map(|r| addr_bits(r.addr));
                }
                BlockSource::Parent(left, right) => {
                    prep.is_parent = 1;
                    prep.left = id(left);
                    prep.right = id(right);
                }
                BlockSource::Merkle { bit, cur, sib } => {
                    prep.reads_slots = 1;
                    prep.is_merkle = 1;
                    prep.bit_addr = addr_bits(bit.addr);
                    prep.slots = [cur[0], cur[1], sib[0], sib[1]].map(|r| addr_bits(r.addr));
                }
            }
            match c.output {
                Output::Root { base, reads } => {
                    prep.out_base = addr_bits(base);
                    prep.writes = reads.map(u8::from);
                }
                Output::Link => prep.links = 1,
            }
            prep.counter = word(c.counter);
            prep.block_len = word(c.block_len);
            prep.flags = word(c.flags);
        }
        Self { log_height, preprocessed }
    }

    #[must_use]
    pub const fn log_height(&self) -> usize {
        self.log_height
    }

    /// The state each compression starts from and its block, the round
    /// table's inputs.
    #[must_use]
    pub fn round_inputs(
        program: &Program,
        states: &[CompressionState],
    ) -> Vec<([u32; STATE_WORDS], [u32; STATE_WORDS])> {
        program
            .compressions
            .iter()
            .zip(states)
            .map(|(c, s)| {
                let mut state = [0u32; STATE_WORDS];
                state[..8].copy_from_slice(&s.cv);
                state[8..12].copy_from_slice(&IV[..4]);
                state[12] = c.counter;
                state[14] = c.block_len;
                state[15] = c.flags;
                (state, s.block)
            })
            .collect()
    }

    /// The witness: each compression's cells, bit, chaining value, block
    /// and final state.
    #[must_use]
    pub fn main_table(
        &self,
        program: &Program,
        values: &[F],
        states: &[CompressionState],
        finals: &[[u32; STATE_WORDS]],
    ) -> Table<F> {
        let mut rows = BitRows::new(NUM_HASH_COLS, self.log_height);
        let mut row_bits = vec![0u8; NUM_HASH_COLS];
        for (row, ((c, s), last)) in program.compressions.iter().zip(states).zip(finals).enumerate()
        {
            row_bits.fill(0);
            let cols: &mut HashCols<u8> = row_bits.as_mut_slice().borrow_mut();
            let cells: [F; SLOTS] = match c.block {
                BlockSource::Slots(reads) => reads.map(|r| Program::value(values, r.cell)),
                BlockSource::Merkle { cur, sib, .. } => {
                    [cur[0], cur[1], sib[0], sib[1]].map(|r| Program::value(values, r.cell))
                }
                BlockSource::Parent(..) => core::array::from_fn(|k| {
                    let repr = (0..4)
                        .fold(0u128, |acc, w| acc | (u128::from(s.block[4 * k + w]) << (32 * w)));
                    F::from_repr(repr)
                }),
            };
            cols.cells = cells.map(super::cells::value_bits);
            cols.bit = u8::from(s.bit);
            cols.cv = s.cv.map(word);
            cols.block = s.block.map(word);
            cols.final_state = last.map(word);
            rows.set_row(row, &row_bits);
        }
        rows.into_table()
    }
}

impl<X: Field> BaseAir<X> for HashAir {
    fn width(&self) -> usize {
        NUM_HASH_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_HASH_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_HASH_PREP_COLS))
    }
}

/// A chaining value on [`CHAIN`]: the compression's identity, and the
/// value as two elements.
fn chain_tuple<AB: AirBuilder<F: BinaryBase>>(
    id: &[AB::Var; PERMUTATION_ID_BITS],
    words: &[[AB::Expr; WORD_BITS]],
) -> Vec<AB::Expr> {
    let half = |range: core::ops::Range<usize>| -> AB::Expr {
        let bits: Vec<AB::Expr> = words[range].iter().flatten().cloned().collect();
        pack_field::<AB>(&bits)
    };
    vec![pack::<AB>(id), half(0..4), half(4..8)]
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for HashAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &HashCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep: HashPrep<AB::Var> = *prep.current_slice().borrow();

        let cells: [AB::Expr; SLOTS] = core::array::from_fn(|k| pack::<AB>(&local.cells[k]));
        let block_cells: [AB::Expr; SLOTS] = core::array::from_fn(|k| {
            let bits: Vec<AB::Var> =
                local.block[4 * k..4 * k + 4].iter().flatten().copied().collect();
            pack::<AB>(&bits)
        });
        let bit: AB::Expr = local.bit.into();
        for k in 0..SLOTS {
            let swapped = cells[k ^ 2].clone();
            builder.assert_eq(
                block_cells[k].clone(),
                cells[k].clone() + bit.clone() * (cells[k].clone() + swapped),
            );
        }
        builder.assert_zero((AB::Expr::ONE - prep.is_merkle.into()) * bit.clone());

        let cv: Vec<[AB::Expr; WORD_BITS]> =
            local.cv.iter().map(|w| exprs::<AB, WORD_BITS>(w)).collect();
        for (half, words) in [(0usize, &IV[..4]), (1, &IV[4..])] {
            let iv = words
                .iter()
                .enumerate()
                .fold(0u128, |acc, (w, &x)| acc | (u128::from(x) << (32 * w)));
            let bits: Vec<AB::Expr> =
                cv[4 * half..4 * half + 4].iter().flatten().cloned().collect();
            builder
                .when(prep.starts)
                .assert_eq(pack_field::<AB>(&bits), constant::<AB>(F::from_repr(iv)));
        }
        builder.declare_bus(
            CHAIN,
            BusDirection::Pull,
            chain_tuple::<AB>(&prep.previous, &cv),
            BusActivation::Boolean(prep.chained.into()),
        );
        for (k, slot) in prep.slots.iter().enumerate() {
            builder.declare_bus(
                MEMORY,
                BusDirection::Pull,
                cell::<AB>(slot, 0, cells[k].clone()),
                BusActivation::Boolean(prep.reads_slots.into()),
            );
        }
        builder.declare_bus(
            MEMORY,
            BusDirection::Pull,
            cell::<AB>(&prep.bit_addr, 0, bit),
            BusActivation::Boolean(prep.is_merkle.into()),
        );
        let cell_words = |range: core::ops::Range<usize>| -> Vec<[AB::Expr; WORD_BITS]> {
            range
                .flat_map(|k| {
                    (0..4).map(move |w| core::array::from_fn(|b| local.cells[k][32 * w + b].into()))
                })
                .collect()
        };
        builder.declare_bus(
            CHAIN,
            BusDirection::Pull,
            chain_tuple::<AB>(&prep.left, &cell_words(0..2)),
            BusActivation::Boolean(prep.is_parent.into()),
        );
        builder.declare_bus(
            CHAIN,
            BusDirection::Pull,
            chain_tuple::<AB>(&prep.right, &cell_words(2..4)),
            BusActivation::Boolean(prep.is_parent.into()),
        );

        let is_real: AB::Expr = prep.is_real.into();
        let initial: [[AB::Expr; WORD_BITS]; STATE_WORDS] = core::array::from_fn(|i| match i {
            0..=7 => cv[i].clone(),
            8..=11 => {
                let iv = constant_bits::<AB, WORD_BITS>(u64::from(IV[i - 8]));
                core::array::from_fn(|k| iv[k].clone() * is_real.clone())
            }
            12 => exprs::<AB, WORD_BITS>(&prep.counter),
            13 => constant_bits::<AB, WORD_BITS>(0),
            14 => exprs::<AB, WORD_BITS>(&prep.block_len),
            _ => exprs::<AB, WORD_BITS>(&prep.flags),
        });
        let words: [[AB::Expr; WORD_BITS]; STATE_WORDS] =
            core::array::from_fn(|i| exprs::<AB, WORD_BITS>(&local.block[i]));
        let id: [AB::Expr; PERMUTATION_ID_BITS] = exprs::<AB, PERMUTATION_ID_BITS>(&prep.id);
        builder.declare_bus(
            BLAKE3,
            BusDirection::Push,
            blake3_tuple::<AB>(&id, &constant_bits::<AB, BLAKE3_ROUND_BITS>(0), &initial, &words),
            BusActivation::Boolean(is_real.clone()),
        );
        let mut final_words = words;
        for _ in 0..ROUNDS {
            final_words = permute(&final_words);
        }
        let last: [[AB::Expr; WORD_BITS]; STATE_WORDS] =
            core::array::from_fn(|i| exprs::<AB, WORD_BITS>(&local.final_state[i]));
        builder.declare_bus(
            BLAKE3,
            BusDirection::Pull,
            blake3_tuple::<AB>(
                &id,
                &constant_bits::<AB, BLAKE3_ROUND_BITS>(ROUNDS as u64),
                &last,
                &final_words,
            ),
            BusActivation::Boolean(is_real),
        );

        let out: Vec<[AB::Expr; WORD_BITS]> = (0..8)
            .map(|i| core::array::from_fn(|k| last[i][k].clone() + last[i + 8][k].clone()))
            .collect();
        builder.declare_bus(
            CHAIN,
            BusDirection::Push,
            chain_tuple::<AB>(&prep.id, &out),
            BusActivation::Boolean(prep.links.into()),
        );
        for half in 0..2 {
            let bits: Vec<AB::Expr> =
                out[4 * half..4 * half + 4].iter().flatten().cloned().collect();
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell::<AB>(&prep.out_base, half as u32, pack_field::<AB>(&bits)),
                BusActivation::Boolean(prep.writes[half].into()),
            );
        }
    }
}
