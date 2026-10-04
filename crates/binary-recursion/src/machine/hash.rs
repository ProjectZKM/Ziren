//! The Blake3 input and output table: three rows per compression.
//!
//! Two *message* rows read the block and start the state; one *output* row
//! takes the state after the last round and sends the chaining value on.
//! The round table moves the state one lane at a time on [`LANE`] and each
//! message word from round to round on [`MSG`]:
//!
//! - **The block** is four cells of sixteen bytes; message row `p` holds
//!   cells `p` and `p + 2`, pulled from [`MEMORY`], or for a parent the
//!   halves `p` of its two children's chaining values, pulled on [`CHAIN`].
//!   A Merkle node's cells are its digest and its sibling, swapped when its
//!   path bit is one: cell `k` of the block is `x + bit (x + x')`, `x'` the
//!   cell two places on, which is in the same row.  The row pushes the
//!   eight message words of its two cells at their first use.
//! - **The state** starts with the chaining value in lanes 0 to 7 and the
//!   initial value, counter, block length and flags in lanes 8 to 15, which
//!   message row 0 pushes at version zero.  The chaining value is the
//!   initial value for the first block of a chunk, for a parent and for a
//!   Merkle node, pushed by the same row; otherwise the output row of the
//!   compression before pushes it, as this compression's lanes.
//! - **The output** of a root is the digest, its two halves pushed on
//!   [`WRITE`]; a parent's child pushes its halves on [`CHAIN`].
//!
//! A row is 512 columns: a message row holds 257 of them, an output row the
//! sixteen final lanes.  Every column of a table is a value the machine's
//! verifier opens, and the rows of a compression were one row of 2,048.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_binary_stark::machine::bits::{
    dense, log_height_for, pack_field, BitRows, MEMORY, PERMUTATION_ID_BITS, WRITE,
};
use zkm_binary_stark::machine::blake3::{STATE_WORDS, WORD_BITS};
use zkm_binary_stark::machine_builder::MachineBuilder;
use zkm_binary_stark::word::{bits_le, constant_bits, exprs};
use zkm_binary_stark::BinaryBase;
use zkm_derive::AlignedBorrow;
use zkm_recursion_core::runtime::blake3::IV;

use super::cells::{
    addr_bits, cell, pack, word_tuple, CHAIN, LANE, LANE_BITS, MSG, MSG_INDEX_BITS, USE_BITS,
    VALUE_BITS, VERSION_BITS,
};
use super::program::{BlockSource, CompressionState, CvSource, Output, Program, ADDR_BITS};
use super::rounds::FINAL_VERSION;
use crate::tape::F;
use p3_binary_field::TowerLevel;

/// Rows of a compression.
pub const ROWS_PER_COMPRESSION: usize = 3;

/// Bits of a counter, a block length and a flags word that the program
/// can set; the rest of each word is zero.
const COUNTER_BITS: usize = 16;
const LEN_BITS: usize = 7;
const FLAG_BITS: usize = 7;

/// The program's part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct HashPrep<T> {
    pub id: [T; PERMUTATION_ID_BITS],
    /// A message row's left child; an output row's successor.
    pub other: [T; PERMUTATION_ID_BITS],
    /// A message row's right child.
    pub right: [T; PERMUTATION_ID_BITS],
    /// Where a message row's two cells are read.
    pub slots: [[T; ADDR_BITS]; 2],
    pub bit_addr: [T; ADDR_BITS],
    pub out_base: [T; ADDR_BITS],
    /// Which pair of cells a message row holds.
    pub pair: T,
    pub is_msg: T,
    pub is_out: T,
    /// Message row 0, which starts the state.
    pub first: T,
    /// The chaining value is the initial value.
    pub starts: T,
    /// The cells are pulled from memory.
    pub reads_slots: T,
    /// The cells are the children's chaining values.
    pub is_parent: T,
    /// The row is a Merkle node's, and pulls its bit.
    pub is_merkle: T,
    /// The digest's halves are pushed, each where it is read.
    pub writes: [T; 2],
    /// The chaining value is the successor's state.
    pub links_cv: T,
    /// The chaining value is pushed for a parent.
    pub links_parent: T,
    pub counter: [T; COUNTER_BITS],
    pub block_len: [T; LEN_BITS],
    pub flags: [T; FLAG_BITS],
    /// Zeros, which make the width a power of two.
    pub pad: [T; 256 - 7 * PERMUTATION_ID_BITS - 12 - COUNTER_BITS - LEN_BITS - FLAG_BITS],
}

/// A message row's witness.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct MsgCols<T> {
    /// Cells `p` and `p + 2` as pulled, before a Merkle node's swap.
    pub cells: [[T; VALUE_BITS]; 2],
    pub bit: T,
    /// Zeros: the output row is the wider.
    pub pad: [T; 512 - 2 * VALUE_BITS - 1],
}

/// An output row's witness: the lanes after the last round.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct OutCols<T> {
    pub last: [[T; WORD_BITS]; STATE_WORDS],
}

pub const NUM_HASH_PREP_COLS: usize = core::mem::size_of::<HashPrep<u8>>();
pub const NUM_HASH_COLS: usize = core::mem::size_of::<OutCols<u8>>();
const _: () = assert!(core::mem::size_of::<MsgCols<u8>>() == NUM_HASH_COLS);
const _: () = assert!(NUM_HASH_PREP_COLS == 256);
const _: () = assert!(ADDR_BITS == PERMUTATION_ID_BITS);

/// The compression table of one program.
pub struct HashAir {
    log_height: usize,
    preprocessed: Vec<u8>,
}

/// The bits of a word.
fn word(value: u32) -> [u8; WORD_BITS] {
    bits_le::<WORD_BITS>(u64::from(value))
}

/// Each compression's consumer: the compression that continues from its
/// chaining value, or the parent it is a child of.
#[derive(Clone, Copy)]
enum Consumer {
    None,
    Successor(usize),
    Parent,
}

fn consumers(program: &Program) -> Vec<Consumer> {
    let mut consumers = vec![Consumer::None; program.compressions.len()];
    let mut set = |i: usize, consumer: Consumer| {
        assert!(matches!(consumers[i], Consumer::None), "a chaining value is consumed once");
        consumers[i] = consumer;
    };
    for (d, c) in program.compressions.iter().enumerate() {
        if let CvSource::Chained(previous) = c.cv {
            set(previous, Consumer::Successor(d));
        }
        if let BlockSource::Parent(left, right) = c.block {
            set(left, Consumer::Parent);
            set(right, Consumer::Parent);
        }
    }
    consumers
}

impl HashAir {
    #[must_use]
    pub fn new(program: &Program) -> Self {
        let n = program.compressions.len();
        let log_height = log_height_for(ROWS_PER_COMPRESSION * n);
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_HASH_PREP_COLS];
        let consumers = consumers(program);
        let id = |i: usize| bits_le::<PERMUTATION_ID_BITS>(i as u64);
        for (c, compression) in program.compressions.iter().enumerate() {
            assert!(compression.counter < 1 << COUNTER_BITS, "a counter fits its bits");
            assert!(compression.block_len < 1 << LEN_BITS, "a block length fits its bits");
            assert!(compression.flags < 1 << FLAG_BITS, "flags fit their bits");
            for r in 0..ROWS_PER_COMPRESSION {
                let at = (ROWS_PER_COMPRESSION * c + r) * NUM_HASH_PREP_COLS;
                let prep: &mut HashPrep<u8> =
                    preprocessed[at..at + NUM_HASH_PREP_COLS].borrow_mut();
                prep.id = id(c);
                if r < 2 {
                    prep.is_msg = 1;
                    prep.pair = r as u8;
                    if r == 0 {
                        prep.first = 1;
                        prep.starts = u8::from(matches!(compression.cv, CvSource::Iv));
                        prep.counter = bits_le::<COUNTER_BITS>(u64::from(compression.counter));
                        prep.block_len = bits_le::<LEN_BITS>(u64::from(compression.block_len));
                        prep.flags = bits_le::<FLAG_BITS>(u64::from(compression.flags));
                    }
                    match compression.block {
                        BlockSource::Slots(reads) => {
                            prep.reads_slots = 1;
                            prep.slots = [addr_bits(reads[r].addr), addr_bits(reads[r + 2].addr)];
                        }
                        BlockSource::Parent(left, right) => {
                            prep.is_parent = 1;
                            prep.other = id(left);
                            prep.right = id(right);
                        }
                        BlockSource::Merkle { bit, cur, sib } => {
                            prep.reads_slots = 1;
                            prep.is_merkle = 1;
                            prep.bit_addr = addr_bits(bit.addr);
                            prep.slots = [addr_bits(cur[r].addr), addr_bits(sib[r].addr)];
                        }
                    }
                } else {
                    prep.is_out = 1;
                    match compression.output {
                        Output::Root { base, reads } => {
                            prep.out_base = addr_bits(base);
                            prep.writes = reads.map(u8::from);
                        }
                        Output::Link => match consumers[c] {
                            Consumer::Successor(d) => {
                                prep.links_cv = 1;
                                prep.other = id(d);
                            }
                            Consumer::Parent => prep.links_parent = 1,
                            Consumer::None => panic!("a link has a consumer"),
                        },
                    }
                }
            }
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

    /// The witness: each compression's cells and bit, and its final lanes.
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
        for (c, ((compression, s), last)) in
            program.compressions.iter().zip(states).zip(finals).enumerate()
        {
            let cells: [F; 4] = match compression.block {
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
            for pair in 0..2 {
                row_bits.fill(0);
                let cols: &mut MsgCols<u8> = row_bits.as_mut_slice().borrow_mut();
                cols.cells = [cells[pair], cells[pair + 2]].map(super::cells::value_bits);
                cols.bit = u8::from(s.bit);
                rows.set_row(ROWS_PER_COMPRESSION * c + pair, &row_bits);
            }
            row_bits.fill(0);
            let cols: &mut OutCols<u8> = row_bits.as_mut_slice().borrow_mut();
            cols.last = last.map(word);
            rows.set_row(ROWS_PER_COMPRESSION * c + 2, &row_bits);
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

/// Half `half` of a chaining value on [`CHAIN`]: the compression's identity
/// and the half in one element, the value in another.
fn chain_tuple<AB: AirBuilder<F: BinaryBase>>(
    id: &[AB::Expr; PERMUTATION_ID_BITS],
    half: AB::Expr,
    value: AB::Expr,
) -> Vec<AB::Expr> {
    let header: Vec<AB::Expr> = id.iter().cloned().chain(core::iter::once(half)).collect();
    vec![pack_field::<AB>(&header), value]
}

/// `bits` of a word, widened to a word with zeros above.
fn word_of<AB: AirBuilder, const N: usize>(bits: &[AB::Var; N]) -> [AB::Expr; WORD_BITS] {
    core::array::from_fn(|k| if k < N { bits[k].into() } else { AB::Expr::ZERO })
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for HashAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let msg: &MsgCols<AB::Var> = row.borrow();
        let out_cols: &OutCols<AB::Var> = row.borrow();
        let prep = builder.preprocessed();
        let prep: HashPrep<AB::Var> = *prep.current_slice().borrow();

        let id = exprs::<AB, PERMUTATION_ID_BITS>(&prep.id);
        let pair: AB::Expr = prep.pair.into();
        let is_msg: AB::Expr = prep.is_msg.into();
        let bit: AB::Expr = msg.bit.into();
        builder.assert_zero(is_msg.clone() * (AB::Expr::ONE - prep.is_merkle.into()) * bit.clone());

        let cells: [AB::Expr; 2] = core::array::from_fn(|k| pack::<AB>(&msg.cells[k]));
        for k in 0..2 {
            builder.declare_bus(
                MEMORY,
                BusDirection::Pull,
                cell::<AB>(&prep.slots[k], 0, cells[k].clone()),
                BusActivation::Boolean(prep.reads_slots.into()),
            );
        }
        builder.declare_bus(
            MEMORY,
            BusDirection::Pull,
            cell::<AB>(&prep.bit_addr, 0, bit.clone()),
            BusActivation::Boolean(prep.is_merkle.into()),
        );
        let children = [
            exprs::<AB, PERMUTATION_ID_BITS>(&prep.other),
            exprs::<AB, PERMUTATION_ID_BITS>(&prep.right),
        ];
        for k in 0..2 {
            builder.declare_bus(
                CHAIN,
                BusDirection::Pull,
                chain_tuple::<AB>(&children[k], pair.clone(), cells[k].clone()),
                BusActivation::Boolean(prep.is_parent.into()),
            );
        }
        let first_use = constant_bits::<AB, USE_BITS>(0);
        for k in 0..2 {
            let other = 1 - k;
            for w in 0..4 {
                let word: [AB::Expr; WORD_BITS] = core::array::from_fn(|b| {
                    let x: AB::Expr = msg.cells[k][32 * w + b].into();
                    let x2: AB::Expr = msg.cells[other][32 * w + b].into();
                    x.clone() + bit.clone() * (x + x2)
                });
                let index: [AB::Expr; MSG_INDEX_BITS] = [
                    AB::Expr::from_bool(w & 1 == 1),
                    AB::Expr::from_bool(w & 2 == 2),
                    pair.clone(),
                    AB::Expr::from_bool(k == 1),
                ];
                builder.declare_bus(
                    MSG,
                    BusDirection::Push,
                    word_tuple::<AB>(&id, &index, &first_use, &word),
                    BusActivation::Boolean(is_msg.clone()),
                );
            }
        }

        let start = constant_bits::<AB, VERSION_BITS>(0);
        let lane_index = |i: usize| constant_bits::<AB, LANE_BITS>(i as u64);
        for i in 0..STATE_WORDS {
            let (value, activation): ([AB::Expr; WORD_BITS], AB::Expr) = match i {
                0..=7 => (constant_bits::<AB, WORD_BITS>(u64::from(IV[i])), prep.starts.into()),
                8..=11 => (constant_bits::<AB, WORD_BITS>(u64::from(IV[i - 8])), prep.first.into()),
                12 => (word_of::<AB, COUNTER_BITS>(&prep.counter), prep.first.into()),
                13 => (constant_bits::<AB, WORD_BITS>(0), prep.first.into()),
                14 => (word_of::<AB, LEN_BITS>(&prep.block_len), prep.first.into()),
                _ => (word_of::<AB, FLAG_BITS>(&prep.flags), prep.first.into()),
            };
            builder.declare_bus(
                LANE,
                BusDirection::Push,
                word_tuple::<AB>(&id, &lane_index(i), &start, &value),
                BusActivation::Boolean(activation),
            );
        }

        let last: [[AB::Expr; WORD_BITS]; STATE_WORDS] =
            core::array::from_fn(|i| exprs::<AB, WORD_BITS>(&out_cols.last[i]));
        let final_version = constant_bits::<AB, VERSION_BITS>(FINAL_VERSION as u64);
        for (i, lane) in last.iter().enumerate() {
            builder.declare_bus(
                LANE,
                BusDirection::Pull,
                word_tuple::<AB>(&id, &lane_index(i), &final_version, lane),
                BusActivation::Boolean(prep.is_out.into()),
            );
        }
        let out: [[AB::Expr; WORD_BITS]; 8] = core::array::from_fn(|i| {
            core::array::from_fn(|k| last[i][k].clone() + last[i + 8][k].clone())
        });
        let successor = exprs::<AB, PERMUTATION_ID_BITS>(&prep.other);
        for (i, word) in out.iter().enumerate() {
            builder.declare_bus(
                LANE,
                BusDirection::Push,
                word_tuple::<AB>(&successor, &lane_index(i), &start, word),
                BusActivation::Boolean(prep.links_cv.into()),
            );
        }
        for half in 0..2 {
            let bits: Vec<AB::Expr> =
                out[4 * half..4 * half + 4].iter().flatten().cloned().collect();
            let value = pack_field::<AB>(&bits);
            builder.declare_bus(
                CHAIN,
                BusDirection::Push,
                chain_tuple::<AB>(&id, AB::Expr::from_bool(half == 1), value.clone()),
                BusActivation::Boolean(prep.links_parent.into()),
            );
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell::<AB>(&prep.out_base, half as u32, value),
                BusActivation::Boolean(prep.writes[half].into()),
            );
        }
    }
}
