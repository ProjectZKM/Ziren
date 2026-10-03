//! The Blake3 tables: one row per compression for its inputs and output,
//! and one row per round, the state travelling from row to row on the
//! [`BLAKE3`] channel.
//!
//! The input row reads the chaining value and the block as 16-bit limbs,
//! assembles the state at round zero and pushes it with the block's words;
//! each round row pulls the state and the words at its round, holds the
//! witness of the round's eight quarter-rounds, and pushes the state at the
//! next round with the words permuted; the input row pulls the state after
//! the last round and writes the eight output words as limbs.  Over a
//! binary field the xors and rotations of a round are wiring, so a round's
//! witness is the sums and carries of its forty-eight 32-bit additions.
//! The block length and the flags are the program's, preprocessed; the
//! counter is zero.

use core::borrow::{Borrow, BorrowMut};
use std::sync::Arc;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::{Field, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_derive::AlignedBorrow;
use zkm_recursion_core::runtime::blake3::{IV, MSG_PERMUTATION};
use zkm_recursion_core::{
    Blake3CompressIo, ExecutionRecord, Instruction, RecursionProgram, BLAKE3_BLOCK_LIMBS,
    BLAKE3_CV_LIMBS, BLAKE3_OUT_LIMBS,
};

use super::bits::{
    blake3_tuple, cell_tuple, dense, log_height_for, single_block, BitRows, Cell, ADDRESS_BITS,
    BLAKE3, BLAKE3_ROUND_BITS, MEMORY, PERMUTATION_ID_BITS, WRITE,
};
use crate::machine_builder::MachineBuilder;
use crate::word::{add_bits, add_carries, bits_le, constant_bits, exprs, widen, KB_BITS};
use crate::BinaryBase;
use crate::F;

/// Rounds of a compression.
pub const ROUNDS: usize = 7;

/// Bits of a word.
pub const WORD_BITS: usize = 32;

/// Bits of a limb.
pub const LIMB_BITS: usize = 16;

/// Words of a state, and of a block.
pub const STATE_WORDS: usize = 16;

/// Quarter-rounds of a round.
const QUARTER_ROUNDS: usize = 8;

/// A word as bits.
pub type WordBits<T> = [T; WORD_BITS];

/// A limb as bits.
pub type LimbBits<T> = [T; LIMB_BITS];

/// A state, or a block, as words of bits.
pub type StateBits<T> = [WordBits<T>; STATE_WORDS];

/// A state, or a block, as words of expressions.
pub type StateExprs<AB> = [[<AB as AirBuilder>::Expr; WORD_BITS]; STATE_WORDS];

/// The witness of one 32-bit addition: the sum and the carry into each bit
/// above the first, the last being the carry out, which is dropped.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Add32Cols<T> {
    pub sum: WordBits<T>,
    pub carries: WordBits<T>,
}

/// The witness of one quarter-round: its six additions, in order.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct QuarterRoundCols<T> {
    /// `a + b`.
    pub a_b: Add32Cols<T>,
    /// `a' = a + b + m0`.
    pub a_prime: Add32Cols<T>,
    /// `c' = c + d'`.
    pub c_prime: Add32Cols<T>,
    /// `a' + b'`.
    pub a_prime_b_prime: Add32Cols<T>,
    /// `a'' = a' + b' + m1`.
    pub a_out: Add32Cols<T>,
    /// `c'' = c' + d''`.
    pub c_out: Add32Cols<T>,
}

/// The program's part of an input row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Blake3IoPrep<T> {
    /// The compression's identity on the channel.
    pub id: [T; PERMUTATION_ID_BITS],
    /// Where each chaining value limb is read.
    pub addr_cv: [[T; ADDRESS_BITS]; BLAKE3_CV_LIMBS],
    /// Where each block limb is read.
    pub addr_block: [[T; ADDRESS_BITS]; BLAKE3_BLOCK_LIMBS],
    /// Where each output limb is written.
    pub addr_out: [[T; ADDRESS_BITS]; BLAKE3_OUT_LIMBS],
    /// The block length.
    pub block_len: WordBits<T>,
    /// The domain flags.
    pub flags: WordBits<T>,
    /// The row holds an instruction.
    pub is_real: T,
    /// Each output limb is read at least once.
    pub has_out: [T; BLAKE3_OUT_LIMBS],
}

/// The witness part of an input row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Blake3IoCols<T> {
    /// The chaining value's limbs.
    pub cv: [LimbBits<T>; BLAKE3_CV_LIMBS],
    /// The block's limbs.
    pub block: [LimbBits<T>; BLAKE3_BLOCK_LIMBS],
    /// The state after the last round.
    pub final_state: StateBits<T>,
}

/// The program's part of a round row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Blake3RoundPrep<T> {
    /// The compression's identity on the channel.
    pub id: [T; PERMUTATION_ID_BITS],
    /// The round the row pulls its state at.
    pub round: [T; BLAKE3_ROUND_BITS],
    /// The round the row pushes its state at.
    pub next_round: [T; BLAKE3_ROUND_BITS],
    /// The row holds a round.
    pub is_real: T,
    /// A zero, which makes the width a power of two: a table is opened in
    /// one aligned block of columns per power of two in its width, and
    /// each block costs the verifier a claim.
    pub pad: T,
}

/// The witness part of a round row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Blake3RoundCols<T> {
    /// The state entering the round.
    pub state: StateBits<T>,
    /// The message words of the round.
    pub words: StateBits<T>,
    /// The four column quarter-rounds, then the four diagonal ones.
    pub quarter_rounds: [QuarterRoundCols<T>; QUARTER_ROUNDS],
}

/// Columns of [`Blake3IoPrep`].
pub const NUM_BLAKE3_IO_PREP_COLS: usize = core::mem::size_of::<Blake3IoPrep<u8>>();

/// Columns of [`Blake3IoCols`].
pub const NUM_BLAKE3_IO_COLS: usize = core::mem::size_of::<Blake3IoCols<u8>>();

/// Columns of [`Blake3RoundPrep`].
pub const NUM_BLAKE3_ROUND_PREP_COLS: usize = core::mem::size_of::<Blake3RoundPrep<u8>>();

/// Columns of [`Blake3RoundCols`].
pub const NUM_BLAKE3_ROUND_COLS: usize = core::mem::size_of::<Blake3RoundCols<u8>>();

/// A word as bits.
#[must_use]
pub fn word_bits(value: u32) -> WordBits<u8> {
    bits_le::<WORD_BITS>(u64::from(value))
}

/// A limb as bits.
#[must_use]
pub fn limb_bits(value: u32) -> LimbBits<u8> {
    assert!(value < 1 << LIMB_BITS, "a limb is sixteen bits");
    bits_le::<LIMB_BITS>(u64::from(value))
}

/// The words of `limbs`, low limb first.
fn words_of_limbs<const N: usize>(limbs: &[KoalaBear]) -> [u32; N] {
    assert_eq!(limbs.len(), 2 * N);
    core::array::from_fn(|i| {
        let low = limbs[2 * i].as_canonical_u32();
        let high = limbs[2 * i + 1].as_canonical_u32();
        assert!(low < 1 << LIMB_BITS && high < 1 << LIMB_BITS, "a limb is sixteen bits");
        low | (high << LIMB_BITS)
    })
}

/// The words permuted for the next round.
pub fn permute<T: Clone>(words: &[T; STATE_WORDS]) -> [T; STATE_WORDS] {
    core::array::from_fn(|i| words[MSG_PERMUTATION[i]].clone())
}

/// One instruction's program part.
struct CompressionSite {
    cv: [u32; BLAKE3_CV_LIMBS],
    block: [u32; BLAKE3_BLOCK_LIMBS],
    /// `(address, reads)` of each output limb.
    out: [(u32, u32); BLAKE3_OUT_LIMBS],
    block_len: u32,
    flags: u32,
}

/// The compressions of one program, shared by the two tables.
pub struct Compressions {
    sites: Vec<CompressionSite>,
}

/// One compression's witness: the state entering each round, the words of
/// each round, and the round rows.
struct Filled {
    states: [[u32; STATE_WORDS]; ROUNDS + 1],
    rounds: Vec<Vec<u8>>,
}

impl Compressions {
    /// The compressions of `program`.
    #[must_use]
    pub fn new(program: &RecursionProgram<KoalaBear>) -> Self {
        let sites = program
            .iter_instructions()
            .filter_map(|instruction| {
                let Instruction::Blake3Compress(instr) = instruction else { return None };
                let Blake3CompressIo { chaining_value, block, output } = &instr.addrs;
                Some(CompressionSite {
                    cv: chaining_value.map(|a| a.0.as_canonical_u32()),
                    block: block.map(|a| a.0.as_canonical_u32()),
                    out: core::array::from_fn(|i| {
                        (output[i].0.as_canonical_u32(), instr.mults[i].as_canonical_u32())
                    }),
                    block_len: instr.block_len.as_canonical_u32(),
                    flags: instr.flags.as_canonical_u32(),
                })
            })
            .collect();
        Self { sites }
    }

    /// The number of compressions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sites.len()
    }

    /// Whether the program compresses at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sites.is_empty()
    }

    /// Every compression's witness, in order.
    fn fill_all(&self, record: &ExecutionRecord<KoalaBear>) -> Vec<Filled> {
        assert_eq!(record.blake3_compress_events.len(), self.len(), "one event per instruction");
        record
            .blake3_compress_events
            .iter()
            .zip(&self.sites)
            .map(|(event, site)| {
                let cv: [u32; 8] = words_of_limbs(&event.io.chaining_value);
                let block: [u32; STATE_WORDS] = words_of_limbs(&event.io.block);
                assert_eq!(event.block_len.as_canonical_u32(), site.block_len);
                assert_eq!(event.flags.as_canonical_u32(), site.flags);
                let mut state = [0u32; STATE_WORDS];
                state[..8].copy_from_slice(&cv);
                state[8..12].copy_from_slice(&IV[..4]);
                state[14] = site.block_len;
                state[15] = site.flags;
                let Filled { states, rounds } = fill_compression(state, block);
                let expected: [u32; 8] = words_of_limbs(&event.io.output);
                for i in 0..8 {
                    assert_eq!(
                        states[ROUNDS][i] ^ states[ROUNDS][i + 8],
                        expected[i],
                        "the compression over bits agrees with the VM"
                    );
                }
                Filled { states, rounds }
            })
            .collect()
    }
}

/// One compression's witness from the state entering it and its block.
fn fill_compression(state: [u32; STATE_WORDS], block: [u32; STATE_WORDS]) -> Filled {
    let mut states = [[0u32; STATE_WORDS]; ROUNDS + 1];
    states[0] = state;
    let mut words = block;
    let mut rounds = Vec::with_capacity(ROUNDS);
    for round in 0..ROUNDS {
        let mut row = vec![0u8; NUM_BLAKE3_ROUND_COLS];
        let cols: &mut Blake3RoundCols<u8> = row.as_mut_slice().borrow_mut();
        cols.state = states[round].map(word_bits);
        cols.words = words.map(word_bits);
        states[round + 1] = fill_round(&states[round], &words, &mut cols.quarter_rounds);
        words = permute(&words);
        rounds.push(row);
    }
    Filled { states, rounds }
}

/// The witness of `sum = x + y mod 2^32`.
fn fill_add(x: u32, y: u32, cols: &mut Add32Cols<u8>) -> u32 {
    let sum = x.wrapping_add(y);
    cols.sum = word_bits(sum);
    cols.carries = add_carries::<WORD_BITS>(u64::from(x), u64::from(y));
    sum
}

/// The witness of one quarter-round, returning `(a'', b'', c'', d'')`.
fn fill_quarter_round(
    (a, b, c, d): (u32, u32, u32, u32),
    (m0, m1): (u32, u32),
    cols: &mut QuarterRoundCols<u8>,
) -> (u32, u32, u32, u32) {
    let a_b = fill_add(a, b, &mut cols.a_b);
    let a_prime = fill_add(a_b, m0, &mut cols.a_prime);
    let d_prime = (a_prime ^ d).rotate_right(16);
    let c_prime = fill_add(c, d_prime, &mut cols.c_prime);
    let b_prime = (c_prime ^ b).rotate_right(12);
    let a_prime_b_prime = fill_add(a_prime, b_prime, &mut cols.a_prime_b_prime);
    let a_out = fill_add(a_prime_b_prime, m1, &mut cols.a_out);
    let d_out = (a_out ^ d_prime).rotate_right(8);
    let c_out = fill_add(c_prime, d_out, &mut cols.c_out);
    let b_out = (c_out ^ b_prime).rotate_right(7);
    (a_out, b_out, c_out, d_out)
}

/// The lanes of quarter-round `q`: the four columns, then the four
/// diagonals.
const fn lanes(q: usize) -> [usize; 4] {
    if q < 4 {
        [q, q + 4, q + 8, q + 12]
    } else {
        let i = q - 4;
        [i, 4 + (i + 1) % 4, 8 + (i + 2) % 4, 12 + (i + 3) % 4]
    }
}

/// The witness of one round, returning the state leaving it.
fn fill_round(
    state: &[u32; STATE_WORDS],
    words: &[u32; STATE_WORDS],
    cols: &mut [QuarterRoundCols<u8>; QUARTER_ROUNDS],
) -> [u32; STATE_WORDS] {
    let mut s = *state;
    for (q, quarter) in cols.iter_mut().enumerate() {
        let [ia, ib, ic, id] = lanes(q);
        let (a, b, c, d) = fill_quarter_round(
            (s[ia], s[ib], s[ic], s[id]),
            (words[2 * q], words[2 * q + 1]),
            quarter,
        );
        s[ia] = a;
        s[ib] = b;
        s[ic] = c;
        s[id] = d;
    }
    s
}

/// `x ^ y`, bit by bit.
fn xor<AB: AirBuilder>(
    x: &[AB::Expr; WORD_BITS],
    y: &[AB::Expr; WORD_BITS],
) -> [AB::Expr; WORD_BITS] {
    core::array::from_fn(|k| x[k].clone() + y[k].clone())
}

/// `x` rotated right by `n`.
fn rotate_right<AB: AirBuilder>(x: &[AB::Expr; WORD_BITS], n: usize) -> [AB::Expr; WORD_BITS] {
    core::array::from_fn(|k| x[(k + n) % WORD_BITS].clone())
}

/// Constrain `cols` to the sum of `x` and `y` modulo `2^32`, returning it.
fn eval_add<AB: AirBuilder>(
    builder: &mut AB,
    x: &[AB::Expr; WORD_BITS],
    y: &[AB::Expr; WORD_BITS],
    cols: &Add32Cols<AB::Var>,
) -> [AB::Expr; WORD_BITS] {
    let sum = exprs::<AB, WORD_BITS>(&cols.sum);
    let _carry_out = add_bits::<AB, WORD_BITS>(builder, x, y, &cols.carries, &sum);
    sum
}

/// Constrain one quarter-round on `(a, b, c, d)` with words `(m0, m1)`,
/// returning `(a'', b'', c'', d'')`.
#[allow(clippy::type_complexity)]
fn eval_quarter_round<AB: AirBuilder>(
    builder: &mut AB,
    (a, b, c, d): (
        &[AB::Expr; WORD_BITS],
        &[AB::Expr; WORD_BITS],
        &[AB::Expr; WORD_BITS],
        &[AB::Expr; WORD_BITS],
    ),
    (m0, m1): (&[AB::Expr; WORD_BITS], &[AB::Expr; WORD_BITS]),
    cols: &QuarterRoundCols<AB::Var>,
) -> ([AB::Expr; WORD_BITS], [AB::Expr; WORD_BITS], [AB::Expr; WORD_BITS], [AB::Expr; WORD_BITS]) {
    let a_b = eval_add(builder, a, b, &cols.a_b);
    let a_prime = eval_add(builder, &a_b, m0, &cols.a_prime);
    let d_prime = rotate_right::<AB>(&xor::<AB>(&a_prime, d), 16);
    let c_prime = eval_add(builder, c, &d_prime, &cols.c_prime);
    let b_prime = rotate_right::<AB>(&xor::<AB>(&c_prime, b), 12);
    let a_prime_b_prime = eval_add(builder, &a_prime, &b_prime, &cols.a_prime_b_prime);
    let a_out = eval_add(builder, &a_prime_b_prime, m1, &cols.a_out);
    let d_out = rotate_right::<AB>(&xor::<AB>(&a_out, &d_prime), 8);
    let c_out = eval_add(builder, &c_prime, &d_out, &cols.c_out);
    let b_out = rotate_right::<AB>(&xor::<AB>(&c_out, &b_prime), 7);
    (a_out, b_out, c_out, d_out)
}

/// Constrain one round on `state` with `words`, returning the state
/// leaving it.
fn eval_round<AB: AirBuilder>(
    builder: &mut AB,
    state: &StateExprs<AB>,
    words: &StateExprs<AB>,
    cols: &[QuarterRoundCols<AB::Var>; QUARTER_ROUNDS],
) -> StateExprs<AB> {
    let mut s = state.clone();
    for (q, quarter) in cols.iter().enumerate() {
        let [ia, ib, ic, id] = lanes(q);
        let (a, b, c, d) = eval_quarter_round(
            builder,
            (&s[ia], &s[ib], &s[ic], &s[id]),
            (&words[2 * q], &words[2 * q + 1]),
            quarter,
        );
        s[ia] = a;
        s[ib] = b;
        s[ic] = c;
        s[id] = d;
    }
    s
}

/// The input and output table.
pub struct Blake3IoAir {
    log_height: usize,
    preprocessed: Vec<u8>,
    compressions: Arc<Compressions>,
}

impl Blake3IoAir {
    /// The table of `compressions`.
    #[must_use]
    pub fn new(compressions: Arc<Compressions>) -> Self {
        let log_height = log_height_for(compressions.len());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_BLAKE3_IO_PREP_COLS];
        for (row, site) in compressions.sites.iter().enumerate() {
            let prep: &mut Blake3IoPrep<u8> = preprocessed
                [row * NUM_BLAKE3_IO_PREP_COLS..(row + 1) * NUM_BLAKE3_IO_PREP_COLS]
                .borrow_mut();
            prep.id = bits_le::<PERMUTATION_ID_BITS>(row as u64);
            prep.addr_cv = site.cv.map(|a| bits_le::<ADDRESS_BITS>(u64::from(a)));
            prep.addr_block = site.block.map(|a| bits_le::<ADDRESS_BITS>(u64::from(a)));
            prep.addr_out = site.out.map(|(a, _)| bits_le::<ADDRESS_BITS>(u64::from(a)));
            prep.has_out = site.out.map(|(_, reads)| u8::from(reads > 0));
            prep.block_len = word_bits(site.block_len);
            prep.flags = word_bits(site.flags);
            prep.is_real = 1;
        }
        Self { log_height, preprocessed, compressions }
    }

    /// The log height of the table.
    #[must_use]
    pub fn log_height(&self) -> usize {
        self.log_height
    }

    /// The writes `(address, reads)` of the table that are read, in order.
    #[must_use]
    pub fn writes(&self) -> Vec<(u32, u32)> {
        self.compressions
            .sites
            .iter()
            .flat_map(|site| site.out.iter().copied())
            .filter(|&(_, reads)| reads > 0)
            .collect()
    }

    /// The values of [`Self::writes`], in order.
    #[must_use]
    pub fn written_values(&self, record: &ExecutionRecord<KoalaBear>) -> Vec<Cell> {
        assert_eq!(record.blake3_compress_events.len(), self.compressions.len());
        record
            .blake3_compress_events
            .iter()
            .zip(&self.compressions.sites)
            .flat_map(|(event, site)| {
                event
                    .io
                    .output
                    .iter()
                    .zip(&site.out)
                    .filter(|(_, &(_, reads))| reads > 0)
                    .map(|(value, _)| [value.as_canonical_u32(), 0, 0, 0])
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// The witness: every compression's limbs and final state; the rows
    /// past the program are zero.
    #[must_use]
    pub fn main_table(&self, record: &ExecutionRecord<KoalaBear>) -> Table<F> {
        let filled = self.compressions.fill_all(record);
        let mut rows = BitRows::new(NUM_BLAKE3_IO_COLS, self.log_height);
        let mut row = vec![0u8; NUM_BLAKE3_IO_COLS];
        for (r, (compression, event)) in
            filled.iter().zip(&record.blake3_compress_events).enumerate()
        {
            row.fill(0);
            let cols: &mut Blake3IoCols<u8> = row.as_mut_slice().borrow_mut();
            cols.cv = event.io.chaining_value.map(|x| limb_bits(x.as_canonical_u32()));
            cols.block = event.io.block.map(|x| limb_bits(x.as_canonical_u32()));
            cols.final_state = compression.states[ROUNDS].map(word_bits);
            rows.set_row(r, &row);
        }
        rows.into_table()
    }
}

impl<X: Field> BaseAir<X> for Blake3IoAir {
    fn width(&self) -> usize {
        NUM_BLAKE3_IO_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BLAKE3_IO_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_BLAKE3_IO_PREP_COLS))
    }
}

/// The word of two limbs.
fn word_of_limbs<AB: AirBuilder>(
    low: &[AB::Expr; LIMB_BITS],
    high: &[AB::Expr; LIMB_BITS],
) -> [AB::Expr; WORD_BITS] {
    core::array::from_fn(
        |k| if k < LIMB_BITS { low[k].clone() } else { high[k - LIMB_BITS].clone() },
    )
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for Blake3IoAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Blake3IoCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: Blake3IoPrep<AB::Var> = *prep.current_slice().borrow();

        for bit in local.cv.iter().chain(local.block.iter()).flatten() {
            builder.assert_bool(*bit);
        }
        for bit in local.final_state.iter().flatten() {
            builder.assert_bool(*bit);
        }
        let is_real: AB::Expr = prep_local.is_real.into();
        let cv: [[AB::Expr; LIMB_BITS]; BLAKE3_CV_LIMBS] =
            core::array::from_fn(|i| exprs::<AB, LIMB_BITS>(&local.cv[i]));
        let block: [[AB::Expr; LIMB_BITS]; BLAKE3_BLOCK_LIMBS] =
            core::array::from_fn(|i| exprs::<AB, LIMB_BITS>(&local.block[i]));
        let id = exprs::<AB, PERMUTATION_ID_BITS>(&prep_local.id);

        let initial: StateExprs<AB> = core::array::from_fn(|i| match i {
            0..=7 => word_of_limbs::<AB>(&cv[2 * i], &cv[2 * i + 1]),
            8..=11 => {
                let iv = constant_bits::<AB, WORD_BITS>(u64::from(IV[i - 8]));
                core::array::from_fn(|k| iv[k].clone() * is_real.clone())
            }
            12 | 13 => constant_bits::<AB, WORD_BITS>(0),
            14 => exprs::<AB, WORD_BITS>(&prep_local.block_len),
            _ => exprs::<AB, WORD_BITS>(&prep_local.flags),
        });
        let words: StateExprs<AB> =
            core::array::from_fn(|i| word_of_limbs::<AB>(&block[2 * i], &block[2 * i + 1]));
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
        let final_state: StateExprs<AB> =
            core::array::from_fn(|i| exprs::<AB, WORD_BITS>(&local.final_state[i]));
        builder.declare_bus(
            BLAKE3,
            BusDirection::Pull,
            blake3_tuple::<AB>(
                &id,
                &constant_bits::<AB, BLAKE3_ROUND_BITS>(ROUNDS as u64),
                &final_state,
                &final_words,
            ),
            BusActivation::Boolean(is_real.clone()),
        );

        for (limb, addr) in cv.iter().zip(&prep_local.addr_cv) {
            builder.declare_bus(
                MEMORY,
                BusDirection::Pull,
                cell_tuple::<AB>(
                    &exprs::<AB, ADDRESS_BITS>(addr),
                    &single_block::<AB>(&widen::<AB, LIMB_BITS, KB_BITS>(limb)),
                ),
                BusActivation::Boolean(is_real.clone()),
            );
        }
        for (limb, addr) in block.iter().zip(&prep_local.addr_block) {
            builder.declare_bus(
                MEMORY,
                BusDirection::Pull,
                cell_tuple::<AB>(
                    &exprs::<AB, ADDRESS_BITS>(addr),
                    &single_block::<AB>(&widen::<AB, LIMB_BITS, KB_BITS>(limb)),
                ),
                BusActivation::Boolean(is_real.clone()),
            );
        }
        for i in 0..8 {
            let output = xor::<AB>(&final_state[i], &final_state[i + 8]);
            for half in 0..2 {
                let limb: [AB::Expr; LIMB_BITS] =
                    core::array::from_fn(|k| output[half * LIMB_BITS + k].clone());
                let j = 2 * i + half;
                builder.declare_bus(
                    WRITE,
                    BusDirection::Push,
                    cell_tuple::<AB>(
                        &exprs::<AB, ADDRESS_BITS>(&prep_local.addr_out[j]),
                        &single_block::<AB>(&widen::<AB, LIMB_BITS, KB_BITS>(&limb)),
                    ),
                    BusActivation::Boolean(prep_local.has_out[j].into()),
                );
            }
        }
    }
}

/// The round table.
pub struct Blake3RoundAir {
    log_height: usize,
    preprocessed: Vec<u8>,
    compressions: Option<Arc<Compressions>>,
}

impl Blake3RoundAir {
    /// The table of `compressions`' rounds.
    #[must_use]
    pub fn new(compressions: Arc<Compressions>) -> Self {
        let mut air = Self::for_count(compressions.len());
        air.compressions = Some(compressions);
        air
    }

    /// The table of `count` compressions' rounds, compression `i` having
    /// identity `i` on [`BLAKE3`], filled by [`Self::table_of`].
    #[must_use]
    pub fn for_count(count: usize) -> Self {
        let rows = count * ROUNDS;
        let log_height = log_height_for(rows);
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_BLAKE3_ROUND_PREP_COLS];
        for row in 0..rows {
            let (compression, round) = (row / ROUNDS, row % ROUNDS);
            let prep: &mut Blake3RoundPrep<u8> = preprocessed
                [row * NUM_BLAKE3_ROUND_PREP_COLS..(row + 1) * NUM_BLAKE3_ROUND_PREP_COLS]
                .borrow_mut();
            prep.id = bits_le::<PERMUTATION_ID_BITS>(compression as u64);
            prep.round = bits_le::<BLAKE3_ROUND_BITS>(round as u64);
            prep.next_round = bits_le::<BLAKE3_ROUND_BITS>(round as u64 + 1);
            prep.is_real = 1;
        }
        Self { log_height, preprocessed, compressions: None }
    }

    /// The witness of compressions entering with these states and blocks,
    /// in order, with the state each leaves its last round with.
    ///
    /// # Panics
    /// Panics if there are more compressions than the table was built for.
    #[must_use]
    pub fn table_of(
        &self,
        inputs: &[([u32; STATE_WORDS], [u32; STATE_WORDS])],
    ) -> (Table<F>, Vec<[u32; STATE_WORDS]>) {
        assert!(inputs.len() * ROUNDS <= 1 << self.log_height, "one input per compression");
        let mut rows = BitRows::new(NUM_BLAKE3_ROUND_COLS, self.log_height);
        let mut finals = Vec::with_capacity(inputs.len());
        for (c, &(state, block)) in inputs.iter().enumerate() {
            let filled = fill_compression(state, block);
            for (round, row) in filled.rounds.iter().enumerate() {
                rows.set_row(c * ROUNDS + round, row);
            }
            finals.push(filled.states[ROUNDS]);
        }
        (rows.into_table(), finals)
    }

    /// The log height of the table.
    #[must_use]
    pub fn log_height(&self) -> usize {
        self.log_height
    }

    /// The witness: every round's entering state, words and additions; the
    /// rows past the program are zero.
    #[must_use]
    pub fn main_table(&self, record: &ExecutionRecord<KoalaBear>) -> Table<F> {
        let filled = self
            .compressions
            .as_ref()
            .expect("a table built from a program fills from its record")
            .fill_all(record);
        let mut rows = BitRows::new(NUM_BLAKE3_ROUND_COLS, self.log_height);
        for (c, compression) in filled.iter().enumerate() {
            for (round, row) in compression.rounds.iter().enumerate() {
                rows.set_row(c * ROUNDS + round, row);
            }
        }
        rows.into_table()
    }
}

impl<X: Field> BaseAir<X> for Blake3RoundAir {
    fn width(&self) -> usize {
        NUM_BLAKE3_ROUND_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BLAKE3_ROUND_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_BLAKE3_ROUND_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for Blake3RoundAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Blake3RoundCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: Blake3RoundPrep<AB::Var> = *prep.current_slice().borrow();

        for bit in local.state.iter().chain(local.words.iter()).flatten() {
            builder.assert_bool(*bit);
        }
        let state: StateExprs<AB> =
            core::array::from_fn(|i| exprs::<AB, WORD_BITS>(&local.state[i]));
        let words: StateExprs<AB> =
            core::array::from_fn(|i| exprs::<AB, WORD_BITS>(&local.words[i]));
        let output = eval_round(builder, &state, &words, &local.quarter_rounds);
        let next_words = permute(&words);
        let id = exprs::<AB, PERMUTATION_ID_BITS>(&prep_local.id);
        builder.declare_bus(
            BLAKE3,
            BusDirection::Pull,
            blake3_tuple::<AB>(
                &id,
                &exprs::<AB, BLAKE3_ROUND_BITS>(&prep_local.round),
                &state,
                &words,
            ),
            BusActivation::Boolean(prep_local.is_real.into()),
        );
        builder.declare_bus(
            BLAKE3,
            BusDirection::Push,
            blake3_tuple::<AB>(
                &id,
                &exprs::<AB, BLAKE3_ROUND_BITS>(&prep_local.next_round),
                &output,
                &next_words,
            ),
            BusActivation::Boolean(prep_local.is_real.into()),
        );
    }
}

#[cfg(test)]
mod tests {
    use zkm_recursion_core::runtime::blake3::compress;

    use super::*;

    /// The witness of a round agrees with the reference compression.
    #[test]
    fn rounds_agree_with_the_reference() {
        let cv: [u32; 8] = core::array::from_fn(|i| 0x0123_4567u32.wrapping_mul(i as u32 + 1));
        let block: [u32; 16] = core::array::from_fn(|i| 0x89ab_cdefu32.rotate_left(i as u32));
        let (block_len, flags) = (64, 11);
        let mut state = [0u32; STATE_WORDS];
        state[..8].copy_from_slice(&cv);
        state[8..12].copy_from_slice(&IV[..4]);
        state[14] = block_len;
        state[15] = flags;
        let mut words = block;
        let mut cols = [QuarterRoundCols { ..scratch() }; QUARTER_ROUNDS];
        for _ in 0..ROUNDS {
            state = fill_round(&state, &words, &mut cols);
            words = permute(&words);
        }
        let expected = compress(&cv, &block, 0, block_len, flags);
        for i in 0..8 {
            assert_eq!(state[i] ^ state[i + 8], expected[i]);
            assert_eq!(state[i + 8] ^ cv[i], expected[i + 8]);
        }
    }

    fn scratch() -> QuarterRoundCols<u8> {
        let zero = Add32Cols { sum: [0; WORD_BITS], carries: [0; WORD_BITS] };
        QuarterRoundCols {
            a_b: zero,
            a_prime: zero,
            c_prime: zero,
            a_prime_b_prime: zero,
            a_out: zero,
            c_out: zero,
        }
    }
}
