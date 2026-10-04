//! The Blake3 round table: one row per half quarter-round.
//!
//! A quarter-round `G` on lanes `(a, b, c, d)` with message words
//! `(m0, m1)` is two halves of one shape, rotations `(16, 12)` then
//! `(8, 7)`:
//!
//! ```text
//!     a1 = a + b + m       d1 = (a1 ^ d) >>> r1
//!     c1 = c + d1          b1 = (c1 ^ b) >>> r2
//! ```
//!
//! A row pulls the four lanes it reads on [`LANE`] at their version and
//! pushes `(a1, b1, c1, d1)` at the next, and pulls its message word on
//! [`MSG`] at its round and pushes it at the next, for the round that uses
//! it after.  Over a binary field the xors and rotations are wiring, so a
//! row's witness is its lanes, its word, its three 32-bit additions and the
//! two rotated lanes; which rotations apply is the row's half, preprocessed.
//! A round is sixteen rows, a compression 112, and the table is 512
//! columns wide where a row holding a whole round was 4,096: every column of
//! a table is a value the machine's verifier opens.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_binary_stark::machine::bits::{dense, log_height_for, BitRows, PERMUTATION_ID_BITS};
use zkm_binary_stark::machine::blake3::{ROUNDS, STATE_WORDS, WORD_BITS};
use zkm_binary_stark::machine_builder::MachineBuilder;
use zkm_binary_stark::word::{add_bits, add_carries, bits_le, exprs};
use zkm_binary_stark::BinaryBase;
use zkm_derive::AlignedBorrow;
use zkm_recursion_core::runtime::blake3::MSG_PERMUTATION;

use super::cells::{word_tuple, LANE, LANE_BITS, MSG, MSG_INDEX_BITS, USE_BITS, VERSION_BITS};
use crate::tape::F;

/// Quarter-rounds of a round.
const QUARTER_ROUNDS: usize = 8;

/// Rows of a compression.
pub const ROWS_PER_COMPRESSION: usize = ROUNDS * QUARTER_ROUNDS * 2;

/// The version every lane has after the last round.
pub const FINAL_VERSION: usize = 4 * ROUNDS;

/// The rotations of each half.
const ROTATIONS: [(usize, usize); 2] = [(16, 12), (8, 7)];

/// The witness of one 32-bit addition: the sum and the carry out of each
/// bit, the last being the carry out, which is dropped.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct AddCols<T> {
    pub sum: [T; WORD_BITS],
    pub carries: [T; WORD_BITS],
}

/// The program's part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RoundsPrep<T> {
    pub id: [T; PERMUTATION_ID_BITS],
    /// The lanes `a, b, c, d` are read from.
    pub lanes: [[T; LANE_BITS]; 4],
    /// The version the lanes are read at, and written at.
    pub version: [T; VERSION_BITS],
    pub next_version: [T; VERSION_BITS],
    /// The message word, and the round it is used at.
    pub msg: [T; MSG_INDEX_BITS],
    pub round: [T; USE_BITS],
    pub next_round: [T; USE_BITS],
    /// The row is the second half of its quarter-round.
    pub second: T,
    pub is_real: T,
    /// The word is used again, in the next round.
    pub relays: T,
    /// Zeros, which make the width a power of two.
    pub pad: T,
}

/// The witness part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RoundsCols<T> {
    /// The lanes `a, b, c, d` as read.
    pub lanes: [[T; WORD_BITS]; 4],
    pub msg: [T; WORD_BITS],
    /// `a + b`.
    pub a_b: AddCols<T>,
    /// `a1 = a + b + m`.
    pub a1: AddCols<T>,
    /// `c1 = c + d1`.
    pub c1: AddCols<T>,
    pub d1: [T; WORD_BITS],
    pub b1: [T; WORD_BITS],
    /// Zeros, which make the width a power of two.
    pub pad: [T; 512 - 13 * WORD_BITS],
}

pub const NUM_ROUNDS_PREP_COLS: usize = core::mem::size_of::<RoundsPrep<u8>>();
pub const NUM_ROUNDS_COLS: usize = core::mem::size_of::<RoundsCols<u8>>();

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

/// The block word round `round` uses at position `position`: the words are
/// permuted once a round, so a round's words are the block's in the order
/// the permutation, applied `round` times, gives.
fn message_index(round: usize, position: usize) -> usize {
    (0..round).fold(position, |p, _| MSG_PERMUTATION[p])
}

/// What one row does, as numbers.
#[derive(Clone, Copy)]
struct RowPlan {
    lanes: [usize; 4],
    version: usize,
    msg: usize,
    round: usize,
    second: bool,
}

/// The rows of one compression, in order.
fn plan() -> Vec<RowPlan> {
    let mut rows = Vec::with_capacity(ROWS_PER_COMPRESSION);
    for round in 0..ROUNDS {
        for q in 0..QUARTER_ROUNDS {
            let version = 4 * round + if q < 4 { 0 } else { 2 };
            for half in 0..2 {
                rows.push(RowPlan {
                    lanes: lanes(q),
                    version: version + half,
                    msg: message_index(round, 2 * q + half),
                    round,
                    second: half == 1,
                });
            }
        }
    }
    rows
}

/// The witness of `x + y mod 2^32`, returning the sum.
fn fill_add(x: u32, y: u32, cols: &mut AddCols<u8>) -> u32 {
    let sum = x.wrapping_add(y);
    cols.sum = bits_le::<WORD_BITS>(u64::from(sum));
    cols.carries = add_carries::<WORD_BITS>(u64::from(x), u64::from(y));
    sum
}

/// The round table of a program's compressions.
pub struct RoundsAir {
    log_height: usize,
    preprocessed: Vec<u8>,
}

impl RoundsAir {
    /// The table of `count` compressions, compression `i` having identity
    /// `i` on the channels.
    #[must_use]
    pub fn new(count: usize) -> Self {
        let log_height = log_height_for(count * ROWS_PER_COMPRESSION);
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_ROUNDS_PREP_COLS];
        let rows = plan();
        for c in 0..count {
            for (r, row) in rows.iter().enumerate() {
                let at = (c * ROWS_PER_COMPRESSION + r) * NUM_ROUNDS_PREP_COLS;
                let prep: &mut RoundsPrep<u8> =
                    preprocessed[at..at + NUM_ROUNDS_PREP_COLS].borrow_mut();
                prep.id = bits_le::<PERMUTATION_ID_BITS>(c as u64);
                prep.lanes = row.lanes.map(|l| bits_le::<LANE_BITS>(l as u64));
                prep.version = bits_le::<VERSION_BITS>(row.version as u64);
                prep.next_version = bits_le::<VERSION_BITS>(row.version as u64 + 1);
                prep.msg = bits_le::<MSG_INDEX_BITS>(row.msg as u64);
                prep.round = bits_le::<USE_BITS>(row.round as u64);
                prep.next_round = bits_le::<USE_BITS>(row.round as u64 + 1);
                prep.second = u8::from(row.second);
                prep.is_real = 1;
                prep.relays = u8::from(row.round + 1 < ROUNDS);
            }
        }
        Self { log_height, preprocessed }
    }

    #[must_use]
    pub const fn log_height(&self) -> usize {
        self.log_height
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
        assert!(
            inputs.len() * ROWS_PER_COMPRESSION <= 1 << self.log_height,
            "one input per compression"
        );
        let rows_plan = plan();
        let mut rows = BitRows::new(NUM_ROUNDS_COLS, self.log_height);
        let mut row_bits = vec![0u8; NUM_ROUNDS_COLS];
        let mut finals = Vec::with_capacity(inputs.len());
        for (c, &(state, block)) in inputs.iter().enumerate() {
            let mut s = state;
            for (r, row) in rows_plan.iter().enumerate() {
                row_bits.fill(0);
                let cols: &mut RoundsCols<u8> = row_bits.as_mut_slice().borrow_mut();
                let [ia, ib, ic, id] = row.lanes;
                let (a, b, c_, d) = (s[ia], s[ib], s[ic], s[id]);
                let m = block[row.msg];
                let (r1, r2) = ROTATIONS[usize::from(row.second)];
                cols.lanes = [a, b, c_, d].map(|w| bits_le::<WORD_BITS>(u64::from(w)));
                cols.msg = bits_le::<WORD_BITS>(u64::from(m));
                let a_b = fill_add(a, b, &mut cols.a_b);
                let a1 = fill_add(a_b, m, &mut cols.a1);
                let d1 = (a1 ^ d).rotate_right(r1 as u32);
                let c1 = fill_add(c_, d1, &mut cols.c1);
                let b1 = (c1 ^ b).rotate_right(r2 as u32);
                cols.d1 = bits_le::<WORD_BITS>(u64::from(d1));
                cols.b1 = bits_le::<WORD_BITS>(u64::from(b1));
                s[ia] = a1;
                s[ib] = b1;
                s[ic] = c1;
                s[id] = d1;
                rows.set_row(c * ROWS_PER_COMPRESSION + r, &row_bits);
            }
            finals.push(s);
        }
        (rows.into_table(), finals)
    }
}

impl<X: Field> BaseAir<X> for RoundsAir {
    fn width(&self) -> usize {
        NUM_ROUNDS_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_ROUNDS_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_ROUNDS_PREP_COLS))
    }
}

/// `x` rotated right by `n`.
fn rotate_right<E: Clone>(x: &[E; WORD_BITS], n: usize) -> [E; WORD_BITS] {
    core::array::from_fn(|k| x[(k + n) % WORD_BITS].clone())
}

/// Constrain `out` to `x` rotated right by `r1` on a first half and by
/// `r2` on a second.
fn assert_rotation<AB: AirBuilder>(
    builder: &mut AB,
    second: &AB::Expr,
    x: &[AB::Expr; WORD_BITS],
    out: &[AB::Var; WORD_BITS],
    (first_shift, second_shift): (usize, usize),
) {
    let first_way = rotate_right(x, first_shift);
    let second_way = rotate_right(x, second_shift);
    for k in 0..WORD_BITS {
        let rotated =
            first_way[k].clone() + second.clone() * (first_way[k].clone() + second_way[k].clone());
        builder.assert_eq(out[k], rotated);
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for RoundsAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &RoundsCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep: RoundsPrep<AB::Var> = *prep.current_slice().borrow();

        let lane: [[AB::Expr; WORD_BITS]; 4] =
            core::array::from_fn(|i| exprs::<AB, WORD_BITS>(&local.lanes[i]));
        let [a, b, c, d] = &lane;
        let m = exprs::<AB, WORD_BITS>(&local.msg);
        let second: AB::Expr = prep.second.into();

        let a_b = exprs::<AB, WORD_BITS>(&local.a_b.sum);
        let _ = add_bits::<AB, WORD_BITS>(builder, a, b, &local.a_b.carries, &a_b);
        let a1 = exprs::<AB, WORD_BITS>(&local.a1.sum);
        let _ = add_bits::<AB, WORD_BITS>(builder, &a_b, &m, &local.a1.carries, &a1);
        let a1_d: [AB::Expr; WORD_BITS] = core::array::from_fn(|k| a1[k].clone() + d[k].clone());
        let rotations = (ROTATIONS[0].0, ROTATIONS[1].0);
        assert_rotation(builder, &second, &a1_d, &local.d1, rotations);
        let d1 = exprs::<AB, WORD_BITS>(&local.d1);
        let c1 = exprs::<AB, WORD_BITS>(&local.c1.sum);
        let _ = add_bits::<AB, WORD_BITS>(builder, c, &d1, &local.c1.carries, &c1);
        let c1_b: [AB::Expr; WORD_BITS] = core::array::from_fn(|k| c1[k].clone() + b[k].clone());
        let rotations = (ROTATIONS[0].1, ROTATIONS[1].1);
        assert_rotation(builder, &second, &c1_b, &local.b1, rotations);
        let b1 = exprs::<AB, WORD_BITS>(&local.b1);

        let id = exprs::<AB, PERMUTATION_ID_BITS>(&prep.id);
        let version = exprs::<AB, VERSION_BITS>(&prep.version);
        let next_version = exprs::<AB, VERSION_BITS>(&prep.next_version);
        let is_real: AB::Expr = prep.is_real.into();
        let outputs = [&a1, &b1, &c1, &d1];
        for i in 0..4 {
            let index = exprs::<AB, LANE_BITS>(&prep.lanes[i]);
            builder.declare_bus(
                LANE,
                BusDirection::Pull,
                word_tuple::<AB>(&id, &index, &version, &lane[i]),
                BusActivation::Boolean(is_real.clone()),
            );
            builder.declare_bus(
                LANE,
                BusDirection::Push,
                word_tuple::<AB>(&id, &index, &next_version, outputs[i]),
                BusActivation::Boolean(is_real.clone()),
            );
        }
        let msg = exprs::<AB, MSG_INDEX_BITS>(&prep.msg);
        builder.declare_bus(
            MSG,
            BusDirection::Pull,
            word_tuple::<AB>(&id, &msg, &exprs::<AB, USE_BITS>(&prep.round), &m),
            BusActivation::Boolean(is_real),
        );
        builder.declare_bus(
            MSG,
            BusDirection::Push,
            word_tuple::<AB>(&id, &msg, &exprs::<AB, USE_BITS>(&prep.next_round), &m),
            BusActivation::Boolean(prep.relays.into()),
        );
    }
}

#[cfg(test)]
mod tests {
    use zkm_recursion_core::runtime::blake3::{compress, IV};

    use super::*;

    /// The rows of a compression compute the reference compression.
    #[test]
    fn rows_agree_with_the_reference() {
        let cv: [u32; 8] = core::array::from_fn(|i| 0x0123_4567u32.wrapping_mul(i as u32 + 1));
        let block: [u32; 16] = core::array::from_fn(|i| 0x89ab_cdefu32.rotate_left(i as u32));
        let (counter, block_len, flags) = (3u32, 64, 11);
        let mut state = [0u32; STATE_WORDS];
        state[..8].copy_from_slice(&cv);
        state[8..12].copy_from_slice(&IV[..4]);
        state[12] = counter;
        state[14] = block_len;
        state[15] = flags;
        let air = RoundsAir::new(1);
        let (_, finals) = air.table_of(&[(state, block)]);
        let expected = compress(&cv, &block, u64::from(counter), block_len, flags);
        for i in 0..8 {
            assert_eq!(finals[0][i] ^ finals[0][i + 8], expected[i]);
            assert_eq!(finals[0][i + 8] ^ cv[i], expected[i + 8]);
        }
    }

    /// Every lane is touched four times a round, and every word once.
    #[test]
    fn versions_and_uses_count() {
        let rows = plan();
        let mut touches = [0usize; STATE_WORDS];
        let mut uses = [[0usize; ROUNDS]; STATE_WORDS];
        for row in &rows {
            for lane in row.lanes {
                assert_eq!(row.version, touches[lane], "lane {lane} read at its version");
                touches[lane] += 1;
            }
            uses[row.msg][row.round] += 1;
        }
        assert!(touches.iter().all(|&t| t == FINAL_VERSION));
        assert!(uses.iter().flatten().all(|&u| u == 1));
    }
}
