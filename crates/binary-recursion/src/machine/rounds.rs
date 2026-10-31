//! The Blake3 round table: one row per round.
//!
//! A round is eight quarter-rounds `G`, each on lanes `(a, b, c, d)` with
//! message words `(m0, m1)` and two halves of one shape, rotations
//! `(16, 12)` then `(8, 7)`:
//!
//! ```text
//!     a1 = a + b + m       d1 = (a1 ^ d) >>> r1
//!     c1 = c + d1          b1 = (c1 ^ b) >>> r2
//! ```
//!
//! A row pulls the sixteen lanes on [`LANE`] at the round's version and
//! pushes them at the next, four touches later, and pulls the round's
//! sixteen message words on [`MSG`] at its round and pushes them at the
//! next, for the round that uses them after.  Over a binary field the xors
//! and rotations are wiring, so a row's witness is the lanes and words it
//! reads and the sum and carries of each of its 48 additions: 4,096
//! columns, seven rows a compression.  Rows of one half quarter-round each
//! were 512 columns but 112 rows a compression, twice the bits, and the
//! machine commits a power of two of its total bits.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_binary_stark::machine::bits::{
    dense, log_height_for, packed, BitRows, PERMUTATION_ID_BITS,
};
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

/// Halves of a round, two per quarter-round.
pub const HALVES: usize = 2 * QUARTER_ROUNDS;

/// Rows of a compression.
pub const ROWS_PER_COMPRESSION: usize = ROUNDS;

/// The version every lane has after the last round: a round touches each
/// lane four times.
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
    /// The version the lanes are read at, and written at.
    pub version: [T; VERSION_BITS],
    pub next_version: [T; VERSION_BITS],
    /// The round, which the words are used at, and the next.
    pub round: [T; USE_BITS],
    pub next_round: [T; USE_BITS],
    /// The block word at each of the round's positions.
    pub msg: [[T; MSG_INDEX_BITS]; HALVES],
    pub is_real: T,
    /// The words are used again, in the next round.
    pub relays: T,
}

/// The witness part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RoundsCols<T> {
    /// The lanes as the round reads them.
    pub lanes: [[T; WORD_BITS]; STATE_WORDS],
    /// The round's words, in the order its positions use them.
    pub msg: [[T; WORD_BITS]; HALVES],
    /// Each half's `a + b`, `a1 = a + b + m` and `c1 = c + d1`.
    pub adds: [[AddCols<T>; 3]; HALVES],
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

/// The block word each half quarter-round of each round reads.
#[must_use]
pub fn message_schedule() -> [[u8; HALVES]; ROUNDS] {
    core::array::from_fn(|round| core::array::from_fn(|p| message_index(round, p) as u8))
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
    pub(super) log_height: usize,
    pub(super) preprocessed: Vec<u8>,
}

impl RoundsAir {
    /// The table of `count` compressions, compression `i` having identity
    /// `i` on the channels.
    #[must_use]
    pub fn new(count: usize) -> Self {
        let log_height = log_height_for(count * ROWS_PER_COMPRESSION);
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_ROUNDS_PREP_COLS];
        for c in 0..count {
            for round in 0..ROUNDS {
                let at = (c * ROWS_PER_COMPRESSION + round) * NUM_ROUNDS_PREP_COLS;
                let prep: &mut RoundsPrep<u8> =
                    preprocessed[at..at + NUM_ROUNDS_PREP_COLS].borrow_mut();
                prep.id = bits_le::<PERMUTATION_ID_BITS>(c as u64);
                prep.version = bits_le::<VERSION_BITS>(4 * round as u64);
                prep.next_version = bits_le::<VERSION_BITS>(4 * round as u64 + 4);
                prep.round = bits_le::<USE_BITS>(round as u64);
                prep.next_round = bits_le::<USE_BITS>(round as u64 + 1);
                prep.msg = core::array::from_fn(|p| {
                    bits_le::<MSG_INDEX_BITS>(message_index(round, p) as u64)
                });
                prep.is_real = 1;
                prep.relays = u8::from(round + 1 < ROUNDS);
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
        let mut rows = BitRows::new(NUM_ROUNDS_COLS, self.log_height);
        let mut row_bits = vec![0u8; NUM_ROUNDS_COLS];
        let mut finals = Vec::with_capacity(inputs.len());
        for (c, &(state, block)) in inputs.iter().enumerate() {
            let mut s = state;
            for round in 0..ROUNDS {
                row_bits.fill(0);
                let cols: &mut RoundsCols<u8> = row_bits.as_mut_slice().borrow_mut();
                cols.lanes = s.map(|w| bits_le::<WORD_BITS>(u64::from(w)));
                let words: [u32; HALVES] = core::array::from_fn(|p| block[message_index(round, p)]);
                cols.msg = words.map(|w| bits_le::<WORD_BITS>(u64::from(w)));
                for (h, adds) in cols.adds.iter_mut().enumerate() {
                    let [ia, ib, ic, id] = lanes(h / 2);
                    let (r1, r2) = ROTATIONS[h % 2];
                    let a_b = fill_add(s[ia], s[ib], &mut adds[0]);
                    let a1 = fill_add(a_b, words[h], &mut adds[1]);
                    let d1 = (a1 ^ s[id]).rotate_right(r1 as u32);
                    let c1 = fill_add(s[ic], d1, &mut adds[2]);
                    let b1 = (c1 ^ s[ib]).rotate_right(r2 as u32);
                    s[ia] = a1;
                    s[ib] = b1;
                    s[ic] = c1;
                    s[id] = d1;
                }
                rows.set_row(c * ROWS_PER_COMPRESSION + round, &row_bits);
            }
            finals.push(s);
        }
        (rows.into_table(), finals)
    }
}

impl RoundsAir {
    /// The preprocessed columns as the bit table setup commits.
    #[must_use]
    pub fn preprocessed_table(&self) -> Table<F> {
        packed(&self.preprocessed, NUM_ROUNDS_PREP_COLS)
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

/// `x ^ y`, bit by bit: a sum over a field of characteristic two.
fn xor<E: Clone + core::ops::Add<Output = E>>(
    x: &[E; WORD_BITS],
    y: &[E; WORD_BITS],
) -> [E; WORD_BITS] {
    core::array::from_fn(|k| x[k].clone() + y[k].clone())
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for RoundsAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &RoundsCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep: RoundsPrep<AB::Var> = *prep.current_slice().borrow();

        let read: [[AB::Expr; WORD_BITS]; STATE_WORDS] =
            core::array::from_fn(|i| exprs::<AB, WORD_BITS>(&local.lanes[i]));
        let words: [[AB::Expr; WORD_BITS]; HALVES] =
            core::array::from_fn(|p| exprs::<AB, WORD_BITS>(&local.msg[p]));
        let mut state = read.clone();
        for (h, adds) in local.adds.iter().enumerate() {
            let [ia, ib, ic, id] = lanes(h / 2);
            let (r1, r2) = ROTATIONS[h % 2];
            let a_b = exprs::<AB, WORD_BITS>(&adds[0].sum);
            let _ =
                add_bits::<AB, WORD_BITS>(builder, &state[ia], &state[ib], &adds[0].carries, &a_b);
            let a1 = exprs::<AB, WORD_BITS>(&adds[1].sum);
            let _ = add_bits::<AB, WORD_BITS>(builder, &a_b, &words[h], &adds[1].carries, &a1);
            let d1 = rotate_right(&xor(&a1, &state[id]), r1);
            let c1 = exprs::<AB, WORD_BITS>(&adds[2].sum);
            let _ = add_bits::<AB, WORD_BITS>(builder, &state[ic], &d1, &adds[2].carries, &c1);
            let b1 = rotate_right(&xor(&c1, &state[ib]), r2);
            state[ia] = a1;
            state[ib] = b1;
            state[ic] = c1;
            state[id] = d1;
        }

        let id = exprs::<AB, PERMUTATION_ID_BITS>(&prep.id);
        let version = exprs::<AB, VERSION_BITS>(&prep.version);
        let next_version = exprs::<AB, VERSION_BITS>(&prep.next_version);
        let is_real: AB::Expr = prep.is_real.into();
        for lane in 0..STATE_WORDS {
            let index: [AB::Expr; LANE_BITS] =
                core::array::from_fn(|k| AB::Expr::from_bool((lane >> k) & 1 == 1));
            builder.declare_bus(
                LANE,
                BusDirection::Pull,
                word_tuple::<AB>(&id, &index, &version, &read[lane]),
                BusActivation::Boolean(is_real.clone()),
            );
            builder.declare_bus(
                LANE,
                BusDirection::Push,
                word_tuple::<AB>(&id, &index, &next_version, &state[lane]),
                BusActivation::Boolean(is_real.clone()),
            );
        }
        let round = exprs::<AB, USE_BITS>(&prep.round);
        let next_round = exprs::<AB, USE_BITS>(&prep.next_round);
        for (p, word) in words.iter().enumerate() {
            let msg = exprs::<AB, MSG_INDEX_BITS>(&prep.msg[p]);
            builder.declare_bus(
                MSG,
                BusDirection::Pull,
                word_tuple::<AB>(&id, &msg, &round, word),
                BusActivation::Boolean(is_real.clone()),
            );
            builder.declare_bus(
                MSG,
                BusDirection::Push,
                word_tuple::<AB>(&id, &msg, &next_round, word),
                BusActivation::Boolean(prep.relays.into()),
            );
        }
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

    /// Every round reads each block word once, and touches each lane four
    /// times.
    #[test]
    fn versions_and_uses_count() {
        for round in 0..ROUNDS {
            let mut used = [false; HALVES];
            for p in 0..HALVES {
                used[message_index(round, p)] = true;
            }
            assert!(used.iter().all(|&u| u), "round {round} uses every word once");
        }
        let mut touches = [0usize; STATE_WORDS];
        for q in 0..QUARTER_ROUNDS {
            for lane in lanes(q) {
                touches[lane] += 2;
            }
        }
        assert!(touches.iter().all(|&t| t == FINAL_VERSION / ROUNDS));
    }
}
