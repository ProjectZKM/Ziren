//! Bit rows, packed tables and bus tuples shared by the machine's tables.
//!
//! Every table of the machine is a matrix of bits.  A row is built as one
//! `u8` per cell, packed sixty-four rows to a word into the layout
//! [`Table::from_packed_bits`] reads, and a preprocessed trace is the same
//! bits as a dense matrix, which is what [`p3_air::BaseAir::preprocessed_trace`]
//! returns.  A memory cell on a bus is two field elements, the address and
//! the block, each with one bit per coordinate of the field.

use p3_air::AirBuilder;
use p3_binary_pcs::coordinate_basis;
use p3_bus::{BusActivation, BusDirection, BusName};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use p3_sumcheck::layout::Table;

use crate::machine_builder::MachineBuilder;
use crate::word::{bits_le, KB_BITS};
use crate::BinaryBase;
use crate::F;

/// Bits of a memory address, a KoalaBear element.
pub const ADDRESS_BITS: usize = KB_BITS;

/// Bits of a memory block, four KoalaBear elements.
pub const BLOCK_BITS: usize = 4 * KB_BITS;

/// The smallest table height, one packed word per column.
pub const MIN_LOG_HEIGHT: usize = 6;

/// The channel every read of a cell pulls from, fed by the ledger.
pub const MEMORY: BusName<'static> = BusName::new("memory");

/// The channel every write of a cell pushes to, once, for the ledger.
pub const WRITE: BusName<'static> = BusName::new("write");

/// The channel every product of two words is asked for on, served by the
/// multiply table.
pub const MUL: BusName<'static> = BusName::new("mul");

/// The channel a Blake3 compression's state and message words travel on
/// from round to round.
pub const BLAKE3: BusName<'static> = BusName::new("blake3");

/// Bits of a Blake3 round index on that channel.
pub const BLAKE3_ROUND_BITS: usize = 3;

/// Bits of a compression's identity on that channel.
pub const PERMUTATION_ID_BITS: usize = 26;

/// A memory block as integers.
pub type Cell = [u32; 4];

/// The bits of `cell`, element after element.
#[must_use]
pub fn cell_bits(cell: &Cell) -> [u8; BLOCK_BITS] {
    let mut bits = [0u8; BLOCK_BITS];
    for (chunk, &element) in bits.chunks_mut(KB_BITS).zip(cell) {
        chunk.copy_from_slice(&bits_le::<KB_BITS>(u64::from(element)));
    }
    bits
}

/// The width a table of `raw` columns is committed at.
///
/// A table is opened in one aligned block of columns per power of two in
/// its width, and the verifier pays for each block at every point it opens
/// the table, so a width is padded with zero columns to the next power of
/// two when that adds at most half again, and otherwise to the sum of its
/// top power of two and the power of two that covers the rest: two blocks.
/// A table of 512 columns or more takes a third block when that saves an
/// eighth of the width: its bits, which the prover pays for row by row,
/// outweigh the verifier's claim.
#[must_use]
pub const fn padded_width(raw: usize) -> usize {
    if raw == 0 {
        return 0;
    }
    let next = raw.next_power_of_two();
    let top = if next == raw { raw } else { next / 2 };
    let fewest = if next - raw <= raw / 2 || top == raw {
        next
    } else {
        top + (raw - top).next_power_of_two()
    };
    let rest = raw - top;
    if rest == 0 {
        return fewest;
    }
    let second = if rest.is_power_of_two() { rest } else { rest.next_power_of_two() / 2 };
    let three = if rest == second {
        top + second
    } else {
        top + second + (rest - second).next_power_of_two()
    };
    if raw >= 512 && three <= fewest - fewest / 8 {
        three
    } else {
        fewest
    }
}

/// The log height of a table of `rows` rows, at least [`MIN_LOG_HEIGHT`].
#[must_use]
pub fn log_height_for(rows: usize) -> usize {
    let log = rows.max(1).next_power_of_two().trailing_zeros() as usize;
    log.max(MIN_LOG_HEIGHT)
}

/// Rows of bits packed into the table layout: word `w` of a column holds
/// rows `64w..64w+63`, row `r` at bit `r % 64`.
pub struct BitRows {
    width: usize,
    log_height: usize,
    words: Vec<u64>,
}

impl BitRows {
    /// An all-zero table of `width` columns and `2^log_height` rows.
    #[must_use]
    pub fn new(width: usize, log_height: usize) -> Self {
        assert!(log_height >= MIN_LOG_HEIGHT, "a packed table holds at least one word per column");
        Self { width, log_height, words: vec![0; (1 << log_height) / 64 * width] }
    }

    /// An all-zero table of `raw` columns padded to [`padded_width`].
    #[must_use]
    pub fn padded(raw: usize, log_height: usize) -> Self {
        Self::new(padded_width(raw), log_height)
    }

    /// Set row `r` to `row`, the columns past it zero, which must be all
    /// zero before.
    pub fn set_row(&mut self, r: usize, row: &[u8]) {
        assert!(row.len() <= self.width, "a row fits its table");
        let block = &mut self.words[(r / 64) * self.width..(r / 64 + 1) * self.width];
        for (word, &bit) in block.iter_mut().zip(row) {
            *word |= u64::from(bit) << (r % 64);
        }
    }

    /// The table.
    #[must_use]
    pub fn into_table(self) -> Table<F> {
        Table::from_packed_bits(RowMajorMatrix::new(self.words, self.width), self.log_height)
    }
}

/// Rows of bits row-major: row `r` holds `words_per_row` words, column `c`
/// on bit `c % 64` of its word `c / 64`.  A table's rows are written here a
/// value at a time and turned into [`BitRows`]' layout in one transposition.
pub struct RowBits {
    width: usize,
    log_height: usize,
    words: Vec<u64>,
}

impl RowBits {
    /// An all-zero table of `width` columns and `2^log_height` rows.
    #[must_use]
    pub fn new(width: usize, log_height: usize) -> Self {
        assert!(log_height >= MIN_LOG_HEIGHT, "a packed table holds at least one word per column");
        Self { width, log_height, words: vec![0; (1 << log_height) * width.div_ceil(64)] }
    }

    /// The low `bits` bits of `value` on row `r` from column `column` up, the
    /// columns there zero before.
    pub fn put(&mut self, r: usize, column: usize, value: u128, bits: usize) {
        let (width, per_row) = (self.width, self.words_per_row());
        RowMut { width, words: &mut self.words[r * per_row..(r + 1) * per_row] }.put(column, value, bits);
    }

    /// Every row, to be written side by side.
    pub fn par_rows_mut(&mut self) -> impl IndexedParallelIterator<Item = RowMut<'_>> {
        let (width, per_row) = (self.width, self.words_per_row());
        self.words.par_chunks_mut(per_row).map(move |words| RowMut { width, words })
    }

    #[must_use]
    pub const fn width(&self) -> usize {
        self.width
    }

    #[must_use]
    pub const fn log_height(&self) -> usize {
        self.log_height
    }

    #[must_use]
    pub const fn words_per_row(&self) -> usize {
        self.width.div_ceil(64)
    }

    /// The rows' words, row after row.
    #[must_use]
    pub fn words(&self) -> &[u64] {
        &self.words
    }

    /// The table, transposed on the host.
    #[must_use]
    pub fn into_table(self) -> Table<F> {
        let (width, per_row) = (self.width, self.words_per_row());
        let mut out = vec![0u64; (1 << self.log_height) / 64 * width];
        out.par_chunks_mut(width).enumerate().for_each(|(block, columns)| {
            for w in 0..per_row {
                let mut square: [u64; 64] =
                    core::array::from_fn(|r| self.words[(64 * block + r) * per_row + w]);
                transpose64(&mut square);
                for (k, &column) in square.iter().enumerate().take(width.saturating_sub(64 * w)) {
                    columns[64 * w + k] = column;
                }
            }
        });
        Table::from_packed_bits(RowMajorMatrix::new(out, width), self.log_height)
    }
}

/// One row of a [`RowBits`].
pub struct RowMut<'a> {
    width: usize,
    words: &'a mut [u64],
}

impl RowMut<'_> {
    /// The low `bits` bits of `value` from column `column` up, the columns
    /// there zero before.
    pub fn put(&mut self, column: usize, value: u128, bits: usize) {
        assert!(column + bits <= self.width && bits <= 128, "a value fits its row");
        if bits == 0 {
            return;
        }
        let value = if bits == 128 { value } else { value & ((1u128 << bits) - 1) };
        let (word, shift) = (column / 64, column % 64);
        self.words[word] |= (value as u64) << shift;
        let rest = if shift == 0 { value >> 64 } else { value >> (64 - shift) };
        if rest != 0 {
            self.words[word + 1] |= rest as u64;
            let rest = if shift == 0 { 0 } else { rest >> 64 };
            if rest != 0 {
                self.words[word + 2] |= rest as u64;
            }
        }
    }
}

/// Transpose a 64 by 64 bit matrix, row `r` in word `r` with column `c` on
/// bit `c`, in place.
fn transpose64(m: &mut [u64; 64]) {
    let mut j = 32;
    let mut mask = 0x0000_0000_ffff_ffffu64;
    while j != 0 {
        let mut k = 0;
        while k < 64 {
            let t = ((m[k] >> j) ^ m[k + j]) & mask;
            m[k] ^= t << j;
            m[k + j] ^= t;
            k = (k + j + 1) & !j;
        }
        j >>= 1;
        mask ^= mask << j;
    }
}

/// `bits`, row-major with `width` columns, as a dense matrix of zeros and
/// ones.
#[must_use]
pub fn dense<X: Field>(bits: &[u8], width: usize) -> RowMajorMatrix<X> {
    assert!(!bits.is_empty(), "the preprocessed trace was released once setup committed it");
    RowMajorMatrix::new(
        bits.iter().map(|&bit| if bit == 1 { X::ONE } else { X::ZERO }).collect(),
        width,
    )
}

/// `bits`, row-major with `raw` columns, as a dense matrix of zeros and
/// ones padded with zero columns to [`padded_width`].
#[must_use]
pub fn dense_padded<X: Field>(bits: &[u8], raw: usize) -> RowMajorMatrix<X> {
    assert!(!bits.is_empty(), "the preprocessed trace was released once setup committed it");
    let width = padded_width(raw);
    let mut values = vec![X::ZERO; bits.len() / raw * width];
    for (row, out) in bits.chunks_exact(raw).zip(values.chunks_exact_mut(width)) {
        for (bit, value) in row.iter().zip(out.iter_mut()) {
            if *bit == 1 {
                *value = X::ONE;
            }
        }
    }
    RowMajorMatrix::new(values, width)
}

/// `bits`, row-major with `width` columns, as the bit table a bit
/// commitment packs [`dense`] into, without the dense matrix.
#[must_use]
pub fn packed(bits: &[u8], width: usize) -> Table<F> {
    pack_rows(bits, width, width)
}

/// `bits`, row-major with `raw` columns, as the bit table a bit commitment
/// packs [`dense_padded`] into, without the dense matrix.
#[must_use]
pub fn packed_padded(bits: &[u8], raw: usize) -> Table<F> {
    pack_rows(bits, raw, padded_width(raw))
}

/// The rows of `bits`, `raw` to a row, as a table `width` columns wide: a
/// word per column and 64 rows, row `r` on bit `r % 64`.
fn pack_rows(bits: &[u8], raw: usize, width: usize) -> Table<F> {
    assert!(!bits.is_empty(), "the preprocessed trace was released once setup committed it");
    let height = bits.len() / raw;
    assert!(height.is_power_of_two(), "a table's height is a power of two");
    let mut words = vec![0u64; width * height.div_ceil(64)];
    words.par_chunks_mut(width).enumerate().for_each(|(block, word_row)| {
        let rows = 64 * block..(64 * block + 64).min(height);
        for (lane, row) in bits[rows.start * raw..rows.end * raw].chunks_exact(raw).enumerate() {
            for (&bit, word) in row.iter().zip(word_row.iter_mut()) {
                *word |= u64::from(bit == 1) << lane;
            }
        }
    });
    Table::from_packed_bits(RowMajorMatrix::new(words, width), height.trailing_zeros() as usize)
}

/// `bits` as one field element, bit `i` on coordinate `i`.
#[must_use]
pub fn pack_field<AB: AirBuilder<F: BinaryBase>>(bits: &[AB::Expr]) -> AB::Expr {
    let basis = coordinate_basis::<F>();
    assert!(bits.len() <= basis.len(), "a field element holds at most one bit per coordinate");
    bits.iter()
        .zip(basis.iter())
        .fold(AB::Expr::ZERO, |acc, (bit, e)| acc + bit.clone() * AB::F::from_native(*e))
}

/// The bus tuple of a cell: its address and its block, one field each.
#[must_use]
pub fn cell_tuple<AB: AirBuilder<F: BinaryBase>>(
    addr: &[AB::Expr; ADDRESS_BITS],
    block: &[AB::Expr; BLOCK_BITS],
) -> Vec<AB::Expr> {
    vec![pack_field::<AB>(addr), pack_field::<AB>(block)]
}

/// The block of a single element: the element in the first slot, zeros
/// after.
#[must_use]
pub fn single_block<AB: AirBuilder>(element: &[AB::Expr; KB_BITS]) -> [AB::Expr; BLOCK_BITS] {
    core::array::from_fn(|i| if i < KB_BITS { element[i].clone() } else { AB::Expr::ZERO })
}

/// The bus tuple of a product: both factors in one field, the product in
/// another.
#[must_use]
pub fn mul_tuple<AB: AirBuilder<F: BinaryBase>>(
    a: &[AB::Expr; KB_BITS],
    b: &[AB::Expr; KB_BITS],
    c: &[AB::Expr; KB_BITS],
) -> Vec<AB::Expr> {
    let factors: Vec<AB::Expr> = a.iter().chain(b.iter()).cloned().collect();
    vec![pack_field::<AB>(&factors), pack_field::<AB>(c)]
}

/// Ask the multiply table for `c = a * b` on rows where `active`.
pub fn request_mul<AB: MachineBuilder<F: BinaryBase>>(
    builder: &mut AB,
    a: &[AB::Expr; KB_BITS],
    b: &[AB::Expr; KB_BITS],
    c: &[AB::Expr; KB_BITS],
    active: AB::Expr,
) {
    builder.declare_bus(
        MUL,
        BusDirection::Push,
        mul_tuple::<AB>(a, b, c),
        BusActivation::Boolean(active),
    );
}

/// The bus tuple of a Blake3 compression at a round: the identity and the
/// round in one field, the sixteen state words in four and the sixteen
/// message words in four more.
#[must_use]
pub fn blake3_tuple<AB: AirBuilder<F: BinaryBase>>(
    id: &[AB::Expr; PERMUTATION_ID_BITS],
    round: &[AB::Expr; BLAKE3_ROUND_BITS],
    state: &[[AB::Expr; 32]; 16],
    words: &[[AB::Expr; 32]; 16],
) -> Vec<AB::Expr> {
    let header: Vec<AB::Expr> = id.iter().chain(round.iter()).cloned().collect();
    let mut tuple = vec![pack_field::<AB>(&header)];
    for lanes in state.chunks(4).chain(words.chunks(4)) {
        let block: Vec<AB::Expr> = lanes.iter().flatten().cloned().collect();
        tuple.push(pack_field::<AB>(&block));
    }
    tuple
}

#[cfg(test)]
mod tests {
    use super::{BitRows, RowBits};

    #[test]
    fn row_bits_transpose_to_the_bit_rows() {
        let (width, log_height) = (300, 7);
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut by_value = RowBits::new(width, log_height);
        let mut by_bit = BitRows::new(width, log_height);
        for r in 0..1 << log_height {
            let mut bits = vec![0u8; width];
            let mut column = (next() % 7) as usize;
            while column < width {
                let n = (1 + next() % 128).min((width - column) as u64) as usize;
                let value = u128::from(next()) | (u128::from(next()) << 64);
                by_value.put(r, column, value, n);
                for (i, bit) in bits[column..column + n].iter_mut().enumerate() {
                    *bit = ((value >> i) & 1) as u8;
                }
                column += n + (next() % 5) as usize;
            }
            by_bit.set_row(r, &bits);
        }
        assert_eq!(
            by_value.into_table().packed_bits().map(|m| m.values.clone()),
            by_bit.into_table().packed_bits().map(|m| m.values.clone())
        );
    }
}
