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
pub const PERMUTATION_ID_BITS: usize = 24;

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

    /// Set row `r` to `row`, which must be all zero before.
    pub fn set_row(&mut self, r: usize, row: &[u8]) {
        assert_eq!(row.len(), self.width);
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

/// `bits`, row-major with `width` columns, as a dense matrix of zeros and
/// ones.
#[must_use]
pub fn dense<X: Field>(bits: &[u8], width: usize) -> RowMajorMatrix<X> {
    RowMajorMatrix::new(
        bits.iter().map(|&bit| if bit == 1 { X::ONE } else { X::ZERO }).collect(),
        width,
    )
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
