//! Bytes, bits and Blake3 over traced values.
//!
//! A byte is a [`Traced`] whose representation is below `2^8`, a bit one
//! whose representation is `0` or `1`.  Each conversion is recorded as one
//! operation, which the machine proves by wiring: an element's bytes, a
//! byte's bits and an element assembled from bytes are permutations of the
//! same bits.  A whole Blake3 digest is one operation too, expanded into
//! compressions by the machine.

use p3_binary_field::TowerLevel;

use crate::tape::{self, Op, F};
use crate::traced::Traced;

/// The element a byte is held as: the byte as its low representation bits.
pub fn byte_field(b: u8) -> F {
    F::from_repr(u128::from(b))
}

/// The byte `b` as a constant.
#[must_use]
pub fn constant_byte(b: u8) -> Traced {
    Traced::constant(byte_field(b))
}

/// The value of a byte.
///
/// # Panics
/// Panics if the value is not a byte.
#[must_use]
pub fn byte_value(b: &Traced) -> u8 {
    u8::try_from(b.value().to_repr()).expect("a traced byte holds a byte")
}

/// The sixteen little-endian bytes of an element's representation.
#[must_use]
pub fn to_bytes(x: Traced) -> [Traced; 16] {
    let bytes = x.value().to_repr().to_le_bytes();
    if x.is_constant() {
        return bytes.map(constant_byte);
    }
    Traced::defined_many(Op::ToBytes(x.operand()), bytes.map(|b| F::from_repr(u128::from(b))))
}

/// The element whose representation has these sixteen little-endian bytes.
#[must_use]
pub fn from_bytes(bytes: &[Traced; 16]) -> Traced {
    let value = F::from_repr(u128::from_le_bytes(bytes.each_ref().map(byte_value)));
    if bytes.iter().all(Traced::is_constant) {
        return Traced::constant(value);
    }
    let [element] =
        Traced::defined_many(Op::FromBytes(bytes.iter().map(Traced::operand).collect()), [value]);
    element
}

/// The eight bits of a byte, lowest first.
#[must_use]
pub fn byte_bits(b: Traced) -> [Traced; 8] {
    let value = byte_value(&b);
    let bits: [F; 8] = core::array::from_fn(|i| F::from_repr(u128::from((value >> i) & 1)));
    if b.is_constant() {
        return bits.map(Traced::constant);
    }
    Traced::defined_many(Op::ByteBits(b.operand()), bits)
}

/// A piece of a message to hash: an element's sixteen little-endian bytes,
/// or one byte.
#[derive(Clone, Copy, Debug)]
pub enum Piece {
    Element(Traced),
    Byte(Traced),
}

impl Piece {
    const fn len(&self) -> usize {
        match self {
            Self::Element(_) => 16,
            Self::Byte(_) => 1,
        }
    }
}

/// The message `pieces` spell, as the sixteen-byte slots the machine hashes:
/// an element starting on a slot boundary is its own slot, and any other
/// slot is assembled from bytes, zero past the end.
fn slots(pieces: &[Piece]) -> Vec<Traced> {
    let len: usize = pieces.iter().map(Piece::len).sum();
    let mut slots = Vec::with_capacity(len.div_ceil(16));
    let mut pending: Vec<Traced> = Vec::with_capacity(16);
    let mut offset = 0;
    for piece in pieces {
        match *piece {
            Piece::Element(x) if offset % 16 == 0 => slots.push(x),
            Piece::Element(x) => pending.extend(to_bytes(x)),
            Piece::Byte(b) => pending.push(b),
        }
        offset += piece.len();
        while pending.len() >= 16 {
            let slot: [Traced; 16] = core::array::from_fn(|i| pending[i]);
            slots.push(from_bytes(&slot));
            pending.drain(..16);
        }
    }
    if !pending.is_empty() {
        let slot: [Traced; 16] =
            core::array::from_fn(|i| pending.get(i).copied().unwrap_or_else(|| constant_byte(0)));
        slots.push(from_bytes(&slot));
    }
    slots
}

/// The Blake3 digest of the message `pieces` spell, as two elements: its
/// low and its high sixteen bytes.
#[must_use]
pub fn blake3(pieces: &[Piece]) -> [Traced; 2] {
    let len: usize = pieces.iter().map(Piece::len).sum();
    let slots = slots(pieces);
    let message: Vec<u8> =
        slots.iter().flat_map(|slot| slot.value().to_repr().to_le_bytes()).take(len).collect();
    let digest = tape::digest_elements(tape::blake3_bytes(&message));
    if slots.iter().all(Traced::is_constant) {
        return digest.map(Traced::constant);
    }
    Traced::defined_many(
        Op::Blake3 { slots: slots.iter().map(Traced::operand).collect(), len },
        digest,
    )
}

/// One node of a Merkle path: the digest of `cur ‖ sib` if `bit` is zero,
/// of `sib ‖ cur` if it is one.
///
/// # Panics
/// Panics if `bit` is not `0` or `1`.
#[must_use]
pub fn merkle_node(bit: Traced, cur: [Traced; 2], sib: [Traced; 2]) -> [Traced; 2] {
    let selector = bit.value().to_repr();
    assert!(selector <= 1, "a path bit is a bit");
    let (left, right) = if selector == 1 { (sib, cur) } else { (cur, sib) };
    let message: Vec<u8> =
        left.iter().chain(&right).flat_map(|x| x.value().to_repr().to_le_bytes()).collect();
    let digest = tape::digest_elements(tape::blake3_bytes(&message));
    if bit.is_constant() {
        let pieces = left.iter().chain(&right).map(|&x| Piece::Element(x)).collect::<Vec<_>>();
        return blake3(&pieces);
    }
    Traced::defined_many(
        Op::MerkleNode {
            bit: bit.operand(),
            cur: cur.map(|x| x.operand()),
            sib: sib.map(|x| x.operand()),
        },
        digest,
    )
}

/// The thirty-two bytes of a digest held as two elements.
#[must_use]
pub fn digest_bytes(digest: [Traced; 2]) -> [Traced; 32] {
    let [lo, hi] = digest.map(to_bytes);
    core::array::from_fn(|i| if i < 16 { lo[i] } else { hi[i - 16] })
}

/// The bit matrix whose rows are `rows`, at most 128, read by column.
///
/// # Panics
/// Panics if there are more than 128 rows.
#[must_use]
pub fn transpose(rows: &[Traced]) -> [Traced; 128] {
    let reprs: Vec<u128> = rows.iter().map(|row| row.value().to_repr()).collect();
    let columns = tape::transpose(&reprs).map(F::from_repr);
    if rows.iter().all(Traced::is_constant) {
        return columns.map(Traced::constant);
    }
    Traced::defined_many(Op::Transpose(rows.iter().map(Traced::operand).collect()), columns)
}

/// `if bit { b } else { a }`, for a bit and two values: a multiplexer, not
/// a multiplication, so it is recorded as one.
///
/// # Panics
/// Panics if `bit` is not `0` or `1`.
#[must_use]
pub fn select(bit: Traced, a: Traced, b: Traced) -> Traced {
    let selector = bit.value().to_repr();
    assert!(selector <= 1, "a selector is a bit");
    let value = if selector == 1 { b.value() } else { a.value() };
    if bit.is_constant() {
        return if selector == 1 { b } else { a };
    }
    if a.is_constant() && b.is_constant() && a.value() == b.value() {
        return a;
    }
    let [chosen] =
        Traced::defined_many(Op::Select(bit.operand(), a.operand(), b.operand()), [value]);
    chosen
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::tape;

    /// Bytes round-trip through an element, bits recompose a byte, and the
    /// recorded digest is Blake3's.
    #[test]
    fn conversions_agree_with_the_values() {
        let ((), tape) = tape::record(|| {
            let x = Traced::input(F::from_repr(0x0123_4567_89ab_cdef_fedc_ba98_7654_3210));
            let bytes = to_bytes(x);
            assert_eq!(byte_value(&bytes[0]), 0x10);
            assert_eq!(from_bytes(&bytes).value(), x.value());
            let bits = byte_bits(bytes[1]);
            let recomposed: u8 = bits.iter().enumerate().map(|(i, b)| (byte_value(b)) << i).sum();
            assert_eq!(recomposed, 0x32);
            let digest = digest_bytes(blake3(&[Piece::Byte(bytes[2]), Piece::Element(x)]));
            let mut message = vec![0x54];
            message.extend_from_slice(&x.value().to_repr().to_le_bytes());
            let expected = *::blake3::hash(&message).as_bytes();
            assert_eq!(digest.map(|b| byte_value(&b)), expected);
            assert_eq!(select(Traced::ONE, x, Traced::ZERO).value(), F::ZERO);
        });
        assert_eq!(tape.census()[6..10], [4, 3, 1, 1]);
    }
}
