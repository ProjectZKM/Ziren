//! How every committed word of a lowered program is computed, so a leaf of
//! a known program fills its witness from the runtime's memory alone.
//!
//! Each word is one [`Op`] over operands, every operand an XOR of shifted
//! words before it, the public words included.  An instruction's results
//! are read from the memory the runtime left, so a word depends only on
//! words of its own gadget: the tape is shallow and its levels are wide.

use p3_field::{
    extension::BinomialExtensionField, BasedVectorSpace, Field, PrimeCharacteristicRing,
    PrimeField32,
};
use p3_koala_bear::KoalaBear;
use p3_word::{Segment, ShiftKind};
use serde::{Deserialize, Serialize};

use crate::builder::Term;
use crate::kb::{quotient, P};

/// How a committed word is computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Op {
    /// Coefficient `imm & 3` of the memory element at `imm >> 2`.
    Memory = 0,
    /// The 32-bit word of the 16-bit limbs at memory `imm` (low 32 bits) and `imm >> 32`.
    Limbs = 1,
    /// `x`.
    Xor = 2,
    /// The carry-out vector of `x + y`, on each 32-bit lane when `imm` is 1.
    Carry = 3,
    /// Whether `x + y` reaches `p`.
    Wraps = 4,
    /// Whether `x < y`.
    Borrows = 5,
    /// `x / p`.
    QuotientP = 6,
    /// `x * y`, wrapping.
    Product = 7,
    /// `3 x / p`.
    TripleQuotient = 8,
    /// `3 x mod p`.
    TripleRemainder = 9,
    /// `(x + y) mod p`, for canonical `x` and `y`.
    AddMod = 10,
    /// `(x - y) mod p`, for canonical `x` and `y`.
    SubMod = 11,
    /// `x y mod p`.
    MulMod = 12,
    /// The runtime's quotient `x / y` in the field.
    Quotient = 13,
    /// Coefficient `imm` of the extension product of `x0..x3` and `y0..y3`.
    ExtMul = 14,
    /// Coefficient `imm` of the runtime's extension quotient of `x0..x3` by `y0..y3`.
    ExtDiv = 15,
    /// `bit ? x ^ y : 0` for the operands `bit, x, y`.
    SelectDiff = 16,
    /// The constant `imm`.
    Constant = 17,
}

impl Op {
    /// The number of operands the op reads.
    pub const fn arity(self) -> usize {
        match self {
            Self::Memory | Self::Limbs | Self::Constant => 0,
            Self::Xor | Self::QuotientP | Self::TripleQuotient | Self::TripleRemainder => 1,
            Self::Carry
            | Self::Wraps
            | Self::Borrows
            | Self::Product
            | Self::AddMod
            | Self::SubMod
            | Self::MulMod
            | Self::Quotient => 2,
            Self::SelectDiff => 3,
            Self::ExtMul | Self::ExtDiv => 8,
        }
    }

    /// Every op, by code.
    pub const ALL: [Self; 18] = [
        Self::Memory,
        Self::Limbs,
        Self::Xor,
        Self::Carry,
        Self::Wraps,
        Self::Borrows,
        Self::QuotientP,
        Self::Product,
        Self::TripleQuotient,
        Self::TripleRemainder,
        Self::AddMod,
        Self::SubMod,
        Self::MulMod,
        Self::Quotient,
        Self::ExtMul,
        Self::ExtDiv,
        Self::SelectDiff,
        Self::Constant,
    ];

    fn from_code(code: u8) -> Self {
        Self::ALL[code as usize]
    }
}

/// A term as one integer: the position in bits `0..31`, bit 31 set for a
/// committed word, then the code and amount of the inner shift in bits
/// `32..35` and `35..41`, and of the outer shift in bits `41..44` and
/// `44..50`.  A shift of amount zero is the identity.
pub fn encode(term: Term) -> u64 {
    let index = term.index();
    let position = u64::from(index.position());
    assert!(position < 1 << 31, "a word position fits 31 bits");
    let committed = u64::from(index.segment() == Segment::Witness) << 31;
    let [inner, outer] = term.shifts();
    let shift = |kind: ShiftKind, amount: u8| u64::from(kind.code()) | (u64::from(amount) << 3);
    position
        | committed
        | (shift(inner.kind(), inner.amount()) << 32)
        | (shift(outer.kind(), outer.amount()) << 41)
}

fn shift(word: u64, code: u64) -> u64 {
    let amount = (code >> 3) as u32;
    if amount == 0 {
        return word;
    }
    let lanes = |f: &dyn Fn(u32) -> u32| u64::from(f(word as u32)) | (u64::from(f((word >> 32) as u32)) << 32);
    match code & 7 {
        0 => word << amount,
        1 => word >> amount,
        2 => ((word as i64) >> amount) as u64,
        3 => word.rotate_right(amount),
        4 => lanes(&|lane| lane << amount),
        5 => lanes(&|lane| lane >> amount),
        6 => lanes(&|lane| ((lane as i32) >> amount) as u32),
        _ => lanes(&|lane| lane.rotate_right(amount)),
    }
}

/// The value of an encoded term over `public` and `witness`.
pub fn term_value(term: u64, public: &[u64], witness: &[u64]) -> u64 {
    let position = (term & 0x7fff_ffff) as usize;
    let base = if term >> 31 & 1 == 1 { witness[position] } else { public[position] };
    shift(shift(base, (term >> 32) & 0x1ff), (term >> 41) & 0x1ff)
}

type Ef = BinomialExtensionField<KoalaBear, 4>;

fn ext(values: &[u64]) -> Ef {
    Ef::from_basis_coefficients_fn(|i| KoalaBear::from_u64(values[i]))
}

fn coefficient(value: Ef, k: u64) -> u64 {
    let coefficients: &[KoalaBear] = value.as_basis_coefficients_slice();
    u64::from(coefficients[k as usize].as_canonical_u32())
}

/// The value of `op` with immediate `imm` over operand values `x`.
pub fn apply(op: Op, imm: u64, x: &[u64], memory: &dyn Fn(usize, usize) -> u64) -> u64 {
    match op {
        Op::Memory => memory((imm >> 2) as usize, (imm & 3) as usize),
        Op::Limbs => memory((imm & 0xffff_ffff) as usize, 0) | (memory((imm >> 32) as usize, 0) << 16),
        Op::Xor => x[0],
        Op::Carry => {
            let sum = if imm == 1 { crate::builder::lane_add(x[0], x[1]) } else { x[0].wrapping_add(x[1]) };
            (x[0] & x[1]) | ((sum ^ x[0] ^ x[1]) & (x[0] ^ x[1]))
        }
        Op::Wraps => u64::from(x[0] + x[1] >= P),
        Op::Borrows => u64::from(x[0] < x[1]),
        Op::QuotientP => x[0] / P,
        Op::Product => x[0].wrapping_mul(x[1]),
        Op::TripleQuotient => 3 * x[0] / P,
        Op::TripleRemainder => 3 * x[0] % P,
        Op::AddMod => {
            let sum = x[0] + x[1];
            sum - u64::from(sum >= P) * P
        }
        Op::SubMod => x[0] + u64::from(x[0] < x[1]) * P - x[1],
        Op::MulMod => x[0] * x[1] % P,
        Op::Quotient => quotient(x[0], x[1]),
        Op::ExtMul => coefficient(ext(&x[..4]) * ext(&x[4..]), imm),
        Op::ExtDiv => {
            let (a, b) = (ext(&x[..4]), ext(&x[4..]));
            let value = if b.is_zero() {
                if a.is_zero() {
                    Ef::ONE
                } else {
                    Ef::ZERO
                }
            } else {
                a * b.inverse()
            };
            coefficient(value, imm)
        }
        Op::SelectDiff => {
            if x[0] == 1 {
                x[1] ^ x[2]
            } else {
                0
            }
        }
        Op::Constant => imm,
    }
}

/// How each committed word of a program is computed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tape {
    /// Each word's op code.
    pub ops: Vec<u8>,
    /// Each word's immediate.
    pub imms: Vec<u64>,
    /// Each word's first operand, into `operand_starts`.
    pub first_operand: Vec<u32>,
    /// Each operand's first term, into `terms`, with a closing entry.
    pub operand_starts: Vec<u32>,
    /// Every operand's encoded terms.
    pub terms: Vec<u64>,
    /// The memory address of each output.
    pub outputs: Vec<u32>,
    /// The words in level order, once [`Self::schedule`] ran.
    #[serde(default)]
    pub order: Vec<u32>,
    /// Where each level starts in `order`, with a closing entry, once [`Self::schedule`] ran.
    #[serde(default)]
    pub level_starts: Vec<u32>,
}

impl Tape {
    /// An empty tape.
    pub fn new() -> Self {
        Self { operand_starts: vec![0], ..Self::default() }
    }

    /// The number of words.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Whether the tape has no words.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Starts the next word.
    pub(crate) fn begin(&mut self, op: Op, imm: u64) {
        self.ops.push(op as u8);
        self.imms.push(imm);
        self.first_operand.push((self.operand_starts.len() - 1) as u32);
    }

    /// Adds an operand to the word begun last.
    pub(crate) fn operand(&mut self, terms: impl IntoIterator<Item = Term>) {
        self.terms.extend(terms.into_iter().map(encode));
        self.operand_starts.push(self.terms.len() as u32);
    }

    /// Defines word `index` anew as `op` with `imm` and no operands.
    pub(crate) fn redefine(&mut self, index: usize, op: Op, imm: u64) {
        debug_assert_eq!(op.arity(), 0);
        self.ops[index] = op as u8;
        self.imms[index] = imm;
    }

    /// The operands of word `index`.
    fn operands(&self, index: usize) -> impl Iterator<Item = &[u64]> + '_ {
        let op = Op::from_code(self.ops[index]);
        let first = self.first_operand[index] as usize;
        (first..first + op.arity()).map(move |o| {
            &self.terms[self.operand_starts[o] as usize..self.operand_starts[o + 1] as usize]
        })
    }

    /// The witness, word by word, over `memory` and the public words.
    pub fn evaluate(&self, public: &[u64], memory: &dyn Fn(usize, usize) -> u64) -> Vec<u64> {
        let mut witness = Vec::with_capacity(self.len());
        let mut values = [0u64; 8];
        for index in 0..self.len() {
            let op = Op::from_code(self.ops[index]);
            for (value, operand) in values.iter_mut().zip(self.operands(index)) {
                *value = operand.iter().fold(0, |acc, &t| acc ^ term_value(t, public, &witness));
            }
            witness.push(apply(op, self.imms[index], &values[..op.arity()], memory));
        }
        witness
    }

    /// The public words of a leaf: the outputs read from memory, then `constants`.
    pub fn public(&self, constants: &[u64], memory: &dyn Fn(usize, usize) -> u64) -> Vec<u64> {
        self.outputs.iter().map(|&addr| memory(addr as usize, 0)).chain(constants.iter().copied()).collect()
    }

    /// Orders the words by level into `order` and `level_starts`, for an evaluator that
    /// computes a level's words at once.
    pub fn schedule(&mut self) {
        (self.order, self.level_starts) = self.level_order();
    }

    /// The words in level order and where each level starts, with a closing entry: every
    /// word reads only words of earlier levels.
    pub fn level_order(&self) -> (Vec<u32>, Vec<u32>) {
        let levels = self.levels();
        let depth = levels.iter().copied().max().map_or(0, |d| d as usize + 1);
        let mut starts = vec![0u32; depth + 1];
        for &level in &levels {
            starts[level as usize + 1] += 1;
        }
        for level in 0..depth {
            starts[level + 1] += starts[level];
        }
        let mut next = starts.clone();
        let mut order = vec![0u32; levels.len()];
        for (word, &level) in levels.iter().enumerate() {
            order[next[level as usize] as usize] = word as u32;
            next[level as usize] += 1;
        }
        (order, starts)
    }

    /// Each word's level: one past the deepest committed word it reads, zero for a word
    /// that reads none.
    pub fn levels(&self) -> Vec<u32> {
        let mut levels: Vec<u32> = Vec::with_capacity(self.len());
        for index in 0..self.len() {
            let level = self
                .operands(index)
                .flatten()
                .filter(|&&t| t >> 31 & 1 == 1)
                .map(|&t| levels[(t & 0x7fff_ffff) as usize] + 1)
                .max()
                .unwrap_or(0);
            levels.push(level);
        }
        levels
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::builder::Built;

    /// The tape computes `built`'s witness from its public words alone.
    pub(crate) fn computes(built: &Built, tape: &Tape) {
        let public: Vec<u64> = built.public.iter().map(|w| w.get()).collect();
        let witness: Vec<u64> = built.witness.iter().map(|w| w.get()).collect();
        let computed = tape.evaluate(&public, &|_, _| unreachable!("no memory in a builder test"));
        assert_eq!(computed.len(), witness.len());
        if let Some(word) = (0..witness.len()).find(|&i| computed[i] != witness[i]) {
            panic!(
                "word {word} ({:?}) computes to {:#x}, the witness has {:#x}",
                Op::from_code(tape.ops[word]),
                computed[word],
                witness[word]
            );
        }
    }

    #[test]
    fn shifts_match_the_words() {
        use p3_word::{Shift, ShiftedValue, ValueIndex, Word64};
        let word = 0x8123_4567_89ab_cdefu64;
        for code in 0..8u8 {
            let kind = ShiftKind::from_code(code).unwrap();
            let width = if kind.is_lane32() { 32 } else { 64 };
            for amount in 0..width {
                let term = ShiftedValue::single(
                    ValueIndex::witness(0).unwrap(),
                    Shift::<Word64>::new(kind, amount).unwrap(),
                );
                assert_eq!(
                    term_value(encode(term), &[], &[word]),
                    term.apply(Word64::new(word)).get(),
                    "{kind:?} by {amount}"
                );
            }
        }
    }
}
