//! The constraint builder: committed and public words, values as XORs of
//! shifted words, and the carry chain every integer gadget is made of.
//!
//! Relations are those of `p3-word` over 64-bit words: a zero relation
//! `x = 0`, a bitwise `x & y = z` and a full-width product
//! `x * y = lo + 2^64 hi`, where each operand is an XOR of words each moved
//! by at most two shifts.  XOR and shifts cost nothing, so a value is kept
//! as such an expression until a gadget needs it as a single word.

use std::collections::HashMap;

use p3_word::{
    AndConstraint, ConstraintSystem, IntegerMulConstraint, Operand, Segment, Shift, ShiftKind,
    ShiftSequenceError, ShiftedValue, SystemError, ValueIndex, Word64, ZeroConstraint,
};

/// One shifted word of an operand.
pub type Term = ShiftedValue<Word64>;

/// A value: the XOR of at most two terms, with its native 64-bit value.
///
/// No terms is the structural zero, which every gadget may treat as a known
/// zero: whether a value is zero this way depends on the program alone, so
/// the constraint system does not depend on the witness.
#[derive(Clone, Copy, Debug)]
pub struct Val {
    terms: [Option<Term>; 2],
    /// The native value of the XOR.
    pub value: u64,
    /// Whether the value is a constant of the program.
    pub constant: bool,
    /// Whether the value is known to be below `2^16`.
    pub narrow: bool,
}

impl Val {
    /// The structural zero.
    pub const ZERO: Self = Self { terms: [None, None], value: 0, constant: true, narrow: true };

    fn single(term: Term, value: u64) -> Self {
        Self { terms: [Some(term), None], value, constant: false, narrow: false }
    }

    /// The terms whose XOR is the value.
    pub fn terms(&self) -> impl Iterator<Item = Term> + '_ {
        self.terms.iter().flatten().copied()
    }

    /// The number of terms.
    pub fn term_count(&self) -> usize {
        self.terms.iter().flatten().count()
    }

    /// Whether the value is the structural zero.
    pub fn is_zero(&self) -> bool {
        self.terms[0].is_none()
    }

    /// The one unshifted word the value is, if it is one.
    pub fn plain(&self) -> Option<Term> {
        match self.terms {
            [Some(term), None] if term.shifts().iter().all(|shift| shift.is_identity()) => {
                Some(term)
            }
            _ => None,
        }
    }

    /// The value with `narrow` set.
    pub fn narrowed(mut self) -> Self {
        self.narrow = true;
        self
    }
}

/// The outcome of a carry chain `x + y`.
pub struct Chain {
    /// The carry-out word.
    pub carry: Term,
    /// The terms whose XOR is the sum.
    pub sum: Vec<Term>,
    /// The sum's native value.
    pub value: u64,
}

/// Counts of what a lowering emitted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cost {
    /// Bitwise AND relations.
    pub and: usize,
    /// Integer product relations.
    pub mul: usize,
    /// Zero relations.
    pub zero: usize,
    /// Committed words.
    pub words: usize,
}

impl std::ops::Sub for Cost {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self {
            and: self.and - rhs.and,
            mul: self.mul - rhs.mul,
            zero: self.zero - rhs.zero,
            words: self.words - rhs.words,
        }
    }
}

impl std::ops::AddAssign for Cost {
    fn add_assign(&mut self, rhs: Self) {
        self.and += rhs.and;
        self.mul += rhs.mul;
        self.zero += rhs.zero;
        self.words += rhs.words;
    }
}

/// A constraint system together with the words that satisfy it.
pub struct Built {
    /// The relations.
    pub system: ConstraintSystem<Word64>,
    /// The verifier-known words: the reserved outputs, then the constants.
    pub public: Vec<Word64>,
    /// The committed words.
    pub witness: Vec<Word64>,
}

impl Built {
    /// Writes the relations and words as little-endian integers: the five
    /// counts (public, witness, zero, AND and product relations), the public
    /// and committed words, then every operand of every relation in family
    /// order as a term count followed by its terms.  A term is its position
    /// with the top bit set for a committed word, then the code and amount
    /// of its inner and of its outer shift, one byte each.
    pub fn write(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        let system = &self.system;
        let counts = [
            self.public.len(),
            self.witness.len(),
            system.zero_constraints().len(),
            system.and_constraints().len(),
            system.integer_mul_constraints().len(),
        ];
        for count in counts {
            out.write_all(&(count as u64).to_le_bytes())?;
        }
        for word in self.public.iter().chain(&self.witness) {
            out.write_all(&word.get().to_le_bytes())?;
        }
        self.write_relations(out)
    }

    /// Writes every operand of every relation as [`Self::write`] does.
    pub fn write_relations(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        let system = &self.system;
        let zero = system.zero_constraints().iter().map(|c| vec![c.value()]);
        let and = system.and_constraints().iter().map(|c| vec![c.left(), c.right(), c.output()]);
        let mul = system
            .integer_mul_constraints()
            .iter()
            .map(|c| vec![c.left(), c.right(), c.low(), c.high()]);
        for operand in zero.chain(and).chain(mul).flatten() {
            out.write_all(&(operand.terms().len() as u32).to_le_bytes())?;
            for term in operand.terms() {
                let index = term.index();
                let committed = u32::from(index.segment() == Segment::Witness) << 31;
                out.write_all(&(index.position() | committed).to_le_bytes())?;
                let [inner, outer] = term.shifts();
                out.write_all(&[
                    inner.kind().code(),
                    inner.amount(),
                    outer.kind().code(),
                    outer.amount(),
                ])?;
            }
        }
        Ok(())
    }
}

/// Accumulates words and relations.
pub struct Builder {
    public: Vec<u64>,
    constants: HashMap<u64, usize>,
    witness: Vec<u64>,
    zero: Vec<ZeroConstraint<Word64>>,
    and: Vec<AndConstraint<Word64>>,
    mul: Vec<IntegerMulConstraint<Word64>>,
    pub(crate) compressions: Vec<crate::blake3::Compression>,
    pub(crate) pending_range: Option<Val>,
}

fn shift(kind: ShiftKind, amount: usize) -> Shift<Word64> {
    Shift::new(kind, amount).expect("a shift amount within the word")
}

fn operand(terms: impl IntoIterator<Item = Term>) -> Operand<Word64> {
    Operand::new(terms.into_iter().collect())
}

/// `x + y` on each 32-bit lane, every lane wrapping on its own.
pub fn lane_add(x: u64, y: u64) -> u64 {
    let lo = (x as u32).wrapping_add(y as u32);
    let hi = ((x >> 32) as u32).wrapping_add((y >> 32) as u32);
    u64::from(lo) | (u64::from(hi) << 32)
}

impl Builder {
    /// A builder whose first `outputs` public words are outputs the
    /// lowering sets later; the constants follow them.
    pub fn new(outputs: usize) -> Self {
        Self {
            public: vec![0; outputs],
            constants: HashMap::new(),
            witness: Vec::new(),
            zero: Vec::new(),
            and: Vec::new(),
            mul: Vec::new(),
            compressions: Vec::new(),
            pending_range: None,
        }
    }

    /// What has been emitted so far.
    pub fn cost(&self) -> Cost {
        Cost {
            and: self.and.len(),
            mul: self.mul.len(),
            zero: self.zero.len(),
            words: self.witness.len(),
        }
    }

    /// Sets reserved output `index` and returns its word.
    pub fn output(&mut self, index: usize, value: u64) -> Term {
        self.public[index] = value;
        ShiftedValue::plain(ValueIndex::public(index).expect("a public index"))
    }

    /// The constant `value`, one public word per distinct value; zero is
    /// the structural zero.
    pub fn constant(&mut self, value: u64) -> Val {
        if value == 0 {
            return Val::ZERO;
        }
        let next = self.public.len();
        let index = *self.constants.entry(value).or_insert(next);
        if index == next {
            self.public.push(value);
        }
        let term = ShiftedValue::plain(ValueIndex::public(index).expect("a public index"));
        Val { terms: [Some(term), None], value, constant: true, narrow: value < 1 << 16 }
    }

    /// A fresh committed word.
    pub fn word(&mut self, value: u64) -> Val {
        let index = self.witness.len();
        self.witness.push(value);
        Val::single(
            ShiftedValue::plain(ValueIndex::witness(index).expect("a witness index")),
            value,
        )
    }

    fn word_term(&mut self, value: u64) -> Term {
        self.word(value).plain().expect("a fresh word is plain")
    }

    /// The native value of `term`.
    pub fn term_value(&self, term: Term) -> u64 {
        let index = term.index();
        let base = match index.segment() {
            Segment::Public => self.public[index.position() as usize],
            Segment::Witness => self.witness[index.position() as usize],
        };
        term.apply(Word64::new(base)).get()
    }

    /// `terms = 0`.
    pub fn assert_zero(&mut self, terms: impl IntoIterator<Item = Term>) {
        self.zero.push(ZeroConstraint::new(operand(terms)));
    }

    /// `left & right = out`.
    pub fn and(
        &mut self,
        left: impl IntoIterator<Item = Term>,
        right: impl IntoIterator<Item = Term>,
        out: impl IntoIterator<Item = Term>,
    ) {
        self.and.push(AndConstraint::new(operand(left), operand(right), operand(out)));
    }

    /// `left * right = lo + 2^64 hi`.
    pub fn imul(
        &mut self,
        left: impl IntoIterator<Item = Term>,
        right: impl IntoIterator<Item = Term>,
        lo: impl IntoIterator<Item = Term>,
        hi: impl IntoIterator<Item = Term>,
    ) {
        self.mul.push(IntegerMulConstraint::new(
            operand(left),
            operand(right),
            operand(lo),
            operand(hi),
        ));
    }

    /// `value` as one unshifted word, committing it if it is not one.
    pub fn materialize(&mut self, value: Val) -> Val {
        if value.is_zero() || value.plain().is_some() {
            return value;
        }
        let word = self.word(value.value);
        self.assert_zero(value.terms().chain(word.terms()));
        Val { narrow: value.narrow, ..word }
    }

    /// `a ^ b`, committing an operand when the XOR would exceed two terms.
    pub fn xor(&mut self, a: Val, b: Val) -> Val {
        if a.is_zero() {
            return b;
        }
        if b.is_zero() {
            return a;
        }
        let (a, b) = match (a.term_count(), b.term_count()) {
            (1, 1) => (a, b),
            (1, _) => (a, self.materialize(b)),
            _ => (self.materialize(a), self.materialize(b)),
        };
        Val {
            terms: [a.terms[0], b.terms[0]],
            value: a.value ^ b.value,
            constant: a.constant && b.constant,
            narrow: a.narrow && b.narrow,
        }
    }

    fn shift_term(term: Term, kind: ShiftKind, amount: usize) -> Result<Option<Term>, ()> {
        let outer = shift(kind, amount);
        let [inner, last] = term.shifts();
        if inner.is_identity() {
            return Ok(Some(ShiftedValue::single(term.index(), outer)));
        }
        if !last.is_identity() {
            return Err(());
        }
        match ShiftedValue::pair(term.index(), inner, outer) {
            Ok(term) => Ok(Some(term)),
            Err(ShiftSequenceError::AlwaysZero) => Ok(None),
            Err(ShiftSequenceError::Reducible) => {
                let width = if kind.is_lane32() { 32 } else { 64 };
                let total = usize::from(inner.amount()) + amount;
                match (inner.kind() == kind, kind) {
                    (true, ShiftKind::RotateRight | ShiftKind::Lane32RotateRight) => {
                        Ok(Some(ShiftedValue::single(term.index(), shift(kind, total % width))))
                    }
                    (
                        true,
                        ShiftKind::LogicalLeft
                        | ShiftKind::LogicalRight
                        | ShiftKind::Lane32LogicalLeft
                        | ShiftKind::Lane32LogicalRight,
                    ) if total >= width => Ok(None),
                    (
                        true,
                        ShiftKind::LogicalLeft
                        | ShiftKind::LogicalRight
                        | ShiftKind::Lane32LogicalLeft
                        | ShiftKind::Lane32LogicalRight,
                    ) => Ok(Some(ShiftedValue::single(term.index(), shift(kind, total)))),
                    _ => Err(()),
                }
            }
        }
    }

    /// `value` moved by one shift; terms that already carry shifts the
    /// move cannot compose with are committed first.
    pub fn shifted(&mut self, value: Val, kind: ShiftKind, amount: usize) -> Val {
        if value.is_zero() || amount == 0 {
            return value;
        }
        let moved = shift(kind, amount).apply(Word64::new(value.value)).get();
        let mut terms = [None, None];
        let mut count = 0;
        let mut direct = true;
        for term in value.terms() {
            match Self::shift_term(term, kind, amount) {
                Ok(Some(term)) => {
                    terms[count] = Some(term);
                    count += 1;
                }
                Ok(None) => {}
                Err(()) => direct = false,
            }
        }
        if !direct {
            let plain = self.materialize(value);
            let term = plain.plain().expect("a materialized value is plain");
            terms = [Self::shift_term(term, kind, amount).expect("a plain term shifts"), None];
        }
        Val { terms, value: moved, constant: value.constant, narrow: false }
    }

    /// The carry chain `x + y`: one AND over the carry word `c`, with the
    /// carries into each bit `c << 1`, plus `c >> 63 = 0` when
    /// `no_overflow` asks the sum not to wrap.  With `lane32` the two
    /// 32-bit lanes add independently, each wrapping.
    ///
    /// `(x ^ c') & (y ^ c') = c ^ c'` with `c' = c << 1` holds bitwise
    /// exactly when `c` is the carry-out vector of `x + y`, since
    /// `(x ^ c')(y ^ c') = maj(x, y, c') ^ c'`.
    pub fn chain(
        &mut self,
        x: &[Term],
        x_value: u64,
        y: &[Term],
        y_value: u64,
        lane32: bool,
        no_overflow: bool,
    ) -> Chain {
        let sum = if lane32 { lane_add(x_value, y_value) } else { x_value.wrapping_add(y_value) };
        let carries = (x_value & y_value) | ((sum ^ x_value ^ y_value) & (x_value ^ y_value));
        let carry = self.word_term(carries);
        let kind = if lane32 { ShiftKind::Lane32LogicalLeft } else { ShiftKind::LogicalLeft };
        let carry_in = ShiftedValue::single(carry.index(), shift(kind, 1));
        self.and(
            x.iter().copied().chain([carry_in]),
            y.iter().copied().chain([carry_in]),
            [carry, carry_in],
        );
        if no_overflow {
            self.assert_zero([ShiftedValue::single(
                carry.index(),
                shift(ShiftKind::LogicalRight, 63),
            )]);
        }
        Chain { carry, sum: x.iter().chain(y).copied().chain([carry_in]).collect(), value: sum }
    }

    /// The carry chain of two values with the sum committed.
    pub fn add_word(&mut self, x: Val, y: Val, lane32: bool) -> Val {
        if x.is_zero() {
            return y;
        }
        if y.is_zero() {
            return x;
        }
        let x_terms: Vec<Term> = x.terms().collect();
        let y_terms: Vec<Term> = y.terms().collect();
        let chain = self.chain(&x_terms, x.value, &y_terms, y.value, lane32, false);
        let sum = self.word(chain.value);
        self.assert_zero(chain.sum.into_iter().chain(sum.terms()));
        sum
    }

    /// `term < 2^bits`.
    pub fn below_bits(&mut self, term: Term, bits: usize) {
        self.assert_zero([ShiftedValue::single(
            term.index(),
            shift(ShiftKind::LogicalRight, bits),
        )]);
    }

    /// The relations and the words that satisfy them.
    pub fn build(mut self) -> Result<Built, SystemError> {
        self.flush_compressions();
        self.flush_ranges();
        let system = ConstraintSystem::new(
            self.public.len(),
            self.witness.len(),
            self.zero,
            self.and,
            self.mul,
        )?;
        Ok(Built {
            system,
            public: self.public.into_iter().map(Word64::new).collect(),
            witness: self.witness.into_iter().map(Word64::new).collect(),
        })
    }
}
