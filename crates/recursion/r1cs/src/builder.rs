//! The constraint builder: committed and public words, values as XORs of
//! shifted words, and the carry chain every integer gadget is made of.
//!
//! Relations are those of `p3-word` over 64-bit words: a zero relation
//! `x = 0`, a bitwise `x & y = z` and a full-width product
//! `x * y = lo + 2^64 hi`, where each operand is an XOR of words each moved
//! by at most two shifts.  XOR and shifts cost nothing, so a value is kept
//! as such an expression until a gadget needs it as a single word.

use std::collections::HashMap;

use p3_maybe_rayon::prelude::*;
use p3_word::{
    AndConstraint, ConstraintSystem, IntegerMulConstraint, Operand, Segment, Shift, ShiftKind,
    ShiftSequenceError, ShiftedValue, SystemError, ValueIndex, Word64, ZeroConstraint,
};

use crate::tape::{Op, Tape};

mod compose;

pub use compose::{ComposeError, Composed};

/// One shifted word of an operand.
pub type Term = ShiftedValue<Word64>;

/// An operand of a computed word: a value, or the terms of one.
pub(crate) enum Arg<'a> {
    Val(Val),
    Terms(&'a [Term]),
}

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
/// One family's operands end to end, each constraint's in order, so recording
/// a relation allocates nothing; the relations are made from them in parallel.
#[derive(Default)]
struct Operands {
    terms: Vec<Term>,
    ends: Vec<usize>,
}

impl Operands {
    fn push(&mut self, terms: impl IntoIterator<Item = Term>) {
        self.terms.extend(terms);
        self.ends.push(self.terms.len());
    }

    fn operand(&self, index: usize) -> Operand<Word64> {
        let start = index.checked_sub(1).map_or(0, |previous| self.ends[previous]);
        Operand::new(self.terms[start..self.ends[index]].to_vec())
    }

    /// The relations of `ARITY` operands each, made by `make`.
    fn relations<const ARITY: usize, C: Send>(
        self,
        make: impl Fn([Operand<Word64>; ARITY]) -> C + Sync,
    ) -> Vec<C> {
        (0..self.ends.len() / ARITY)
            .into_par_iter()
            .map(|index| make(std::array::from_fn(|i| self.operand(index * ARITY + i))))
            .collect()
    }
}

pub struct Builder {
    public: Vec<u64>,
    constants: HashMap<u64, usize>,
    witness: Vec<u64>,
    zero: Operands,
    and: Operands,
    mul: Operands,
    pub(crate) compressions: Vec<crate::blake3::Compression>,
    pub(crate) pending_range: Option<Val>,
    /// How each committed word is computed.
    pub(crate) tape: Tape,
    /// Which gadget owns each word and relation, when a template census asks.
    pub(crate) owners: Option<Owners>,
    /// The committed word of each constant a gadget reads as a word.
    pool: HashMap<u64, Val>,
}

/// The gadget instance that owns each committed word and each relation: a gadget is an
/// instruction's lowering or a flushed range or compression, which may nest in one.
#[derive(Default)]
pub(crate) struct Owners {
    stack: Vec<u32>,
    kinds: Vec<&'static str>,
    words: Vec<u32>,
    relations: [Vec<u32>; 3],
    /// The zero relations that copy a word into a gadget's port, in order.
    links: Vec<u32>,
}

impl Owners {
    fn current(&self) -> u32 {
        self.stack.last().copied().unwrap_or(u32::MAX)
    }
}

/// The items `owner_of` assigns to `gadgets` gadgets, grouped by gadget in order: gadget
/// `g`'s are `order[start[g]..start[g + 1]]`, and those of no gadget follow the last.
fn by_owner(owner_of: &[u32], gadgets: usize) -> (Vec<u32>, Vec<u32>) {
    let mut start = vec![0_u32; gadgets + 2];
    for &owner in owner_of {
        start[(owner.min(gadgets as u32) + 2) as usize] += 1;
    }
    for i in 1..start.len() {
        start[i] += start[i - 1];
    }
    let mut order = vec![0_u32; owner_of.len()];
    for (index, &owner) in owner_of.iter().enumerate() {
        let slot = &mut start[(owner.min(gadgets as u32) + 1) as usize];
        order[*slot as usize] = index as u32;
        *slot += 1;
    }
    (start, order)
}

/// How often one gadget template occurs, and its size.
struct Template {
    kind: &'static str,
    instances: usize,
    words: usize,
    relations: [usize; 3],
    imports: usize,
    constants: usize,
}

/// A term of a gadget template: its class (local, imported, output or constant word), the
/// class index, and its two shifts.
fn template_term(class: u64, index: u32, term: Term) -> u64 {
    let [inner, outer] = term.shifts();
    (class << 62)
        | (u64::from(index) << 32)
        | (u64::from(inner.kind().code()) << 24)
        | (u64::from(inner.amount()) << 16)
        | (u64::from(outer.kind().code()) << 8)
        | u64::from(outer.amount())
}

fn shift(kind: ShiftKind, amount: usize) -> Shift<Word64> {
    Shift::new(kind, amount).expect("a shift amount within the word")
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
            zero: Operands::default(),
            and: Operands::default(),
            mul: Operands::default(),
            compressions: Vec::new(),
            pending_range: None,
            tape: Tape::new(),
            owners: None,
            pool: HashMap::new(),
        }
    }

    /// The committed word holding the constant `value`, one per distinct value and tied to
    /// its public word, so a gadget reads a constant as it reads any other word.
    pub(crate) fn pool_word(&mut self, value: u64) -> Val {
        if let Some(&word) = self.pool.get(&value) {
            return word;
        }
        self.begin_gadget("Const");
        let terms: Vec<Term> = self.constant(value).terms().collect();
        let word = self.computed(value, Op::Xor, 0, &[Arg::Terms(&terms)]);
        self.assert_zero(terms.into_iter().chain(word.terms()));
        self.end_gadget();
        self.pool.insert(value, word);
        word
    }

    /// A port of the current gadget holding `value`: a fresh word the gadget owns, equal to
    /// the one word `value` is made, which the gadget reads in place of it.
    pub(crate) fn port_copy(&mut self, value: Val) -> Val {
        let source = self.port(value);
        let word = self.computed(source.value, Op::Xor, 0, &[Arg::Val(source)]);
        self.assert_zero(source.terms().chain(word.terms()));
        if let Some(owners) = &mut self.owners {
            owners.links.push(self.zero.ends.len() as u32 - 1);
        }
        Val { narrow: source.narrow, ..word }
    }

    /// `value` as one unshifted committed word: a constant is its pool word, any other XOR
    /// is committed.
    pub(crate) fn port(&mut self, value: Val) -> Val {
        if value.constant {
            return self.pool_word(value.value);
        }
        self.materialize(value)
    }

    /// Records which gadget owns each word and relation from now on.
    pub(crate) fn track_gadgets(&mut self) {
        self.owners = Some(Owners::default());
    }

    /// Opens a gadget of `kind`, owning what is emitted until [`Self::end_gadget`].
    pub(crate) fn begin_gadget(&mut self, kind: &'static str) {
        if let Some(owners) = &mut self.owners {
            owners.stack.push(owners.kinds.len() as u32);
            owners.kinds.push(kind);
        }
    }

    /// Closes the innermost gadget.
    pub(crate) fn end_gadget(&mut self) {
        if let Some(owners) = &mut self.owners {
            owners.stack.pop();
        }
    }

    fn own_relation(&mut self, family: usize) {
        if let Some(owners) = &mut self.owners {
            let owner = owners.current();
            owners.relations[family].push(owner);
        }
    }

    /// Logs the distinct gadget templates: a gadget's relations with its own words numbered
    /// in order, the committed words it reads from other gadgets numbered by first read, and
    /// the constants likewise; `positional` numbers every read of another gadget's word or of a
    /// constant on its own, so equal values do not split a template.  With `dump`, writes one
    /// line per template there.
    pub(crate) fn template_census(
        &self,
        outputs: usize,
        dump: Option<&std::path::Path>,
        positional: bool,
    ) {
        let Some(owners) = &self.owners else { return };
        let gadgets = owners.kinds.len();
        let words = by_owner(&owners.words, gadgets);
        let families = [&self.zero, &self.and, &self.mul];
        let arity = [1, 3, 4];
        let relations: Vec<_> =
            owners.relations.iter().map(|owner_of| by_owner(owner_of, gadgets)).collect();
        let mut templates: HashMap<Vec<u64>, Template> = HashMap::new();
        let mut local = HashMap::new();
        let mut imported = HashMap::new();
        let mut constants = HashMap::new();
        let mut code = Vec::new();
        let mut link = vec![false; self.zero.ends.len()];
        for &relation in &owners.links {
            link[relation as usize] = true;
        }
        let mut ports = 0;
        for gadget in 0..gadgets {
            local.clear();
            imported.clear();
            constants.clear();
            code.clear();
            let (start, order) = &words;
            for &word in &order[start[gadget] as usize..start[gadget + 1] as usize] {
                let next = local.len() as u32;
                local.insert(word, next);
            }
            let mut counts = [0; 3];
            for (family, (start, order)) in relations.iter().enumerate() {
                let owned = &order[start[gadget] as usize..start[gadget + 1] as usize];
                counts[family] = owned.len();
                for &relation in owned {
                    if family == 0 && link[relation as usize] {
                        ports += 1;
                        counts[0] -= 1;
                        continue;
                    }
                    code.push(family as u64 + 1);
                    for operand in 0..arity[family] {
                        let index = relation as usize * arity[family] + operand;
                        let from = index.checked_sub(1).map_or(0, |i| families[family].ends[i]);
                        let terms = &families[family].terms[from..families[family].ends[index]];
                        code.push(terms.len() as u64);
                        for &term in terms {
                            let position = term.index().position();
                            let entry = match term.index().segment() {
                                Segment::Witness => match local.get(&position) {
                                    Some(&slot) => (0, slot),
                                    None if positional => {
                                        let next = imported.len() as u32;
                                        imported.insert(u32::MAX - next, next);
                                        (1, next)
                                    }
                                    None => {
                                        let next = imported.len() as u32;
                                        (1, *imported.entry(position).or_insert(next))
                                    }
                                },
                                Segment::Public if (position as usize) < outputs => (2, position),
                                Segment::Public if positional => {
                                    let next = constants.len() as u32;
                                    constants.insert(u32::MAX - next, next);
                                    (3, next)
                                }
                                Segment::Public => {
                                    let next = constants.len() as u32;
                                    (3, *constants.entry(position).or_insert(next))
                                }
                            };
                            code.push(template_term(entry.0, entry.1, term));
                        }
                    }
                }
            }
            code.push(local.len() as u64);
            let template = templates.entry(code.clone()).or_insert_with(|| Template {
                kind: owners.kinds[gadget],
                instances: 0,
                words: local.len(),
                relations: counts,
                imports: imported.len(),
                constants: constants.len(),
            });
            template.instances += 1;
        }
        let unowned = words.0[gadgets + 1] - words.0[gadgets];
        let mut list: Vec<_> = templates.into_iter().collect();
        list.sort_by_key(|(_, t)| std::cmp::Reverse(t.instances * t.words.max(1)));
        let total: usize = list.iter().map(|(_, t)| t.instances * t.words).sum();
        let reads: usize = list.iter().map(|(_, t)| t.instances * t.imports).sum();
        let singles: usize = list.iter().filter(|(_, t)| t.instances == 1).map(|(_, t)| t.words).sum();
        tracing::info!(
            "template census{}: {gadgets} gadgets, {} templates, {total} owned words ({unowned} unowned), {reads} imported reads, {ports} port copies; templates of one instance: {} holding {singles} words",
            if positional { " positional" } else { "" },
            list.len(),
            list.iter().filter(|(_, t)| t.instances == 1).count(),
        );
        let mut covered = 0;
        for (rank, (_, t)) in list.iter().enumerate() {
            covered += t.instances * t.words;
            if rank < 24 || [39, 59, 99, 199, 499].contains(&rank) {
                tracing::info!(
                    "template census{}: #{rank} {} x{} w{} z{} a{} m{} imports {} constants {}; covers {:.1}%",
                    if positional { " positional" } else { "" },
                    t.kind, t.instances, t.words, t.relations[0], t.relations[1], t.relations[2],
                    t.imports, t.constants, 100.0 * covered as f64 / total.max(1) as f64
                );
            }
        }
        if let Some(path) = dump {
            let mut out = String::new();
            for (code, t) in &list {
                let digest = blake3::hash(&code.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<_>>());
                out.push_str(&format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\n",
                    &digest.to_hex()[..16], t.kind, t.instances, t.words, t.imports, t.constants
                ));
            }
            let mode = if positional { "positional" } else { "shared" };
            let path = path.with_extension(format!("{}.{mode}.tsv", self.witness.len()));
            if let Err(error) = std::fs::write(&path, out) {
                tracing::warn!("template census: write {}: {error}", path.display());
            }
        }
    }

    /// The number of committed words so far.
    pub fn witness_len(&self) -> usize {
        self.witness.len()
    }

    /// Where each family's operand terms end so far.
    pub(crate) fn term_marks(&self) -> [usize; 3] {
        [self.zero.terms.len(), self.and.terms.len(), self.mul.terms.len()]
    }

    /// The distinct committed words before `mark` that the terms after `marks` read, and the
    /// number of such reads.
    pub(crate) fn imports(&self, marks: [usize; 3], mark: usize) -> (usize, usize) {
        let mut words: Vec<usize> = [&self.zero, &self.and, &self.mul]
            .into_iter()
            .zip(marks)
            .flat_map(|(family, from)| family.terms[from..].iter())
            .filter_map(|term| {
                let index = term.index();
                (index.segment() == Segment::Witness && (index.position() as usize) < mark)
                    .then_some(index.position() as usize)
            })
            .collect();
        let reads = words.len();
        words.sort_unstable();
        words.dedup();
        (words.len(), reads)
    }

    /// What has been emitted so far.
    pub fn cost(&self) -> Cost {
        Cost {
            and: self.and.ends.len() / 3,
            mul: self.mul.ends.len() / 4,
            zero: self.zero.ends.len(),
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

    /// A fresh committed word given as the constant `value`, which a lowering never
    /// commits: its words are all computed.
    pub fn word(&mut self, value: u64) -> Val {
        self.computed(value, Op::Constant, value, &[])
    }

    /// A fresh committed word of `value`, which `op` with `imm` computes over `args`.
    pub(crate) fn computed(&mut self, value: u64, op: Op, imm: u64, args: &[Arg<'_>]) -> Val {
        debug_assert_eq!(op.arity(), args.len());
        self.tape.begin(op, imm);
        for arg in args {
            match arg {
                Arg::Val(value) => self.tape.operand(value.terms()),
                Arg::Terms(terms) => self.tape.operand(terms.iter().copied()),
            }
        }
        let index = self.witness.len();
        self.witness.push(value);
        if let Some(owners) = &mut self.owners {
            let owner = owners.current();
            owners.words.push(owner);
        }
        Val::single(
            ShiftedValue::plain(ValueIndex::witness(index).expect("a witness index")),
            value,
        )
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
        self.zero.push(terms);
        self.own_relation(0);
    }

    /// `left & right = out`.
    pub fn and(
        &mut self,
        left: impl IntoIterator<Item = Term>,
        right: impl IntoIterator<Item = Term>,
        out: impl IntoIterator<Item = Term>,
    ) {
        self.and.push(left);
        self.and.push(right);
        self.and.push(out);
        self.own_relation(1);
    }

    /// `left * right = lo + 2^64 hi`.
    pub fn imul(
        &mut self,
        left: impl IntoIterator<Item = Term>,
        right: impl IntoIterator<Item = Term>,
        lo: impl IntoIterator<Item = Term>,
        hi: impl IntoIterator<Item = Term>,
    ) {
        self.mul.push(left);
        self.mul.push(right);
        self.mul.push(lo);
        self.mul.push(hi);
        self.own_relation(2);
    }

    /// `value` as one unshifted word, committing it if it is not one.
    pub fn materialize(&mut self, value: Val) -> Val {
        if value.is_zero() || value.plain().is_some() {
            return value;
        }
        let word = self.computed(value.value, Op::Xor, 0, &[Arg::Val(value)]);
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
            Err(_) => Err(()),
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
        let carry = self
            .computed(carries, Op::Carry, u64::from(lane32), &[Arg::Terms(x), Arg::Terms(y)])
            .plain()
            .expect("a fresh word is plain");
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
        let sum = self.computed(chain.value, Op::Xor, 0, &[Arg::Terms(&chain.sum)]);
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

    /// [`Self::build`], with how each committed word is computed.
    pub fn build_with_tape(mut self) -> Result<(Built, Tape), SystemError> {
        self.flush_compressions();
        self.flush_ranges();
        let tape = std::mem::take(&mut self.tape);
        debug_assert_eq!(tape.len(), self.witness.len());
        Ok((self.build()?, tape))
    }

    /// The relations and the words that satisfy them.
    pub fn build(mut self) -> Result<Built, SystemError> {
        self.flush_compressions();
        self.flush_ranges();
        let zero = self.zero.relations(|[value]| ZeroConstraint::new(value));
        let and = self.and.relations(|[left, right, out]| AndConstraint::new(left, right, out));
        let mul = self
            .mul
            .relations(|[left, right, lo, hi]| IntegerMulConstraint::new(left, right, lo, hi));
        let system =
            ConstraintSystem::new(self.public.len(), self.witness.len(), zero, and, mul)?;
        Ok(Built {
            system,
            public: self.public.into_iter().map(Word64::new).collect(),
            witness: self.witness.into_iter().map(Word64::new).collect(),
        })
    }
}
