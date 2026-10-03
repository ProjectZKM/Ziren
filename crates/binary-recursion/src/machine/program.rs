//! A tape laid out as the machine's tables: every variable read at an
//! address, every operation a row.
//!
//! The machine proves a tape the way the binary stage proves a recursion
//! program: values live in cells of one memory, each written once and read
//! as often as the program reads it, and every table pulls the cells it
//! reads and pushes the cells it writes.  This module fixes everything the
//! tape fixes, which is everything but the values: the address of each
//! cell, how often it is read and where its value comes from, and the rows
//! of each table with the addresses they touch.  It is the preprocessed
//! half of the machine; the values of one run fill the other half.
//!
//! Three choices keep the tables narrow:
//!
//! - **Constants are cells.**  Each distinct constant operand is a cell of
//!   its own, so every operand of every row is a read.
//! - **Outputs are aligned.**  An operation with `n` outputs writes them at
//!   a base address aligned to the next power of two, so output `i` sits at
//!   `base ^ i`, and a table names one address for all of them.
//! - **Inputs of a rewiring are gathered.**  A transpose reads 128 cells
//!   and an assembly of bytes 16; each is first copied, by the arithmetic
//!   table, to an aligned block, so the rewiring table too names one
//!   address for all its inputs.

use std::collections::HashMap;

use p3_binary_field::TowerLevel;
use p3_field::PrimeCharacteristicRing;
use zkm_recursion_core::runtime::blake3::{compress, CHUNK_END, CHUNK_START, IV, PARENT, ROOT};

use crate::tape::{Op, Operand, Tape, Var, F};

/// Bits of an address.
pub const ADDR_BITS: usize = 24;

/// Bytes of a Blake3 chunk.
const CHUNK_BYTES: usize = 1024;

/// Slots, of sixteen bytes each, of a Blake3 block.
const BLOCK_SLOTS: usize = 4;

/// Slots of a Blake3 chunk.
const CHUNK_SLOTS: usize = CHUNK_BYTES / 16;

/// Where a cell's value comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// A row of some table computes it and pushes it once.
    Write,
    /// It is a value of the proof, free.
    Input,
    /// It is the `i`-th public value.
    Public(usize),
    /// It is this constant.
    Const(F),
}

/// A cell that is read: its address, how often, and its value.
#[derive(Clone, Copy, Debug)]
pub struct Group {
    pub addr: u32,
    pub reads: u32,
    pub source: Source,
    /// The value, as the tape names it.
    pub cell: Operand,
}

/// What an arithmetic row computes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArithKind {
    /// `c = a + b`.
    Add,
    /// `c = a * b`.
    Mul,
    /// `c = a * a`.
    Square,
    /// `a * c = 1`: `c` is `a`'s inverse, written or not.
    Inv,
    /// `a = b`.
    Eq,
    /// `c = b` if `s` else `a`.
    Select,
    /// `c = a`.
    Copy,
}

/// An operand of a row: the address it is read at and its value.
#[derive(Clone, Copy, Debug)]
pub struct Read {
    pub addr: u32,
    pub cell: Operand,
}

/// One row of the arithmetic table.
#[derive(Clone, Copy, Debug)]
pub struct ArithRow {
    pub kind: ArithKind,
    pub a: Option<Read>,
    pub b: Option<Read>,
    pub s: Option<Read>,
    /// The address `c` is written at, for a kind that writes it.
    pub c: Option<u32>,
    /// Whether `c` is read, which [`Program::new`] settles last.
    pub write_c: bool,
}

/// What a rewiring row does with its bit matrix, whose row `u` is the bits
/// of input `u`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RewireKind {
    /// 128 inputs; output `v` is column `v`.
    Transpose,
    /// One input; output `j` is its byte `j`.
    ToBytes,
    /// Sixteen byte inputs; the output has byte `u` from input `u`.
    FromBytes,
    /// One input; output `i`, of `outputs`, is its bit `i`.
    Bits { outputs: usize },
}

/// One row of the rewiring table.
#[derive(Clone, Debug)]
pub struct RewireRow {
    pub kind: RewireKind,
    /// Input `u` is read at `in_base ^ u`.
    pub in_base: u32,
    /// The inputs' values, as the tape names them.
    pub inputs: Vec<Operand>,
    /// Output `i` is written at `out_base ^ i`.
    pub out_base: u32,
    /// Whether each output is read, which [`Program::new`] settles last.
    pub out_reads: Vec<bool>,
}

/// Where a compression's chaining value comes from.
#[derive(Clone, Copy, Debug)]
pub enum CvSource {
    /// The Blake3 initial value: the first block of a chunk.
    Iv,
    /// The compression before it in its chunk.
    Chained(usize),
}

/// Where a compression's block comes from.
#[derive(Clone, Copy, Debug)]
pub enum BlockSource {
    /// Four cells of sixteen bytes.
    Slots([Read; BLOCK_SLOTS]),
    /// The chaining values of two compressions: a parent node.
    Parent(usize, usize),
    /// A Merkle node: `cur ‖ sib`, or `sib ‖ cur` when the bit is one.
    Merkle { bit: Read, cur: [Read; 2], sib: [Read; 2] },
}

/// Where a compression's output goes.
#[derive(Clone, Copy, Debug)]
pub enum Output {
    /// A digest: its two halves written at `base` and `base ^ 1`.
    Root { base: u32, reads: [bool; 2] },
    /// A chaining value, consumed by one later compression.
    Link,
}

/// One compression.
#[derive(Clone, Copy, Debug)]
pub struct Compression {
    pub cv: CvSource,
    pub block: BlockSource,
    pub counter: u32,
    pub block_len: u32,
    pub flags: u32,
    pub output: Output,
}

/// A tape laid out for the machine.
#[derive(Clone, Debug, Default)]
pub struct Program {
    /// The cells that are read, in the ledger's order.
    pub groups: Vec<Group>,
    pub arith: Vec<ArithRow>,
    pub rewire: Vec<RewireRow>,
    pub compressions: Vec<Compression>,
    /// How many of the tape's first inputs are public values.
    pub num_public: usize,
}

/// The program as it is being laid out.
struct Builder {
    next_addr: u32,
    var_addr: Vec<u32>,
    var_source: Vec<Source>,
    const_addr: HashMap<u128, u32>,
    reads: HashMap<u32, (u32, Operand, Source)>,
    program: Program,
}

impl Builder {
    /// A block of `n` addresses aligned to the next power of two.
    fn allocate(&mut self, n: usize) -> u32 {
        let align = u32::try_from(n.next_power_of_two()).expect("a block fits an address");
        let base = self.next_addr.div_ceil(align) * align;
        self.next_addr = base + align;
        assert!(self.next_addr <= 1 << ADDR_BITS, "the program fits {ADDR_BITS}-bit addresses");
        base
    }

    /// The address of an operand, a constant getting its cell on first use.
    fn address(&mut self, operand: Operand) -> (u32, Source) {
        match operand {
            Operand::Var(v) => (self.var_addr[v as usize], self.var_source[v as usize]),
            Operand::Const(c) => {
                let key = c.to_repr();
                let addr = match self.const_addr.get(&key) {
                    Some(&addr) => addr,
                    None => {
                        let addr = self.allocate(1);
                        self.const_addr.insert(key, addr);
                        addr
                    }
                };
                (addr, Source::Const(c))
            }
        }
    }

    /// A read of `operand`, counted.
    fn read(&mut self, operand: Operand) -> Read {
        let (addr, source) = self.address(operand);
        self.reads.entry(addr).or_insert((0, operand, source)).0 += 1;
        Read { addr, cell: operand }
    }

    /// Copy `operands` to a fresh aligned block, returning its base.
    fn gather(&mut self, operands: &[Operand]) -> u32 {
        let base = self.allocate(operands.len());
        for (u, &operand) in operands.iter().enumerate() {
            let a = self.read(operand);
            self.program.arith.push(ArithRow {
                kind: ArithKind::Copy,
                a: Some(a),
                b: None,
                s: None,
                c: Some(base ^ u as u32),
                write_c: false,
            });
            self.reads.entry(base ^ u as u32).or_insert((0, operand, Source::Write)).0 += 1;
        }
        base
    }

    fn arith(&mut self, kind: ArithKind, operands: &[Operand], c: Option<u32>) {
        let mut reads = operands.iter().map(|&x| self.read(x));
        let a = reads.next();
        let b = reads.next();
        let s = if kind == ArithKind::Select { a } else { None };
        let (a, b) = if kind == ArithKind::Select { (b, reads.next()) } else { (a, b) };
        self.program.arith.push(ArithRow { kind, a, b, s, c, write_c: false });
    }

    /// The compressions hashing the `len` bytes of `slots`, returning the
    /// root's index.
    fn hash(&mut self, slots: &[Operand], len: usize, out: u32) -> usize {
        let chunks = len.div_ceil(CHUNK_BYTES).max(1);
        let mut chunk_roots = Vec::with_capacity(chunks);
        for chunk in 0..chunks {
            let chunk_len = (len - chunk * CHUNK_BYTES).min(CHUNK_BYTES);
            let blocks = chunk_len.div_ceil(64).max(1);
            let mut previous = None;
            for block in 0..blocks {
                let first = chunk * CHUNK_SLOTS + block * BLOCK_SLOTS;
                let cells: [Operand; BLOCK_SLOTS] = core::array::from_fn(|k| {
                    slots.get(first + k).copied().unwrap_or(Operand::Const(F::ZERO))
                });
                let reads = cells.map(|cell| self.read(cell));
                let mut flags = 0;
                if block == 0 {
                    flags |= CHUNK_START;
                }
                if block + 1 == blocks {
                    flags |= CHUNK_END;
                    if chunks == 1 {
                        flags |= ROOT;
                    }
                }
                let block_len = (chunk_len - block * 64).min(64) as u32;
                let is_root = chunks == 1 && block + 1 == blocks;
                self.program.compressions.push(Compression {
                    cv: previous.map_or(CvSource::Iv, CvSource::Chained),
                    block: BlockSource::Slots(reads),
                    counter: chunk as u32,
                    block_len,
                    flags,
                    output: if is_root {
                        Output::Root { base: out, reads: [false; 2] }
                    } else {
                        Output::Link
                    },
                });
                previous = Some(self.program.compressions.len() - 1);
            }
            chunk_roots.push(previous.expect("a chunk has a block"));
        }
        if chunks == 1 {
            return chunk_roots[0];
        }
        self.parents(&chunk_roots, out)
    }

    /// The parent nodes over `children`, left subtree the largest power of
    /// two that leaves the right one nonempty, returning the root's index.
    fn parents(&mut self, children: &[usize], out: u32) -> usize {
        let root = self.subtree(children, true, out);
        root.expect("a tree of two or more chunks has a parent")
    }

    fn subtree(&mut self, children: &[usize], is_root: bool, out: u32) -> Option<usize> {
        if children.len() == 1 {
            return None;
        }
        let split = (children.len() - 1).next_power_of_two();
        let split = if split >= children.len() { split / 2 } else { split };
        let left = self.subtree(&children[..split], false, out).unwrap_or(children[0]);
        let right = self.subtree(&children[split..], false, out).unwrap_or(children[split]);
        self.program.compressions.push(Compression {
            cv: CvSource::Iv,
            block: BlockSource::Parent(left, right),
            counter: 0,
            block_len: 64,
            flags: PARENT | if is_root { ROOT } else { 0 },
            output: if is_root {
                Output::Root { base: out, reads: [false; 2] }
            } else {
                Output::Link
            },
        });
        Some(self.program.compressions.len() - 1)
    }
}

impl Program {
    /// The layout of `tape`, whose first `num_public` inputs are public.
    ///
    /// # Panics
    /// Panics if the tape does not fit the machine: more than `2^ADDR_BITS`
    /// addresses, or a transpose of neither one nor 128 rows.
    #[must_use]
    pub fn new(tape: &Tape, num_public: usize) -> Self {
        let mut builder = Builder {
            next_addr: 0,
            var_addr: vec![u32::MAX; tape.values.len()],
            var_source: vec![Source::Write; tape.values.len()],
            const_addr: HashMap::new(),
            reads: HashMap::new(),
            program: Program { num_public, ..Program::default() },
        };
        for (op, defined) in tape.ops.iter().zip(&tape.defined) {
            let outputs = op.defines();
            let base = defined.map(|first| {
                let base = builder.allocate(outputs);
                for i in 0..outputs {
                    builder.var_addr[first as usize + i] = base ^ i as u32;
                }
                base
            });
            match op {
                Op::Input(n) => {
                    let v = defined.expect("an input defines its value") as usize;
                    builder.var_source[v] =
                        if *n < num_public { Source::Public(*n) } else { Source::Input };
                }
                Op::Add(a, b) => builder.arith(ArithKind::Add, &[*a, *b], base),
                Op::Mul(a, b) => builder.arith(ArithKind::Mul, &[*a, *b], base),
                Op::Square(a) => builder.arith(ArithKind::Square, &[*a], base),
                Op::Inv(a) => builder.arith(ArithKind::Inv, &[*a], base),
                Op::AssertEq(a, b) => builder.arith(ArithKind::Eq, &[*a, *b], None),
                Op::AssertNonZero(a) => builder.arith(ArithKind::Inv, &[*a], None),
                Op::Select(s, a, b) => builder.arith(ArithKind::Select, &[*s, *a, *b], base),
                Op::ToBytes(x) | Op::ByteBits(x) => {
                    let read = builder.read(*x);
                    let kind = if matches!(op, Op::ToBytes(_)) {
                        RewireKind::ToBytes
                    } else {
                        RewireKind::Bits { outputs: 8 }
                    };
                    builder.program.rewire.push(RewireRow {
                        kind,
                        in_base: read.addr,
                        inputs: vec![*x],
                        out_base: base.expect("a rewiring has outputs"),
                        out_reads: vec![false; outputs],
                    });
                }
                Op::Transpose(rows) if rows.len() == 1 => {
                    let read = builder.read(rows[0]);
                    builder.program.rewire.push(RewireRow {
                        kind: RewireKind::Bits { outputs: 128 },
                        in_base: read.addr,
                        inputs: rows.clone(),
                        out_base: base.expect("a transpose has outputs"),
                        out_reads: vec![false; 128],
                    });
                }
                Op::Transpose(rows) | Op::FromBytes(rows) => {
                    let kind = if matches!(op, Op::Transpose(_)) {
                        assert_eq!(rows.len(), 128, "a transpose has one row or 128");
                        RewireKind::Transpose
                    } else {
                        RewireKind::FromBytes
                    };
                    let in_base = builder.gather(rows);
                    builder.program.rewire.push(RewireRow {
                        kind,
                        in_base,
                        inputs: rows.clone(),
                        out_base: base.expect("a rewiring has outputs"),
                        out_reads: vec![false; outputs],
                    });
                }
                Op::Blake3 { slots, len } => {
                    builder.hash(slots, *len, base.expect("a hash has a digest"));
                }
                Op::MerkleNode { bit, cur, sib } => {
                    let bit = builder.read(*bit);
                    let cur = cur.map(|x| builder.read(x));
                    let sib = sib.map(|x| builder.read(x));
                    builder.program.compressions.push(Compression {
                        cv: CvSource::Iv,
                        block: BlockSource::Merkle { bit, cur, sib },
                        counter: 0,
                        block_len: 64,
                        flags: CHUNK_START | CHUNK_END | ROOT,
                        output: Output::Root {
                            base: base.expect("a node has a digest"),
                            reads: [false; 2],
                        },
                    });
                }
            }
        }

        let reads = core::mem::take(&mut builder.reads);
        let is_read = |addr: u32| reads.contains_key(&addr);
        let mut program = builder.program;
        for row in &mut program.arith {
            row.write_c = row.c.is_some_and(is_read);
        }
        for row in &mut program.rewire {
            for (i, read) in row.out_reads.iter_mut().enumerate() {
                *read = is_read(row.out_base ^ i as u32);
            }
        }
        for compression in &mut program.compressions {
            if let Output::Root { base, reads } = &mut compression.output {
                *reads = [is_read(*base), is_read(*base ^ 1)];
            }
        }
        let mut groups: Vec<Group> = reads
            .into_iter()
            .map(|(addr, (reads, cell, source))| Group { addr, reads, source, cell })
            .collect();
        groups.sort_by_key(|group| group.addr);
        program.groups = groups;
        program
    }

    /// The value of `cell` in a run whose variables have `values`.
    pub fn value(values: &[F], cell: Operand) -> F {
        match cell {
            Operand::Var(v) => values[v as usize],
            Operand::Const(c) => c,
        }
    }

    /// Every compression's chaining value in and block, as words, and its
    /// output state, in order: the witness of the hash tables.
    #[must_use]
    pub fn compression_states(&self, values: &[F]) -> Vec<CompressionState> {
        let mut states: Vec<CompressionState> = Vec::with_capacity(self.compressions.len());
        for c in &self.compressions {
            let cv = match c.cv {
                CvSource::Iv => IV,
                CvSource::Chained(i) => states[i].cv_out(),
            };
            let element_words = |x: F| -> [u32; 4] {
                let repr = x.to_repr();
                core::array::from_fn(|k| (repr >> (32 * k)) as u32)
            };
            let slot_words = |cells: [F; BLOCK_SLOTS]| -> [u32; 16] {
                core::array::from_fn(|w| element_words(cells[w / 4])[w % 4])
            };
            let (block, bit) = match c.block {
                BlockSource::Slots(reads) => {
                    (slot_words(reads.map(|r| Self::value(values, r.cell))), false)
                }
                BlockSource::Parent(left, right) => {
                    let (l, r) = (states[left].cv_out(), states[right].cv_out());
                    (core::array::from_fn(|w| if w < 8 { l[w] } else { r[w - 8] }), false)
                }
                BlockSource::Merkle { bit, cur, sib } => {
                    let bit = Self::value(values, bit.cell) == F::ONE;
                    let cur = cur.map(|r| Self::value(values, r.cell));
                    let sib = sib.map(|r| Self::value(values, r.cell));
                    let cells = if bit {
                        [sib[0], sib[1], cur[0], cur[1]]
                    } else {
                        [cur[0], cur[1], sib[0], sib[1]]
                    };
                    (slot_words(cells), bit)
                }
            };
            let out = compress(&cv, &block, u64::from(c.counter), c.block_len, c.flags);
            states.push(CompressionState { cv, block, bit, out });
        }
        states
    }

    /// The bits of address space the program uses.
    #[must_use]
    pub fn census(&self) -> String {
        let reads: u64 = self.groups.iter().map(|g| u64::from(g.reads)).sum();
        let kinds = [
            ArithKind::Add,
            ArithKind::Mul,
            ArithKind::Square,
            ArithKind::Inv,
            ArithKind::Eq,
            ArithKind::Select,
            ArithKind::Copy,
        ];
        let arith: Vec<String> = kinds
            .iter()
            .map(|kind| {
                let n = self.arith.iter().filter(|row| row.kind == *kind).count();
                format!("{kind:?} {n}")
            })
            .collect();
        format!(
            "{} cells read {reads} times; arith {} rows ({}); rewire {} rows; {} compressions",
            self.groups.len(),
            self.arith.len(),
            arith.join(", "),
            self.rewire.len(),
            self.compressions.len()
        )
    }
}

/// One compression's words in and out.
#[derive(Clone, Copy, Debug)]
pub struct CompressionState {
    pub cv: [u32; 8],
    pub block: [u32; 16],
    /// The Merkle bit, zero for any other compression.
    pub bit: bool,
    /// The sixteen output words; the chaining value is the first eight.
    pub out: [u32; 16],
}

impl CompressionState {
    /// The chaining value it hands on.
    #[must_use]
    pub fn cv_out(&self) -> [u32; 8] {
        core::array::from_fn(|i| self.out[i])
    }
}

/// The variable a cell is, if it is one.
#[must_use]
pub const fn var_of(cell: Operand) -> Option<Var> {
    match cell {
        Operand::Var(v) => Some(v),
        Operand::Const(_) => None,
    }
}
