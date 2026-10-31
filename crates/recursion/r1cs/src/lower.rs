//! Lowering a recursion program to word relations.
//!
//! Every address is written once, so a value is the output of the one
//! instruction that writes it, and a read is a copy of that value into the
//! reading gadget's operands: the dataflow is carried by the operands
//! themselves, with no memory argument.  Values are kept per address as an
//! element or, when any instruction uses the address as an extension
//! element, as four coefficients.
//!
//! With the runtime's memory the lowering also fills the witness, taking
//! hints from it, and checks every value it computes against it.

use std::collections::BTreeMap;

use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use p3_word::{Segment, SystemError};
use thiserror::Error;
use zkm_recursion_core::{
    air::Block,
    instruction::{
        HintAddCurveInstr, HintBitsInstr, HintExt2FeltsInstr, HintInstr, PrefixSumChecksInstr,
    },
    BaseAluInstr, BaseAluOpcode, Blake3CompressInstr, CommitPublicValuesInstr, ExtAluInstr,
    ExtAluOpcode, FeltLimbsInstr, Instruction, MemAccessKind, MemInstr, RecursionProgram,
    SelectInstr, DIGEST_SIZE,
};

use crate::{
    builder::{Builder, Built, Cost, Val},
    kb::{memory_imm, Ext},
    tape::{Op, Tape},
};

type F = KoalaBear;

/// Why a program could not be lowered.
#[derive(Debug, Error)]
pub enum LowerError {
    /// The program uses an instruction this compiler has no gadget for.
    #[error("instruction {index}: {kind} is not supported")]
    Unsupported { index: usize, kind: &'static str },
    /// An instruction reads an address no earlier instruction wrote.
    #[error("instruction {index}: address {addr} is read before it is written")]
    Unwritten { index: usize, addr: usize },
    /// A computed value differs from the runtime's.
    #[error("instruction {index} ({kind}): address {addr} is {computed:?}, the runtime has {expected:?}")]
    Mismatch {
        index: usize,
        kind: &'static str,
        addr: usize,
        computed: [u64; 4],
        expected: [u64; 4],
    },
    /// The program commits its public values other than once.
    #[error("the program commits public values {0} times")]
    Commits(usize),
    /// The relations do not form a system.
    #[error("system: {0}")]
    System(#[from] SystemError),
    /// A committed word has no computation from the memory and the words before it.
    #[error("committed word {0} is not computed")]
    Uncomputed(usize),
}

/// A lowered program.
pub struct Lowered {
    /// The relations and their witness.
    pub built: Built,
    /// The digest the program commits, which is public words `0..8`.
    pub digest: [u32; DIGEST_SIZE],
    /// What each kind of instruction cost.
    pub census: BTreeMap<&'static str, (usize, Cost)>,
    /// How each committed word is computed from the runtime's memory.
    pub tape: Tape,
}

/// The spread of one kind's instances, for the census.
struct Shape {
    words: (usize, usize),
    relations: (usize, usize),
    imported: usize,
    reads: usize,
    histogram: BTreeMap<(usize, usize, usize, usize), usize>,
}

impl Default for Shape {
    fn default() -> Self {
        Self {
            words: (usize::MAX, 0),
            relations: (usize::MAX, 0),
            imported: 0,
            reads: 0,
            histogram: BTreeMap::new(),
        }
    }
}

impl Shape {
    fn add(&mut self, cost: &Cost, imported: usize, reads: usize) {
        let relations = cost.and + cost.mul + cost.zero;
        self.words = (self.words.0.min(cost.words), self.words.1.max(cost.words));
        self.relations = (self.relations.0.min(relations), self.relations.1.max(relations));
        self.imported += imported;
        self.reads += reads;
        *self.histogram.entry((cost.words, cost.and, cost.mul, cost.zero)).or_default() += 1;
    }
}

#[derive(Clone)]
enum Slot {
    Unset,
    Felt(Val),
    Ext(Box<Ext>),
    Dead,
}

struct Lowering<'a> {
    builder: Builder,
    slots: Vec<Slot>,
    is_ext: Vec<bool>,
    memory: Option<&'a [Block<F>]>,
    index: usize,
    kind: &'static str,
    commits: usize,
    digest: [u32; DIGEST_SIZE],
    /// The first committed word of the instruction being lowered.
    mark: usize,
}

/// Lowers `program` again as gadgets, composes them, and proves and verifies the composition
/// on the host, logging its size and times beside the flat lowering's `flat` words.
fn compose_experiment(program: &RecursionProgram<F>, memory: Option<&[Block<F>]>, flat: (usize, usize)) {
    use p3_word_backend::{PackedWitness, WordProofKey};
    use zkm_binary_stark::{challenger, config::bit_commitment, F as Gf};

    let started = std::time::Instant::now();
    let mut lowering = Lowering {
        builder: Builder::new(DIGEST_SIZE),
        slots: vec![Slot::Unset; program.total_memory],
        is_ext: ext_addresses(program),
        memory,
        index: 0,
        kind: "",
        commits: 0,
        digest: [0; DIGEST_SIZE],
        mark: 0,
    };
    lowering.builder.track_gadgets();
    for (index, instruction) in program.iter_instructions().enumerate() {
        lowering.index = index;
        lowering.kind = kind_of(instruction);
        lowering.mark = lowering.builder.witness_len();
        lowering.builder.begin_gadget(lowering.kind);
        if let Err(error) = lowering.lower(instruction) {
            tracing::warn!("compose experiment: lowering failed: {error}");
            return;
        }
        lowering.builder.end_gadget();
    }
    let composed = match lowering.builder.compose(DIGEST_SIZE) {
        Ok(composed) => composed,
        Err(error) => {
            tracing::warn!("compose experiment: {error}");
            return;
        }
    };
    let composition = &composed.composition;
    tracing::info!(
        "compose experiment: flat {} words + {} public; composed {} words + {} public in {} calls, {} blocks, 2^{} port cells; lowered and composed in {:.1} s",
        flat.0, flat.1, composition.witness_len(), composition.public_len(), composition.calls().len(),
        composition.blocks().len(), composed.routing.cell_variables(), started.elapsed().as_secs_f64()
    );
    let started = std::time::Instant::now();
    let key = match WordProofKey::with_ports(composition.clone(), composed.routing.clone()) {
        Ok(key) => key,
        Err(error) => {
            tracing::warn!("compose experiment: key: {error:?}");
            return;
        }
    };
    let pcs = bit_commitment(key.trace_variables(), &crate::prove::schedule()).expect("a commitment");
    let routing = key
        .port_commitment::<Gf, _, _>(&pcs, &mut challenger())
        .expect("the routing commits")
        .expect("the key routes ports");
    let keyed = started.elapsed().as_secs_f64();
    let started = std::time::Instant::now();
    let values = PackedWitness::new(key.statement(), &composed.public, &composed.witness)
        .expect("the composed words fit the statement");
    let proved = key.prove::<Gf, Gf, _, _>(&pcs, &values, &mut challenger());
    let (commitment, proof) = match proved {
        Ok(proved) => proved,
        Err(error) => {
            tracing::warn!("compose experiment: prove: {error:?}");
            return;
        }
    };
    let prove = started.elapsed().as_secs_f64();
    let started = std::time::Instant::now();
    let verdict = key.verify_routed::<Gf, Gf, _, _>(
        &pcs,
        &commitment,
        &routing,
        &composed.public,
        &proof,
        &mut challenger(),
    );
    tracing::info!(
        "compose experiment: trace 2^{}, key + routing commitment {keyed:.1} s, host prove {prove:.1} s, verify {:.2} s: {verdict:?}; proof {} bytes, key {} bytes",
        key.trace_variables(),
        started.elapsed().as_secs_f64(),
        crate::prove::proof_size(&proof),
        postcard::to_allocvec(&key).map_or(0, |bytes| bytes.len()),
    );
}

fn kind_of(instruction: &Instruction<F>) -> &'static str {
    match instruction {
        Instruction::BaseAlu(BaseAluInstr { opcode, .. }) => match opcode {
            BaseAluOpcode::AddF => "BaseAlu/AddF",
            BaseAluOpcode::SubF => "BaseAlu/SubF",
            BaseAluOpcode::MulF => "BaseAlu/MulF",
            BaseAluOpcode::DivF => "BaseAlu/DivF",
            BaseAluOpcode::DivFAssert => "BaseAlu/DivFAssert",
        },
        Instruction::ExtAlu(ExtAluInstr { opcode, .. }) => match opcode {
            ExtAluOpcode::AddE => "ExtAlu/AddE",
            ExtAluOpcode::SubE => "ExtAlu/SubE",
            ExtAluOpcode::MulE => "ExtAlu/MulE",
            ExtAluOpcode::DivE => "ExtAlu/DivE",
            ExtAluOpcode::DivEAssert => "ExtAlu/DivEAssert",
        },
        Instruction::Mem(_) => "Mem",
        Instruction::Poseidon2(_) => "Poseidon2",
        Instruction::Blake3Compress(_) => "Blake3Compress",
        Instruction::FeltLimbs(_) => "FeltLimbs",
        Instruction::Select(_) => "Select",
        Instruction::HintBits(_) => "HintBits",
        Instruction::HintAddCurve(_) => "HintAddCurve",
        Instruction::Print(_) => "Print",
        Instruction::HintExt2Felts(_) => "HintExt2Felts",
        Instruction::Ext2Felts(_) => "Ext2Felts",
        Instruction::CommitPublicValues(_) => "CommitPublicValues",
        Instruction::Hint(_) => "Hint",
        Instruction::PrefixSumChecks(_) => "PrefixSumChecks",
    }
}

fn ext_addresses(program: &RecursionProgram<F>) -> Vec<bool> {
    let mut is_ext = vec![false; program.total_memory];
    let mut mark = |addr: usize| is_ext[addr] = true;
    for instruction in program.iter_instructions() {
        match instruction {
            Instruction::ExtAlu(ExtAluInstr { addrs, .. }) => {
                mark(addrs.out.as_usize());
                mark(addrs.in1.as_usize());
                mark(addrs.in2.as_usize());
            }
            Instruction::Ext2Felts(HintExt2FeltsInstr { input_addr, .. })
            | Instruction::HintExt2Felts(HintExt2FeltsInstr { input_addr, .. }) => {
                mark(input_addr.as_usize());
            }
            Instruction::PrefixSumChecks(instr) => {
                instr.addrs.x2.iter().chain(&instr.addrs.accs).for_each(|a| mark(a.as_usize()));
            }
            Instruction::Mem(MemInstr { addrs, vals, .. }) => {
                if vals.inner.0[1..].iter().any(|v| v.as_canonical_u32() != 0) {
                    mark(addrs.inner.as_usize());
                }
            }
            _ => {}
        }
    }
    is_ext
}

impl Lowering<'_> {
    fn felt(&self, addr: usize) -> Result<Val, LowerError> {
        match &self.slots[addr] {
            Slot::Felt(value) => Ok(*value),
            Slot::Ext(value) => Ok(value[0]),
            Slot::Unset | Slot::Dead => Err(LowerError::Unwritten { index: self.index, addr }),
        }
    }

    fn ext(&self, addr: usize) -> Result<Ext, LowerError> {
        match &self.slots[addr] {
            Slot::Felt(value) => Ok(Builder::embed(*value)),
            Slot::Ext(value) => Ok(**value),
            Slot::Unset | Slot::Dead => Err(LowerError::Unwritten { index: self.index, addr }),
        }
    }

    fn memory(&self, addr: usize) -> [u64; 4] {
        self.memory
            .map(|memory| memory[addr].0.map(|v| u64::from(v.as_canonical_u32())))
            .unwrap_or_default()
    }

    fn check(&self, addr: usize, computed: [u64; 4]) -> Result<(), LowerError> {
        if self.memory.is_none() {
            return Ok(());
        }
        let expected = self.memory(addr);
        if computed != expected {
            return Err(LowerError::Mismatch {
                index: self.index,
                kind: self.kind,
                addr,
                computed,
                expected,
            });
        }
        Ok(())
    }

    /// Reads `value` from coefficient `coefficient` at `addr` if the instruction committed
    /// it: the runtime left it there, so it depends on no other word.
    fn from_memory(&mut self, value: Val, addr: usize, coefficient: usize) {
        if let Some(term) = value.plain() {
            let index = term.index();
            let position = index.position() as usize;
            if index.segment() == Segment::Witness && position >= self.mark {
                self.builder.tape.redefine(position, Op::Memory, memory_imm(addr, coefficient));
            }
        }
    }

    fn set_felt(&mut self, addr: usize, value: Val) -> Result<(), LowerError> {
        let mut computed = self.memory(addr);
        computed[0] = value.value;
        self.check(addr, computed)?;
        self.from_memory(value, addr, 0);
        self.slots[addr] = if self.is_ext[addr] {
            Slot::Ext(Box::new(Builder::embed(value)))
        } else {
            Slot::Felt(value)
        };
        Ok(())
    }

    fn set_ext(&mut self, addr: usize, value: Ext) -> Result<(), LowerError> {
        self.check(addr, value.map(|v| v.value))?;
        for (coefficient, value) in value.into_iter().enumerate() {
            self.from_memory(value, addr, coefficient);
        }
        self.slots[addr] = Slot::Ext(Box::new(value));
        Ok(())
    }

    fn hint_felt(&mut self, addr: usize) -> Result<(), LowerError> {
        if self.is_ext[addr] {
            let values = self.memory(addr);
            let value: Ext = std::array::from_fn(|i| self.builder.hint_at(values[i], addr, i));
            self.set_ext(addr, value)
        } else {
            let value = self.builder.hint_at(self.memory(addr)[0], addr, 0);
            self.set_felt(addr, value)
        }
    }

    fn base_alu(&mut self, instr: &BaseAluInstr<F>) -> Result<(), LowerError> {
        let out = instr.addrs.out.as_usize();
        let a = self.felt(instr.addrs.in1.as_usize())?;
        let b = self.felt(instr.addrs.in2.as_usize())?;
        let value = match instr.opcode {
            BaseAluOpcode::AddF => self.builder.add(a, b),
            BaseAluOpcode::SubF => self.builder.sub(a, b),
            BaseAluOpcode::MulF => self.builder.mul(a, b),
            BaseAluOpcode::DivF if instr.mult.as_canonical_u32() == 0 => {
                self.slots[out] = Slot::Dead;
                return Ok(());
            }
            BaseAluOpcode::DivF => self.builder.div(a, b, true),
            BaseAluOpcode::DivFAssert => self.builder.div(a, b, instr.mult.as_canonical_u32() != 0),
        };
        self.set_felt(out, value)
    }

    fn ext_alu(&mut self, instr: &ExtAluInstr<F>) -> Result<(), LowerError> {
        let out = instr.addrs.out.as_usize();
        let a = self.ext(instr.addrs.in1.as_usize())?;
        let b = self.ext(instr.addrs.in2.as_usize())?;
        let value = match instr.opcode {
            ExtAluOpcode::AddE => self.builder.ext_add(a, b),
            ExtAluOpcode::SubE => self.builder.ext_sub(a, b),
            ExtAluOpcode::MulE => self.builder.ext_mul(a, b),
            ExtAluOpcode::DivE if instr.mult.as_canonical_u32() == 0 => {
                self.slots[out] = Slot::Dead;
                return Ok(());
            }
            ExtAluOpcode::DivE | ExtAluOpcode::DivEAssert => self.builder.ext_div(a, b),
        };
        self.set_ext(out, value)
    }

    fn mem(&mut self, instr: &MemInstr<F>) -> Result<(), LowerError> {
        if instr.kind != MemAccessKind::Write {
            return Err(LowerError::Unsupported { index: self.index, kind: "Mem/Read" });
        }
        let addr = instr.addrs.inner.as_usize();
        let values = instr.vals.inner.0.map(|v| u64::from(v.as_canonical_u32()));
        if self.is_ext[addr] {
            let value: Ext = std::array::from_fn(|i| self.builder.constant(values[i]));
            self.set_ext(addr, value)
        } else {
            let value = self.builder.constant(values[0]);
            self.set_felt(addr, value)
        }
    }

    fn select(&mut self, instr: &SelectInstr<F>) -> Result<(), LowerError> {
        let bit = self.felt(instr.addrs.bit.as_usize())?;
        let a = self.felt(instr.addrs.in1.as_usize())?;
        let b = self.felt(instr.addrs.in2.as_usize())?;
        let (first, second) = self.builder.select(bit, a, b);
        self.set_felt(instr.addrs.out1.as_usize(), first)?;
        self.set_felt(instr.addrs.out2.as_usize(), second)
    }

    fn blake3(&mut self, instr: &Blake3CompressInstr<F>) -> Result<(), LowerError> {
        let addrs = &instr.addrs;
        let mut words = |limbs: &[zkm_recursion_core::Address<F>]| -> Result<Vec<Val>, LowerError> {
            limbs
                .chunks(2)
                .map(|pair| {
                    let low = self.felt(pair[0].as_usize())?;
                    let high = self.felt(pair[1].as_usize())?;
                    Ok(self.builder.limbs_to_word(low, high))
                })
                .collect()
        };
        let chaining_value: [Val; 8] =
            words(&addrs.chaining_value)?.try_into().expect("eight chaining words");
        let block: [Val; 16] = words(&addrs.block)?.try_into().expect("sixteen block words");
        let out = self.builder.blake3_compress(
            chaining_value,
            block,
            instr.counter.as_canonical_u32(),
            instr.block_len.as_canonical_u32(),
            instr.flags.as_canonical_u32(),
        );
        for (word, pair) in out.into_iter().zip(addrs.output.chunks(2)) {
            let position = word.plain().expect("a compression's output is a fresh word").index().position();
            let limbs = pair[0].as_usize() as u64 | ((pair[1].as_usize() as u64) << 32);
            self.builder.tape.redefine(position as usize, Op::Limbs, limbs);
            let [low, high] = self.builder.word_to_limbs(word);
            self.set_felt(pair[0].as_usize(), low)?;
            self.set_felt(pair[1].as_usize(), high)?;
        }
        Ok(())
    }

    fn felt_limbs(&mut self, instr: &FeltLimbsInstr<F>) -> Result<(), LowerError> {
        let value = self.felt(instr.addrs.input.as_usize())?;
        let [low, high] = self.builder.word_to_limbs(value);
        self.set_felt(instr.addrs.output[0].as_usize(), low)?;
        self.set_felt(instr.addrs.output[1].as_usize(), high)
    }

    /// The jagged prefix-sum chains.  With `x1` a bit, the Lagrange step
    /// `acc (1 - x1 - x2 + 2 x1 x2)` is `x1 ? acc x2 : acc - acc x2`: one
    /// extension product, one difference and a selection, with `x1`
    /// checked to be a bit.
    fn prefix_sum_checks(&mut self, instr: &PrefixSumChecksInstr<F>) -> Result<(), LowerError> {
        let addrs = &instr.addrs;
        let one = self.builder.constant(1);
        let mut acc = Builder::embed(one);
        let mut field_acc = Val::ZERO;
        for i in 0..addrs.x1.len() {
            let x1 = self.felt(addrs.x1[i].as_usize())?;
            let x1 = self.builder.bit(x1);
            let x2 = self.ext(addrs.x2[i].as_usize())?;
            let matched = self.builder.ext_mul(acc, x2);
            let missed = self.builder.ext_sub(acc, matched);
            acc = std::array::from_fn(|j| self.builder.select(x1, missed[j], matched[j]).0);
            let doubled = self.builder.add(field_acc, field_acc);
            field_acc = self.builder.add(x1, doubled);
            self.set_ext(addrs.accs[i].as_usize(), acc)?;
            self.set_felt(addrs.field_accs[i].as_usize(), field_acc)?;
        }
        Ok(())
    }

    fn commit(&mut self, instr: &CommitPublicValuesInstr<F>) -> Result<(), LowerError> {
        self.commits += 1;
        for (i, addr) in instr.pv_addrs.digest.iter().enumerate() {
            let value = self.felt(addr.as_usize())?;
            self.builder.tape.outputs.push(addr.as_usize() as u32);
            let output = self.builder.output(i, value.value);
            self.builder.assert_zero(value.terms().chain([output]));
            self.digest[i] = value.value as u32;
        }
        Ok(())
    }

    fn lower(&mut self, instruction: &Instruction<F>) -> Result<(), LowerError> {
        match instruction {
            Instruction::BaseAlu(instr) => self.base_alu(instr),
            Instruction::ExtAlu(instr) => self.ext_alu(instr),
            Instruction::Mem(instr) => self.mem(instr),
            Instruction::Select(instr) => self.select(instr),
            Instruction::Blake3Compress(instr) => self.blake3(instr),
            Instruction::FeltLimbs(instr) => self.felt_limbs(instr),
            Instruction::PrefixSumChecks(instr) => self.prefix_sum_checks(instr),
            Instruction::CommitPublicValues(instr) => self.commit(instr),
            Instruction::HintBits(HintBitsInstr { output_addrs_mults, .. }) => {
                for (addr, _) in output_addrs_mults {
                    let addr = addr.as_usize();
                    let bit = self.builder.hint_bit_at(self.memory(addr)[0], addr);
                    self.set_felt(addr, bit)?;
                }
                Ok(())
            }
            Instruction::Hint(HintInstr { output_addrs_mults }) => {
                for (addr, _) in output_addrs_mults {
                    self.hint_felt(addr.as_usize())?;
                }
                Ok(())
            }
            Instruction::HintExt2Felts(HintExt2FeltsInstr { output_addrs_mults, .. }) => {
                for (addr, _) in output_addrs_mults {
                    self.hint_felt(addr.as_usize())?;
                }
                Ok(())
            }
            Instruction::HintAddCurve(instr) => {
                let HintAddCurveInstr { output_x_addrs_mults, output_y_addrs_mults, .. } =
                    instr.as_ref();
                for (addr, _) in output_x_addrs_mults.iter().chain(output_y_addrs_mults) {
                    self.hint_felt(addr.as_usize())?;
                }
                Ok(())
            }
            Instruction::Ext2Felts(HintExt2FeltsInstr { output_addrs_mults, input_addr }) => {
                let value = self.ext(input_addr.as_usize())?;
                for (i, (addr, _)) in output_addrs_mults.iter().enumerate() {
                    self.set_felt(addr.as_usize(), value[i])?;
                }
                Ok(())
            }
            Instruction::Print(_) => Ok(()),
            Instruction::Poseidon2(_) => {
                Err(LowerError::Unsupported { index: self.index, kind: "Poseidon2" })
            }
        }
    }
}

/// Lowers `program`.  With `memory`, the runtime's memory after running
/// the program, the witness is filled and every computed value checked
/// against it; without, the witness is a placeholder and only the
/// relations are meaningful.
pub fn lower(
    program: &RecursionProgram<F>,
    memory: Option<&[Block<F>]>,
) -> Result<Lowered, LowerError> {
    let mut lowering = Lowering {
        builder: Builder::new(DIGEST_SIZE),
        slots: vec![Slot::Unset; program.total_memory],
        is_ext: ext_addresses(program),
        memory,
        index: 0,
        kind: "",
        commits: 0,
        digest: [0; DIGEST_SIZE],
        mark: 0,
    };
    let mut census: BTreeMap<&'static str, (usize, Cost)> = BTreeMap::new();
    let sizes = std::env::var_os("ZIREN_LOWER_CENSUS").is_some();
    let templates = std::env::var_os("ZIREN_LOWER_TEMPLATES");
    if templates.is_some() {
        lowering.builder.track_gadgets();
    }
    let mut shapes: BTreeMap<&'static str, Shape> = BTreeMap::new();
    for (index, instruction) in program.iter_instructions().enumerate() {
        lowering.index = index;
        lowering.kind = kind_of(instruction);
        lowering.mark = lowering.builder.witness_len();
        let before = lowering.builder.cost();
        let marks = lowering.builder.term_marks();
        lowering.builder.begin_gadget(lowering.kind);
        lowering.lower(instruction)?;
        lowering.builder.end_gadget();
        let cost = lowering.builder.cost() - before;
        if sizes {
            let (words, reads) = lowering.builder.imports(marks, lowering.mark);
            shapes.entry(lowering.kind).or_default().add(&cost, words, reads);
        }
        let entry = census.entry(lowering.kind).or_default();
        entry.0 += 1;
        entry.1 += cost;
    }
    if sizes {
        for (kind, shape) in &shapes {
            let (count, cost) = &census[kind];
            tracing::info!(
                "lower census: {kind}: {count} instances, {} words, {} and, {} mul, {} zero; words per instance {}..={}, relations per instance {}..={}; imports {} words in {} reads",
                cost.words, cost.and, cost.mul, cost.zero, shape.words.0, shape.words.1, shape.relations.0, shape.relations.1, shape.imported, shape.reads
            );
            let mut variants: Vec<_> = shape.histogram.iter().collect();
            variants.sort_by(|a, b| b.1.cmp(a.1));
            let top: Vec<String> = variants
                .iter()
                .take(8)
                .map(|((w, a, m, z), n)| format!("{n}x(w{w} a{a} m{m} z{z})"))
                .collect();
            tracing::info!("lower census: {kind} variants {}: {}", variants.len(), top.join(" "));
        }
    }
    lowering.kind = "Blake3Compress";
    let before = lowering.builder.cost();
    let (marks, mark) = (lowering.builder.term_marks(), lowering.builder.witness_len());
    lowering.builder.flush_compressions();
    census.entry(lowering.kind).or_default().1 += lowering.builder.cost() - before;
    if sizes {
        let (words, reads) = lowering.builder.imports(marks, mark);
        tracing::info!("lower census: compression flush imports {words} words in {reads} reads");
    }
    lowering.kind = "Range";
    let before = lowering.builder.cost();
    let (marks, mark) = (lowering.builder.term_marks(), lowering.builder.witness_len());
    lowering.builder.flush_ranges();
    let cost = lowering.builder.cost() - before;
    census.entry(lowering.kind).or_default().1 += cost;
    if sizes {
        let (words, reads) = lowering.builder.imports(marks, mark);
        tracing::info!(
            "lower census: range flush: {} words, {} and, {} mul, {} zero; imports {words} words in {reads} reads",
            cost.words, cost.and, cost.mul, cost.zero
        );
    }
    if lowering.commits != 1 {
        return Err(LowerError::Commits(lowering.commits));
    }
    if let Some(dump) = &templates {
        let dump = (dump != "1").then(|| std::path::Path::new(dump));
        tracing::info_span!("template census")
            .in_scope(|| {
                lowering.builder.template_census(DIGEST_SIZE, dump, false);
                lowering.builder.template_census(DIGEST_SIZE, dump, true);
            });
    }
    let (built, tape) = lowering.builder.build_with_tape()?;
    if let Some(word) = tape.ops.iter().position(|&op| op == Op::Constant as u8) {
        return Err(LowerError::Uncomputed(word));
    }
    static COMPOSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if std::env::var_os("ZIREN_LOWER_COMPOSE").is_some()
        && memory.is_some()
        && !COMPOSED.swap(true, std::sync::atomic::Ordering::Relaxed)
    {
        let flat = (built.witness.len(), built.public.len());
        tracing::info_span!("compose experiment")
            .in_scope(|| compose_experiment(program, memory, flat));
    }
    Ok(Lowered { built, digest: lowering.digest, census, tape })
}
