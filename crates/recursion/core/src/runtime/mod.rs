pub mod instruction;
mod memory;
mod opcode;
mod program;
mod record;
mod seq_block;

pub use seq_block::{BasicBlock, RawProgram, SeqBlock};

// Avoid triggering annoying branch of thiserror derive macro.
use backtrace::Backtrace as Trace;
use hashbrown::HashMap;
use instruction::HintAddCurveInstr;
pub use instruction::{Instruction, SumcheckVerifyInstr};
use instruction::{FieldEltType, HintBitsInstr, HintExt2FeltsInstr, HintInstr, PrintInstr};
use itertools::Itertools;
use machine::RecursionAirEventCount;
use memory::*;
pub use opcode::*;
pub use program::*;
pub use record::*;

use std::{
    array,
    borrow::Borrow,
    collections::VecDeque,
    fmt::Debug,
    io::{stdout, Write},
    iter::zip,
    marker::PhantomData,
    sync::Arc,
};

use p3_field::{ExtensionField, PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::Poseidon2ExternalLayerKoalaBear;
use p3_poseidon2::Poseidon2;
use p3_symmetric::{CryptographicPermutation, Permutation};
use p3_util::reverse_bits_len;
use thiserror::Error;

use zkm_stark::septic_curve::SepticCurve;
use zkm_stark::septic_extension::SepticExtension;

use crate::air::{Block, RECURSIVE_PROOF_NUM_PV_ELTS};

/// TODO expand glob import once things are organized enough
use crate::*;

pub const STACK_SIZE: usize = 1 << 24;
pub const MEMORY_SIZE: usize = 1 << 28;

/// The heap pointer address.
pub const HEAP_PTR: i32 = -4;
pub const HEAP_START_ADDRESS: usize = STACK_SIZE + 4;

/// The width of the Poseidon2 permutation.
pub const PERMUTATION_WIDTH: usize = 16;
pub const POSEIDON2_SBOX_DEGREE: u64 = 3;
pub const HASH_RATE: usize = 8;

/// The current verifier implementation assumes that we are using a 256-bit hash with 32-bit
/// elements.
pub const DIGEST_SIZE: usize = 8;

pub const NUM_BITS: usize = 31;

pub const D: usize = 4;

#[derive(Debug, Clone, Default)]
pub struct CycleTrackerEntry {
    pub span_entered: bool,
    pub span_enter_cycle: usize,
    pub cumulative_cycles: usize,
}

/// TODO fully document.
/// Taken from [`zkm_recursion_core::runtime::Runtime`].
/// Many missing things (compared to the old `Runtime`) will need to be implemented.
pub struct Runtime<'a, F: PrimeField32, EF: ExtensionField<F>, Diffusion> {
    pub timestamp: usize,

    pub nb_poseidons: usize,

    pub nb_wide_poseidons: usize,

    pub nb_bit_decompositions: usize,

    pub nb_ext_ops: usize,

    pub nb_base_ops: usize,

    pub nb_memory_ops: usize,

    pub nb_branch_ops: usize,

    pub nb_select: usize,

    pub nb_exp_reverse_bits: usize,

    pub nb_fri_fold: usize,

    pub nb_batch_fri: usize,

    pub nb_print_f: usize,

    pub nb_print_e: usize,

    /// The current clock.
    pub clk: F,

    /// The program counter.
    pub pc: F,

    /// The program.
    pub program: Arc<RecursionProgram<F>>,

    /// Memory. From canonical usize of an Address to a MemoryEntry.
    pub memory: MemVecMap<F>,

    /// The execution record.
    pub record: ExecutionRecord<F>,

    pub witness_stream: VecDeque<Block<F>>,

    pub cycle_tracker: HashMap<String, CycleTrackerEntry>,

    /// The stream that print statements write to.
    pub debug_stdout: Box<dyn Write + 'a>,

    /// Entries for dealing with the Poseidon2 hash state.
    perm: Option<
        Poseidon2<
            F::Packing,
            Poseidon2ExternalLayerKoalaBear<16>,
            Diffusion,
            PERMUTATION_WIDTH,
            POSEIDON2_SBOX_DEGREE,
        >,
    >,

    _marker_ef: PhantomData<EF>,

    _marker_diffusion: PhantomData<Diffusion>,
}

#[derive(Error, Debug)]
pub enum RuntimeError<F: Debug, EF: Debug> {
    #[error(
        "attempted to perform base field division {in1:?}/{in2:?} \
        from instruction {instr:?} at pc {pc:?}\nnearest pc with backtrace:\n{trace:?}"
    )]
    DivFOutOfDomain {
        in1: F,
        in2: F,
        instr: BaseAluInstr<F>,
        pc: usize,
        trace: Option<(usize, Trace)>,
    },
    #[error(
        "attempted to perform extension field division {in1:?}/{in2:?} \
        from instruction {instr:?} at pc {pc:?}\nnearest pc with backtrace:\n{trace:?}"
    )]
    DivEOutOfDomain {
        in1: EF,
        in2: EF,
        instr: ExtAluInstr<F>,
        pc: usize,
        trace: Option<(usize, Trace)>,
    },
    #[error("failed to print to `debug_stdout`: {0}")]
    DebugPrint(#[from] std::io::Error),
    #[error("attempted to read from empty witness stream")]
    EmptyWitnessStream,
}

impl<F: PrimeField32, EF: ExtensionField<F>, Diffusion> Runtime<'_, F, EF, Diffusion>
where
    Poseidon2<
        F::Packing,
        Poseidon2ExternalLayerKoalaBear<16>,
        Diffusion,
        PERMUTATION_WIDTH,
        POSEIDON2_SBOX_DEGREE,
    >: CryptographicPermutation<[F; PERMUTATION_WIDTH]>,
{
    pub fn new(
        program: Arc<RecursionProgram<F>>,
        perm: Poseidon2<
            F::Packing,
            Poseidon2ExternalLayerKoalaBear<16>,
            Diffusion,
            PERMUTATION_WIDTH,
            POSEIDON2_SBOX_DEGREE,
        >,
    ) -> Self {
        let record = ExecutionRecord::<F> { program: program.clone(), ..Default::default() };
        let memory = Memory::with_capacity(program.total_memory);
        Self {
            timestamp: 0,
            nb_poseidons: 0,
            nb_wide_poseidons: 0,
            nb_bit_decompositions: 0,
            nb_select: 0,
            nb_exp_reverse_bits: 0,
            nb_ext_ops: 0,
            nb_base_ops: 0,
            nb_memory_ops: 0,
            nb_branch_ops: 0,
            nb_fri_fold: 0,
            nb_batch_fri: 0,
            nb_print_f: 0,
            nb_print_e: 0,
            clk: F::ZERO,
            program,
            pc: F::ZERO,
            memory,
            record,
            witness_stream: VecDeque::new(),
            cycle_tracker: HashMap::new(),
            debug_stdout: Box::new(stdout()),
            perm: Some(perm),
            _marker_ef: PhantomData,
            _marker_diffusion: PhantomData,
        }
    }

    pub fn print_stats(&self) {
        tracing::debug!("Total Cycles: {}", self.timestamp);
        tracing::debug!("Poseidon Skinny Operations: {}", self.nb_poseidons);
        tracing::debug!("Poseidon Wide Operations: {}", self.nb_wide_poseidons);
        tracing::debug!("Exp Reverse Bits Operations: {}", self.nb_exp_reverse_bits);
        tracing::debug!("FriFold Operations: {}", self.nb_fri_fold);
        tracing::debug!("Field Operations: {}", self.nb_base_ops);
        tracing::debug!("Select Operations: {}", self.nb_select);
        tracing::debug!("Extension Operations: {}", self.nb_ext_ops);
        tracing::debug!("BatchFRI Operations: {}", self.nb_batch_fri);
        tracing::debug!("Memory Operations: {}", self.nb_memory_ops);
        tracing::debug!("Branch Operations: {}", self.nb_branch_ops);
        for (name, entry) in self.cycle_tracker.iter().sorted_by_key(|(name, _)| *name) {
            tracing::debug!("> {}: {}", name, entry.cumulative_cycles);
        }
    }

    fn nearest_pc_backtrace(&mut self) -> Option<(usize, Trace)> {
        let trap_pc = self.pc.as_canonical_u32() as usize;
        let trace = self.program.traces.get(trap_pc).cloned()?;
        if let Some(mut trace) = trace {
            trace.resolve();
            Some((trap_pc, trace))
        } else {
            (0..trap_pc)
                .rev()
                .filter_map(|nearby_pc| {
                    let mut trace = self.program.traces.get(nearby_pc)?.clone()?;
                    trace.resolve();
                    Some((nearby_pc, trace))
                })
                .next()
        }
    }

    /// Compare to [zkm_recursion_core::runtime::Runtime::run].
    pub fn run(&mut self) -> Result<(), RuntimeError<F, EF>> {
        let early_exit_ts = std::env::var("RECURSION_EARLY_EXIT_TS")
            .map_or(usize::MAX, |ts: String| ts.parse().unwrap());
        // `ZIREN_DUMP_PROGRAM=<path>` dumps the instruction list to
        // `<path>` at runtime entry — used to map PCs surfaced by
        // `ZIREN_DEBUG_READ_SHAPES` to their concrete instructions
        // for debugging.  Each shard's run() rewrites the same path,
        // so set the env var in a shard-isolated test (e.g. Test::Compress
        // for compress shard, Test::All to capture wrap shard last).
        if let Ok(path) = std::env::var("ZIREN_DUMP_PROGRAM") {
            use std::io::Write as _;
            if let Ok(mut f) = std::fs::File::create(&path) {
                for (pc, instr) in self.program.iter_instructions().enumerate() {
                    let _ = writeln!(f, "{:5} {}", pc, instr_short(instr));
                }
            }
        }
        self.preallocate_record();
        // Phase A4 (#259): walk seq_blocks via iter_instructions() instead
        // of indexing the flat instructions Vec by PC. PC is incremented
        // sequentially per instruction so that backtrace lookups
        // (`nearest_pc_backtrace`) and pc-as-value debug logging continue
        // to work unchanged. seq_blocks contains the same instruction
        // sequence in the same order today (single Basic block) so this
        // is zero behavior change. Foundation for Phase B+C parallel
        // runtime.
        // SP1 ref: `/tmp/sp1/crates/recursion/executor/src/runtime/mod.rs`
        // (the Runtime::run loop iterates the RawProgram).
        // Snapshot an Arc-clone of the program so the iterator borrow
        // doesn't conflict with the &mut self field accesses inside the
        // loop body. Arc::clone is just a refcount bump, not a deep
        // copy.
        let program = self.program.clone();
        for instr in program.iter_instructions() {
            let next_clk = self.clk + F::from_u32(4);
            let next_pc = self.pc + F::ONE;
            let instruction = instr.clone();
            match instruction {
                Instruction::BaseAlu(instr @ BaseAluInstr { opcode, mult, addrs }) => {
                    self.nb_base_ops += 1;
                    // `ZIREN_DEBUG_READ_SHAPES=1`: log when BaseAlu reads an
                    // address that holds an Ext-shaped Block (non-zero v1/v2/v3).
                    // Those reads cause the wrap cumsum mismatch.
                    let debug_shapes = std::env::var("ZIREN_DEBUG_READ_SHAPES").is_ok();
                    if debug_shapes {
                        let pc = self.pc.as_canonical_u32();
                        let e1 = self.memory.mr(addrs.in1).val;
                        if !e1.0[1].is_zero() || !e1.0[2].is_zero() || !e1.0[3].is_zero() {
                            eprintln!(
                                "[read shape] pc={} chip=BaseAlu op={:?} addr={} out_addr={} ext=true",
                                pc, opcode, addrs.in1.as_usize(), addrs.out.as_usize()
                            );
                        }
                        let e2 = self.memory.mr(addrs.in2).val;
                        if !e2.0[1].is_zero() || !e2.0[2].is_zero() || !e2.0[3].is_zero() {
                            eprintln!(
                                "[read shape] pc={} chip=BaseAlu op={:?} addr={} out_addr={} ext=true",
                                pc, opcode, addrs.in2.as_usize(), addrs.out.as_usize()
                            );
                        }
                    }
                    let in1 = self.memory.mr(addrs.in1).val[0];
                    let in2 = self.memory.mr(addrs.in2).val[0];
                    let out = match opcode {
                        BaseAluOpcode::AddF => in1 + in2,
                        BaseAluOpcode::SubF => in1 - in2,
                        BaseAluOpcode::MulF => in1 * in2,
                        BaseAluOpcode::DivF | BaseAluOpcode::DivFAssert => match in2.try_inverse().map(|x| x * in1) {
                            Some(x) => x,
                            None => {
                                if in1.is_zero() {
                                    PrimeCharacteristicRing::ONE
                                } else if mult.is_zero() && !opcode.is_div_assert() {
                                    // Dead regular DivF (mult=0): result never read; safe to skip.
                                    // DivFAssert ALWAYS errors out on out-of-domain since it
                                    // represents a soundness check that must trip.
                                    F::ZERO
                                } else {
                                    return Err(RuntimeError::DivFOutOfDomain {
                                        in1,
                                        in2,
                                        instr,
                                        pc: self.pc.as_canonical_u32() as usize,
                                        trace: self.nearest_pc_backtrace(),
                                    });
                                }
                            }
                        },
                    };
                    self.memory.mw(addrs.out, Block::from(out), mult);
                    self.record.base_alu_events.push(BaseAluEvent { out, in1, in2 });
                }
                Instruction::ExtAlu(instr @ ExtAluInstr { opcode, mult, addrs }) => {
                    self.nb_ext_ops += 1;
                    let in1 = self.memory.mr(addrs.in1).val;
                    let in2 = self.memory.mr(addrs.in2).val;
                    let in1_ef = EF::from_basis_coefficients_slice(&in1.0).unwrap();
                    let in2_ef = EF::from_basis_coefficients_slice(&in2.0).unwrap();
                    let out_ef = match opcode {
                        ExtAluOpcode::AddE => in1_ef + in2_ef,
                        ExtAluOpcode::SubE => in1_ef - in2_ef,
                        ExtAluOpcode::MulE => in1_ef * in2_ef,
                        ExtAluOpcode::DivE | ExtAluOpcode::DivEAssert => match in2_ef.try_inverse().map(|x| x * in1_ef) {
                            Some(x) => x,
                            None => {
                                if in1_ef.is_zero() {
                                    PrimeCharacteristicRing::ONE
                                } else if mult.is_zero() && !opcode.is_div_assert() {
                                    EF::ZERO
                                } else {
                                    return Err(RuntimeError::DivEOutOfDomain {
                                        in1: in1_ef,
                                        in2: in2_ef,
                                        instr,
                                        pc: self.pc.as_canonical_u32() as usize,
                                        trace: self.nearest_pc_backtrace(),
                                    });
                                }
                            }
                        },
                    };
                    let out = Block::from(out_ef.as_basis_coefficients_slice());
                    self.memory.mw(addrs.out, out, mult);
                    self.record.ext_alu_events.push(ExtAluEvent { out, in1, in2 });
                }
                Instruction::Mem(MemInstr {
                    addrs: MemIo { inner: addr },
                    vals: MemIo { inner: val },
                    mult,
                    kind,
                }) => {
                    self.nb_memory_ops += 1;
                    match kind {
                        MemAccessKind::Read => {
                            let mem_entry = self.memory.mr(addr);
                            assert_eq!(
                                mem_entry.val, val,
                                "stored memory value should be the specified value"
                            );
                        }
                        MemAccessKind::Write => drop(self.memory.mw(addr, val, mult)),
                    }
                    self.record.mem_const_count += 1;
                }
                Instruction::Poseidon2(instr) => {
                    let Poseidon2Instr { addrs: Poseidon2Io { input, output }, mults } = *instr;
                    self.nb_poseidons += 1;
                    // `ZIREN_DEBUG_READ_SHAPES=1`: log Poseidon2 inputs at
                    // Ext-shaped addresses.
                    if std::env::var("ZIREN_DEBUG_READ_SHAPES").is_ok() {
                        let pc = self.pc.as_canonical_u32();
                        for (i, &addr) in input.iter().enumerate() {
                            let e = self.memory.mr(addr).val;
                            if !e.0[1].is_zero() || !e.0[2].is_zero() || !e.0[3].is_zero() {
                                eprintln!(
                                    "[read shape] pc={} chip=Poseidon2 slot={} addr={} ext=true",
                                    pc, i, addr.as_usize()
                                );
                            }
                        }
                    }
                    let in_vals = std::array::from_fn(|i| self.memory.mr(input[i]).val[0]);
                    let perm_output = self.perm.as_ref().unwrap().permute(in_vals);

                    perm_output.iter().zip(output).zip(mults).for_each(|((&val, addr), mult)| {
                        self.memory.mw(addr, Block::from(val), mult);
                    });
                    self.record
                        .poseidon2_events
                        .push(Poseidon2Event { input: in_vals, output: perm_output });
                }
                Instruction::Select(SelectInstr {
                    addrs: SelectIo { bit, out1, out2, in1, in2 },
                    mult1,
                    mult2,
                }) => {
                    self.nb_select += 1;
                    let bit = self.memory.mr(bit).val[0];
                    let in1 = self.memory.mr(in1).val[0];
                    let in2 = self.memory.mr(in2).val[0];
                    let out1_val = bit * in2 + (F::ONE - bit) * in1;
                    let out2_val = bit * in1 + (F::ONE - bit) * in2;
                    self.memory.mw(out1, Block::from(out1_val), mult1);
                    self.memory.mw(out2, Block::from(out2_val), mult2);
                    self.record.select_events.push(SelectEvent {
                        bit,
                        out1: out1_val,
                        out2: out2_val,
                        in1,
                        in2,
                    })
                }
                Instruction::ExpReverseBitsLen(ExpReverseBitsInstr {
                    addrs: ExpReverseBitsIo { base, exp, result },
                    mult,
                }) => {
                    self.nb_exp_reverse_bits += 1;
                    let base_val = self.memory.mr(base).val[0];
                    let exp_bits: Vec<_> =
                        exp.iter().map(|bit| self.memory.mr(*bit).val[0]).collect();
                    let exp_val = exp_bits
                        .iter()
                        .enumerate()
                        .fold(0, |acc, (i, &val)| acc + val.as_canonical_u32() * (1 << i));
                    let out =
                        base_val.exp_u64(reverse_bits_len(exp_val as usize, exp_bits.len()) as u64);
                    self.memory.mw(result, Block::from(out), mult);
                    self.record.exp_reverse_bits_len_events.push(ExpReverseBitsEvent {
                        result: out,
                        base: base_val,
                        exp: exp_bits,
                    });
                }
                Instruction::HintBits(HintBitsInstr { output_addrs_mults, input_addr }) => {
                    self.nb_bit_decompositions += 1;
                    let num = self.memory.mr(input_addr).val[0].as_canonical_u32();
                    // Decompose the num into LE bits.
                    let bits = (0..output_addrs_mults.len())
                        .map(|i| Block::from(F::from_u32((num >> i) & 1)))
                        .collect::<Vec<_>>();
                    // Write the bits to the array at dst.
                    for (bit, (addr, mult)) in bits.into_iter().zip(output_addrs_mults) {
                        self.memory.mw(addr, bit, mult);
                        self.record.mem_var_events.push(MemEvent { inner: bit });
                    }
                }
                Instruction::HintAddCurve(HintAddCurveInstr {
                    output_x_addrs_mults,
                    output_y_addrs_mults,
                    input1_x_addrs,
                    input1_y_addrs,
                    input2_x_addrs,
                    input2_y_addrs,
                }) => {
                    let input1_x = SepticExtension::<F>::from_base_fn(|i| {
                        self.memory.mr(input1_x_addrs[i]).val[0]
                    });
                    let input1_y = SepticExtension::<F>::from_base_fn(|i| {
                        self.memory.mr(input1_y_addrs[i]).val[0]
                    });
                    let input2_x = SepticExtension::<F>::from_base_fn(|i| {
                        self.memory.mr(input2_x_addrs[i]).val[0]
                    });
                    let input2_y = SepticExtension::<F>::from_base_fn(|i| {
                        self.memory.mr(input2_y_addrs[i]).val[0]
                    });
                    let point1 = SepticCurve { x: input1_x, y: input1_y };
                    let point2 = SepticCurve { x: input2_x, y: input2_y };
                    let output = point1.add_incomplete(point2);

                    for (val, (addr, mult)) in
                        output.x.0.into_iter().zip(output_x_addrs_mults.into_iter())
                    {
                        self.memory.mw(addr, Block::from(val), mult);
                        self.record.mem_var_events.push(MemEvent { inner: Block::from(val) });
                    }
                    for (val, (addr, mult)) in
                        output.y.0.into_iter().zip(output_y_addrs_mults.into_iter())
                    {
                        self.memory.mw(addr, Block::from(val), mult);
                        self.record.mem_var_events.push(MemEvent { inner: Block::from(val) });
                    }
                }

                Instruction::FriFold(instr) => {
                    let FriFoldInstr {
                        base_single_addrs,
                        ext_single_addrs,
                        ext_vec_addrs,
                        alpha_pow_mults,
                        ro_mults,
                    } = *instr;
                    self.nb_fri_fold += 1;
                    let x = self.memory.mr(base_single_addrs.x).val[0];
                    let z = self.memory.mr(ext_single_addrs.z).val;
                    let z: EF = z.ext();
                    let alpha = self.memory.mr(ext_single_addrs.alpha).val;
                    let alpha: EF = alpha.ext();
                    let mat_opening = ext_vec_addrs
                        .mat_opening
                        .iter()
                        .map(|addr| self.memory.mr(*addr).val)
                        .collect_vec();
                    let ps_at_z = ext_vec_addrs
                        .ps_at_z
                        .iter()
                        .map(|addr| self.memory.mr(*addr).val)
                        .collect_vec();

                    for m in 0..ps_at_z.len() {
                        // let m = F::from_u32(m);
                        // Get the opening values.
                        let p_at_x = mat_opening[m];
                        let p_at_x: EF = p_at_x.ext();
                        let p_at_z = ps_at_z[m];
                        let p_at_z: EF = p_at_z.ext();

                        // Calculate the quotient and update the values
                        let quotient = (-p_at_z + p_at_x) / (-z + x);

                        // First we peek to get the current value.
                        let alpha_pow: EF =
                            self.memory.mr(ext_vec_addrs.alpha_pow_input[m]).val.ext();

                        let ro: EF = self.memory.mr(ext_vec_addrs.ro_input[m]).val.ext();

                        let new_ro = ro + alpha_pow * quotient;
                        let new_alpha_pow = alpha_pow * alpha;

                        let _ = self.memory.mw(
                            ext_vec_addrs.ro_output[m],
                            Block::from(new_ro.as_basis_coefficients_slice()),
                            ro_mults[m],
                        );

                        let _ = self.memory.mw(
                            ext_vec_addrs.alpha_pow_output[m],
                            Block::from(new_alpha_pow.as_basis_coefficients_slice()),
                            alpha_pow_mults[m],
                        );

                        self.record.fri_fold_events.push(FriFoldEvent {
                            base_single: FriFoldBaseIo { x },
                            ext_single: FriFoldExtSingleIo {
                                z: Block::from(z.as_basis_coefficients_slice()),
                                alpha: Block::from(alpha.as_basis_coefficients_slice()),
                            },
                            ext_vec: FriFoldExtVecIo {
                                mat_opening: Block::from(p_at_x.as_basis_coefficients_slice()),
                                ps_at_z: Block::from(p_at_z.as_basis_coefficients_slice()),
                                alpha_pow_input: Block::from(alpha_pow.as_basis_coefficients_slice()),
                                ro_input: Block::from(ro.as_basis_coefficients_slice()),
                                alpha_pow_output: Block::from(new_alpha_pow.as_basis_coefficients_slice()),
                                ro_output: Block::from(new_ro.as_basis_coefficients_slice()),
                            },
                        });
                    }
                }
                Instruction::BatchFRI(instr) => {
                    let BatchFRIInstr { base_vec_addrs, ext_single_addrs, ext_vec_addrs, acc_mult } =
                        *instr;

                    let mut acc = EF::ZERO;
                    let p_at_xs = base_vec_addrs
                        .p_at_x
                        .iter()
                        .map(|addr| self.memory.mr(*addr).val[0])
                        .collect_vec();
                    let p_at_zs = ext_vec_addrs
                        .p_at_z
                        .iter()
                        .map(|addr| self.memory.mr(*addr).val.ext::<EF>())
                        .collect_vec();
                    let alpha_pows: Vec<_> = ext_vec_addrs
                        .alpha_pow
                        .iter()
                        .map(|addr| self.memory.mr(*addr).val.ext::<EF>())
                        .collect_vec();

                    self.nb_batch_fri += p_at_zs.len();
                    for m in 0..p_at_zs.len() {
                        acc += alpha_pows[m] * (p_at_zs[m] - EF::from(p_at_xs[m]));
                        self.record.batch_fri_events.push(BatchFRIEvent {
                            base_vec: BatchFRIBaseVecIo { p_at_x: p_at_xs[m] },
                            ext_single: BatchFRIExtSingleIo {
                                acc: Block::from(acc.as_basis_coefficients_slice()),
                            },
                            ext_vec: BatchFRIExtVecIo {
                                p_at_z: Block::from(p_at_zs[m].as_basis_coefficients_slice()),
                                alpha_pow: Block::from(alpha_pows[m].as_basis_coefficients_slice()),
                            },
                        });
                    }

                    let _ = self.memory.mw(
                        ext_single_addrs.acc,
                        Block::from(acc.as_basis_coefficients_slice()),
                        acc_mult,
                    );
                }
                Instruction::CommitPublicValues(instr) => {
                    let pv_addrs = instr.pv_addrs.as_array();
                    let pv_values: [F; RECURSIVE_PROOF_NUM_PV_ELTS] =
                        array::from_fn(|i| self.memory.mr(pv_addrs[i]).val[0]);
                    self.record.public_values = *pv_values.as_slice().borrow();
                    self.record
                        .commit_pv_hash_events
                        .push(CommitPublicValuesEvent { public_values: self.record.public_values });
                }

                Instruction::Print(PrintInstr { field_elt_type, addr }) => match field_elt_type {
                    FieldEltType::Base => {
                        self.nb_print_f += 1;
                        let f = self.memory.mr(addr).val[0];
                        writeln!(self.debug_stdout, "PRINTF={f}")
                    }
                    FieldEltType::Extension => {
                        self.nb_print_e += 1;
                        let ef = self.memory.mr(addr).val;
                        writeln!(self.debug_stdout, "PRINTEF={ef:?}")
                    }
                }
                .map_err(RuntimeError::DebugPrint)?,
                Instruction::HintExt2Felts(HintExt2FeltsInstr {
                    output_addrs_mults,
                    input_addr,
                }) => {
                    self.nb_bit_decompositions += 1;
                    let fs = self.memory.mr(input_addr).val;
                    // Write the bits to the array at dst.
                    for (f, (addr, mult)) in fs.into_iter().zip(output_addrs_mults) {
                        let felt = Block::from(f);
                        self.memory.mw(addr, felt, mult);
                        self.record.mem_var_events.push(MemEvent { inner: felt });
                    }
                }
                Instruction::Hint(HintInstr { output_addrs_mults }) => {
                    // Check that enough Blocks can be read, so `drain` does not panic.
                    if self.witness_stream.len() < output_addrs_mults.len() {
                        return Err(RuntimeError::EmptyWitnessStream);
                    }
                    let witness = self.witness_stream.drain(0..output_addrs_mults.len());
                    let debug_hint = std::env::var("ZIREN_DEBUG_HINT_BLOCKS").is_ok();
                    for ((addr, mult), val) in zip(output_addrs_mults, witness) {
                        if debug_hint {
                            // Print addresses whose written Block has non-zero
                            // v1/v2/v3 — these are Ext values whose later
                            // Felt-typed reads would logup-mismatch.
                            let is_ext_shape = !val.0[1].is_zero()
                                || !val.0[2].is_zero()
                                || !val.0[3].is_zero();
                            if is_ext_shape {
                                eprintln!(
                                    "[hint block] addr={} ext=true val=({:?}, {:?}, {:?}, {:?}) mult={:?}",
                                    addr.as_usize(), val.0[0], val.0[1], val.0[2], val.0[3], mult
                                );
                            }
                        }
                        // Inline [`Self::mw`] to mutably borrow multiple fields of `self`.
                        self.memory.mw(addr, val, mult);
                        self.record.mem_var_events.push(MemEvent { inner: val });
                    }
                }
                Instruction::SumcheckVerify(instr) => {
                    // Read inputs from memory.
                    let challenge = self.memory.mr(instr.challenge_addr).val;
                    let claimed_sum = self.memory.mr(instr.claimed_sum_addr).val;
                    let c0 = self.memory.mr(instr.c0_addr).val;
                    let c1 = self.memory.mr(instr.c1_addr).val;
                    let c2 = self.memory.mr(instr.c2_addr).val;

                    // The actual verification (p(0)+p(1)=s, new_claim=p(r))
                    // is done by the SumcheckVerifyChip's AIR constraints.
                    // The runtime only needs to read/write memory and
                    // emit the event for trace generation.

                    // Compute new_claim = c_0 + c_1*r + c_2*r^2 and write.
                    // For the runtime, we read the hint from the witness stream.
                    if self.witness_stream.is_empty() {
                        return Err(RuntimeError::EmptyWitnessStream);
                    }
                    let new_claim = self.witness_stream.drain(0..1).next().unwrap();
                    self.memory.mw(instr.new_claim_addr, new_claim, instr.new_claim_mult);
                    self.record.mem_var_events.push(MemEvent { inner: new_claim });

                    // Emit the SumcheckVerifyEvent so the
                    // SumcheckVerifyChip can materialise this row in
                    // its trace.  The chip's AIR re-checks the
                    // sumcheck identities against this data.
                    self.record.sumcheck_verify_events.push(SumcheckVerifyEvent {
                        claimed_sum,
                        coeffs: [c0, c1, c2],
                        challenge,
                        new_claim,
                    });
                }
            }

            self.pc = next_pc;
            self.clk = next_clk;
            self.timestamp += 1;

            if self.timestamp >= early_exit_ts {
                break;
            }
        }
        Ok(())
    }

    pub fn preallocate_record(&mut self) {
        let event_counts = self
            .program
            .iter_instructions()
            .fold(RecursionAirEventCount::default(), |heights, instruction| heights + instruction);
        self.record.poseidon2_events.reserve(event_counts.poseidon2_wide_events);
        self.record.mem_var_events.reserve(event_counts.mem_var_events);
        self.record.base_alu_events.reserve(event_counts.base_alu_events);
        self.record.ext_alu_events.reserve(event_counts.ext_alu_events);
        self.record.exp_reverse_bits_len_events.reserve(event_counts.exp_reverse_bits_len_events);
        self.record.select_events.reserve(event_counts.select_events);
    }
}

/// Short textual form of an instruction for the `ZIREN_DUMP_PROGRAM`
/// debug dump — just uses Rust's Debug on the variant, which is enough
/// to grep for addresses.
fn instr_short<F: std::fmt::Debug>(instr: &Instruction<F>) -> String {
    format!("{:?}", instr)
}
