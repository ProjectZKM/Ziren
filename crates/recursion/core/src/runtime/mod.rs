mod analyzed;
pub mod instruction;
mod memory;
mod opcode;
mod program;
mod record;
mod seq_block;

pub use analyzed::AnalyzedInstruction;
pub use seq_block::{BasicBlock, RawProgram, SeqBlock};

// Avoid triggering annoying branch of thiserror derive macro.
use backtrace::Backtrace as Trace;
use hashbrown::HashMap;
use instruction::HintAddCurveInstr;
pub use instruction::Instruction;
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
    cell::UnsafeCell,
    collections::VecDeque,
    fmt::Debug,
    io::{stdout, Write},
    iter::zip,
    marker::PhantomData,
    mem::MaybeUninit,
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

/// #259 C-2d step 2 foundation: per-walker mutable state. Each parallel
/// sub-walker allocates its own `WalkerState` on the stack so the walker
/// can take `&self` and dispatch `SeqBlock::Parallel` sub-walks via
/// rayon `par_iter` without aliasing on shared mutable fields.
///
/// pc/clk in sub-walkers are best-effort (used only by trap-error
/// reporting); only the root walker's pc/clk feed back to `Runtime`
/// after `execute_blocks` returns. The `nb_*` counters are summed back
/// at sub-walker join (single-threaded after `try_for_each` returns).
///
/// SP1 ref: `/tmp/sp1/crates/recursion/executor/src/lib.rs:856` (ExecState).
#[derive(Debug, Clone, Default)]
pub struct WalkerState<F: Default + Copy> {
    pub pc: F,
    pub clk: F,
    pub timestamp: usize,
    pub nb_poseidons: usize,
    pub nb_wide_poseidons: usize,
    pub nb_bit_decompositions: usize,
    pub nb_select: usize,
    pub nb_exp_reverse_bits: usize,
    pub nb_ext_ops: usize,
    pub nb_base_ops: usize,
    pub nb_memory_ops: usize,
    pub nb_branch_ops: usize,
    pub nb_fri_fold: usize,
    pub nb_batch_fri: usize,
    pub nb_print_f: usize,
    pub nb_print_e: usize,
}

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

    /// Memory. Parallel-safe cell-per-address layer (#259 Phase C 2d
    /// foundation). The `&mut self` walker still drives mr/mw via the
    /// safe variants; once the SeqBlock::Parallel walker arm is ported
    /// to par_iter, the `&self` `mr_unchecked`/`mw_unchecked` can be
    /// used directly for race-free disjoint-address writes.
    /// SP1 ref: `/tmp/sp1/crates/recursion/executor/src/lib.rs:380`.
    pub memory: ParMemVec<F>,

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

// SAFETY: #259 C-2d step 2 walker dispatches `SeqBlock::Parallel`
// sub-walks via `&Runtime` shared across rayon worker threads. The
// walker only touches Sync fields (memory: ParMemVec has unsafe
// Sync impl, perm: Option<Poseidon2> shared read-only, program: Arc).
// Non-Sync fields (debug_stdout: Box<dyn Write>, witness_stream,
// cycle_tracker) are explicitly taken out of `self` via mem::replace
// at the start of `run()` and threaded through as `&mut` through
// the recursive walker — sub-walks always pass `None` for these
// (verified by `hint_in_par`/Print absence in parallel sub-programs).
unsafe impl<'a, F, EF, Diffusion> Sync for Runtime<'a, F, EF, Diffusion>
where
    F: PrimeField32 + Sync,
    EF: ExtensionField<F> + Sync,
{
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

impl<'a, F: PrimeField32, EF: ExtensionField<F>, Diffusion> Runtime<'a, F, EF, Diffusion>
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
        let memory = ParMemVec::with_capacity(program.total_memory);
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

    fn nearest_pc_backtrace(&self) -> Option<(usize, Trace)> {
        let trap_pc = self.pc.as_canonical_u32() as usize;
        self.nearest_pc_backtrace_at(trap_pc)
    }

    /// #259 C-2d step 2: `&self` memory-read helper that wraps the
    /// `unsafe { mr_unchecked }` discipline. Soundness comes from
    /// the IR-level `SeqBlock::Parallel` disjoint-address invariant
    /// (each parallel sub-program writes to a non-overlapping address
    /// range — the analyze pass relies on it; the runtime walker
    /// inherits it via `&self.memory.mr_unchecked`).
    #[inline(always)]
    fn mr_us(&self, addr: Address<F>) -> &MemoryEntry<F> {
        unsafe { self.memory.mr_unchecked(addr) }
    }

    /// `&self` memory-write helper. Same soundness contract as `mr_us`.
    #[inline(always)]
    fn mw_us(&self, addr: Address<F>, val: Block<F>, mult: F) {
        unsafe { self.memory.mw_unchecked(addr, val, mult) }
    }

    /// #259 C-2d step 2 record-write helper. Wraps the SP1 raw_get
    /// idiom so the type parameter `T` is inferred from the slot.
    /// Soundness: caller must ensure the slot is written exactly once
    /// across all threads — guaranteed by analyze pass + IR-level
    /// `SeqBlock::Parallel` disjoint-offset invariant.
    #[inline(always)]
    unsafe fn raw_write_ev<T>(slot: &MaybeUninit<UnsafeCell<T>>, ev: T) {
        unsafe { UnsafeCell::raw_get(slot.as_ptr() as *const UnsafeCell<T>).write(ev) }
    }

    /// #259 C-2d step 2 variant: takes `trap_pc` explicitly so it can
    /// be called from `execute_one` (which holds pc in `WalkerState`,
    /// not `Runtime`).
    fn nearest_pc_backtrace_at(&self, trap_pc: usize) -> Option<(usize, Trace)> {
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
        // #259 step 2 sizing: print parallelism opportunity per Runtime::run
        // when ZIREN_DUMP_PARALLELISM is set. Validates whether C-2d step 2
        // (par_iter walker dispatch) would actually pay off on this workload.
        if std::env::var("ZIREN_DUMP_PARALLELISM").is_ok() {
            let (n_par, n_subs, n_par_instrs) = self.program.seq_blocks.parallelism_summary();
            let total = self.program.instruction_count();
            let pct = if total > 0 { 100.0 * n_par_instrs as f64 / total as f64 } else { 0.0 };
            // Count witness consumers (Hint) inside parallel sub-programs
            // to determine whether par_iter dispatch is sound without
            // witness-slicing. A non-zero count means par_iter would race
            // on the shared witness stream.
            let mut hint_in_par: usize = 0;
            fn walk_par<F>(
                block: &SeqBlock<Instruction<F>>,
                hint: &mut usize,
                inside: bool,
            ) {
                match block {
                    SeqBlock::Basic(b) => {
                        if inside {
                            for instr in &b.instrs {
                                if let Instruction::Hint(h) = instr {
                                    *hint += h.output_addrs_mults.len();
                                }
                            }
                        }
                    }
                    SeqBlock::Parallel(subs) => {
                        for sub in subs {
                            for sb in &sub.seq_blocks {
                                walk_par(sb, hint, true);
                            }
                        }
                    }
                }
            }
            for b in &self.program.seq_blocks.seq_blocks {
                walk_par(b, &mut hint_in_par, false);
            }
            eprintln!(
                "[par-summary] parallel_blocks={} total_sub_programs={} parallel_instrs={}/{} ({:.1}%) hint_in_par={}",
                n_par, n_subs, n_par_instrs, total, pct, hint_in_par
            );
        }
        if let Ok(path) = std::env::var("ZIREN_DUMP_PROGRAM") {
            use std::io::Write as _;
            if let Ok(mut f) = std::fs::File::create(&path) {
                for (pc, instr) in self.program.iter_instructions().enumerate() {
                    let _ = writeln!(f, "{:5} {}", pc, instr_short(instr));
                }
            }
        }
        // #259 Phase C 2c-ii: replace push-based ExecutionRecord writes
        // with offset-based UnsafeRecord writes. Analyze the program
        // once at run() entry to assign per-instruction offsets, then
        // walk the analyzed seq_blocks. After the walk, finalize via
        // `into_record()` which transmutes the layout-equivalent
        // `MaybeUninit<UnsafeCell<T>>` Vec into `Vec<T>`. The
        // SeqBlock::Parallel arm walks sequentially in this commit
        // (Phase 2d adds par_iter dispatch); UnsafeRecord's Sync impl
        // and the disjoint-offset invariant from analyze make the
        // future swap a one-liner.
        // SP1 ref: `/tmp/sp1/crates/recursion/executor/src/runtime/mod.rs`
        // (the Runtime::run loop iterates RawProgram<AnalyzedInstruction>).
        let program_arc = self.program.clone();
        let (analyzed_program, event_counts) =
            program_arc.seq_blocks.clone().analyze();
        let unsafe_record = UnsafeRecord::<F>::new(event_counts);
        // Pre-init public_values cell with default via SP1's raw_get
        // pattern — works through `&UnsafeRecord` so it's compatible
        // with the new `&self` walker. CommitPublicValues overwrites.
        unsafe {
            UnsafeCell::raw_get(
                unsafe_record.public_values.as_ptr()
                    as *const UnsafeCell<crate::air::RecursionPublicValues<F>>,
            )
            .write(crate::air::RecursionPublicValues::default());
        }

        // #259 C-2d step 2: hoist mutable per-walker state into a
        // stack-allocated `WalkerState` so the recursive walker can take
        // `&self` and dispatch `SeqBlock::Parallel` sub-walks via rayon
        // par_iter without aliasing on shared mutable Runtime fields.
        let mut state = WalkerState::<F> {
            pc: self.pc,
            clk: self.clk,
            timestamp: self.timestamp,
            nb_poseidons: self.nb_poseidons,
            nb_wide_poseidons: self.nb_wide_poseidons,
            nb_bit_decompositions: self.nb_bit_decompositions,
            nb_select: self.nb_select,
            nb_exp_reverse_bits: self.nb_exp_reverse_bits,
            nb_ext_ops: self.nb_ext_ops,
            nb_base_ops: self.nb_base_ops,
            nb_memory_ops: self.nb_memory_ops,
            nb_branch_ops: self.nb_branch_ops,
            nb_fri_fold: self.nb_fri_fold,
            nb_batch_fri: self.nb_batch_fri,
            nb_print_f: self.nb_print_f,
            nb_print_e: self.nb_print_e,
        };
        // Take witness/debug_stdout out so we can pass them as `&mut`
        // through the recursive `&self` walker without aliasing self.
        let mut witness = std::mem::take(&mut self.witness_stream);
        let mut debug_stdout: Box<dyn Write + 'a> =
            std::mem::replace(&mut self.debug_stdout, Box::new(stdout()));

        let walker_result = self.execute_blocks(
            &analyzed_program.seq_blocks,
            &mut state,
            Some(&mut witness),
            Some(&mut *debug_stdout),
            &unsafe_record,
            early_exit_ts,
        );

        // Restore taken-out fields and sync state regardless of result
        // (so error reporting downstream sees the updated pc/clk).
        self.witness_stream = witness;
        self.debug_stdout = debug_stdout;
        self.pc = state.pc;
        self.clk = state.clk;
        self.timestamp = state.timestamp;
        self.nb_poseidons = state.nb_poseidons;
        self.nb_wide_poseidons = state.nb_wide_poseidons;
        self.nb_bit_decompositions = state.nb_bit_decompositions;
        self.nb_select = state.nb_select;
        self.nb_exp_reverse_bits = state.nb_exp_reverse_bits;
        self.nb_ext_ops = state.nb_ext_ops;
        self.nb_base_ops = state.nb_base_ops;
        self.nb_memory_ops = state.nb_memory_ops;
        self.nb_branch_ops = state.nb_branch_ops;
        self.nb_fri_fold = state.nb_fri_fold;
        self.nb_batch_fri = state.nb_batch_fri;
        self.nb_print_f = state.nb_print_f;
        self.nb_print_e = state.nb_print_e;
        walker_result?;

        // Finalize: transmute layout-equivalent `MaybeUninit<UnsafeCell<T>>`
        // Vec into `Vec<T>`. Sound because every event slot is initialized
        // exactly once by execute_one (analyze pass guarantees one offset
        // per emit) and public_values has at least the default written.
        self.record =
            unsafe { unsafe_record.into_record(self.program.clone(), self.record.index) };
        Ok(())
    }

    /// #259 C-2d step 2 walker. Walks the SeqBlock tree, dispatching
    /// `SeqBlock::Parallel` sub-programs via `par_iter` (each sub-walker
    /// allocates its own `WalkerState`, shares `&self` + `&unsafe_record`,
    /// passes `witness=None`/`debug_stdout=None` since parallel sub-programs
    /// in compose are pure compute — verified by `hint_in_par`
    /// counter at commit eace827).
    ///
    /// SP1 ref: `/tmp/sp1/crates/recursion/executor/src/lib.rs:799-834`
    /// (execute_raw_inner).
    #[allow(clippy::too_many_arguments)]
    fn execute_blocks(
        &self,
        blocks: &[SeqBlock<AnalyzedInstruction<F>>],
        state: &mut WalkerState<F>,
        mut witness: Option<&mut VecDeque<Block<F>>>,
        mut debug_stdout: Option<&mut (dyn Write + 'a)>,
        rec: &UnsafeRecord<F>,
        early_exit_ts: usize,
    ) -> Result<(), RuntimeError<F, EF>> {
        for block in blocks {
            match block {
                SeqBlock::Basic(basic) => {
                    for ai in &basic.instrs {
                        self.execute_one(
                            ai,
                            state,
                            witness.as_deref_mut(),
                            debug_stdout.as_deref_mut(),
                            rec,
                        )?;
                        if state.timestamp >= early_exit_ts {
                            return Ok(());
                        }
                    }
                }
                SeqBlock::Parallel(par_blocks) => {
                    use p3_maybe_rayon::prelude::*;
                    par_blocks.par_iter().try_for_each(
                        |sub: &RawProgram<AnalyzedInstruction<F>>| -> Result<(), RuntimeError<F, EF>> {
                            let mut substate = WalkerState::<F>::default();
                            substate.pc = state.pc;
                            substate.clk = state.clk;
                            // Sub-walks: no witness / debug_stdout — verified
                            // pure-compute (hint_in_par=0).
                            self.execute_blocks(
                                &sub.seq_blocks,
                                &mut substate,
                                None,
                                None,
                                rec,
                                early_exit_ts,
                            )
                        },
                    )?;
                }
            }
        }
        Ok(())
    }

    /// #259 C-2d step 2 per-instruction body. Identical semantics to the
    /// original `Runtime::run` for-loop body, with mechanical substitutions:
    /// - `self.nb_*` → `state.nb_*`
    /// - `self.pc/clk/timestamp` → `state.pc/clk/timestamp`
    /// - `self.memory.mr/mw` → `unsafe { self.memory.mr_unchecked / mw_unchecked }`
    /// - `self.witness_stream` → `witness.as_mut().expect(...)`
    /// - `self.debug_stdout` → `debug_stdout.as_mut().expect(...)`
    /// - `unsafe_record.X[off] = MaybeUninit::new(UnsafeCell::new(ev))`
    ///   → `unsafe { UnsafeCell::raw_get(rec.X[off].as_ptr() as *const UnsafeCell<_>).write(ev) }`
    ///
    /// SP1 ref: `/tmp/sp1/crates/recursion/executor/src/lib.rs::execute_one`.
    #[allow(clippy::too_many_arguments)]
    fn execute_one(
        &self,
        ai: &AnalyzedInstruction<F>,
        state: &mut WalkerState<F>,
        mut witness: Option<&mut VecDeque<Block<F>>>,
        mut debug_stdout: Option<&mut (dyn Write + 'a)>,
        rec: &UnsafeRecord<F>,
    ) -> Result<(), RuntimeError<F, EF>> {
        let next_clk = state.clk + F::from_u32(4);
        let next_pc = state.pc + F::ONE;
        let _offset = ai.offset();
        let instruction = ai.inner().clone();
        match instruction {
                Instruction::BaseAlu(instr @ BaseAluInstr { opcode, mult, addrs }) => {
                    state.nb_base_ops += 1;
                    // `ZIREN_DEBUG_READ_SHAPES=1`: log when BaseAlu reads an
                    // address that holds an Ext-shaped Block (non-zero v1/v2/v3).
                    // Those reads cause the wrap cumsum mismatch.
                    let debug_shapes = std::env::var("ZIREN_DEBUG_READ_SHAPES").is_ok();
                    if debug_shapes {
                        let pc = state.pc.as_canonical_u32();
                        let e1 = self.mr_us(addrs.in1).val;
                        if !e1.0[1].is_zero() || !e1.0[2].is_zero() || !e1.0[3].is_zero() {
                            eprintln!(
                                "[read shape] pc={} chip=BaseAlu op={:?} addr={} out_addr={} ext=true",
                                pc, opcode, addrs.in1.as_usize(), addrs.out.as_usize()
                            );
                        }
                        let e2 = self.mr_us(addrs.in2).val;
                        if !e2.0[1].is_zero() || !e2.0[2].is_zero() || !e2.0[3].is_zero() {
                            eprintln!(
                                "[read shape] pc={} chip=BaseAlu op={:?} addr={} out_addr={} ext=true",
                                pc, opcode, addrs.in2.as_usize(), addrs.out.as_usize()
                            );
                        }
                    }
                    let in1 = self.mr_us(addrs.in1).val[0];
                    let in2 = self.mr_us(addrs.in2).val[0];
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
                                        pc: state.pc.as_canonical_u32() as usize,
                                        trace: self.nearest_pc_backtrace_at(state.pc.as_canonical_u32() as usize),
                                    });
                                }
                            }
                        },
                    };
                    self.mw_us(addrs.out, Block::from(out), mult);
                    unsafe { Self::raw_write_ev(&rec.base_alu_events[_offset], BaseAluEvent { out, in1, in2 }); }
                }
                Instruction::ExtAlu(instr @ ExtAluInstr { opcode, mult, addrs }) => {
                    state.nb_ext_ops += 1;
                    let in1 = self.mr_us(addrs.in1).val;
                    let in2 = self.mr_us(addrs.in2).val;
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
                                        pc: state.pc.as_canonical_u32() as usize,
                                        trace: self.nearest_pc_backtrace_at(state.pc.as_canonical_u32() as usize),
                                    });
                                }
                            }
                        },
                    };
                    let out = Block::from(out_ef.as_basis_coefficients_slice());
                    self.mw_us(addrs.out, out, mult);
                    unsafe { Self::raw_write_ev(&rec.ext_alu_events[_offset], ExtAluEvent { out, in1, in2 }); }
                }
                Instruction::Mem(MemInstr {
                    addrs: MemIo { inner: addr },
                    vals: MemIo { inner: val },
                    mult,
                    kind,
                }) => {
                    state.nb_memory_ops += 1;
                    match kind {
                        MemAccessKind::Read => {
                            let mem_entry = self.mr_us(addr);
                            assert_eq!(
                                mem_entry.val, val,
                                "stored memory value should be the specified value"
                            );
                        }
                        MemAccessKind::Write => drop(self.mw_us(addr, val, mult)),
                    }
                    // mem_const_count is pre-sized by `UnsafeRecord::new`
                    // from the analyzed Mem-instruction count (SP1 ref:
                    // /tmp/sp1/crates/recursion/executor/src/record.rs:111).
                    // No per-instruction increment needed.
                }
                Instruction::Poseidon2(instr) => {
                    let Poseidon2Instr { addrs: Poseidon2Io { input, output }, mults } = *instr;
                    state.nb_poseidons += 1;
                    // `ZIREN_DEBUG_READ_SHAPES=1`: log Poseidon2 inputs at
                    // Ext-shaped addresses.
                    if std::env::var("ZIREN_DEBUG_READ_SHAPES").is_ok() {
                        let pc = state.pc.as_canonical_u32();
                        for (i, &addr) in input.iter().enumerate() {
                            let e = self.mr_us(addr).val;
                            if !e.0[1].is_zero() || !e.0[2].is_zero() || !e.0[3].is_zero() {
                                eprintln!(
                                    "[read shape] pc={} chip=Poseidon2 slot={} addr={} ext=true",
                                    pc, i, addr.as_usize()
                                );
                            }
                        }
                    }
                    let in_vals = std::array::from_fn(|i| self.mr_us(input[i]).val[0]);
                    let perm_output = self.perm.as_ref().unwrap().permute(in_vals);

                    perm_output.iter().zip(output).zip(mults).for_each(|((&val, addr), mult)| {
                        self.mw_us(addr, Block::from(val), mult);
                    });
                    unsafe { Self::raw_write_ev(&rec.poseidon2_events[_offset], 
                        Poseidon2Event { input: in_vals, output: perm_output },
                    ); }
                }
                Instruction::Select(SelectInstr {
                    addrs: SelectIo { bit, out1, out2, in1, in2 },
                    mult1,
                    mult2,
                }) => {
                    state.nb_select += 1;
                    let bit = self.mr_us(bit).val[0];
                    let in1 = self.mr_us(in1).val[0];
                    let in2 = self.mr_us(in2).val[0];
                    let out1_val = bit * in2 + (F::ONE - bit) * in1;
                    let out2_val = bit * in1 + (F::ONE - bit) * in2;
                    self.mw_us(out1, Block::from(out1_val), mult1);
                    self.mw_us(out2, Block::from(out2_val), mult2);
                    unsafe { Self::raw_write_ev(&rec.select_events[_offset], 
                        SelectEvent {
                            bit,
                            out1: out1_val,
                            out2: out2_val,
                            in1,
                            in2,
                        },
                    ); }
                }
                Instruction::ExpReverseBitsLen(ExpReverseBitsInstr {
                    addrs: ExpReverseBitsIo { base, exp, result },
                    mult,
                }) => {
                    state.nb_exp_reverse_bits += 1;
                    let base_val = self.mr_us(base).val[0];
                    let exp_bits: Vec<_> =
                        exp.iter().map(|bit| self.mr_us(*bit).val[0]).collect();
                    let exp_val = exp_bits
                        .iter()
                        .enumerate()
                        .fold(0, |acc, (i, &val)| acc + val.as_canonical_u32() * (1 << i));
                    let out =
                        base_val.exp_u64(reverse_bits_len(exp_val as usize, exp_bits.len()) as u64);
                    self.mw_us(result, Block::from(out), mult);
                    unsafe { Self::raw_write_ev(&rec.exp_reverse_bits_len_events[_offset], ExpReverseBitsEvent {
                            result: out,
                            base: base_val,
                            exp: exp_bits,
                        }); }
                }
                Instruction::HintBits(HintBitsInstr { output_addrs_mults, input_addr }) => {
                    state.nb_bit_decompositions += 1;
                    let num = self.mr_us(input_addr).val[0].as_canonical_u32();
                    // Decompose the num into LE bits.
                    let bits = (0..output_addrs_mults.len())
                        .map(|i| Block::from(F::from_u32((num >> i) & 1)))
                        .collect::<Vec<_>>();
                    // Write the bits to the array at dst.
                    for (i, (bit, (addr, mult))) in
                        bits.into_iter().zip(output_addrs_mults).enumerate()
                    {
                        self.mw_us(addr, bit, mult);
                        unsafe { Self::raw_write_ev(&rec.mem_var_events[_offset + i], MemEvent { inner: bit }); }
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
                        self.mr_us(input1_x_addrs[i]).val[0]
                    });
                    let input1_y = SepticExtension::<F>::from_base_fn(|i| {
                        self.mr_us(input1_y_addrs[i]).val[0]
                    });
                    let input2_x = SepticExtension::<F>::from_base_fn(|i| {
                        self.mr_us(input2_x_addrs[i]).val[0]
                    });
                    let input2_y = SepticExtension::<F>::from_base_fn(|i| {
                        self.mr_us(input2_y_addrs[i]).val[0]
                    });
                    let point1 = SepticCurve { x: input1_x, y: input1_y };
                    let point2 = SepticCurve { x: input2_x, y: input2_y };
                    let output = point1.add_incomplete(point2);

                    let _x_count = output_x_addrs_mults.len();
                    for (i, (val, (addr, mult))) in output
                        .x
                        .0
                        .into_iter()
                        .zip(output_x_addrs_mults.into_iter())
                        .enumerate()
                    {
                        self.mw_us(addr, Block::from(val), mult);
                        unsafe { Self::raw_write_ev(&rec.mem_var_events[_offset + i], MemEvent { inner: Block::from(val) }); }
                    }
                    for (i, (val, (addr, mult))) in output
                        .y
                        .0
                        .into_iter()
                        .zip(output_y_addrs_mults.into_iter())
                        .enumerate()
                    {
                        self.mw_us(addr, Block::from(val), mult);
                        unsafe { Self::raw_write_ev(&rec.mem_var_events[_offset + _x_count + i], MemEvent { inner: Block::from(val) }); }
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
                    state.nb_fri_fold += 1;
                    let x = self.mr_us(base_single_addrs.x).val[0];
                    let z = self.mr_us(ext_single_addrs.z).val;
                    let z: EF = z.ext();
                    let alpha = self.mr_us(ext_single_addrs.alpha).val;
                    let alpha: EF = alpha.ext();
                    let mat_opening = ext_vec_addrs
                        .mat_opening
                        .iter()
                        .map(|addr| self.mr_us(*addr).val)
                        .collect_vec();
                    let ps_at_z = ext_vec_addrs
                        .ps_at_z
                        .iter()
                        .map(|addr| self.mr_us(*addr).val)
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
                            self.mr_us(ext_vec_addrs.alpha_pow_input[m]).val.ext();

                        let ro: EF = self.mr_us(ext_vec_addrs.ro_input[m]).val.ext();

                        let new_ro = ro + alpha_pow * quotient;
                        let new_alpha_pow = alpha_pow * alpha;

                        let _ = self.mw_us(
                            ext_vec_addrs.ro_output[m],
                            Block::from(new_ro.as_basis_coefficients_slice()),
                            ro_mults[m],
                        );

                        let _ = self.mw_us(
                            ext_vec_addrs.alpha_pow_output[m],
                            Block::from(new_alpha_pow.as_basis_coefficients_slice()),
                            alpha_pow_mults[m],
                        );

                        unsafe { Self::raw_write_ev(&rec.fri_fold_events[_offset + m], FriFoldEvent {
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
                            }); }
                    }
                }
                Instruction::BatchFRI(instr) => {
                    let BatchFRIInstr { base_vec_addrs, ext_single_addrs, ext_vec_addrs, acc_mult } =
                        *instr;

                    let mut acc = EF::ZERO;
                    let p_at_xs = base_vec_addrs
                        .p_at_x
                        .iter()
                        .map(|addr| self.mr_us(*addr).val[0])
                        .collect_vec();
                    let p_at_zs = ext_vec_addrs
                        .p_at_z
                        .iter()
                        .map(|addr| self.mr_us(*addr).val.ext::<EF>())
                        .collect_vec();
                    let alpha_pows: Vec<_> = ext_vec_addrs
                        .alpha_pow
                        .iter()
                        .map(|addr| self.mr_us(*addr).val.ext::<EF>())
                        .collect_vec();

                    state.nb_batch_fri += p_at_zs.len();
                    for m in 0..p_at_zs.len() {
                        acc += alpha_pows[m] * (p_at_zs[m] - EF::from(p_at_xs[m]));
                        unsafe { Self::raw_write_ev(&rec.batch_fri_events[_offset + m], BatchFRIEvent {
                                base_vec: BatchFRIBaseVecIo { p_at_x: p_at_xs[m] },
                                ext_single: BatchFRIExtSingleIo {
                                    acc: Block::from(acc.as_basis_coefficients_slice()),
                                },
                                ext_vec: BatchFRIExtVecIo {
                                    p_at_z: Block::from(p_at_zs[m].as_basis_coefficients_slice()),
                                    alpha_pow: Block::from(alpha_pows[m].as_basis_coefficients_slice()),
                                },
                            }); }
                    }

                    let _ = self.mw_us(
                        ext_single_addrs.acc,
                        Block::from(acc.as_basis_coefficients_slice()),
                        acc_mult,
                    );
                }
                Instruction::CommitPublicValues(instr) => {
                    let pv_addrs = instr.pv_addrs.as_array();
                    let pv_values: [F; RECURSIVE_PROOF_NUM_PV_ELTS] =
                        array::from_fn(|i| self.mr_us(pv_addrs[i]).val[0]);
                    let public_values: crate::air::RecursionPublicValues<F> =
                        *pv_values.as_slice().borrow();
                    // Overwrite the default-init public_values cell.
                    unsafe { Self::raw_write_ev(&rec.public_values, public_values); }
                    unsafe { Self::raw_write_ev(&rec.commit_pv_hash_events[_offset], CommitPublicValuesEvent { public_values }); }
                }

                Instruction::Print(PrintInstr { field_elt_type, addr }) => match field_elt_type {
                    FieldEltType::Base => {
                        state.nb_print_f += 1;
                        let f = self.mr_us(addr).val[0];
                        writeln!(debug_stdout.as_mut().expect("debug_stdout must be Some at root walker"), "PRINTF={f}")
                    }
                    FieldEltType::Extension => {
                        state.nb_print_e += 1;
                        let ef = self.mr_us(addr).val;
                        writeln!(debug_stdout.as_mut().expect("debug_stdout must be Some at root walker"), "PRINTEF={ef:?}")
                    }
                }
                .map_err(RuntimeError::DebugPrint)?,
                Instruction::HintExt2Felts(HintExt2FeltsInstr {
                    output_addrs_mults,
                    input_addr,
                }) => {
                    state.nb_bit_decompositions += 1;
                    let fs = self.mr_us(input_addr).val;
                    // Write the bits to the array at dst.
                    for (i, (f, (addr, mult))) in
                        fs.into_iter().zip(output_addrs_mults).enumerate()
                    {
                        let felt = Block::from(f);
                        self.mw_us(addr, felt, mult);
                        unsafe { Self::raw_write_ev(&rec.mem_var_events[_offset + i], MemEvent { inner: felt }); }
                    }
                }
                Instruction::Hint(HintInstr { output_addrs_mults }) => {
                    // Check that enough Blocks can be read, so `drain` does not panic.
                    if witness.as_mut().expect("witness must be Some at root walker").len() < output_addrs_mults.len() {
                        return Err(RuntimeError::EmptyWitnessStream);
                    }
                    let witness = witness.as_mut().expect("witness must be Some at root walker").drain(0..output_addrs_mults.len());
                    let debug_hint = std::env::var("ZIREN_DEBUG_HINT_BLOCKS").is_ok();
                    for (i, ((addr, mult), val)) in zip(output_addrs_mults, witness).enumerate() {
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
                        self.mw_us(addr, val, mult);
                        unsafe { Self::raw_write_ev(&rec.mem_var_events[_offset + i], MemEvent { inner: val }); }
                    }
                }
            }

        state.pc = next_pc;
        state.clk = next_clk;
        state.timestamp += 1;
        Ok(())
    }

    pub fn preallocate_record(&mut self) {
        // #259 Phase C step 2c: walk seq_blocks recursively (handling
        // SeqBlock::Parallel) via the analyze module's `event_counts`
        // helper instead of flattening through `iter_instructions`. The
        // counts are identical today (compiler emits a single Basic
        // block; no Parallel blocks yet), but the recursive walk is the
        // correct foundation for when parallel blocks land.
        let event_counts = self.program.seq_blocks.event_counts();
        self.record.poseidon2_events.reserve(event_counts.poseidon2_wide_events);
        self.record.mem_var_events.reserve(event_counts.mem_var_events);
        self.record.base_alu_events.reserve(event_counts.base_alu_events);
        self.record.ext_alu_events.reserve(event_counts.ext_alu_events);
        self.record.exp_reverse_bits_len_events.reserve(event_counts.exp_reverse_bits_len_events);
        self.record.select_events.reserve(event_counts.select_events);
        // #259 Phase C step 2c-ii prep: reserve the newly-tracked event vecs.
        self.record.fri_fold_events.reserve(event_counts.fri_fold_events);
        self.record.batch_fri_events.reserve(event_counts.batch_fri_events);
        self.record.commit_pv_hash_events.reserve(event_counts.commit_pv_hash_events);
    }
}

/// Short textual form of an instruction for the `ZIREN_DUMP_PROGRAM`
/// debug dump — just uses Rust's Debug on the variant, which is enough
/// to grep for addresses.
fn instr_short<F: std::fmt::Debug>(instr: &Instruction<F>) -> String {
    format!("{:?}", instr)
}
