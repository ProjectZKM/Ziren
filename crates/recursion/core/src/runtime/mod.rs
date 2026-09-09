mod analyzed;
pub mod instruction;
// Public because the recursion JIT (`zkm-recursion-jit`) emits code that
// addresses this memory directly — `base + addr * size_of::<MemoryEntry>()`
// — and asserts that layout at compile time.  Keeping the module private
// would leave the emitter's addressing unverifiable from outside.
pub mod memory;
mod opcode;
mod program;
mod record;
mod seq_block;

pub use analyzed::{AnalyzedInstruction, DivPlan};
pub use seq_block::{BasicBlock, RawProgram, SeqBlock};

// Avoid triggering annoying branch of thiserror derive macro.
use backtrace::Backtrace as Trace;
use hashbrown::HashMap;
use instruction::HintAddCurveInstr;
pub use instruction::Instruction;
use instruction::{FieldEltType, HintBitsInstr, HintExt2FeltsInstr, HintInstr, PrintInstr};
use itertools::Itertools;
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
use thiserror::Error;

use zkm_pcs::septic_curve::SepticCurve;
use zkm_pcs::septic_extension::SepticExtension;

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

/// Montgomery's trick: `vals[i]` becomes `1/vals[i]`, at a cost of `3n`
/// multiplies and ONE inversion instead of `n` inversions.
///
/// A zero is carried through as a zero and skipped in the product chain, so
/// one out-of-domain divisor neither poisons its neighbours nor makes the
/// single inversion fail; the caller reads the zero back as "no inverse".
///
/// `scratch` holds the prefix products.  It is passed in rather than
/// allocated so a walk that enters thousands of basic blocks reuses one
/// buffer.
fn batch_invert<F: p3_field::Field>(vals: &mut [F], scratch: &mut Vec<F>) {
    scratch.clear();
    scratch.reserve(vals.len());
    // P_i = product of the non-zero values before i.
    let mut acc = F::ONE;
    for &v in vals.iter() {
        scratch.push(acc);
        if !v.is_zero() {
            acc *= v;
        }
    }
    // A product of non-zero field elements is non-zero, so this cannot fail.
    let mut inv_acc =
        acc.try_inverse().expect("a product of non-zero field elements is non-zero");
    // Walking back down: `inv_acc` is 1/P_{i+1}, so P_i / P_{i+1} = 1/v_i.
    for i in (0..vals.len()).rev() {
        let v = vals[i];
        if v.is_zero() {
            vals[i] = F::ZERO;
        } else {
            vals[i] = scratch[i] * inv_acc;
            inv_acc *= v;
        }
    }
}

/// Per-walker mutable state for the parallel SeqBlock executor. Each parallel
/// sub-walker allocates its own `WalkerState` on the stack so the walker
/// can take `&self` and dispatch `SeqBlock::Parallel` sub-walks via
/// rayon `par_iter` without aliasing on shared mutable fields.
///
/// pc/clk in sub-walkers are best-effort (used only by trap-error
/// reporting); only the root walker's pc/clk feed back to `Runtime`
/// after `execute_blocks` returns. The `nb_*` counters are summed back
/// at sub-walker join (single-threaded after `try_for_each` returns).
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
    /// Batch-inverted `DivF` divisors for the basic block being walked, in
    /// the order the block's divisions execute; `div_cursor` is how many
    /// have been consumed.  Empty when the block has no plan, which puts
    /// the `DivF` arm back on `try_inverse` per instruction.
    ///
    /// A zero entry means the divisor WAS zero — an inverse is never zero,
    /// so the sentinel is unambiguous and the arm falls through to the
    /// original out-of-domain handling.
    pub div_inv: Vec<F>,
    pub div_cursor: usize,
    /// Prefix-product scratch for the batch inversion; kept on the state so
    /// a block entry reuses the allocation instead of making one.
    pub div_scratch: Vec<F>,
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

    /// Memory. Parallel-safe cell-per-address layer.
    /// The `&mut self` walker still drives mr/mw via the
    /// safe variants; once the SeqBlock::Parallel walker arm is ported
    /// to par_iter, the `&self` `mr_unchecked`/`mw_unchecked` can be
    /// used directly for race-free disjoint-address writes.
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
            F,
            Poseidon2ExternalLayerKoalaBear<16>,
            Diffusion,
            PERMUTATION_WIDTH,
            POSEIDON2_SBOX_DEGREE,
        >,
    >,

    _marker_ef: PhantomData<EF>,

    _marker_diffusion: PhantomData<Diffusion>,
}

// SAFETY: the walker dispatches `SeqBlock::Parallel`
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
        F,
        Poseidon2ExternalLayerKoalaBear<16>,
        Diffusion,
        PERMUTATION_WIDTH,
        POSEIDON2_SBOX_DEGREE,
    >: CryptographicPermutation<[F; PERMUTATION_WIDTH]>,
{
    pub fn new(
        program: Arc<RecursionProgram<F>>,
        perm: Poseidon2<
            F,
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

    /// `&self` memory-read helper that wraps the
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

    /// Record-write helper. Wraps the raw_get
    /// idiom so the type parameter `T` is inferred from the slot.
    /// Soundness: caller must ensure the slot is written exactly once
    /// across all threads — guaranteed by analyze pass + IR-level
    /// `SeqBlock::Parallel` disjoint-offset invariant.
    #[inline(always)]
    unsafe fn raw_write_ev<T>(slot: &MaybeUninit<UnsafeCell<T>>, ev: T) {
        unsafe { UnsafeCell::raw_get(slot.as_ptr() as *const UnsafeCell<T>).write(ev) }
    }

    /// Variant that takes `trap_pc` explicitly so it can
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
        // Replace push-based ExecutionRecord writes
        // with offset-based UnsafeRecord writes. Analyze the program
        // once at run() entry to assign per-instruction offsets, then
        // walk the analyzed seq_blocks. After the walk, finalize via
        // `into_record()` which transmutes the layout-equivalent
        // `MaybeUninit<UnsafeCell<T>>` Vec into `Vec<T>`. The
        // SeqBlock::Parallel arm currently walks sequentially; once it
        // dispatches via par_iter, UnsafeRecord's Sync impl
        // and the disjoint-offset invariant from analyze make the
        // swap a one-liner.
        // ZIREN_REC_EXEC_TIMING=1 splits a recursion program's execution into
        // its two host phases.  The walk is the interpreter SP1 JITs away for
        // the guest (sp1-jit / crates/core/jit here); this is the measurement
        // that says what a recursion JIT would be worth.
        let timing = std::env::var("ZIREN_REC_EXEC_TIMING").is_ok_and(|v| v != "0");
        let t_analyze = std::time::Instant::now();
        let program_arc = self.program.clone();
        // Nothing to derive: the program was analyzed once when it was built,
        // as SP1's `RootProgram` is.  `analyze_secs` stays in the instrument
        // so the timing line keeps its shape and shows the phase at ~0.
        let analyzed_program = &program_arc.seq_blocks;
        let event_counts = program_arc.event_counts;
        let analyze_secs = t_analyze.elapsed().as_secs_f64();
        let t_walk = std::time::Instant::now();
        let unsafe_record = UnsafeRecord::<F>::new(event_counts);
        // Pre-init public_values cell with default via the raw_get
        // pattern — works through `&UnsafeRecord` so it's compatible
        // with the new `&self` walker. CommitPublicValues overwrites.
        unsafe {
            UnsafeCell::raw_get(unsafe_record.public_values.as_ptr()
                as *const UnsafeCell<crate::air::RecursionPublicValues<F>>)
            .write(crate::air::RecursionPublicValues::default());
        }

        // Hoist mutable per-walker state into a
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
            div_inv: Vec::new(),
            div_cursor: 0,
            div_scratch: Vec::new(),
        };
        // Take witness/debug_stdout out so we can pass them as `&mut`
        // through the recursive `&self` walker without aliasing self.
        let mut witness = std::mem::take(&mut self.witness_stream);
        let mut debug_stdout: Box<dyn Write + 'a> =
            std::mem::replace(&mut self.debug_stdout, Box::new(stdout()));

        let walker_result = self.execute_blocks(
            &analyzed_program.seq_blocks,
            Some(program_arc.div_plan.as_slice()),
            &mut state,
            Some(&mut witness),
            Some(&mut *debug_stdout),
            &unsafe_record,
        );
        if timing {
            let walk_secs = t_walk.elapsed().as_secs_f64();
            // Counted off the PROGRAM, not off `state`: a `SeqBlock::Parallel`
            // sub-walk runs on a fresh `WalkerState` whose counters are
            // dropped when it returns, so the `nb_*` totals miss every
            // instruction executed in parallel.
            let instrs = analyzed_program.iter().count();
            // Opcode mix, because a JIT is built one arm at a time: this says
            // what fraction of the walk a first cut covering only the
            // straight-line arithmetic/memory arms would actually replace.
            let mut mix = [0usize; 12];
            for ai in analyzed_program.iter() {
                let k = match ai.inner() {
                    Instruction::BaseAlu(_) => 0,
                    Instruction::ExtAlu(_) => 1,
                    Instruction::Mem(_) => 2,
                    Instruction::Poseidon2(_) => 3,
                    Instruction::Select(_) => 4,
                    Instruction::HintBits(_) => 5,
                    Instruction::HintAddCurve(_) => 6,
                    Instruction::Print(_) => 7,
                    Instruction::HintExt2Felts(_) => 8,
                    Instruction::Ext2Felts(_) => 9,
                    Instruction::CommitPublicValues(_) => 10,
                    Instruction::Hint(_) => 11,
                };
                mix[k] += 1;
            }
            let names = [
                "BaseAlu",
                "ExtAlu",
                "Mem",
                "Poseidon2",
                "Select",
                "HintBits",
                "HintAddCurve",
                "Print",
                "HintExt2Felts",
                "Ext2Felts",
                "CommitPublicValues",
                "Hint",
            ];
            let mix_str: String = names
                .iter()
                .zip(mix.iter())
                .filter(|(_, &n)| n > 0)
                .map(|(nm, n)| format!("{nm}={n} "))
                .collect();
            eprintln!("REC_MIX {mix_str}");
            eprintln!(
                "REC_EXEC analyze={analyze_secs:.4}s walk={walk_secs:.4}s instrs={instrs} \
                 rate={:.2}M/s",
                (instrs as f64) / walk_secs / 1e6
            );
        }

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
        self.record = unsafe { unsafe_record.into_record(self.program.clone(), self.record.index) };
        Ok(())
    }

    /// Walker. Walks the SeqBlock tree, dispatching
    /// `SeqBlock::Parallel` sub-programs via `par_iter` (each sub-walker
    /// allocates its own `WalkerState`, shares `&self` + `&unsafe_record`,
    /// passes `witness=None`/`debug_stdout=None` since parallel sub-programs
    /// in compose are pure compute — verified by `hint_in_par`
    /// counter at commit eace827).
    #[allow(clippy::too_many_arguments)]
    fn execute_blocks(
        &self,
        blocks: &[SeqBlock<AnalyzedInstruction<F>>],
        // Mirrors `blocks` element for element.  `None` — or any length
        // mismatch, which is checked at every level — means "no plan here",
        // and the walk inverts per instruction exactly as it always did.
        plan: Option<&[DivPlan<F>]>,
        state: &mut WalkerState<F>,
        mut witness: Option<&mut VecDeque<Block<F>>>,
        mut debug_stdout: Option<&mut (dyn Write + 'a)>,
        rec: &UnsafeRecord<F>,
    ) -> Result<(), RuntimeError<F, EF>> {
        let plan = plan.filter(|p| p.len() == blocks.len());
        for (i, block) in blocks.iter().enumerate() {
            let block_plan = plan.map(|p| &p[i]);
            match block {
                SeqBlock::Basic(basic) => {
                    // Gather the block's divisors and invert them all at
                    // once.  The reads are pure (`mr_us` only borrows), and
                    // every address here is one no instruction in this block
                    // writes, so the values cannot change under the walk.
                    state.div_cursor = 0;
                    state.div_inv.clear();
                    if let Some(DivPlan::Basic(addrs)) = block_plan {
                        if !addrs.is_empty() {
                            state.div_inv.reserve(addrs.len());
                            for &a in addrs.iter() {
                                state.div_inv.push(self.mr_us(a).val[0]);
                            }
                            let (inv, scratch) =
                                (&mut state.div_inv, &mut state.div_scratch);
                            batch_invert(inv, scratch);
                        }
                    }
                    for ai in &basic.instrs {
                        self.execute_one(
                            ai,
                            state,
                            witness.as_deref_mut(),
                            debug_stdout.as_deref_mut(),
                            rec,
                        )?;
                    }
                    state.div_inv.clear();
                    state.div_cursor = 0;
                }
                SeqBlock::Parallel(par_blocks) => {
                    use p3_maybe_rayon::prelude::*;
                    let sub_plans = match block_plan {
                        Some(DivPlan::Parallel(subs)) if subs.len() == par_blocks.len() => {
                            Some(subs.as_slice())
                        }
                        _ => None,
                    };
                    par_blocks.par_iter().enumerate().try_for_each(
                        |(j, sub): (usize, &RawProgram<AnalyzedInstruction<F>>)| -> Result<(), RuntimeError<F, EF>> {
                            let mut substate = WalkerState::<F>::default();
                            substate.pc = state.pc;
                            substate.clk = state.clk;
                            // Sub-walks: no witness / debug_stdout — verified
                            // pure-compute (hint_in_par=0).
                            self.execute_blocks(
                                &sub.seq_blocks,
                                sub_plans.map(|p| p[j].as_slice()),
                                &mut substate,
                                None,
                                None,
                                rec,
                            )
                        },
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Per-instruction body. Identical semantics to the
    /// original `Runtime::run` for-loop body, with mechanical substitutions:
    /// - `self.nb_*` → `state.nb_*`
    /// - `self.pc/clk/timestamp` → `state.pc/clk/timestamp`
    /// - `self.memory.mr/mw` → `unsafe { self.memory.mr_unchecked / mw_unchecked }`
    /// - `self.witness_stream` → `witness.as_mut().expect(...)`
    /// - `self.debug_stdout` → `debug_stdout.as_mut().expect(...)`
    /// - `unsafe_record.X[off] = MaybeUninit::new(UnsafeCell::new(ev))`
    ///   → `unsafe { UnsafeCell::raw_get(rec.X[off].as_ptr() as *const UnsafeCell<_>).write(ev) }`
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
        // Matched by REFERENCE.  This used to run on a clone of the
        // instruction, copying the full width of the enum -- and heap-
        // allocating the `Vec` variants -- once per executed instruction,
        // millions of times per node.  Every arm reads `Copy` fields or
        // borrows; only the two ALU out-of-domain errors need an owned copy,
        // and they take one where the error is built.
        match ai.inner() {
            Instruction::BaseAlu(instr @ BaseAluInstr { opcode, mult, addrs }) => {
                state.nb_base_ops += 1;
                let in1 = self.mr_us(addrs.in1).val[0];
                let in2 = self.mr_us(addrs.in2).val[0];
                let out = match opcode {
                    BaseAluOpcode::AddF => in1 + in2,
                    BaseAluOpcode::SubF => in1 - in2,
                    BaseAluOpcode::MulF => in1 * in2,
                    BaseAluOpcode::DivF | BaseAluOpcode::DivFAssert => {
                        // Hoisted: this block's divisors were inverted in one
                        // batch at block entry, and the block's divisions
                        // consume them in execution order.  A zero entry is
                        // the "divisor was zero" sentinel (an inverse never
                        // is), which drops through to the same out-of-domain
                        // handling as the un-hoisted path.
                        let hoisted = state.div_inv.get(state.div_cursor).copied();
                        if hoisted.is_some() {
                            state.div_cursor += 1;
                        }
                        match hoisted
                            .filter(|inv| !inv.is_zero())
                            .or_else(|| in2.try_inverse())
                            .map(|x| x * in1)
                        {
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
                                        instr: *instr,
                                        pc: state.pc.as_canonical_u32() as usize,
                                        trace: self.nearest_pc_backtrace_at(
                                            state.pc.as_canonical_u32() as usize,
                                        ),
                                    });
                                }
                            }
                        }
                    }
                };
                self.mw_us(addrs.out, Block::from(out), *mult);
                unsafe {
                    Self::raw_write_ev(
                        &rec.base_alu_events[_offset],
                        BaseAluEvent { out, in1, in2 },
                    );
                }
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
                    ExtAluOpcode::DivE | ExtAluOpcode::DivEAssert => {
                        match in2_ef.try_inverse().map(|x| x * in1_ef) {
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
                                        instr: *instr,
                                        pc: state.pc.as_canonical_u32() as usize,
                                        trace: self.nearest_pc_backtrace_at(
                                            state.pc.as_canonical_u32() as usize,
                                        ),
                                    });
                                }
                            }
                        }
                    }
                };
                let out = Block::from(out_ef.as_basis_coefficients_slice());
                self.mw_us(addrs.out, out, *mult);
                unsafe {
                    Self::raw_write_ev(&rec.ext_alu_events[_offset], ExtAluEvent { out, in1, in2 });
                }
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
                        let mem_entry = self.mr_us(*addr);
                        assert_eq!(
                            mem_entry.val, *val,
                            "stored memory value should be the specified value"
                        );
                    }
                    MemAccessKind::Write => drop(self.mw_us(*addr, *val, *mult)),
                }
                // mem_const_count is pre-sized by `UnsafeRecord::new`
                // from the analyzed Mem-instruction count.
                // No per-instruction increment needed.
            }
            Instruction::Poseidon2(instr) => {
                let Poseidon2Instr { addrs: Poseidon2Io { input, output }, mults } = &**instr;
                state.nb_poseidons += 1;
                let in_vals = std::array::from_fn(|i| self.mr_us(input[i]).val[0]);
                let perm_output = self.perm.as_ref().unwrap().permute(in_vals);

                perm_output.iter().zip(output).zip(mults).for_each(|((&val, addr), mult)| {
                    self.mw_us(*addr, Block::from(val), *mult);
                });
                unsafe {
                    Self::raw_write_ev(
                        &rec.poseidon2_events[_offset],
                        Poseidon2Event { input: in_vals, output: perm_output },
                    );
                }
            }
            Instruction::Select(SelectInstr {
                addrs: SelectIo { bit, out1, out2, in1, in2 },
                mult1,
                mult2,
            }) => {
                state.nb_select += 1;
                let bit = self.mr_us(*bit).val[0];
                let in1 = self.mr_us(*in1).val[0];
                let in2 = self.mr_us(*in2).val[0];
                let out1_val = bit * in2 + (F::ONE - bit) * in1;
                let out2_val = bit * in1 + (F::ONE - bit) * in2;
                self.mw_us(*out1, Block::from(out1_val), *mult1);
                self.mw_us(*out2, Block::from(out2_val), *mult2);
                unsafe {
                    Self::raw_write_ev(
                        &rec.select_events[_offset],
                        SelectEvent { bit, out1: out1_val, out2: out2_val, in1, in2 },
                    );
                }
            }
            Instruction::HintBits(HintBitsInstr { output_addrs_mults, input_addr }) => {
                state.nb_bit_decompositions += 1;
                let num = self.mr_us(*input_addr).val[0].as_canonical_u32();
                // Decompose the num into LE bits.
                let bits = (0..output_addrs_mults.len())
                    .map(|i| Block::from(F::from_u32((num >> i) & 1)))
                    .collect::<Vec<_>>();
                // Write the bits to the array at dst.
                for (i, (bit, (addr, mult))) in
                    bits.into_iter().zip(output_addrs_mults.iter().copied()).enumerate()
                {
                    self.mw_us(addr, bit, mult);
                    unsafe {
                        Self::raw_write_ev(
                            &rec.mem_var_events[_offset + i],
                            MemEvent { inner: bit },
                        );
                    }
                }
            }
            Instruction::HintAddCurve(instr) => {
                let HintAddCurveInstr {
                    output_x_addrs_mults,
                    output_y_addrs_mults,
                    input1_x_addrs,
                    input1_y_addrs,
                    input2_x_addrs,
                    input2_y_addrs,
                } = &**instr;
                let input1_x =
                    SepticExtension::<F>::from_base_fn(|i| self.mr_us(input1_x_addrs[i]).val[0]);
                let input1_y =
                    SepticExtension::<F>::from_base_fn(|i| self.mr_us(input1_y_addrs[i]).val[0]);
                let input2_x =
                    SepticExtension::<F>::from_base_fn(|i| self.mr_us(input2_x_addrs[i]).val[0]);
                let input2_y =
                    SepticExtension::<F>::from_base_fn(|i| self.mr_us(input2_y_addrs[i]).val[0]);
                let point1 = SepticCurve { x: input1_x, y: input1_y };
                let point2 = SepticCurve { x: input2_x, y: input2_y };
                let output = point1.add_incomplete(point2);

                let _x_count = output_x_addrs_mults.len();
                for (i, (val, (addr, mult))) in
                    output.x.0.into_iter().zip(output_x_addrs_mults.iter().copied()).enumerate()
                {
                    self.mw_us(addr, Block::from(val), mult);
                    unsafe {
                        Self::raw_write_ev(
                            &rec.mem_var_events[_offset + i],
                            MemEvent { inner: Block::from(val) },
                        );
                    }
                }
                for (i, (val, (addr, mult))) in
                    output.y.0.into_iter().zip(output_y_addrs_mults.iter().copied()).enumerate()
                {
                    self.mw_us(addr, Block::from(val), mult);
                    unsafe {
                        Self::raw_write_ev(
                            &rec.mem_var_events[_offset + _x_count + i],
                            MemEvent { inner: Block::from(val) },
                        );
                    }
                }
            }

            Instruction::CommitPublicValues(instr) => {
                let pv_addrs = instr.pv_addrs.as_array();
                let pv_values: [F; RECURSIVE_PROOF_NUM_PV_ELTS] =
                    array::from_fn(|i| self.mr_us(pv_addrs[i]).val[0]);
                let public_values: crate::air::RecursionPublicValues<F> =
                    *pv_values.as_slice().borrow();
                // Overwrite the default-init public_values cell.
                unsafe {
                    Self::raw_write_ev(&rec.public_values, public_values);
                }
                unsafe {
                    Self::raw_write_ev(
                        &rec.commit_pv_hash_events[_offset],
                        CommitPublicValuesEvent { public_values },
                    );
                }
            }

            Instruction::Print(PrintInstr { field_elt_type, addr }) => match field_elt_type {
                FieldEltType::Base => {
                    state.nb_print_f += 1;
                    let f = self.mr_us(*addr).val[0];
                    match debug_stdout.as_mut() {
                        Some(w) => writeln!(w, "PRINTF={f}").map_err(RuntimeError::DebugPrint)?,
                        None => eprintln!("PRINTF={f}"),
                    }
                }
                FieldEltType::Extension => {
                    state.nb_print_e += 1;
                    let ef = self.mr_us(*addr).val;
                    match debug_stdout.as_mut() {
                        Some(w) => {
                            writeln!(w, "PRINTEF={ef:?}").map_err(RuntimeError::DebugPrint)?
                        }
                        None => eprintln!("PRINTEF={ef:?}"),
                    }
                }
            },
            Instruction::HintExt2Felts(HintExt2FeltsInstr { output_addrs_mults, input_addr }) => {
                state.nb_bit_decompositions += 1;
                let fs = self.mr_us(*input_addr).val;
                // Write the bits to the array at dst.
                for (i, (f, (addr, mult))) in
                    fs.into_iter().zip(output_addrs_mults.iter().copied()).enumerate()
                {
                    let felt = Block::from(f);
                    self.mw_us(addr, felt, mult);
                    unsafe {
                        Self::raw_write_ev(
                            &rec.mem_var_events[_offset + i],
                            MemEvent { inner: felt },
                        );
                    }
                }
            }
            Instruction::Ext2Felts(HintExt2FeltsInstr { output_addrs_mults, input_addr }) => {
                state.nb_bit_decompositions += 1;
                let fs = self.mr_us(*input_addr).val;
                for (f, (addr, mult)) in fs.into_iter().zip(output_addrs_mults.iter().copied()) {
                    self.mw_us(addr, Block::from(f), mult);
                }
                // One event carrying the whole input block; the Ext2Felt
                // chip receives it and sends the limbs from the same cells.
                unsafe {
                    Self::raw_write_ev(&rec.ext2felt_events[_offset], MemEvent { inner: fs });
                }
            }
            Instruction::Hint(HintInstr { output_addrs_mults }) => {
                // Check that enough Blocks can be read, so `drain` does not panic.
                if witness.as_mut().expect("witness must be Some at root walker").len()
                    < output_addrs_mults.len()
                {
                    return Err(RuntimeError::EmptyWitnessStream);
                }
                let witness = witness
                    .as_mut()
                    .expect("witness must be Some at root walker")
                    .drain(0..output_addrs_mults.len());
                for (i, ((addr, mult), val)) in
                    zip(output_addrs_mults.iter().copied(), witness).enumerate()
                {
                    // Inline [`Self::mw`] to mutably borrow multiple fields of `self`.
                    self.mw_us(addr, val, mult);
                    unsafe {
                        Self::raw_write_ev(
                            &rec.mem_var_events[_offset + i],
                            MemEvent { inner: val },
                        );
                    }
                }
            }
        }

        state.pc = next_pc;
        state.clk = next_clk;
        state.timestamp += 1;
        Ok(())
    }
}

#[cfg(test)]
mod batch_invert_tests {
    use super::batch_invert;
    use p3_field::{Field, PrimeCharacteristicRing};
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;

    fn check(vals: &[F]) {
        let mut got = vals.to_vec();
        let mut scratch = Vec::new();
        batch_invert(&mut got, &mut scratch);
        for (i, (&v, &inv)) in vals.iter().zip(got.iter()).enumerate() {
            match v.try_inverse() {
                Some(want) => assert_eq!(inv, want, "vals[{i}] = {v:?}"),
                // A zero comes back as a zero — the sentinel the DivF arm
                // reads as "no inverse".
                None => assert_eq!(inv, F::ZERO, "vals[{i}] = {v:?}"),
            }
        }
    }

    #[test]
    fn inverts_every_element() {
        check(&(1u32..64).map(F::from_u32).collect::<Vec<_>>());
    }

    #[test]
    fn carries_zeros_through_without_poisoning_neighbours() {
        check(&[F::ZERO]);
        check(&[F::ZERO, F::from_u32(7)]);
        check(&[F::from_u32(7), F::ZERO]);
        check(&[F::from_u32(3), F::ZERO, F::ZERO, F::from_u32(11), F::ZERO]);
        check(&[F::ZERO; 5]);
    }

    #[test]
    fn handles_the_degenerate_lengths() {
        check(&[]);
        check(&[F::ONE]);
        check(&[F::from_u32(2)]);
    }

    #[test]
    fn reuses_the_scratch_across_calls() {
        // The walker keeps one scratch for a whole program; a stale prefix
        // from a longer previous block must not leak into a shorter one.
        let mut scratch = Vec::new();
        let mut long: Vec<F> = (1u32..40).map(F::from_u32).collect();
        batch_invert(&mut long, &mut scratch);
        let mut short = vec![F::from_u32(5), F::from_u32(9)];
        batch_invert(&mut short, &mut scratch);
        assert_eq!(short[0], F::from_u32(5).inverse());
        assert_eq!(short[1], F::from_u32(9).inverse());
    }
}
