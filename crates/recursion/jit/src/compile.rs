//! Program emission: an analyzed recursion program to straight-line x86-64.
//!
//! Phase 2 covers `BaseAlu` Add/Sub/Mul — 35.76% of all recursion
//! instructions and 41.12% of a leaf program.  Everything else, `DivF`
//! included, makes the program ineligible and it stays on the interpreter;
//! there is no partial execution and no mixed mode, so a program either runs
//! entirely as compiled code or entirely as before.
//!
//! What makes the emission trivial is that nothing about an instruction is
//! dynamic.  `analyze()` has already assigned the record offset, and the
//! operand addresses live in the program, so `BaseAlu` becomes:
//!
//! ```text
//!   mov  r8d, [rdi + in1*16]        ; operands: memory is a flat array of
//!   mov  r9d, [rdi + in2*16]        ; 16-byte cells, value at offset 0
//!   <add | sub | montgomery mul>
//!   mov  [rdi + out*16], eax        ; Block::from(out) = [out, 0, 0, 0]
//!   mov  DWORD [rdi + out*16 + 4], 0
//!   mov  DWORD [rdi + out*16 + 8], 0
//!   mov  DWORD [rdi + out*16 + 12], 0
//!   mov  [rsi + off*12], eax        ; BaseAluEvent { out, in1, in2 }
//!   mov  [rsi + off*12 + 4], r8d
//!   mov  [rsi + off*12 + 8], r9d
//! ```
//!
//! No dispatch, no decode, no bounds check — which is where the
//! interpreter's ~100 cycles per instruction go.

use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use zkm_recursion_core::runtime::{
    AnalyzedInstruction, BaseAluOpcode, Instruction, RawProgram, SeqBlock,
};

use p3_koala_bear::KoalaBear;

use crate::x86::{emit_add, emit_mul, emit_sub, PRIME};
use crate::JitError;

/// Bytes per `BaseAluEvent<F>` = `BaseAluIo<F> { out, in1, in2 }`.
pub const BASE_ALU_EVENT_SIZE: usize = 3 * crate::FELT_SIZE;

const _: () = {
    assert!(BASE_ALU_EVENT_SIZE == 12, "the emitted event store is three felts");
};

/// A compiled program, kept alive with its executable buffer.
pub struct Compiled {
    _buf: dynasmrt::ExecutableBuffer,
    entry: RawEntry,
    /// How many instructions were emitted, for the caller's logging.
    pub emitted: usize,
}

/// `(memory base, base_alu event base) -> status`, SysV register arguments.
type RawEntry = unsafe extern "C" fn(*mut u8, *mut u8) -> u32;

impl Compiled {
    /// Run the compiled program.
    ///
    /// # Safety
    /// `mem` must point at the runtime's memory array with at least as many
    /// 16-byte cells as the highest address the program touches, and
    /// `base_alu_events` at least `emitted` events of 12 bytes.  Both are
    /// guaranteed by construction when the caller passes the arrays that
    /// `analyze()` sized, which is why compilation records the maxima it saw.
    pub unsafe fn run(&self, mem: *mut u8, base_alu_events: *mut u8) -> u32 {
        (self.entry)(mem, base_alu_events)
    }
}

/// The largest byte displacement an emitted instruction may use.
///
/// x86 displacements are signed 32-bit.  A program addressing past this
/// cannot be emitted with the simple form and is rejected rather than
/// silently truncated.
const MAX_DISP: usize = i32::MAX as usize;

/// Compile an analyzed program, or explain why it cannot be.
///
/// # Errors
/// Returns [`JitError::Unsupported`] for any instruction this phase cannot
/// emit, and for a program whose addressing exceeds a 32-bit displacement.
pub fn compile<F: PrimeField64>(
    program: &RawProgram<AnalyzedInstruction<F>>,
) -> Result<Compiled, JitError> {
    let mut ops = dynasmrt::x64::Assembler::new().map_err(|_| JitError::Unavailable)?;
    let entry = ops.offset();

    // Callee-saved, because the emitted body uses them across the whole
    // program and the SysV caller expects them preserved.
    // rbx and r12 hold the two bases for the whole program, r13/r14 carry
    // operands across a call-out.  All four are callee-saved, so a call-out
    // preserves them for free.  SysV wants rsp 16-byte aligned AT the call:
    // entry leaves rsp = 8 (mod 16), four pushes bring it back to 8, so one
    // more 8 makes it 0.
    dynasm!(ops
        ; .arch x64
        ; push rbx
        ; push r12
        ; push r13
        ; push r14
        ; sub rsp, 8
        ; mov r12, rsi          // r12 = base_alu event array
        ; mov rbx, rdi          // rbx = memory
    );

    let mut emitted = 0usize;
    emit_blocks(&mut ops, &program.seq_blocks, &mut emitted)?;

    dynasm!(ops
        ; .arch x64
        ; mov eax, DWORD STATUS_OK as i32
        ; jmp ->epilogue
        // A trapped instruction lands here with its status already in eax.
        ; ->fail:
        ; ->epilogue:
        ; add rsp, 8
        ; pop r14
        ; pop r13
        ; pop r12
        ; pop rbx
        ; ret
    );

    let buf = ops.finalize().map_err(|_| JitError::Unavailable)?;
    let ptr = buf.ptr(entry);
    Ok(Compiled {
        entry: unsafe { std::mem::transmute::<*const u8, RawEntry>(ptr) },
        _buf: buf,
        emitted,
    })
}

fn emit_blocks<F: PrimeField64>(
    ops: &mut dynasmrt::x64::Assembler,
    blocks: &[SeqBlock<AnalyzedInstruction<F>>],
    emitted: &mut usize,
) -> Result<(), JitError> {
    for block in blocks {
        match block {
            SeqBlock::Basic(basic) => {
                for ai in &basic.instrs {
                    emit_one(ops, ai, emitted)?;
                }
            }
            // A parallel group is emitted as its sequential concatenation.
            // The runtime's own parallelism is an optimisation over
            // disjoint address ranges, so running them in order is
            // semantically identical — just not yet parallel.
            SeqBlock::Parallel(subs) => {
                for sub in subs {
                    emit_blocks(ops, &sub.seq_blocks, emitted)?;
                }
            }
        }
    }
    Ok(())
}

fn disp(addr: usize, stride: usize) -> Result<i32, JitError> {
    let d = addr.checked_mul(stride).ok_or(JitError::Unsupported("address overflow"))?;
    if d > MAX_DISP {
        return Err(JitError::Unsupported("displacement exceeds 32 bits"));
    }
    Ok(d as i32)
}

fn emit_one<F: PrimeField64>(
    ops: &mut dynasmrt::x64::Assembler,
    ai: &AnalyzedInstruction<F>,
    emitted: &mut usize,
) -> Result<(), JitError> {
    match ai.inner() {
        Instruction::BaseAlu(instr) => {
            let op = match instr.opcode {
                BaseAluOpcode::AddF => Op::Add,
                BaseAluOpcode::SubF => Op::Sub,
                BaseAluOpcode::MulF => Op::Mul,
                // Division is a call-out, not an emitted fragment: it needs a
                // field inverse and its zero-divisor case has three outcomes,
                // one of which must trap.  It is NOT rare -- 16.8% of BaseAlu
                // on a leaf program -- so without this the JIT compiles
                // nothing at all, because one unsupported instruction rejects
                // the whole program.
                BaseAluOpcode::DivF => Op::Div { is_assert: false },
                BaseAluOpcode::DivFAssert => Op::Div { is_assert: true },
            };
            let in1 = disp(instr.addrs.in1.as_usize(), crate::MEMORY_ENTRY_SIZE)?;
            let in2 = disp(instr.addrs.in2.as_usize(), crate::MEMORY_ENTRY_SIZE)?;
            let out = disp(instr.addrs.out.as_usize(), crate::MEMORY_ENTRY_SIZE)?;
            let ev = disp(ai.offset(), BASE_ALU_EVENT_SIZE)?;

            dynasm!(ops
                ; .arch x64
                ; mov r8d, [rbx + in1]
                ; mov r9d, [rbx + in2]
                ; mov eax, r8d
                ; mov ecx, r9d
            );
            match op {
                Op::Add => emit_add(ops),
                Op::Sub => emit_sub(ops),
                Op::Mul => emit_mul(ops),
                Op::Div { is_assert } => {
                    // `mult` is a compile-time constant, so the two flags the
                    // helper needs are folded into one immediate here rather
                    // than being read at run time.
                    let mut flags = 0u32;
                    if instr.mult.is_zero() {
                        flags |= FLAG_MULT_IS_ZERO;
                    }
                    if is_assert {
                        flags |= FLAG_IS_ASSERT;
                    }
                    dynasm!(ops
                        ; .arch x64
                        ; mov r13d, r8d          // keep the operands across
                        ; mov r14d, r9d          // the call (callee-saved)
                        ; mov edi, r8d
                        ; mov esi, r9d
                        ; mov edx, DWORD flags as i32
                        ; mov rax, QWORD div_f as usize as i64
                        ; call rax
                        ; mov rcx, rax
                        ; shr rcx, 32            // status in the high word;
                                                 // shr sets ZF, so ZF=1 means
                                                 // status 0, i.e. SUCCESS
                        ; jz >ok
                        ; mov eax, ecx
                        ; jmp ->fail
                        ; ok:
                        ; mov r8d, r13d
                        ; mov r9d, r14d
                    );
                }
            }
            dynasm!(ops
                ; .arch x64
                // Block::from(out) writes the value and zeroes the three
                // remaining lanes; the interpreter's `mw_us` does the same.
                ; mov [rbx + out], eax
                ; mov DWORD [rbx + out + 4], 0
                ; mov DWORD [rbx + out + 8], 0
                ; mov DWORD [rbx + out + 12], 0
                // BaseAluEvent { out, in1, in2 }, in declaration order.
                ; mov [r12 + ev], eax
                ; mov [r12 + ev + 4], r8d
                ; mov [r12 + ev + 8], r9d
            );
            *emitted += 1;
            Ok(())
        }
        Instruction::ExtAlu(_) => Err(JitError::Unsupported("ExtAlu")),
        Instruction::Mem(_) => Err(JitError::Unsupported("Mem")),
        Instruction::Poseidon2(_) => Err(JitError::Unsupported("Poseidon2")),
        Instruction::Select(_) => Err(JitError::Unsupported("Select")),
        Instruction::HintBits(_) => Err(JitError::Unsupported("HintBits")),
        Instruction::HintAddCurve(_) => Err(JitError::Unsupported("HintAddCurve")),
        Instruction::Print(_) => Err(JitError::Unsupported("Print")),
        Instruction::HintExt2Felts(_) => Err(JitError::Unsupported("HintExt2Felts")),
        Instruction::Ext2Felts(_) => Err(JitError::Unsupported("Ext2Felts")),
        Instruction::CommitPublicValues(_) => Err(JitError::Unsupported("CommitPublicValues")),
        Instruction::Hint(_) => Err(JitError::Unsupported("Hint")),
    }
}

enum Op {
    Add,
    Sub,
    Mul,
    Div { is_assert: bool },
}

/// Status returned by a compiled program: 0 on success, non-zero when an
/// instruction trapped and the caller must fall back to the interpreter to
/// reproduce the exact error.
pub const STATUS_OK: u32 = 0;
/// A `DivF` hit the out-of-domain case that the interpreter reports as
/// `RuntimeError::DivFOutOfDomain`.
pub const STATUS_DIV_OUT_OF_DOMAIN: u32 = 1;

/// Flag bits packed into the call-out's third argument.
const FLAG_MULT_IS_ZERO: u32 = 1;
const FLAG_IS_ASSERT: u32 = 2;

/// `BaseAlu` division, as a call-out.
///
/// Division needs a field inverse, which is far too much to inline, and its
/// zero-divisor case is not arithmetic at all — it is a soundness assertion
/// with three outcomes.  This reproduces `execute_one`'s arm exactly:
///
/// * `in2 != 0` — the quotient.
/// * `in2 == 0, in1 == 0` — one.
/// * `in2 == 0, in1 != 0, mult == 0, not an assert` — zero, because a dead
///   `DivF`'s result is never read.
/// * otherwise — out of domain, which must trip.
///
/// Returns the value in the low word and the status in the high word, so the
/// emitted code needs no stack slot for the error channel.
extern "C" fn div_f(in1: u32, in2: u32, flags: u32) -> u64 {
    use p3_field::{Field, PrimeCharacteristicRing};
    // SAFETY: `MontyField31` is `#[repr(transparent)]` over `u32`, asserted
    // by the layout contract in `lib.rs`.
    let a: KoalaBear = unsafe { core::mem::transmute::<u32, KoalaBear>(in1) };
    let b: KoalaBear = unsafe { core::mem::transmute::<u32, KoalaBear>(in2) };
    let out = match b.try_inverse().map(|x| x * a) {
        Some(x) => x,
        None => {
            if a.is_zero() {
                KoalaBear::ONE
            } else if flags & FLAG_MULT_IS_ZERO != 0 && flags & FLAG_IS_ASSERT == 0 {
                KoalaBear::ZERO
            } else {
                return u64::from(STATUS_DIV_OUT_OF_DOMAIN) << 32;
            }
        }
    };
    u64::from(unsafe { core::mem::transmute::<KoalaBear, u32>(out) })
}

/// The prime, re-exported so tests can build reduced values without
/// depending on the emitter module directly.
pub const P: u32 = PRIME;
