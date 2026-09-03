//! Producer backend: the JIT as the parent's `TraceChunk` producer.
//!
//! The interpreter's `execute_minimal` walks every instruction of the
//! program to produce, per shard, exactly what a worker's replay needs:
//! the memory-read oracle (`recording_chunk_mem_reads`), the register
//! records at the shard boundary, and the boundary itself (the
//! `ShardSplitAccumulator` fence).  This backend emits the same three
//! things natively, so the parent runs the guest at JIT speed and only
//! drops into the interpreter for the instructions that need it
//! (syscalls, traps).
//!
//! Per MIPS instruction the emitted code is the plain lowering from
//! [`crate::driver::lower_one`] (memory ops, the trapping div family and
//! TEQ are lowered here instead) followed by:
//!
//! * **register stamps** — `ctx.reg_stamps[r] = (shard << 32) | (clk +
//!   position)` for every register the interpreter's `rr`/`rw` stamps,
//!   at the highest position it is accessed at (C < B < A < HI);
//! * the **clock** — the pinned [`CLK_SHARD`] register holds `(shard <<
//!   32) | (clk + 3)`, bumped by 5 per instruction;
//! * **shard accounting** — the area budget in the pinned [`AREA_LEFT`]
//!   register and the per-air height budgets in `ctx.height_left` are
//!   charged the exact amounts the interpreter's charging block adds to
//!   the accumulator (supplied per instruction as a [`ProducerInstr`]),
//!   and every charged budget is checked for exhaustion: `<= 0` means
//!   the interpreter's `inc_shard_if_need` would fence here, and the
//!   function exits with [`super::JIT_EXIT_SHARD_FENCE`] so the host
//!   seals the chunk and re-enters.
//!
//! Memory operations translate the guest address against the flat
//! 16-byte-entry memory (`ctx.memory` = `FlatMem::as_ptr()`), copy the
//! entry's `MemValue` to the oracle tail (pinned [`ORACLE_TAIL`]) for
//! addresses `>= 36` exactly as the flat `mr`/`mw` do, charge a touched
//! address when the entry's shard differs from the current one, and
//! stamp the entry with `(clk, shard)`.
//!
//! Anything the interpreter can fail on (division by zero, TEQ, an
//! out-of-bounds or misaligned address, an unlowerable operand form)
//! and every SYSCALL is a *trap site*: the code stores the instruction's
//! PC and jumps to the shared interpreter stub, whose host handler runs
//! that one instruction in the interpreter and resumes the JIT at the
//! resulting PC.  The interpreter thus owns every error path, the
//! unconstrained blocks' bookkeeping, and the precompiles.
//!
//! Delay slots are resolved statically: the program is rejected (host
//! falls back to the interpreter) when a branch/jump is followed by
//! another branch/jump or ends the program, so only the instruction
//! after a branch/jump reads the delayed target.  It rolls
//! `delayed_jump_target` into `pending_jump_at_start` at its start and
//! dispatches through the jump table at its end; the pending slot is
//! never cleared, so nothing else may read it.
//!
//! Register/pinning conventions extend the block JIT's: `r15` =
//! clock+shard, `rsi` = oracle tail, `r8` = area budget; all three are
//! saved to the context around every host call and on exit.

use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};

use super::{
    TranspilerBackend, AREA_LEFT_OFFSET, CLK_LIMIT_OFFSET, CLK_SHARD_OFFSET, CONTEXT,
    DELAYED_JUMP_TARGET_OFFSET, EXIT_CODE_OFFSET, HEIGHT_LEFT_OFFSET, JIT_EXIT_BAD_JUMP,
    JIT_EXIT_FALL_OFF, JIT_EXIT_ORACLE_FULL, JIT_EXIT_SHARD_FENCE, JUMP_TABLE, JUMP_TABLE_LEN_OFFSET,
    JUMP_TABLE_OFFSET, MEMORY_OFFSET, MEMORY_PTR, ORACLE_END_OFFSET, ORACLE_TAIL_OFFSET, PC_OFFSET,
    PENDING_JUMP_AT_START_OFFSET, REG_STAMPS_OFFSET, SHARD_OFFSET, TEMP_A, TEMP_B, TOUCHED_OFFSET,
    BAD_JUMP_TARGET_OFFSET,
};
use crate::driver::{lower_one, DriverError, DriverInstruction, JitOpcode};
use crate::risc::MipsRegister;
use crate::{JitError, JitFunction, SyscallHandler};

/// Pinned `(shard << 32) | (clk + 3)`.
pub const CLK_SHARD: u8 = 15; // r15
/// Pinned oracle tail pointer (`*mut MemValue`, 12-byte stride).
pub const ORACLE_TAIL: u8 = 6; // rsi
/// Pinned trace-area budget (`i64`, fence when `<= 0`).
pub const AREA_LEFT: u8 = 8; // r8

/// Access positions, matching the executor's `MemoryAccessPosition`.
pub const POS_C: u8 = 1;
/// See [`POS_C`].
pub const POS_B: u8 = 2;
/// See [`POS_C`].
pub const POS_A: u8 = 3;
/// See [`POS_C`].
pub const POS_HI: u8 = 4;

/// Most distinct airs one instruction charges (INS: its own + ROR, SLL,
/// SRL, ADD).
pub const MAX_CHARGES: usize = 6;
/// Most registers one instruction stamps (DIV: C, B, LO, HI).
pub const MAX_STAMPS: usize = 4;

/// One height charge: `height_left[slot] -= count`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeightCharge {
    /// Index into `ctx.height_left` (the executor's `MipsAirId` slot).
    pub slot: u8,
    /// Rows charged.
    pub count: u8,
}

/// What the executor charges and stamps for one instruction, computed
/// host-side from the charging block and the per-opcode register
/// access pattern.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProducerInstr {
    /// Trace-area cells the instruction charges.
    pub area: i64,
    /// Height charges (`n_heights` valid).
    pub heights: [HeightCharge; MAX_CHARGES],
    /// Valid prefix of `heights`.
    pub n_heights: u8,
    /// `(register, position)` stamps (`n_stamps` valid); one entry per
    /// register, at its highest position.
    pub stamps: [(u8, u8); MAX_STAMPS],
    /// Valid prefix of `stamps`.
    pub n_stamps: u8,
    /// Slots charged by the preceding branch/jump, checked here when
    /// this is its delay slot (`n_pred` valid).
    pub pred_slots: [u8; MAX_CHARGES],
    /// Valid prefix of `pred_slots`.
    pub n_pred: u8,
    /// This instruction is the delay slot of the previous one.
    pub delay_slot: bool,
}

/// Program-wide producer parameters.
#[derive(Clone, Copy, Debug)]
pub struct ProducerConfig {
    /// Address of instruction 0.
    pub pc_base: u32,
    /// `MipsAirId::Global`'s slot and per-row cost.
    pub global_slot: u8,
    /// See `global_slot`.
    pub global_cost: i64,
    /// `MipsAirId::MemoryLocal`'s slot and per-row cost.
    pub memory_local_slot: u8,
    /// See `memory_local_slot`.
    pub memory_local_cost: i64,
    /// The executor's `MAX_MEMORY`: an aligned address at or past it traps.
    pub max_memory: u32,
    /// Host handler behind the interpreter stub (runs one instruction).
    pub syscall_handler: SyscallHandler,
}

/// Why a program cannot run on the producer (the host uses the
/// interpreter instead).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProducerReject {
    /// A branch/jump is followed by another branch/jump.
    BranchInDelaySlot(u32),
    /// A branch/jump is the last instruction.
    BranchAtEnd(u32),
    /// A branch/jump operand form the lowering does not model
    /// (BEQ/BNE with an immediate comparand, JR/JALR with an immediate).
    BranchForm(u32),
}

const fn is_branch(op: JitOpcode) -> bool {
    matches!(
        op,
        JitOpcode::Beq
            | JitOpcode::Bne
            | JitOpcode::Bgez
            | JitOpcode::Bgtz
            | JitOpcode::Blez
            | JitOpcode::Bltz
    )
}

const fn is_jump(op: JitOpcode) -> bool {
    matches!(op, JitOpcode::Jump | JitOpcode::Jumpi | JitOpcode::JumpDirect)
}

const fn is_load(op: JitOpcode) -> bool {
    matches!(
        op,
        JitOpcode::Lb
            | JitOpcode::Lbu
            | JitOpcode::Lh
            | JitOpcode::Lhu
            | JitOpcode::Lw
            | JitOpcode::Lwl
            | JitOpcode::Lwr
            | JitOpcode::Ll
    )
}

const fn is_store(op: JitOpcode) -> bool {
    matches!(
        op,
        JitOpcode::Sb | JitOpcode::Sh | JitOpcode::Sw | JitOpcode::Swl | JitOpcode::Swr | JitOpcode::Sc
    )
}

/// Static check of the delay-slot scheme and the branch forms.
pub fn producer_reject(instrs: &[DriverInstruction]) -> Option<ProducerReject> {
    for (i, ins) in instrs.iter().enumerate() {
        let op = JitOpcode::from_u8(ins.opcode);
        if !(is_branch(op) || is_jump(op)) {
            continue;
        }
        let i = i as u32;
        match op {
            JitOpcode::Beq | JitOpcode::Bne if ins.imm_b => return Some(ProducerReject::BranchForm(i)),
            JitOpcode::Jump if ins.imm_b => return Some(ProducerReject::BranchForm(i)),
            _ => {}
        }
        match instrs.get(i as usize + 1) {
            None => return Some(ProducerReject::BranchAtEnd(i)),
            Some(next) => {
                let nop = JitOpcode::from_u8(next.opcode);
                if is_branch(nop) || is_jump(nop) {
                    return Some(ProducerReject::BranchInDelaySlot(i));
                }
            }
        }
    }
    None
}

/// The instruction runs in the interpreter (trap site) rather than
/// natively: forms `lower_one` folds differently from the interpreter,
/// statically invalid encodings, and everything unlowerable.
pub fn runs_in_interpreter(ins: &DriverInstruction) -> bool {
    let op = JitOpcode::from_u8(ins.opcode);
    let any_imm = ins.imm_b || ins.imm_c;
    match op {
        JitOpcode::Syscall | JitOpcode::Unimpl => true,
        // `alu_rr` reads `op_b` as a register whenever `op_c` is one.
        JitOpcode::Add
        | JitOpcode::Sub
        | JitOpcode::And
        | JitOpcode::Or
        | JitOpcode::Xor
        | JitOpcode::Slt
        | JitOpcode::Sltu
        | JitOpcode::Sll
        | JitOpcode::Srl
        | JitOpcode::Sra
        | JitOpcode::Ror
        | JitOpcode::Clz
        | JitOpcode::Clo => ins.imm_b && !ins.imm_c,
        // `lower_one` folds a lone immediate against 0 for these.
        JitOpcode::Nor | JitOpcode::Mul => ins.imm_b != ins.imm_c,
        // Lowered here; register operands only.
        JitOpcode::Mult
        | JitOpcode::Multu
        | JitOpcode::Div
        | JitOpcode::Divu
        | JitOpcode::Mod
        | JitOpcode::Modu
        | JitOpcode::Meq
        | JitOpcode::Mne => any_imm,
        // The interpreter writes LO = op_a; the lowering writes LO.
        JitOpcode::Madd | JitOpcode::Maddu | JitOpcode::Msub | JitOpcode::Msubu => {
            any_imm || ins.op_a != MipsRegister::Lo.index()
        }
        // The interpreter ignores the immediate flags on the misc class.
        JitOpcode::Sext | JitOpcode::Wsbh => any_imm,
        JitOpcode::Ext => any_imm || (ins.op_c >> 5) + (ins.op_c & 0x1f) >= 32,
        JitOpcode::Ins => any_imm || (ins.op_c >> 5) < (ins.op_c & 0x1f),
        JitOpcode::Teq => ins.imm_b,
        _ if is_load(op) || is_store(op) => ins.op_b >= 36,
        _ => false,
    }
}

/// Cold code emitted after the fall-off, one entry per site.
enum Cold {
    /// Fence: store the resume PC (the delayed target wins in a delay
    /// slot) and exit with `JIT_EXIT_SHARD_FENCE`.
    Fence { label: dynasmrt::DynamicLabel, pc_next: u32, delay_slot: bool },
    /// Oracle full: un-roll the delay slot, store the PC to re-execute
    /// and exit with `JIT_EXIT_ORACLE_FULL`.
    Full { label: dynasmrt::DynamicLabel, pc: u32, delay_slot: bool },
    /// Trap: store the PC and run the instruction in the interpreter.
    Trap { label: dynasmrt::DynamicLabel, pc: u32 },
    /// Touched address: charge and return to the access.
    Touch { label: dynasmrt::DynamicLabel, back: dynasmrt::DynamicLabel },
}

struct Shared {
    interp_stub: dynasmrt::DynamicLabel,
    fence_exit: dynasmrt::DynamicLabel,
    fence_exit_pending: dynasmrt::DynamicLabel,
    full_exit: dynasmrt::DynamicLabel,
    full_exit_unroll: dynasmrt::DynamicLabel,
    bad_jump: dynasmrt::DynamicLabel,
    touch: dynasmrt::DynamicLabel,
    exit: dynasmrt::DynamicLabel,
}

/// Build the producer function for `instrs` (instruction `i` at
/// `pc_base + 4 * i`) with per-instruction plans `plans`.
///
/// # Errors
///
/// Returns `Err` when an instruction cannot be lowered or the code
/// buffer cannot be finalized.
///
/// # Panics
///
/// Panics when `plans.len() != instrs.len()` or a plan holds a charge
/// or stamp out of range.
pub fn build_producer(
    instrs: &[DriverInstruction],
    plans: &[ProducerInstr],
    cfg: &ProducerConfig,
) -> Result<JitFunction, DriverError> {
    assert_eq!(instrs.len(), plans.len(), "one plan per instruction");
    let mut t = TranspilerBackend::new().map_err(|e| DriverError::Jit(JitError::Io(e)))?;
    t.set_pc_base(cfg.pc_base);
    t.syscall_handler = Some(cfg.syscall_handler);
    let shared = Shared {
        interp_stub: t.assembler.new_dynamic_label(),
        fence_exit: t.assembler.new_dynamic_label(),
        fence_exit_pending: t.assembler.new_dynamic_label(),
        full_exit: t.assembler.new_dynamic_label(),
        full_exit_unroll: t.assembler.new_dynamic_label(),
        bad_jump: t.assembler.new_dynamic_label(),
        touch: t.assembler.new_dynamic_label(),
        exit: t.exit_label.expect("exit label set in `new`"),
    };
    let mut cold: Vec<Cold> = Vec::new();

    t.emit_prologue();
    t.emit_load_all_registers();
    emit_load_pinned(&mut t);
    t.emit_dispatch_to_ctx_pc();

    for (i, (ins, plan)) in instrs.iter().zip(plans).enumerate() {
        let pc = cfg.pc_base.wrapping_add((i as u32).wrapping_mul(4));
        let op = JitOpcode::from_u8(ins.opcode);
        t.jump_table.push(t.assembler.offset().0);

        if plan.delay_slot {
            dynasm!(t.assembler ; .arch x64
                ; mov eax, DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET]
                ; mov DWORD [Rq(CONTEXT) + PENDING_JUMP_AT_START_OFFSET], eax
                ; mov DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET], 0
            );
        }

        if runs_in_interpreter(ins) {
            let stub = shared.interp_stub;
            dynasm!(t.assembler ; .arch x64
                ; mov DWORD [Rq(CONTEXT) + PC_OFFSET], DWORD pc as i32
                ; jmp =>stub
            );
            continue;
        }

        let trap = t.assembler.new_dynamic_label();
        let mut trap_used = false;
        let control_flow = is_branch(op) || is_jump(op);
        let memory = is_load(op) || is_store(op);

        // ── body ────────────────────────────────────────────
        if memory {
            let full = t.assembler.new_dynamic_label();
            let touch = t.assembler.new_dynamic_label();
            let back = t.assembler.new_dynamic_label();
            emit_memory_op(&mut t, op, ins, cfg, trap, full, touch, back);
            trap_used = true;
            cold.push(Cold::Full { label: full, pc, delay_slot: plan.delay_slot });
            cold.push(Cold::Touch { label: touch, back });
        } else {
            match op {
                JitOpcode::Div | JitOpcode::Divu | JitOpcode::Mod | JitOpcode::Modu => {
                    emit_div(&mut t, op, ins, trap);
                    trap_used = true;
                }
                JitOpcode::Teq => {
                    t.emit_register_load(MipsRegister::from_u8(ins.op_a), TEMP_A);
                    t.emit_register_load(MipsRegister::from_u8(ins.op_b as u8), TEMP_B);
                    dynasm!(t.assembler ; .arch x64
                        ; cmp Rd(TEMP_A), Rd(TEMP_B)
                        ; je =>trap
                    );
                    trap_used = true;
                }
                _ => lower_one(&mut t, *ins, pc)?,
            }
        }
        if trap_used {
            cold.push(Cold::Trap { label: trap, pc });
        }

        // ── stamps, clock ───────────────────────────────────
        for &(reg, pos) in &plan.stamps[..plan.n_stamps as usize] {
            assert!(reg < 36 && (POS_C..=POS_HI).contains(&pos), "stamp ({reg}, {pos})");
            let off = REG_STAMPS_OFFSET + i32::from(reg) * 8;
            if pos == POS_A {
                dynasm!(t.assembler ; .arch x64
                    ; mov QWORD [Rq(CONTEXT) + off], Rq(CLK_SHARD)
                );
            } else {
                let delta = i32::from(pos) - i32::from(POS_A);
                dynasm!(t.assembler ; .arch x64
                    ; lea rax, [Rq(CLK_SHARD) + delta]
                    ; mov QWORD [Rq(CONTEXT) + off], rax
                );
            }
        }
        dynasm!(t.assembler ; .arch x64 ; add Rq(CLK_SHARD), 5);

        // ── charges and fence checks ────────────────────────
        let area = i32::try_from(plan.area).expect("area charge fits i32");
        let heights = &plan.heights[..plan.n_heights as usize];
        if control_flow {
            // Charged now, checked by the delay slot.
            if area != 0 {
                dynasm!(t.assembler ; .arch x64 ; sub Rq(AREA_LEFT), DWORD area);
            }
            for h in heights {
                let off = HEIGHT_LEFT_OFFSET + i32::from(h.slot) * 8;
                dynasm!(t.assembler ; .arch x64
                    ; sub QWORD [Rq(CONTEXT) + off], DWORD i32::from(h.count)
                );
            }
        } else {
            let fence = t.assembler.new_dynamic_label();
            // CHARGE FIRST, THEN CHECK. The interpreter applies the whole of
            // `charge_instruction` and only then evaluates `inc_shard_if_need`,
            // so a fence must never pre-empt a charge: a `sub` fused with its
            // own `jle` drops the rest of this instruction's charges on the
            // fencing path, and the shard closes one instruction light. (That
            // was the original shape here, and it cost the shard-closing
            // instruction its row on all 124 clk-fenced reth shards.)
            if area != 0 {
                dynasm!(t.assembler ; .arch x64 ; sub Rq(AREA_LEFT), DWORD area);
            }
            for h in heights {
                let off = HEIGHT_LEFT_OFFSET + i32::from(h.slot) * 8;
                dynasm!(t.assembler ; .arch x64
                    ; sub QWORD [Rq(CONTEXT) + off], DWORD i32::from(h.count)
                );
            }
            dynasm!(t.assembler ; .arch x64
                ; cmp Rd(CLK_SHARD), DWORD [Rq(CONTEXT) + CLK_LIMIT_OFFSET]
                ; jae =>fence
            );
            // A charge of 0 leaves the budget where the last check found it,
            // so only a charged budget (or one the predecessor charged, or the
            // touch stub's) needs re-testing.
            if area != 0 || memory || plan.delay_slot {
                dynasm!(t.assembler ; .arch x64
                    ; test Rq(AREA_LEFT), Rq(AREA_LEFT)
                    ; jle =>fence
                );
            }
            let charged = |slot: u8| heights.iter().any(|h| h.slot == slot);
            let mut check_slot = |t: &mut TranspilerBackend, slot: u8| {
                let off = HEIGHT_LEFT_OFFSET + i32::from(slot) * 8;
                dynasm!(t.assembler ; .arch x64
                    ; cmp QWORD [Rq(CONTEXT) + off], 0
                    ; jle =>fence
                );
            };
            for h in heights {
                check_slot(&mut t, h.slot);
            }
            // The touch stub charges `Global` (and every fourth touch
            // `MemoryLocal`) inside the instruction body.
            if memory {
                for slot in [cfg.global_slot, cfg.memory_local_slot] {
                    if !charged(slot) {
                        check_slot(&mut t, slot);
                    }
                }
            }
            if plan.delay_slot {
                for &slot in &plan.pred_slots[..plan.n_pred as usize] {
                    if !charged(slot) {
                        check_slot(&mut t, slot);
                    }
                }
            }
            cold.push(Cold::Fence {
                label: fence,
                pc_next: pc.wrapping_add(4),
                delay_slot: plan.delay_slot,
            });
        }

        // ── delay-slot dispatch ─────────────────────────────
        if plan.delay_slot {
            let pc_base = cfg.pc_base;
            let bad = shared.bad_jump;
            dynasm!(t.assembler ; .arch x64
                ; mov eax, DWORD [Rq(CONTEXT) + PENDING_JUMP_AT_START_OFFSET]
                ; test eax, eax
                ; jz >sequential
                ; sub eax, DWORD pc_base as i32
                ; shr eax, 2
                ; cmp eax, DWORD [Rq(CONTEXT) + JUMP_TABLE_LEN_OFFSET]
                ; jae =>bad
                ; jmp QWORD [Rq(JUMP_TABLE) + rax * 8]
                ; sequential:
            );
        }
    }

    // Fall-off: the PC after the last instruction.
    let pc_end = cfg.pc_base.wrapping_add((instrs.len() as u32).wrapping_mul(4));
    let exit = shared.exit;
    dynasm!(t.assembler ; .arch x64
        ; mov DWORD [Rq(CONTEXT) + PC_OFFSET], DWORD pc_end as i32
        ; mov DWORD [Rq(CONTEXT) + EXIT_CODE_OFFSET], DWORD JIT_EXIT_FALL_OFF as i32
        ; jmp =>exit
    );

    emit_shared_stubs(&mut t, &shared, cfg);
    for c in cold {
        emit_cold(&mut t, &shared, c);
    }

    t.bind_exit_label();
    t.emit_spill_all_registers();
    emit_save_pinned(&mut t);
    t.emit_epilogue();
    t.finalize(cfg.pc_base).map_err(DriverError::Jit)
}

fn emit_load_pinned(t: &mut TranspilerBackend) {
    dynasm!(t.assembler ; .arch x64
        ; mov Rq(CLK_SHARD), QWORD [Rq(CONTEXT) + CLK_SHARD_OFFSET]
        ; mov Rq(ORACLE_TAIL), QWORD [Rq(CONTEXT) + ORACLE_TAIL_OFFSET]
        ; mov Rq(AREA_LEFT), QWORD [Rq(CONTEXT) + AREA_LEFT_OFFSET]
    );
}

fn emit_save_pinned(t: &mut TranspilerBackend) {
    dynasm!(t.assembler ; .arch x64
        ; mov QWORD [Rq(CONTEXT) + CLK_SHARD_OFFSET], Rq(CLK_SHARD)
        ; mov QWORD [Rq(CONTEXT) + ORACLE_TAIL_OFFSET], Rq(ORACLE_TAIL)
        ; mov QWORD [Rq(CONTEXT) + AREA_LEFT_OFFSET], Rq(AREA_LEFT)
    );
}

/// Loads, stores: translate, bounds/alignment traps, the oracle push,
/// the touched-address charge, the stamp, then the access itself.
#[allow(clippy::too_many_arguments)]
fn emit_memory_op(
    t: &mut TranspilerBackend,
    op: JitOpcode,
    ins: &DriverInstruction,
    cfg: &ProducerConfig,
    trap: dynasmrt::DynamicLabel,
    full: dynasmrt::DynamicLabel,
    touch: dynasmrt::DynamicLabel,
    back: dynasmrt::DynamicLabel,
) {
    let rd = MipsRegister::from_u8(ins.op_a);
    let rs = MipsRegister::from_u8(ins.op_b as u8);
    let imm = ins.op_c as i32;
    let align_mask = match op {
        JitOpcode::Lw | JitOpcode::Ll | JitOpcode::Sw | JitOpcode::Sc => Some(3),
        JitOpcode::Lh | JitOpcode::Lhu | JitOpcode::Sh => Some(1),
        _ => None,
    };
    // TEMP_A = aligned address, eax = byte offset within the word.
    t.emit_register_load(rs, TEMP_A);
    dynasm!(t.assembler ; .arch x64
        ; add Rd(TEMP_A), DWORD imm
        ; mov eax, Rd(TEMP_A)
        ; and eax, 3
        ; and Rd(TEMP_A), -4
        ; cmp Rd(TEMP_A), DWORD cfg.max_memory as i32
        ; jae =>trap
    );
    if let Some(mask) = align_mask {
        dynasm!(t.assembler ; .arch x64
            ; test eax, mask
            ; jnz =>trap
        );
    }
    // TEMP_B = host address of the 16-byte entry.
    dynasm!(t.assembler ; .arch x64
        ; mov Rq(TEMP_B), Rq(TEMP_A)
        ; shl Rq(TEMP_B), 2
        ; add Rq(TEMP_B), Rq(MEMORY_PTR)
        // Oracle push of the entry's `MemValue` (value, timestamp, shard)
        // for non-register addresses.
        ; cmp Rq(ORACLE_TAIL), QWORD [Rq(CONTEXT) + ORACLE_END_OFFSET]
        ; ja =>full
        ; mov rcx, QWORD [Rq(TEMP_B)]
        ; mov edx, DWORD [Rq(TEMP_B) + 8]
        ; cmp Rd(TEMP_A), 36
        ; jb >no_push
        ; mov QWORD [Rq(ORACLE_TAIL)], rcx
        ; mov DWORD [Rq(ORACLE_TAIL) + 8], edx
        ; add Rq(ORACLE_TAIL), 12
        ; no_push:
        // Touched address when the previous access was another shard's.
        ; cmp edx, DWORD [Rq(CONTEXT) + SHARD_OFFSET]
        ; jne =>touch
        ; =>back
        // Stamp (timestamp = clk, shard).
        ; lea rdx, [Rq(CLK_SHARD) - 3]
        ; mov QWORD [Rq(TEMP_B) + 4], rdx
    );
    match op {
        JitOpcode::Lb => {
            dynasm!(t.assembler ; .arch x64 ; movsx Rd(TEMP_A), BYTE [Rq(TEMP_B) + rax]);
            t.emit_register_store(rd, TEMP_A);
        }
        JitOpcode::Lbu => {
            dynasm!(t.assembler ; .arch x64 ; movzx Rd(TEMP_A), BYTE [Rq(TEMP_B) + rax]);
            t.emit_register_store(rd, TEMP_A);
        }
        JitOpcode::Lh => {
            dynasm!(t.assembler ; .arch x64 ; movsx Rd(TEMP_A), WORD [Rq(TEMP_B) + rax]);
            t.emit_register_store(rd, TEMP_A);
        }
        JitOpcode::Lhu => {
            dynasm!(t.assembler ; .arch x64 ; movzx Rd(TEMP_A), WORD [Rq(TEMP_B) + rax]);
            t.emit_register_store(rd, TEMP_A);
        }
        JitOpcode::Lw | JitOpcode::Ll => {
            dynasm!(t.assembler ; .arch x64 ; mov Rd(TEMP_A), DWORD [Rq(TEMP_B)]);
            t.emit_register_store(rd, TEMP_A);
        }
        JitOpcode::Lwl => {
            // rt = (rt & !(0xFFFFFFFF << (24 - 8i))) | (mem << (24 - 8i))
            dynasm!(t.assembler ; .arch x64
                ; mov ecx, eax
                ; shl ecx, 3
                ; neg ecx
                ; add ecx, 24
                ; mov eax, DWORD [Rq(TEMP_B)]
                ; shl eax, cl
                ; mov edx, -1
                ; shl edx, cl
                ; not edx
            );
            t.emit_register_load(rd, TEMP_A);
            dynasm!(t.assembler ; .arch x64
                ; and Rd(TEMP_A), edx
                ; or Rd(TEMP_A), eax
            );
            t.emit_register_store(rd, TEMP_A);
        }
        JitOpcode::Lwr => {
            // rt = (rt & !(0xFFFFFFFF >> 8i)) | (mem >> 8i)
            dynasm!(t.assembler ; .arch x64
                ; mov ecx, eax
                ; shl ecx, 3
                ; mov eax, DWORD [Rq(TEMP_B)]
                ; shr eax, cl
                ; mov edx, -1
                ; shr edx, cl
                ; not edx
            );
            t.emit_register_load(rd, TEMP_A);
            dynasm!(t.assembler ; .arch x64
                ; and Rd(TEMP_A), edx
                ; or Rd(TEMP_A), eax
            );
            t.emit_register_store(rd, TEMP_A);
        }
        JitOpcode::Sb => {
            t.emit_register_load(rd, 1); // ecx
            dynasm!(t.assembler ; .arch x64 ; mov BYTE [Rq(TEMP_B) + rax], cl);
        }
        JitOpcode::Sh => {
            t.emit_register_load(rd, 1);
            dynasm!(t.assembler ; .arch x64 ; mov WORD [Rq(TEMP_B) + rax], cx);
        }
        JitOpcode::Sw => {
            t.emit_register_load(rd, 1);
            dynasm!(t.assembler ; .arch x64 ; mov DWORD [Rq(TEMP_B)], ecx);
        }
        JitOpcode::Sc => {
            t.emit_register_load(rd, 1);
            dynasm!(t.assembler ; .arch x64
                ; mov DWORD [Rq(TEMP_B)], ecx
                ; mov Rd(TEMP_A), 1
            );
            t.emit_register_store(rd, TEMP_A);
        }
        JitOpcode::Swl => {
            // mem = (mem & !(0xFFFFFFFF >> (24 - 8i))) | (rt >> (24 - 8i))
            dynasm!(t.assembler ; .arch x64
                ; mov ecx, eax
                ; shl ecx, 3
                ; neg ecx
                ; add ecx, 24
            );
            t.emit_register_load(rd, 2); // edx
            dynasm!(t.assembler ; .arch x64
                ; shr edx, cl
                ; mov eax, -1
                ; shr eax, cl
                ; not eax
                ; and eax, DWORD [Rq(TEMP_B)]
                ; or eax, edx
                ; mov DWORD [Rq(TEMP_B)], eax
            );
        }
        JitOpcode::Swr => {
            // mem = (mem & !(0xFFFFFFFF << 8i)) | (rt << 8i)
            dynasm!(t.assembler ; .arch x64
                ; mov ecx, eax
                ; shl ecx, 3
            );
            t.emit_register_load(rd, 2);
            dynasm!(t.assembler ; .arch x64
                ; shl edx, cl
                ; mov eax, -1
                ; shl eax, cl
                ; not eax
                ; and eax, DWORD [Rq(TEMP_B)]
                ; or eax, edx
                ; mov DWORD [Rq(TEMP_B)], eax
            );
        }
        _ => unreachable!("not a memory op: {op:?}"),
    }
}

/// DIV/DIVU/MOD/MODU with the interpreter's zero-divisor trap.
fn emit_div(
    t: &mut TranspilerBackend,
    op: JitOpcode,
    ins: &DriverInstruction,
    trap: dynasmrt::DynamicLabel,
) {
    let rd = MipsRegister::from_u8(ins.op_a);
    let rs = MipsRegister::from_u8(ins.op_b as u8);
    let rt = MipsRegister::from_u8(ins.op_c as u8);
    t.emit_register_load(rs, 0); // eax
    t.emit_register_load(rt, TEMP_B);
    dynasm!(t.assembler ; .arch x64
        ; test Rd(TEMP_B), Rd(TEMP_B)
        ; jz =>trap
    );
    match op {
        JitOpcode::Div | JitOpcode::Mod => {
            // 64-bit idiv on sign-extended operands: INT_MIN / -1 yields
            // 0x8000_0000 instead of the interpreter's overflow panic.
            dynasm!(t.assembler ; .arch x64
                ; movsxd rax, eax
                ; movsxd Rq(TEMP_B), Rd(TEMP_B)
                ; cqo
                ; idiv Rq(TEMP_B)
            );
        }
        _ => {
            dynasm!(t.assembler ; .arch x64
                ; xor edx, edx
                ; div Rd(TEMP_B)
            );
        }
    }
    match op {
        JitOpcode::Div | JitOpcode::Divu => {
            t.emit_register_store(MipsRegister::Lo, 0);
            dynasm!(t.assembler ; .arch x64 ; mov Rd(TEMP_A), edx);
            t.emit_register_store(MipsRegister::Hi, TEMP_A);
        }
        _ => {
            dynasm!(t.assembler ; .arch x64 ; mov Rd(TEMP_A), edx);
            t.emit_register_store(rd, TEMP_A);
        }
    }
}

fn emit_shared_stubs(t: &mut TranspilerBackend, s: &Shared, cfg: &ProducerConfig) {
    let Shared {
        interp_stub,
        fence_exit,
        fence_exit_pending,
        full_exit,
        full_exit_unroll,
        bad_jump,
        touch,
        exit,
    } = *s;

    // Interpreter stub: hand the instruction at ctx.pc to the host,
    // then resume at whatever PC it left.
    let handler = cfg.syscall_handler as usize;
    dynasm!(t.assembler ; .arch x64 ; =>interp_stub);
    t.emit_spill_all_registers();
    emit_save_pinned(t);
    dynasm!(t.assembler ; .arch x64
        ; push rax
        ; mov rdi, Rq(CONTEXT)
        ; mov rax, QWORD handler as i64
        ; call rax
        ; pop rcx
        ; mov Rq(JUMP_TABLE), QWORD [Rq(CONTEXT) + JUMP_TABLE_OFFSET]
        ; mov Rq(MEMORY_PTR), QWORD [Rq(CONTEXT) + MEMORY_OFFSET]
    );
    emit_load_pinned(t);
    t.emit_load_all_registers();
    dynasm!(t.assembler ; .arch x64
        ; cmp DWORD [Rq(CONTEXT) + EXIT_CODE_OFFSET], 0
        ; jne =>exit
    );
    t.emit_dispatch_to_ctx_pc();

    dynasm!(t.assembler ; .arch x64
        ; =>fence_exit_pending
        ; mov eax, DWORD [Rq(CONTEXT) + PENDING_JUMP_AT_START_OFFSET]
        ; test eax, eax
        ; jz =>fence_exit
        ; mov DWORD [Rq(CONTEXT) + PC_OFFSET], eax
        ; =>fence_exit
        ; mov DWORD [Rq(CONTEXT) + EXIT_CODE_OFFSET], DWORD JIT_EXIT_SHARD_FENCE as i32
        ; jmp =>exit

        ; =>full_exit_unroll
        ; mov eax, DWORD [Rq(CONTEXT) + PENDING_JUMP_AT_START_OFFSET]
        ; mov DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET], eax
        ; =>full_exit
        ; mov DWORD [Rq(CONTEXT) + EXIT_CODE_OFFSET], DWORD JIT_EXIT_ORACLE_FULL as i32
        ; jmp =>exit

        ; =>bad_jump
        ; mov eax, DWORD [Rq(CONTEXT) + PENDING_JUMP_AT_START_OFFSET]
        ; mov DWORD [Rq(CONTEXT) + BAD_JUMP_TARGET_OFFSET], eax
        ; mov DWORD [Rq(CONTEXT) + EXIT_CODE_OFFSET], DWORD JIT_EXIT_BAD_JUMP as i32
        ; jmp =>exit
    );

    // Touched address (`ShardSplitAccumulator::add_touched_address`):
    // every 4th touch is a MemoryLocal row, every touch two Global rows.
    let ml_off = HEIGHT_LEFT_OFFSET + i32::from(cfg.memory_local_slot) * 8;
    let g_off = HEIGHT_LEFT_OFFSET + i32::from(cfg.global_slot) * 8;
    let ml_cost = i32::try_from(cfg.memory_local_cost).expect("MemoryLocal cost fits i32");
    let g_cost2 = i32::try_from(cfg.global_cost * 2).expect("Global cost fits i32");
    dynasm!(t.assembler ; .arch x64
        ; =>touch
        ; mov rcx, QWORD [Rq(CONTEXT) + TOUCHED_OFFSET]
        ; add QWORD [Rq(CONTEXT) + TOUCHED_OFFSET], 1
        ; test cl, 3
        ; jnz >global
        ; sub Rq(AREA_LEFT), DWORD ml_cost
        ; sub QWORD [Rq(CONTEXT) + ml_off], 1
        ; global:
        ; sub Rq(AREA_LEFT), DWORD g_cost2
        ; sub QWORD [Rq(CONTEXT) + g_off], 2
        ; ret
    );
}

fn emit_cold(t: &mut TranspilerBackend, s: &Shared, c: Cold) {
    match c {
        Cold::Fence { label, pc_next, delay_slot } => {
            let target = if delay_slot { s.fence_exit_pending } else { s.fence_exit };
            dynasm!(t.assembler ; .arch x64
                ; =>label
                ; mov DWORD [Rq(CONTEXT) + PC_OFFSET], DWORD pc_next as i32
                ; jmp =>target
            );
        }
        Cold::Full { label, pc, delay_slot } => {
            let target = if delay_slot { s.full_exit_unroll } else { s.full_exit };
            dynasm!(t.assembler ; .arch x64
                ; =>label
                ; mov DWORD [Rq(CONTEXT) + PC_OFFSET], DWORD pc as i32
                ; jmp =>target
            );
        }
        Cold::Trap { label, pc } => {
            let stub = s.interp_stub;
            dynasm!(t.assembler ; .arch x64
                ; =>label
                ; mov DWORD [Rq(CONTEXT) + PC_OFFSET], DWORD pc as i32
                ; jmp =>stub
            );
        }
        Cold::Touch { label, back } => {
            let touch = s.touch;
            dynasm!(t.assembler ; .arch x64
                ; =>label
                ; call =>touch
                ; jmp =>back
            );
        }
    }
}
