//! The per-instruction "frame" that every instruction-bearing chip needs once
//! the `Cpu` dispatch hub is gone.
//!
//! Today `CpuChip` is a hub: it fetches the instruction (`send_program`), reads
//! and writes the registers (`eval_registers`), chains `(clk, pc)` on the
//! `State` bus, and then hands a fully decoded instruction to the opcode chip
//! over the `Instruction` bus.  The opcode chips are pure receivers.  That costs
//! a second full row per executed instruction: `Cpu` is 59 columns wide and has
//! one row for EVERY instruction, on top of the opcode row that also exists.
//!
//! SP1 has no such chip — each instruction chip carries its own frame, with
//! `Program` / `InstructionFetch` / `InstructionDecode` alongside.  This module
//! is the shared piece that lets Ziren do the same: a chip embeds
//! [`InstructionFrameCols`] and calls [`eval_instruction_frame`], after which it
//! no longer needs `receive_instruction` and `Cpu` no longer needs a row for it.
//!
//! Migration note: the columns here duplicate `CpuCols` deliberately.  While
//! both exist the area is WORSE (both rows are present), so the win only lands
//! when the last chip migrates and `Cpu` is dropped from `MipsAir`.

use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use zkm_core_executor::events::MemoryAccessPosition;
use zkm_derive::AlignedBorrow;
use zkm_pcs::{air::ZKMAirBuilder, Word};

use crate::{
    air::{MemoryAirBuilder, WordAirBuilder, ZKMCoreAirBuilder},
    cpu::columns::InstructionCols,
    memory::{RegisterCols, RegisterReadCols, RegisterReadWriteCols},
};

/// Everything an instruction-bearing chip needs to stand on its own.
///
/// `pc` / `next_pc` are NOT here: most opcode chips already carry them (e.g.
/// `AddSubCols`), so they stay owned by the chip and are passed in.
#[derive(AlignedBorrow, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct InstructionFrameCols<T> {
    /// The shard this instruction executed in.
    pub shard: T,
    /// The least significant 16 bit limb of clk.
    pub clk_16bit_limb: T,
    /// The most significant 8 bit limb of clk.
    pub clk_8bit_limb: T,

    /// The decoded instruction, bound to `pc` through the `Program` bus.
    pub instruction: InstructionCols<T>,

    /// Register accesses for the three operands.
    pub op_a_access: RegisterReadWriteCols<T>,
    pub op_b_access: RegisterReadCols<T>,
    pub op_c_access: RegisterReadCols<T>,

    /// The logical value written to `op_a` (may differ from the register write
    /// when `op_a` is register 0).
    pub op_a_value: Word<T>,
    /// `hi` result, or the previous value of `op_a`, per opcode.
    pub hi_or_prev_a: Word<T>,

    /// Extra cycles this instruction adds to `clk` (syscalls).
    pub num_extra_cycles: T,
    /// Whether the instruction both reads and writes `op_a`.
    pub is_rw_a: T,
    /// Whether `op_a` is an immutable read.
    pub op_a_immutable: T,
    /// The `next_pc` RECEIVED on the `State` bus.  Equals `next_pc` on a normal
    /// row but `pc + 4` on a halt row, so the chain telescopes into the halt.
    pub state_recv_next_pc: T,
}

impl<T: Copy> InstructionFrameCols<T> {
    /// The value of the second operand.
    pub fn op_b_val(&self) -> Word<T> {
        *self.op_b_access.value()
    }

    /// The value of the third operand.
    pub fn op_c_val(&self) -> Word<T> {
        *self.op_c_access.value()
    }
}

/// Evaluate the frame: program fetch, register access, and `(clk, pc)` chaining.
///
/// This is the union of what `CpuChip::eval` does today minus the
/// `send_instruction` dispatch, which disappears entirely once every chip owns
/// its frame.  `is_real` must already be constrained boolean by the caller.
pub fn eval_instruction_frame<AB>(
    builder: &mut AB,
    frame: &InstructionFrameCols<AB::Var>,
    pc: AB::Var,
    next_pc: AB::Var,
    next_next_pc: AB::Expr,
    is_real: AB::Expr,
) where
    AB: ZKMCoreAirBuilder,
{
    let clk = AB::Expr::from_u32(1u32 << 16) * frame.clk_8bit_limb + frame.clk_16bit_limb;

    // ★ On a NON-instruction row every frame column is zero, which would leave
    // the op_b / op_c register-access multiplicities below (`ONE - imm_b`)
    // equal to ONE — the chip would RECEIVE register accesses nobody sent and
    // the LogUp multiset would break with "public-values balance failed".
    //
    // Force the immediate flags high there instead of multiplying the
    // multiplicities by `is_real`: that keeps them degree 1, where
    // `is_real * (ONE - imm_b)` would be degree 2 and risks "degree multiple is
    // too high".  This is exactly the trick `CpuChip::eval` already uses for its
    // padding rows.
    let not_real = AB::Expr::ONE - is_real.clone();
    builder.when(not_real.clone()).assert_zero(AB::Expr::ONE - frame.instruction.imm_b);
    builder.when(not_real).assert_zero(AB::Expr::ONE - frame.instruction.imm_c);

    // The instruction at `pc` must be the one the program committed to.
    builder.send_program(pc, frame.instruction, is_real.clone());

    // Immediates bypass the register read.
    builder
        .when(frame.instruction.imm_b)
        .assert_word_eq(frame.op_b_val(), frame.instruction.op_b);
    builder
        .when(frame.instruction.imm_c)
        .assert_word_eq(frame.op_c_val(), frame.instruction.op_c);

    builder.eval_register_access(
        frame.shard,
        clk.clone() + AB::F::from_u32(MemoryAccessPosition::B as u32),
        frame.instruction.op_b[0],
        &frame.op_b_access,
        AB::Expr::ONE - frame.instruction.imm_b,
    );
    builder.eval_register_access(
        frame.shard,
        clk.clone() + AB::F::from_u32(MemoryAccessPosition::C as u32),
        frame.instruction.op_c[0],
        &frame.op_c_access,
        AB::Expr::ONE - frame.instruction.imm_c,
    );

    // Writes to register 0 are discarded.
    builder.when(frame.instruction.op_a_0).assert_word_zero(*frame.op_a_access.value());
    builder
        .when_not(frame.instruction.op_a_0)
        .assert_word_eq(frame.op_a_value, *frame.op_a_access.value());
    builder
        .when(frame.instruction.op_a_0 * frame.op_a_immutable)
        .assert_word_zero(frame.op_a_value);
    builder
        .when(frame.is_rw_a)
        .assert_word_eq(frame.hi_or_prev_a, frame.op_a_access.prev_value);

    builder.eval_register_access(
        frame.shard,
        clk.clone() + AB::F::from_u32(MemoryAccessPosition::A as u32),
        frame.instruction.op_a,
        &frame.op_a_access,
        is_real.clone(),
    );

    // `(clk, pc)` chaining.  The LogUp multiset balance forces row i+1's
    // `(pc, next_pc)` to equal row i's `(next_pc, next_next_pc)`; the boundary
    // endpoints are emitted by the public-values AIR.
    builder.receive_state(frame.shard, clk.clone(), pc, frame.state_recv_next_pc, is_real.clone());
    builder.send_state(
        frame.shard,
        clk + AB::Expr::from_u32(5) + frame.num_extra_cycles,
        next_pc,
        next_next_pc,
        is_real,
    );
}
