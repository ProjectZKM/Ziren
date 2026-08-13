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
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use zkm_core_executor::events::SyscallEvent;
use zkm_core_executor::events::{
    AluEvent, BranchEvent, ByteLookupEvent, ByteRecord, CompAluEvent, MemoryAccessPosition,
    JumpEvent, MemInstrEvent, MemoryRecordEnum, MiscEvent, MovCondEvent,
    OptionMemoryRecordEnumTag,
};
use zkm_core_executor::{ByteOpcode, Program};
use zkm_derive::AlignedBorrow;
use zkm_pcs::{air::ZKMAirBuilder, Word};

use crate::{
    air::{MemoryAirBuilder, WordAirBuilder, ZKMCoreAirBuilder},
    instruction::InstructionCols,
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
#[allow(clippy::too_many_arguments)]
pub fn eval_instruction_frame<AB>(
    builder: &mut AB,
    frame: &InstructionFrameCols<AB::Var>,
    // Exprs, not Vars: the control-flow and memory chips carry `next_pc` /
    // `next_next_pc` as `Word` columns and pass `word.reduce::<AB>()`.
    pc: AB::Expr,
    next_pc: AB::Expr,
    next_next_pc: AB::Expr,
    // What the `State` receive carries.  Equal to `next_pc` everywhere except
    // the syscall chip's halt row, which receives its predecessor's `pc + 4`
    // lookahead while its own `next_pc` is the exit signal 0.
    recv_next_pc: AB::Expr,
    // Extra cycles this instruction adds to `clk` — ZERO except syscalls.
    num_extra_cycles: AB::Expr,
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
    builder.send_program(pc.clone(), frame.instruction, is_real.clone());

    // Shard fits in 16 bits; clk decomposes into a 16-bit and an 8-bit limb.
    // Mirrors `CpuChip::eval_shard_clk` — the trace side must add the matching
    // U16Range/U8Range byte events for every instruction row.
    builder.send_byte(
        AB::Expr::from_u8(ByteOpcode::U16Range as u8),
        frame.shard,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        is_real.clone(),
    );
    builder.eval_range_check_24bits(
        clk.clone(),
        frame.clk_16bit_limb,
        frame.clk_8bit_limb,
        is_real.clone(),
    );

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
    // The immutable-read rule (`op_a_access.value == prev_value`) lives in the
    // chips that read op_a immutably (Branch, TEQ, the plain stores) — NOT
    // here with a ZERO guard: a zero-guarded constraint still consumes an RLC
    // slot on the verifier while the device bytecode optimizer may elide it.

    builder.eval_register_access(
        frame.shard,
        clk.clone() + AB::F::from_u32(MemoryAccessPosition::A as u32),
        frame.instruction.op_a,
        &frame.op_a_access,
        is_real.clone(),
    );

    // Always range check the word written to `op_a` — mirrors
    // `CpuChip::eval_registers` (JUMP instructions may witness an invalid word).
    builder.slice_range_check_u8(&frame.op_a_access.access.value.0, is_real.clone());

    // `(clk, pc)` chaining.  The LogUp multiset balance forces row i+1's
    // `(pc, next_pc)` to equal row i's `(next_pc, next_next_pc)`; the boundary
    // endpoints are emitted by the public-values AIR.
    builder.receive_state(frame.shard, clk.clone(), pc, recv_next_pc, is_real.clone());
    builder.send_state(
        frame.shard,
        clk + AB::Expr::from_u32(5) + num_extra_cycles,
        next_pc,
        next_next_pc,
        is_real,
    );
}

impl<F: PrimeField32> InstructionFrameCols<F> {
    /// Populate the frame for a REAL instruction from an ALU event, emitting
    /// the byte events its constraints request (shard/clk range checks, the
    /// op_a word range check, and the register-consistency lookups).
    ///
    /// The instruction is fetched from the program by pc, exactly as
    /// `cpu/trace.rs` does — it is not carried in the event.
    pub fn populate_from_alu(
        &mut self,
        event: &AluEvent,
        program: &Program,
        shard: u32,
        blu: &mut impl ByteRecord,
    ) {
        self.populate_raw(
            event.clk,
            event.pc,
            event.recv_next_pc,
            event.a,
            event.b,
            event.c,
            event.a_record,
            event.b_record,
            event.c_record,
            program,
            shard,
            blu,
        );
    }

    /// The shared population body — see [`Self::populate_from_alu`] for the
    /// contract.  Split out because `AluEvent` and `CompAluEvent` carry the
    /// same frame fields but are distinct FFI types.
    #[allow(clippy::too_many_arguments)]
    fn populate_raw(
        &mut self,
        clk: u32,
        pc: u32,
        recv_next_pc: u32,
        a: u32,
        b: u32,
        c: u32,
        a_record: zkm_core_executor::events::OptionMemoryRecordEnum,
        b_record: zkm_core_executor::events::OptionMemoryReadRecord,
        c_record: zkm_core_executor::events::OptionMemoryReadRecord,
        program: &Program,
        shard: u32,
        blu: &mut impl ByteRecord,
    ) {
        self.shard = F::from_u32(shard);
        let clk_16 = (clk & 0xffff) as u16;
        let clk_8 = ((clk >> 16) & 0xff) as u8;
        self.clk_16bit_limb = F::from_u16(clk_16);
        self.clk_8bit_limb = F::from_u8(clk_8);
        blu.add_byte_lookup_event(ByteLookupEvent::new(
            ByteOpcode::U16Range,
            shard as u16,
            0,
            0,
            0,
        ));
        blu.add_byte_lookup_event(ByteLookupEvent::new(ByteOpcode::U16Range, clk_16, 0, 0, 0));
        blu.add_byte_lookup_event(ByteLookupEvent::new(ByteOpcode::U8Range, 0, 0, 0, clk_8));

        self.instruction.populate(&program.fetch(pc));
        let _ = recv_next_pc;

        *self.op_a_access.value_mut() = a.into();
        *self.op_b_access.value_mut() = b.into();
        *self.op_c_access.value_mut() = c.into();
        match a_record.tag {
            OptionMemoryRecordEnumTag::Read => {
                self.op_a_access.populate(MemoryRecordEnum::Read(a_record.read), blu)
            }
            OptionMemoryRecordEnumTag::Write => {
                self.op_a_access.populate(MemoryRecordEnum::Write(a_record.write), blu)
            }
            OptionMemoryRecordEnumTag::None => {}
        }
        if let OptionMemoryRecordEnumTag::Read = b_record.tag {
            self.op_b_access.populate(b_record.read, blu);
        }
        if let OptionMemoryRecordEnumTag::Read = c_record.tag {
            self.op_c_access.populate(c_record.read, blu);
        }

        // The op_a word range check reads back the COLUMN value, exactly as
        // `cpu/trace.rs` does — NOT `a`.  `populate` above overwrites
        // `access.value` with the RECORD's value, and the two differ on a
        // no-link jump (op_a = r0: record value 0, while `a` carries the link).
        // Supplying `a`'s bytes there leaves the AIR's request for (0, 0)
        // unmatched and breaks the Byte bus by exactly 2 events per such row.
        let a_bytes = self
            .op_a_access
            .access
            .value
            .0
            .iter()
            .map(|x| x.as_canonical_u32())
            .collect::<Vec<_>>();
        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a_bytes[0] as u8,
            c: a_bytes[1] as u8,
        });
        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a_bytes[2] as u8,
            c: a_bytes[3] as u8,
        });
    }

    /// `CompAluEvent` variant of [`Self::populate_from_alu`] — the frame
    /// fields carry the same names, so the body is delegated through the
    /// shared raw form.
    pub fn populate_from_comp_alu(
        &mut self,
        event: &CompAluEvent,
        program: &Program,
        shard: u32,
        blu: &mut impl ByteRecord,
    ) {
        self.populate_raw(
            event.clk,
            event.pc,
            event.recv_next_pc,
            event.a,
            event.b,
            event.c,
            event.a_record,
            event.b_record,
            event.c_record,
            program,
            shard,
            blu,
        );
    }

    /// `BranchEvent` variant of [`Self::populate_from_alu`].  The caller must
    /// additionally set `op_a_immutable = ONE`: a branch READS `op_a`, and both
    /// the frame rule and Cpu's legacy bus tuple carry that flag high.
    pub fn populate_from_branch(
        &mut self,
        event: &BranchEvent,
        program: &Program,
        shard: u32,
        blu: &mut impl ByteRecord,
    ) {
        self.populate_raw(
            event.clk,
            event.pc,
            event.recv_next_pc,
            event.a,
            event.b,
            event.c,
            event.a_record,
            event.b_record,
            event.c_record,
            program,
            shard,
            blu,
        );
    }

    /// `JumpEvent` variant of [`Self::populate_from_alu`].  Unlike a branch, a
    /// jump WRITES `op_a` (the link register), so `op_a_immutable` stays 0.  On
    /// a NO-link jump `op_a` is register 0: the record value is 0 while
    /// `event.a` still carries the would-be link — which is why the op_a range
    /// check inside `populate_raw` reads back the COLUMN, not the event.
    pub fn populate_from_jump(
        &mut self,
        event: &JumpEvent,
        program: &Program,
        shard: u32,
        blu: &mut impl ByteRecord,
    ) {
        self.populate_raw(
            event.clk,
            event.pc,
            event.recv_next_pc,
            event.a,
            event.b,
            event.c,
            event.a_record,
            event.b_record,
            event.c_record,
            program,
            shard,
            blu,
        );
    }

    /// `MovCondEvent` variant of [`Self::populate_from_alu`].  MNE/MEQ are
    /// `is_rw_a` instructions: op_a keeps its previous value when the condition
    /// fails, so the frame carries `hi_or_prev_a = prev_a` and the caller sets
    /// `is_rw_a` for them (WSBH is a plain write).
    pub fn populate_from_movcond(
        &mut self,
        event: &MovCondEvent,
        program: &Program,
        shard: u32,
        blu: &mut impl ByteRecord,
    ) {
        self.populate_raw(
            event.clk,
            event.pc,
            event.recv_next_pc,
            event.a,
            event.b,
            event.c,
            event.a_record,
            event.b_record,
            event.c_record,
            program,
            shard,
            blu,
        );
    }

    /// `MiscEvent` variant of [`Self::populate_from_alu`].
    /// MADDU/MSUBU/MADD/MSUB/INS read-and-write op_a (`is_rw_a`); TEQ reads
    /// op_a immutably.  The chip ties both flags in its AIR.
    pub fn populate_from_misc(
        &mut self,
        event: &MiscEvent,
        program: &Program,
        shard: u32,
        blu: &mut impl ByteRecord,
    ) {
        self.populate_raw(
            event.clk,
            event.pc,
            event.recv_next_pc,
            event.a,
            event.b,
            event.c,
            event.a_record,
            event.b_record,
            event.c_record,
            program,
            shard,
            blu,
        );
    }

    /// `MemInstrEvent` variant of [`Self::populate_from_alu`].  Every memory
    /// instruction reads-and-writes op_a (`is_rw_a = 1` — loads write it,
    /// stores carry the previous value through), and the plain stores
    /// (SB/SH/SW/SWL/SWR, but NOT SC, which writes the success flag) read it
    /// immutably.
    pub fn populate_from_mem(
        &mut self,
        event: &MemInstrEvent,
        program: &Program,
        blu: &mut impl ByteRecord,
    ) {
        self.populate_raw(
            event.clk,
            event.pc,
            event.recv_next_pc,
            event.a,
            event.b,
            event.c,
            event.a_record,
            event.b_record,
            event.c_record,
            program,
            event.shard,
            blu,
        );
    }

    /// `SyscallEvent` variant of [`Self::populate_from_alu`].  A syscall
    /// reads-and-writes op_a (the id comes in, the result goes out), so
    /// `is_rw_a = 1` and `hi_or_prev_a` is the op_a PREVIOUS value — read back
    /// from the populated access, since the event carries the write record.
    /// `num_extra_cycles` is byte 3 of the incoming syscall code, exactly as
    /// `cpu/trace.rs` derived it.
    pub fn populate_from_syscall(
        &mut self,
        event: &SyscallEvent,
        program: &Program,
        blu: &mut impl ByteRecord,
    ) {
        let a_record: zkm_core_executor::events::OptionMemoryRecordEnum = if event.a_record_is_real {
            Some(MemoryRecordEnum::Write(event.a_record)).into()
        } else {
            None.into()
        };
        self.populate_raw(
            event.clk,
            event.pc,
            event.recv_next_pc,
            event.a_record.value,
            event.arg1,
            event.arg2,
            a_record,
            event.b_record,
            event.c_record,
            program,
            event.shard,
            blu,
        );
    }

    /// Neutralise the frame on a row that carries no instruction — dependency
    /// rows AND padding rows.  The not-real rule forces the immediate flags
    /// high so the op_b / op_c register-access multiplicities (`ONE - imm_b`)
    /// vanish; forgetting this on either row kind breaks the Memory bus.
    pub fn populate_dependency(&mut self) {
        self.instruction.imm_b = F::ONE;
        self.instruction.imm_c = F::ONE;
    }
}
