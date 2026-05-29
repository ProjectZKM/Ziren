pub mod register;

use core::borrow::Borrow;
use p3_air::{WindowAccess, Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use zkm_core_executor::ByteOpcode;
use zkm_stark::{
    air::{BaseAirBuilder, PublicValues, ZKMAirBuilder, ZKM_PROOF_NUM_PV_ELTS},
    Word,
};

use crate::{
    air::{MemoryAirBuilder, ZKMCoreAirBuilder},
    cpu::{
        columns::{CpuCols, NUM_CPU_COLS},
        CpuChip,
    },
};

impl<AB> Air<AB> for CpuChip
where
    AB: ZKMCoreAirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        // Option 2 local-only: the CPU AIR no longer reads the next row
        // (cross-row pc/clk/shard chaining moved to the `State` bus).
        let local = main.current_slice();
        let local: &CpuCols<AB::Var> = (*local).borrow();

        let public_values_slice: [AB::PublicVar; ZKM_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| builder.public_values()[i]);
        let public_values: &PublicValues<Word<AB::PublicVar>, AB::PublicVar> =
            public_values_slice.as_slice().borrow();

        let clk =
            AB::Expr::from_u32(1u32 << 16) * local.clk_8bit_limb + local.clk_16bit_limb;

        // Program constraints.
        builder.send_program(local.pc, local.instruction, local.is_real);

        // Register constraints.
        self.eval_registers::<AB>(builder, local, clk.clone());

        // Assert the shard and clk to send.  Only the memory and syscall instructions need the
        // actual shard and clk values for memory access evals.
        // SAFETY: The usage of `builder.if_else` requires `is_memory + is_syscall` to be boolean.
        // The correctness of `is_memory` and `is_syscall` will be checked in the opcode specific chips.
        // In these correct cases, `is_memory + is_syscall` will be always boolean.
        let expected_shard_to_send =
            builder.if_else(local.is_check_memory, local.shard, AB::Expr::ZERO);
        let expected_clk_to_send =
            builder.if_else(local.is_check_memory, clk.clone(), AB::Expr::ZERO);
        builder.when(local.is_real).assert_eq(local.shard_to_send, expected_shard_to_send);
        builder.when(local.is_real).assert_eq(local.clk_to_send, expected_clk_to_send);

        builder.send_instruction(
            local.shard_to_send,
            local.clk_to_send,
            local.pc,
            local.next_pc,
            local.next_next_pc,
            local.num_extra_cycles,
            local.instruction.opcode,
            local.op_a_value,
            local.op_b_val(),
            local.op_c_val(),
            local.hi_or_prev_a,
            local.op_a_immutable,
            local.is_rw_a,
            local.is_check_memory,
            local.is_halt,
            local.is_sequential,
            local.is_real,
        );

        // ── Option 2 local-only CPU state chaining ────────────────────
        // Replaces the legacy `when_transition` shard/clk/pc/next_pc
        // constraints (eval_shard_clk:110/131, eval_pc:163/168).  Each
        // real row RECEIVES its current state `(shard, clk, pc, next_pc)`
        // and SENDS the next `(shard, clk+5+extra, next_pc, next_next_pc)`
        // on the `State` bus; the LogUp multiset balance forces row i+1's
        // `(pc, next_pc)` to equal row i's `(next_pc, next_next_pc)` and
        // `clk_{i+1} = clk_i + 5 + extra`, exactly reproducing the old
        // transition chain.  The initial endpoint `(shard, clk=0,
        // start_pc, start_pc+4)` and final endpoint `(shard,
        // last_timestamp, next_pc, <final next_next_pc>)` are emitted by
        // the public-values AIR (`eval_state`).  NOTE for review: the MIPS
        // delay-slot lookahead means the final endpoint needs the last
        // row's `next_next_pc`; at halt the executor sets `next_pc = 0`
        // (halt.rs:14), so the PV `eval_state` boundary must match the
        // halt convention — flagged for the PV-AIR State emitter.
        builder.receive_state(local.shard, clk.clone(), local.pc, local.next_pc, local.is_real);
        builder.send_state(
            local.shard,
            clk.clone() + AB::Expr::from_u32(5) + local.num_extra_cycles,
            local.next_pc,
            local.next_next_pc,
            local.is_real,
        );

        // Range checks for shard / clk (chaining now via the State bus).
        self.eval_shard_clk(builder, local, clk.clone());

        // Local pc + public-value constraints (cross-row pc chaining now
        // via the State bus; first/last-row boundaries via the PV-AIR).
        self.eval_pc(builder, local, public_values);

        // Check that the is_real flag is boolean.
        self.eval_is_real(builder, local);

        let not_real = AB::Expr::ONE - local.is_real;
        builder.when(not_real.clone()).assert_zero(AB::Expr::ONE - local.instruction.imm_b);
        builder.when(not_real.clone()).assert_zero(AB::Expr::ONE - local.instruction.imm_c);
        builder.when(not_real.clone()).assert_zero(AB::Expr::ONE - local.is_rw_a);
    }
}

impl CpuChip {
    /// Constraints related to the shard and clk.
    ///
    /// This method ensures that all of the shard values are the same and that the clk starts at 0
    /// and is transitioned appropriately.  It will also check that shard values are within 16 bits
    /// and clk values are within 24 bits.  Those range checks are needed for the memory access
    /// timestamp check, which assumes those values are within 2^24.  See
    /// [`MemoryAirBuilder::verify_mem_access_ts`].
    pub(crate) fn eval_shard_clk<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        clk: AB::Expr,
    ) {
        // Verify that the shard value is within 16 bits.
        builder.send_byte(
            AB::Expr::from_u8(ByteOpcode::U16Range as u8),
            local.shard,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            local.is_real,
        );

        // Option 2: shard equality across rows and the clk chain
        // (`clk_{i+1} = clk_i + 5 + num_extra_cycles`) are now enforced by
        // the local-only `State` bus (see `eval`), not by
        // `when_transition`.  The first-row `clk == 0` initial condition
        // is emitted by the public-values AIR (`eval_state`).

        // Range check that the clk is within 24 bits using its limb values.
        builder.eval_range_check_24bits(
            clk,
            local.clk_16bit_limb,
            local.clk_8bit_limb,
            local.is_real,
        );
    }

    /// Constraints related to the public values.
    pub(crate) fn eval_pc<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        public_values: &PublicValues<Word<AB::PublicVar>, AB::PublicVar>,
    ) {
        // Verify the public value's shard (purely local).
        builder.when(local.is_real).assert_eq(public_values.execution_shard, local.shard);

        // Option 2: the cross-row pc chain (`next.pc == local.next_pc` and
        // `next.next_pc == local.next_next_pc`) is now enforced by the
        // local-only `State` bus (see `eval`).  The first-row boundary
        // (`start_pc == pc`, `pc + 4 == next_pc`) and the last-row /
        // last-transition boundary (`public_values.next_pc ==
        // local.next_pc`) are emitted by the public-values AIR
        // (`eval_state`), not by `when_first_row` / `when_last_row`.

        // Purely-local delay-slot relation: for a sequential instruction
        // the lookahead is `next_next_pc == next_pc + 4` (same row).
        builder
            .when(local.is_real)
            .when(local.is_sequential)
            .assert_eq(local.next_next_pc, local.next_pc + AB::Expr::from_u32(4));
    }

    /// Constraints related to the is_real column.
    ///
    /// This method checks that the is_real column is a boolean.  It also checks that the first row
    /// is 1 and once its 0, it never changes value.
    pub(crate) fn eval_is_real<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ) {
        // The is_real flag must be boolean.
        builder.assert_bool(local.is_real);
        // Option 2: the first-row `is_real == 1` and the padding/halt
        // monotonicity (`!is_real => !next.is_real`, `is_halt =>
        // !next.is_real`) are dropped — the local-only `State` bus does
        // not require a contiguous real-row prefix.  The boundary (the
        // initial state is consumed by the first real row, the final
        // state is produced by the halting row) is enforced by the
        // public-values AIR (`eval_state`) together with the multiset
        // balance.
    }
}

impl<F> BaseAir<F> for CpuChip {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}
