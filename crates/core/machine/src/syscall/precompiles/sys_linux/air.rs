use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use zkm_core_executor::{syscalls::SyscallCode, Register};
use zkm_stark::{
    air::{LookupScope, ZKMAirBuilder},
    Word,
};

use super::{
    columns::{SysLinuxCols, NUM_SYS_LINUX_COLS},
    SysLinuxChip,
};
use crate::{
    air::{MemoryAirBuilder, WordAirBuilder},
    memory::MemoryCols,
    operations::{AddOperation, GtColsBytes, IsZeroOperation},
};
use zkm_stark::air::BaseAirBuilder;

impl<F> BaseAir<F> for SysLinuxChip {
    fn width(&self) -> usize {
        NUM_SYS_LINUX_COLS
    }
}

impl<AB> Air<AB> for SysLinuxChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SysLinuxCols<AB::Var> = (*local).borrow();

        // ── Phase 1: Canonical syscall decoder ─────────────────────────
        // Derive all branch selectors from syscall_id via IsZeroOperation.
        // Each decode_X.result = 1 iff syscall_id == CODE_X.
        let sid: AB::Expr = local.syscall_id.into();

        IsZeroOperation::<AB::F>::eval(
            builder,
            sid.clone() - AB::Expr::from_canonical_u32(SyscallCode::SYS_MMAP as u32),
            local.decode_mmap,
            local.is_real.into(),
        );
        IsZeroOperation::<AB::F>::eval(
            builder,
            sid.clone() - AB::Expr::from_canonical_u32(SyscallCode::SYS_MMAP2 as u32),
            local.decode_mmap2,
            local.is_real.into(),
        );
        IsZeroOperation::<AB::F>::eval(
            builder,
            sid.clone() - AB::Expr::from_canonical_u32(SyscallCode::SYS_CLONE as u32),
            local.decode_clone,
            local.is_real.into(),
        );
        IsZeroOperation::<AB::F>::eval(
            builder,
            sid.clone() - AB::Expr::from_canonical_u32(SyscallCode::SYS_EXT_GROUP as u32),
            local.decode_exit_group,
            local.is_real.into(),
        );
        IsZeroOperation::<AB::F>::eval(
            builder,
            sid.clone() - AB::Expr::from_canonical_u32(SyscallCode::SYS_BRK as u32),
            local.decode_brk,
            local.is_real.into(),
        );
        IsZeroOperation::<AB::F>::eval(
            builder,
            sid.clone() - AB::Expr::from_canonical_u32(SyscallCode::SYS_FCNTL as u32),
            local.decode_fnctl,
            local.is_real.into(),
        );
        IsZeroOperation::<AB::F>::eval(
            builder,
            sid.clone() - AB::Expr::from_canonical_u32(SyscallCode::SYS_READ as u32),
            local.decode_read,
            local.is_real.into(),
        );
        IsZeroOperation::<AB::F>::eval(
            builder,
            sid - AB::Expr::from_canonical_u32(SyscallCode::SYS_WRITE as u32),
            local.decode_write,
            local.is_real.into(),
        );

        // Convenience aliases (all AB::Var except is_mmap which is stored).
        let is_clone = local.decode_clone.result;
        let is_exit_group = local.decode_exit_group.result;
        let is_brk = local.decode_brk.result;
        let is_fnctl = local.decode_fnctl.result;
        let is_read = local.decode_read.result;
        let is_write = local.decode_write.result;

        // is_mmap is stored as a column for degree reasons.
        builder.when(local.is_real).assert_eq(
            local.is_mmap,
            local.decode_mmap.result + local.decode_mmap2.result,
        );
        builder.assert_bool(local.is_mmap);

        // is_nop = is_real - sum_of_recognized (derived, not stored).
        let recognized_sum: AB::Expr = local.is_mmap.into()
            + is_clone
            + is_exit_group
            + is_brk
            + is_fnctl
            + is_read
            + is_write;
        let is_nop: AB::Expr = local.is_real.into() - recognized_sum.clone();
        // One-hot: recognized_sum + is_nop = is_real, and is_nop is boolean.
        builder.when(local.is_real).assert_bool(is_nop.clone());

        // ── Phase 1b: Canonical a0 / a1 decoder ───────────────────────
        let a0_reduce = local.a0.reduce::<AB>();
        IsZeroOperation::<AB::F>::eval(
            builder,
            a0_reduce.clone(),
            local.decode_a0_0,
            local.is_real.into(),
        );
        IsZeroOperation::<AB::F>::eval(
            builder,
            a0_reduce.clone() - AB::Expr::one(),
            local.decode_a0_1,
            local.is_real.into(),
        );
        IsZeroOperation::<AB::F>::eval(
            builder,
            a0_reduce - AB::Expr::two(),
            local.decode_a0_2,
            local.is_real.into(),
        );

        let a1_reduce = local.a1.reduce::<AB>();
        IsZeroOperation::<AB::F>::eval(
            builder,
            a1_reduce.clone() - AB::Expr::one(),
            local.decode_a1_1,
            local.is_real.into(),
        );
        IsZeroOperation::<AB::F>::eval(
            builder,
            a1_reduce - AB::Expr::from_canonical_u32(3),
            local.decode_a1_3,
            local.is_real.into(),
        );

        let is_a0_0 = local.decode_a0_0.result;
        let is_a0_1 = local.decode_a0_1.result;
        let is_a0_2 = local.decode_a0_2.result;
        let is_a1_1 = local.decode_a1_1.result;
        let is_a1_3 = local.decode_a1_3.result;

        // ── Composite flags ────────────────────────────────────────────
        builder.assert_eq(local.is_mmap_a0_0, local.is_mmap * is_a0_0);
        builder.assert_eq(local.is_fnctl_a1_1, is_fnctl * is_a1_1);
        builder.assert_eq(local.is_fnctl_a1_3, is_fnctl * is_a1_3);

        // ── Branch evaluations ─────────────────────────────────────────
        self.eval_brk(builder, local, is_brk);
        self.eval_clone(builder, local, is_clone);
        self.eval_exit_group(builder, local, is_exit_group);
        self.eval_fnctl(builder, local, is_fnctl, is_a0_0, is_a0_1, is_a0_2, is_a1_1, is_a1_3);
        self.eval_read(builder, local, is_read, is_a0_0);
        self.eval_write(builder, local, is_write);
        self.eval_mmap(builder, local, is_a0_0);
        self.eval_nop(builder, local, is_nop);

        // ── A3 output memory access (shared) ───────────────────────────
        builder.eval_memory_access(
            local.shard,
            local.clk,
            AB::Expr::from_canonical_u32(Register::A3 as u32),
            &local.output,
            local.is_real,
        );

        // ── Cross-chip interactions ────────────────────────────────────
        builder.receive_syscall(
            local.shard,
            local.clk,
            local.syscall_id,
            local.a0.reduce::<AB>(),
            local.a1.reduce::<AB>(),
            local.is_real,
            LookupScope::Local,
        );

        builder.receive_syscall_result(
            local.shard,
            local.clk,
            local.result,
            local.a0,
            local.a1,
            local.is_real,
            LookupScope::Local,
        );
    }
}

impl SysLinuxChip {
    fn eval_brk<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &SysLinuxCols<AB::Var>,
        is_brk: AB::Var,
    ) {
        // MemoryReadCols structurally enforces value == prev_value.
        builder.eval_memory_access(
            local.shard,
            local.clk,
            AB::Expr::from_canonical_u32(Register::BRK as u32),
            &local.read_access,
            is_brk,
        );

        GtColsBytes::<AB::F>::eval(
            builder,
            local.a0,
            *local.read_access.value(),
            is_brk,
            local.is_a0_gt_brk,
        );
        // v0 = max(a0, brk)
        builder
            .when(is_brk)
            .when(local.is_a0_gt_brk.result)
            .assert_word_eq(local.result, local.a0);
        builder
            .when(is_brk)
            .when_not(local.is_a0_gt_brk.result)
            .assert_word_eq(local.result, *local.read_access.prev_value());

        builder.when(is_brk).assert_word_zero(*local.output.value());
    }

    fn eval_clone<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &SysLinuxCols<AB::Var>,
        is_clone: AB::Var,
    ) {
        builder.when(is_clone).assert_word_zero(*local.output.value());
        builder.when(is_clone).assert_one(local.result[0]);
        builder.when(is_clone).assert_zero(local.result[1]);
        builder.when(is_clone).assert_zero(local.result[2]);
        builder.when(is_clone).assert_zero(local.result[3]);
    }

    fn eval_mmap<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &SysLinuxCols<AB::Var>,
        is_a0_0: AB::Var,
    ) {
        // ── Byte-level a1 decomposition (Phase 3) ──────────────────────
        // Decompose a1[1] = a1_byte1_lo + a1_byte1_hi * 16.
        let mut a1_byte1_hi = AB::Expr::zero();
        for bit in 0..4 {
            builder.when(local.is_mmap).assert_bool(local.a1_byte1_hi_bits[bit]);
            a1_byte1_hi = a1_byte1_hi
                + local.a1_byte1_hi_bits[bit] * AB::Expr::from_canonical_u32(1 << bit);
        }
        builder.when(local.is_mmap).assert_eq(
            local.a1[1],
            local.a1_byte1_lo + a1_byte1_hi.clone() * AB::Expr::from_canonical_u32(16),
        );
        // Range check a1_byte1_lo < 16 via byte lookup.
        builder.send_byte(
            AB::Expr::from_canonical_u8(zkm_core_executor::ByteOpcode::U16Range as u8),
            local.a1_byte1_lo,
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_mmap,
        );

        // page_offset = a1[0] + a1_byte1_lo * 256 (directly from bytes, no reduce()).
        builder.when(local.is_mmap).assert_eq(
            local.page_offset,
            local.a1[0] + local.a1_byte1_lo * AB::Expr::from_canonical_u32(256),
        );

        // upper_address from bytes: a1_byte1_hi * 4096 + a1[2] * 65536 + a1[3] * 16777216.
        builder.when(local.is_mmap).assert_eq(
            local.upper_address,
            a1_byte1_hi * AB::Expr::from_canonical_u32(4096)
                + local.a1[2] * AB::Expr::from_canonical_u32(65536)
                + local.a1[3] * AB::Expr::from_canonical_u32(16777216),
        );

        // Prove upper_address is page-aligned.
        builder.when(local.is_mmap).assert_eq(
            local.upper_address,
            local.upper_address_pages * AB::Expr::from_canonical_u32(4096),
        );

        // Bidirectional is_offset_0 = (page_offset == 0).
        IsZeroOperation::<AB::F>::eval(
            builder,
            local.page_offset.into(),
            local.is_page_offset_zero,
            local.is_mmap.into(),
        );
        builder
            .when(local.is_mmap)
            .assert_eq(local.is_offset_0, local.is_page_offset_zero.result);

        // mmap_size Word matching the field-level size computation.
        let size_field = local.upper_address
            + AB::Expr::from_canonical_u32(0x1000) * (AB::Expr::one() - local.is_offset_0);
        builder
            .when(local.is_mmap)
            .when(is_a0_0)
            .assert_eq(local.mmap_size.reduce::<AB>(), size_field);
        builder
            .when(local.is_mmap)
            .when(is_a0_0)
            .slice_range_check_u8(&local.mmap_size.0, local.is_mmap_a0_0.into());

        // Bytewise heap update: new_heap = old_heap + mmap_size.
        AddOperation::<AB::F>::eval(
            builder,
            local.heap_write.prev_value,
            local.mmap_size,
            local.heap_add,
            local.is_mmap_a0_0.into(),
        );
        builder
            .when(local.is_mmap_a0_0)
            .assert_word_eq(*local.heap_write.value(), local.heap_add.value);

        // Heap memory access (only active for mmap with a0==0).
        builder.eval_memory_access(
            local.shard,
            local.clk,
            AB::Expr::from_canonical_u32(Register::HEAP as u32),
            &local.heap_write,
            local.is_mmap_a0_0,
        );

        // result = prev_heap when a0==0, result = a0 otherwise.
        builder
            .when(local.is_mmap_a0_0)
            .assert_word_eq(local.heap_write.prev_value, local.result);
        builder
            .when(local.is_mmap)
            .when_not(is_a0_0)
            .assert_word_eq(local.a0, local.result);

        // mmap always writes A3 = 0.
        builder
            .when(local.is_mmap)
            .assert_word_zero(*local.output.value());
    }

    fn eval_exit_group<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &SysLinuxCols<AB::Var>,
        is_exit_group: AB::Var,
    ) {
        builder.when(is_exit_group).assert_word_zero(*local.output.value());
        builder.when(is_exit_group).assert_word_zero(local.result);
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_fnctl<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &SysLinuxCols<AB::Var>,
        is_fnctl: AB::Var,
        is_a0_0: AB::Var,
        is_a0_1: AB::Var,
        is_a0_2: AB::Var,
        is_a1_1: AB::Var,
        is_a1_3: AB::Var,
    ) {
        // fnctl(a1==1, F_GETFD) result constraints.
        builder
            .when(local.is_fnctl_a1_1)
            .when(is_a0_0)
            .assert_word_zero(local.result);
        builder
            .when(local.is_fnctl_a1_1)
            .when(is_a0_1)
            .assert_word_eq(local.result, Word::<AB::Expr>::from(1u32));
        builder
            .when(local.is_fnctl_a1_1)
            .when(is_a0_2)
            .assert_word_eq(local.result, Word::<AB::Expr>::from(2u32));
        builder
            .when(local.is_fnctl_a1_1)
            .when_not(is_a0_0 + is_a0_1 + is_a0_2)
            .assert_word_eq(local.result, Word::<AB::Expr>::from(0xFFFFFFFFu32));

        // fnctl(a1==3, F_GETFL) result constraints.
        builder
            .when(local.is_fnctl_a1_3)
            .when(is_a0_0)
            .assert_word_zero(local.result);
        builder
            .when(local.is_fnctl_a1_3)
            .when(is_a0_1 + is_a0_2)
            .assert_word_eq(local.result, Word::<AB::Expr>::from(1u32));
        builder
            .when(local.is_fnctl_a1_3)
            .when_not(is_a0_0 + is_a0_1 + is_a0_2)
            .assert_word_eq(local.result, Word::<AB::Expr>::from(0xFFFFFFFFu32));
        builder
            .when(is_fnctl)
            .when_not(is_a1_3 + is_a1_1)
            .assert_word_eq(local.result, Word::<AB::Expr>::from(0xFFFFFFFFu32));

        // Output constraints for fnctl.
        builder
            .when(local.is_fnctl_a1_3 + local.is_fnctl_a1_1)
            .when(is_a0_0 + is_a0_1 + is_a0_2)
            .assert_word_zero(*local.output.value());
        builder
            .when(local.is_fnctl_a1_3 + local.is_fnctl_a1_1)
            .when_not(is_a0_0 + is_a0_1 + is_a0_2)
            .assert_word_eq(*local.output.value(), Word::<AB::Expr>::from(9u32));
        builder
            .when(is_fnctl)
            .when_not(is_a1_3 + is_a1_1)
            .assert_word_eq(*local.output.value(), Word::<AB::Expr>::from(0x9u32));
    }

    fn eval_read<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &SysLinuxCols<AB::Var>,
        is_read: AB::Var,
        is_a0_0: AB::Var,
    ) {
        builder.when(is_read).when(is_a0_0).assert_word_zero(local.result);
        builder.when(is_read).when(is_a0_0).assert_word_zero(*local.output.value());
        builder
            .when(is_read)
            .when_not(is_a0_0)
            .assert_word_eq(local.result, Word::<AB::Expr>::from(0xFFFFFFFFu32));
        builder
            .when(is_read)
            .when_not(is_a0_0)
            .assert_word_eq(*local.output.value(), Word::<AB::Expr>::from(9));
    }

    fn eval_write<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &SysLinuxCols<AB::Var>,
        is_write: AB::Var,
    ) {
        // MemoryReadCols structurally enforces value == prev_value.
        builder.eval_memory_access(
            local.shard,
            local.clk,
            AB::Expr::from_canonical_u32(Register::A2 as u32),
            &local.read_access,
            is_write,
        );

        builder.when(is_write).assert_word_eq(local.result, *local.read_access.value());
        builder.when(is_write).assert_word_zero(*local.output.value());
    }

    fn eval_nop<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &SysLinuxCols<AB::Var>,
        is_nop: AB::Expr,
    ) {
        builder.when(is_nop.clone()).assert_word_zero(*local.output.value());
        builder.when(is_nop).assert_word_zero(local.result);
    }
}
