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
    operations::GtColsBytes,
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

        self.eval_brk(builder, local);
        self.eval_clone(builder, local);
        self.eval_exit_group(builder, local);
        self.eval_fnctl(builder, local);
        self.eval_read(builder, local);
        self.eval_write(builder, local);
        self.eval_mmap(builder, local);
        self.eval_nop(builder, local);

        // Check that the a3 memory access.
        builder.eval_memory_access(
            local.shard,
            local.clk,
            AB::Expr::from_canonical_u32(Register::A3 as u32),
            &local.output,
            local.is_real,
        );

        // Check that the flags are boolean.
        {
            let bool_flags = [
                local.is_a0_0,
                local.is_a0_1,
                local.is_a0_2,
                local.is_mmap,
                local.is_mmap2,
                local.is_mmap_a0_0,
                local.is_offset_0,
                local.is_clone,
                local.is_exit_group,
                local.is_brk,
                local.is_fnctl,
                local.is_a1_1,
                local.is_a1_3,
                local.is_fnctl_a1_1,
                local.is_fnctl_a1_3,
                local.is_read,
                local.is_write,
                local.is_nop,
                local.is_real,
            ];

            for flag in bool_flags.into_iter() {
                builder.assert_bool(flag);
            }
        }

        // Check that the a0 flags are correct.
        {
            builder
                .when(local.is_real)
                .when(local.is_a0_0)
                .assert_eq(local.a0[0], AB::Expr::zero());
            builder.when(local.is_real).when(local.is_a0_1).assert_eq(local.a0[0], AB::Expr::one());
            builder.when(local.is_real).when(local.is_a0_2).assert_eq(local.a0[0], AB::Expr::two());
            builder
                .when(local.is_real)
                .when(local.is_a0_0 + local.is_a0_1 + local.is_a0_2)
                .assert_zero(local.a0[1]);
            builder
                .when(local.is_real)
                .when(local.is_a0_0 + local.is_a0_1 + local.is_a0_2)
                .assert_zero(local.a0[2]);
            builder
                .when(local.is_real)
                .when(local.is_a0_0 + local.is_a0_1 + local.is_a0_2)
                .assert_zero(local.a0[3]);
        }

        // Check that the syscall flags are correct.
        {
            builder.when(local.is_mmap).when_not(local.is_mmap2).assert_eq(
                local.syscall_id,
                AB::Expr::from_canonical_u32(SyscallCode::SYS_MMAP as u32),
            );
            builder.when(local.is_mmap2).assert_eq(
                local.syscall_id,
                AB::Expr::from_canonical_u32(SyscallCode::SYS_MMAP2 as u32),
            );
            builder.when(local.is_mmap2).assert_one(local.is_mmap);
            builder.when(local.is_clone).assert_eq(
                local.syscall_id,
                AB::Expr::from_canonical_u32(SyscallCode::SYS_CLONE as u32),
            );
            builder.when(local.is_exit_group).assert_eq(
                local.syscall_id,
                AB::Expr::from_canonical_u32(SyscallCode::SYS_EXT_GROUP as u32),
            );
            builder.when(local.is_brk).assert_eq(
                local.syscall_id,
                AB::Expr::from_canonical_u32(SyscallCode::SYS_BRK as u32),
            );
            builder.when(local.is_fnctl).assert_eq(
                local.syscall_id,
                AB::Expr::from_canonical_u32(SyscallCode::SYS_FCNTL as u32),
            );
            builder.when(local.is_read).assert_eq(
                local.syscall_id,
                AB::Expr::from_canonical_u32(SyscallCode::SYS_READ as u32),
            );
            builder.when(local.is_write).assert_eq(
                local.syscall_id,
                AB::Expr::from_canonical_u32(SyscallCode::SYS_WRITE as u32),
            );
            builder.when(local.is_real).assert_one(
                local.is_mmap
                    + local.is_clone
                    + local.is_exit_group
                    + local.is_brk
                    + local.is_fnctl
                    + local.is_read
                    + local.is_write
                    + local.is_nop,
            );
        }

        builder.receive_syscall(
            local.shard,
            local.clk,
            local.syscall_id,
            local.a0.reduce::<AB>(),
            local.a1.reduce::<AB>(),
            local.is_real,
            LookupScope::Local,
        );
    }
}

impl SysLinuxChip {
    fn eval_brk<AB: ZKMAirBuilder>(&self, builder: &mut AB, local: &SysLinuxCols<AB::Var>) {
        builder.eval_memory_access(
            local.shard,
            local.clk,
            AB::Expr::from_canonical_u32(Register::BRK as u32),
            &local.inorout,
            local.is_brk,
        );

        GtColsBytes::<AB::F>::eval(
            builder,
            local.a0,
            *local.inorout.value(),
            local.is_brk,
            local.is_a0_gt_brk,
        );
        // v0 = max(a0, brk)
        builder
            .when(local.is_brk)
            .when(local.is_a0_gt_brk.result)
            .assert_word_eq(local.result, local.a0);

        builder
            .when(local.is_brk)
            .when_not(local.is_a0_gt_brk.result)
            .assert_word_eq(local.result, local.inorout.prev_value);

        let res = local.output.value();
        builder.when(local.is_brk).assert_zero(res[0]);
        builder.when(local.is_brk).assert_zero(res[1]);
        builder.when(local.is_brk).assert_zero(res[2]);
        builder.when(local.is_brk).assert_zero(res[3]);
    }

    fn eval_clone<AB: ZKMAirBuilder>(&self, builder: &mut AB, local: &SysLinuxCols<AB::Var>) {
        let res = local.output.value();
        builder.when(local.is_clone).assert_zero(res[0]);
        builder.when(local.is_clone).assert_zero(res[1]);
        builder.when(local.is_clone).assert_zero(res[2]);
        builder.when(local.is_clone).assert_zero(res[3]);

        builder.when(local.is_clone).assert_one(local.result[0]);
        builder.when(local.is_clone).assert_zero(local.result[1]);
        builder.when(local.is_clone).assert_zero(local.result[2]);
        builder.when(local.is_clone).assert_zero(local.result[3]);
    }

    fn eval_mmap<AB: ZKMAirBuilder>(&self, builder: &mut AB, local: &SysLinuxCols<AB::Var>) {
        builder
            .when(local.is_mmap)
            .when(local.is_offset_0)
            .assert_eq(local.page_offset, AB::Expr::zero());

        builder
            .when(local.is_mmap)
            .assert_eq(local.page_offset + local.upper_address, local.a1.reduce::<AB>());
        let size = local.upper_address
            + AB::Expr::from_canonical_u32(0x1000) * (AB::Expr::one() - local.is_offset_0);

        builder.when(local.is_mmap).when(local.is_a0_0).assert_eq(
            local.inorout.value().reduce::<AB>(),
            size + local.inorout.prev_value.reduce::<AB>(),
        );
        builder.when(local.is_mmap_a0_0).assert_one(local.is_mmap * local.is_a0_0);
        builder
            .when(local.is_mmap_a0_0)
            .when(local.is_a0_0)
            .assert_word_eq(local.inorout.prev_value, local.result);

        builder.eval_memory_access(
            local.shard,
            local.clk,
            AB::Expr::from_canonical_u32(Register::HEAP as u32),
            &local.inorout,
            local.is_mmap_a0_0,
        );

        builder.when(local.is_mmap).when_not(local.is_a0_0).assert_word_eq(local.a0, local.result);
    }

    fn eval_exit_group<AB: ZKMAirBuilder>(&self, builder: &mut AB, local: &SysLinuxCols<AB::Var>) {
        builder.when(local.is_exit_group).assert_word_zero(*local.output.value());
    }

    fn eval_fnctl<AB: ZKMAirBuilder>(&self, builder: &mut AB, local: &SysLinuxCols<AB::Var>) {
        builder.when(local.is_fnctl).when(local.is_a1_1).assert_eq(local.a1[0], AB::Expr::one());
        builder
            .when(local.is_fnctl)
            .when(local.is_a1_3)
            .assert_eq(local.a1[0], AB::Expr::from_canonical_u32(3));

        builder.when(local.is_fnctl).when(local.is_a1_1 + local.is_a1_3).assert_zero(local.a1[1]);
        builder.when(local.is_fnctl).when(local.is_a1_1 + local.is_a1_3).assert_zero(local.a1[2]);
        builder.when(local.is_fnctl).when(local.is_a1_1 + local.is_a1_3).assert_zero(local.a1[3]);

        builder.when(local.is_fnctl_a1_3).assert_one(local.is_a1_3 * local.is_fnctl);
        builder.when(local.is_fnctl_a1_1).assert_one(local.is_a1_1 * local.is_fnctl);
        builder.when(local.is_fnctl_a1_3).when(local.is_a0_0).assert_word_zero(local.result);
        builder
            .when(local.is_fnctl_a1_3)
            .when(local.is_a0_1 + local.is_a0_2)
            .assert_word_eq(local.result, Word::<AB::Expr>::from(1u32));
        builder
            .when(local.is_fnctl_a1_3)
            .when_not(local.is_a0_0 + local.is_a0_1 + local.is_a0_2)
            .assert_word_eq(local.result, Word::<AB::Expr>::from(0xFFFFFFFFu32));
        builder
            .when(local.is_fnctl)
            .when_not(local.is_a1_3 + local.is_a1_1)
            .assert_word_eq(local.result, Word::<AB::Expr>::from(0xFFFFFFFFu32));

        builder
            .when(local.is_fnctl_a1_3 + local.is_fnctl_a1_1)
            .when(local.is_a0_0 + local.is_a0_1 + local.is_a0_2)
            .assert_word_zero(*local.output.value());
        builder
            .when(local.is_fnctl_a1_3 + local.is_fnctl_a1_1)
            .when_not(local.is_a0_0 + local.is_a0_1 + local.is_a0_2)
            .assert_word_eq(*local.output.value(), Word::<AB::Expr>::from(9u32));
        builder
            .when(local.is_fnctl)
            .when_not(local.is_a1_3 + local.is_a1_1)
            .assert_word_eq(*local.output.value(), Word::<AB::Expr>::from(0x9u32));
    }

    fn eval_read<AB: ZKMAirBuilder>(&self, builder: &mut AB, local: &SysLinuxCols<AB::Var>) {
        builder.when(local.is_read).when(local.is_a0_0).assert_word_zero(local.result);
        builder.when(local.is_read).when(local.is_a0_0).assert_word_zero(*local.output.value());

        builder
            .when(local.is_read)
            .when_not(local.is_a0_0)
            .assert_word_eq(local.result, Word::<AB::Expr>::from(0xFFFFFFFFu32));
        builder
            .when(local.is_read)
            .when_not(local.is_a0_0)
            .assert_word_eq(*local.output.value(), Word::<AB::Expr>::from(9));
    }

    fn eval_write<AB: ZKMAirBuilder>(&self, builder: &mut AB, local: &SysLinuxCols<AB::Var>) {
        builder.eval_memory_access(
            local.shard,
            local.clk,
            AB::Expr::from_canonical_u32(Register::A2 as u32),
            &local.inorout,
            local.is_write,
        );

        builder.when(local.is_write).assert_word_eq(local.result, *local.inorout.value());
        builder.when(local.is_write).assert_word_zero(*local.output.value());
    }

    fn eval_nop<AB: ZKMAirBuilder>(&self, builder: &mut AB, local: &SysLinuxCols<AB::Var>) {
        builder.when(local.is_nop).assert_word_zero(*local.output.value());
        builder.when(local.is_nop).assert_word_zero(local.result);
    }
}
