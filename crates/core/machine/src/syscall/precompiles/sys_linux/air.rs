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

        // Constrain composite flags: is_fnctl_a1_X = is_fnctl * is_a1_X.
        builder.assert_eq(local.is_fnctl_a1_1, local.is_fnctl * local.is_a1_1);
        builder.assert_eq(local.is_fnctl_a1_3, local.is_fnctl * local.is_a1_3);

        // Check that the a0 flags are correct (forward direction).
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

        // ProjectZKM/Ziren#488:9: Reverse direction — when a0 == 0/1/2, the corresponding flag must be set.
        {
            let a0_reduce = local.a0.reduce::<AB>();
            IsZeroOperation::<AB::F>::eval(
                builder,
                a0_reduce.clone(),
                local.is_a0_eq_0,
                local.is_real.into(),
            );
            IsZeroOperation::<AB::F>::eval(
                builder,
                a0_reduce.clone() - AB::Expr::one(),
                local.is_a0_eq_1,
                local.is_real.into(),
            );
            IsZeroOperation::<AB::F>::eval(
                builder,
                a0_reduce - AB::Expr::two(),
                local.is_a0_eq_2,
                local.is_real.into(),
            );
            // is_a0_eq_0.result = 1 iff a0.reduce() == 0. When result=1, is_a0_0 must be 1.
            builder
                .when(local.is_real)
                .when(local.is_a0_eq_0.result)
                .assert_one(local.is_a0_0);
            builder
                .when(local.is_real)
                .when(local.is_a0_eq_1.result)
                .assert_one(local.is_a0_1);
            builder
                .when(local.is_real)
                .when(local.is_a0_eq_2.result)
                .assert_one(local.is_a0_2);
        }

        // ProjectZKM/Ziren#488:12: Reverse direction — when a1 == 1/3, the corresponding flag must be set.
        {
            let a1_reduce = local.a1.reduce::<AB>();
            IsZeroOperation::<AB::F>::eval(
                builder,
                a1_reduce.clone() - AB::Expr::one(),
                local.is_a1_eq_1,
                local.is_real.into(),
            );
            IsZeroOperation::<AB::F>::eval(
                builder,
                a1_reduce - AB::Expr::from_canonical_u32(3),
                local.is_a1_eq_3,
                local.is_real.into(),
            );
            builder
                .when(local.is_real)
                .when(local.is_a1_eq_1.result)
                .assert_one(local.is_a1_1);
            builder
                .when(local.is_real)
                .when(local.is_a1_eq_3.result)
                .assert_one(local.is_a1_3);
        }

        // Check that the syscall flags are correct (forward direction).
        {
            // When is_mmap, syscall_id must be either SYS_MMAP or SYS_MMAP2.
            builder.when(local.is_mmap).assert_zero(
                (local.syscall_id - AB::Expr::from_canonical_u32(SyscallCode::SYS_MMAP as u32))
                    * (local.syscall_id
                        - AB::Expr::from_canonical_u32(SyscallCode::SYS_MMAP2 as u32)),
            );
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

        // ProjectZKM/Ziren#488:2: Reverse direction — when syscall_id matches a known code, the flag MUST be set.
        // is_not_X.result = 1 iff syscall_id != X. When result = 0, the flag must be 1.
        {
            IsZeroOperation::<AB::F>::eval(
                builder,
                local.syscall_id - AB::Expr::from_canonical_u32(SyscallCode::SYS_MMAP as u32),
                local.is_not_mmap,
                local.is_real.into(),
            );
            IsZeroOperation::<AB::F>::eval(
                builder,
                local.syscall_id - AB::Expr::from_canonical_u32(SyscallCode::SYS_MMAP2 as u32),
                local.is_not_mmap2,
                local.is_real.into(),
            );
            IsZeroOperation::<AB::F>::eval(
                builder,
                local.syscall_id - AB::Expr::from_canonical_u32(SyscallCode::SYS_CLONE as u32),
                local.is_not_clone,
                local.is_real.into(),
            );
            IsZeroOperation::<AB::F>::eval(
                builder,
                local.syscall_id - AB::Expr::from_canonical_u32(SyscallCode::SYS_EXT_GROUP as u32),
                local.is_not_exit_group,
                local.is_real.into(),
            );
            IsZeroOperation::<AB::F>::eval(
                builder,
                local.syscall_id - AB::Expr::from_canonical_u32(SyscallCode::SYS_BRK as u32),
                local.is_not_brk,
                local.is_real.into(),
            );
            IsZeroOperation::<AB::F>::eval(
                builder,
                local.syscall_id - AB::Expr::from_canonical_u32(SyscallCode::SYS_FCNTL as u32),
                local.is_not_fnctl,
                local.is_real.into(),
            );
            IsZeroOperation::<AB::F>::eval(
                builder,
                local.syscall_id - AB::Expr::from_canonical_u32(SyscallCode::SYS_READ as u32),
                local.is_not_read,
                local.is_real.into(),
            );
            IsZeroOperation::<AB::F>::eval(
                builder,
                local.syscall_id - AB::Expr::from_canonical_u32(SyscallCode::SYS_WRITE as u32),
                local.is_not_write,
                local.is_real.into(),
            );

            // When syscall_id == SYS_MMAP or SYS_MMAP2, is_mmap must be 1.
            // is_not_mmap.result = 0 means syscall_id == SYS_MMAP.
            builder
                .when(local.is_real)
                .when_not(local.is_not_mmap.result)
                .assert_one(local.is_mmap);
            builder
                .when(local.is_real)
                .when_not(local.is_not_mmap2.result)
                .assert_one(local.is_mmap);

            // When syscall_id == SYS_CLONE, is_clone must be 1.
            builder
                .when(local.is_real)
                .when_not(local.is_not_clone.result)
                .assert_one(local.is_clone);

            // When syscall_id == SYS_EXT_GROUP, is_exit_group must be 1.
            builder
                .when(local.is_real)
                .when_not(local.is_not_exit_group.result)
                .assert_one(local.is_exit_group);

            // When syscall_id == SYS_BRK, is_brk must be 1.
            builder
                .when(local.is_real)
                .when_not(local.is_not_brk.result)
                .assert_one(local.is_brk);

            // When syscall_id == SYS_FCNTL, is_fnctl must be 1.
            builder
                .when(local.is_real)
                .when_not(local.is_not_fnctl.result)
                .assert_one(local.is_fnctl);

            // When syscall_id == SYS_READ, is_read must be 1.
            builder
                .when(local.is_real)
                .when_not(local.is_not_read.result)
                .assert_one(local.is_read);

            // When syscall_id == SYS_WRITE, is_write must be 1.
            builder
                .when(local.is_real)
                .when_not(local.is_not_write.result)
                .assert_one(local.is_write);
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

        // Receive full Word bytes for linux syscall result linkage and byte-level matching.
        // This ensures op_a_value (result), op_b_value (a0), op_c_value (a1) match byte-by-byte
        // between SyscallInstrsChip and SysLinuxChip, preventing reduce() collisions.
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
        // ProjectZKM/Ziren#488:6: Range check page_offset < 4096 = 2^12.
        // Decompose: page_offset = page_offset_lo + page_offset_hi * 256,
        // where page_offset_lo < 256 (byte) and page_offset_hi < 16 (4 bits).
        // This gives page_offset < 256 + 15*256 = 4096.
        let mut page_offset_hi = AB::Expr::zero();
        for bit in 0..4 {
            builder.when(local.is_mmap).assert_bool(local.page_offset_hi_bits[bit]);
            page_offset_hi = page_offset_hi
                + local.page_offset_hi_bits[bit] * AB::Expr::from_canonical_u32(1 << bit);
        }
        builder.when(local.is_mmap).assert_eq(
            local.page_offset,
            local.page_offset_lo + page_offset_hi * AB::Expr::from_canonical_u32(256),
        );
        // Range check page_offset_lo < 256 via byte lookup.
        builder.send_byte(
            AB::Expr::from_canonical_u8(zkm_core_executor::ByteOpcode::U16Range as u8),
            local.page_offset_lo,
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_mmap,
        );

        // ProjectZKM/Ziren#488:6: Bidirectional is_offset_0 = (page_offset == 0).
        IsZeroOperation::<AB::F>::eval(
            builder,
            local.page_offset.into(),
            local.is_page_offset_zero,
            local.is_mmap.into(),
        );
        builder
            .when(local.is_mmap)
            .assert_eq(local.is_offset_0, local.is_page_offset_zero.result);

        builder
            .when(local.is_mmap)
            .when(local.is_offset_0)
            .assert_eq(local.page_offset, AB::Expr::zero());

        // ProjectZKM/Ziren#488:6: Prove upper_address is page-aligned: upper_address = upper_address_pages * 4096.
        builder.when(local.is_mmap).assert_eq(
            local.upper_address,
            local.upper_address_pages * AB::Expr::from_canonical_u32(4096),
        );
        // No range check needed on upper_address_pages: since page_offset < 4096 and
        // page_offset + upper_address_pages * 4096 = a1.reduce(), and gcd(4096, P) = 1,
        // the decomposition is the unique Euclidean division of a1.reduce() by 4096.
        builder
            .when(local.is_mmap)
            .assert_eq(local.page_offset + local.upper_address, local.a1.reduce::<AB>());

        // ProjectZKM/Ziren#488:11: Constrain mmap_size as a Word matching the field-level size computation.
        let size_field = local.upper_address
            + AB::Expr::from_canonical_u32(0x1000) * (AB::Expr::one() - local.is_offset_0);
        builder
            .when(local.is_mmap)
            .when(local.is_a0_0)
            .assert_eq(local.mmap_size.reduce::<AB>(), size_field);
        // Range check mmap_size bytes (the AddOperation below also does this, but be explicit).
        builder
            .when(local.is_mmap)
            .when(local.is_a0_0)
            .slice_range_check_u8(&local.mmap_size.0, local.is_mmap_a0_0.into());

        // ProjectZKM/Ziren#488:11: Bytewise heap update: new_heap = old_heap + mmap_size (32-bit wrapping add).
        // This replaces the old reduce()-based constraint which was not injective.
        AddOperation::<AB::F>::eval(
            builder,
            local.inorout.prev_value,
            local.mmap_size,
            local.heap_add,
            local.is_mmap_a0_0.into(),
        );
        // The AddOperation proves heap_add.value = prev_value + mmap_size bytewise.
        // Now assert that the memory write (inorout.value) equals the add result.
        builder
            .when(local.is_mmap_a0_0)
            .assert_word_eq(*local.inorout.value(), local.heap_add.value);
        // ProjectZKM/Ziren#488:3: Bidirectional is_mmap_a0_0 = is_mmap * is_a0_0.
        builder.assert_eq(local.is_mmap_a0_0, local.is_mmap * local.is_a0_0);
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

        // ProjectZKM/Ziren#488:5: mmap always writes A3 = 0 (executor does this unconditionally before branching).
        builder
            .when(local.is_mmap)
            .assert_word_zero(*local.output.value());
    }

    fn eval_exit_group<AB: ZKMAirBuilder>(&self, builder: &mut AB, local: &SysLinuxCols<AB::Var>) {
        builder.when(local.is_exit_group).assert_word_zero(*local.output.value());
        // ProjectZKM/Ziren#488:7: Constrain result to zero (executor returns v0 = 0).
        builder.when(local.is_exit_group).assert_word_zero(local.result);
    }

    fn eval_fnctl<AB: ZKMAirBuilder>(&self, builder: &mut AB, local: &SysLinuxCols<AB::Var>) {
        builder.when(local.is_fnctl_a1_1).assert_eq(local.a1[0], AB::Expr::one());
        builder.when(local.is_fnctl_a1_3).assert_eq(local.a1[0], AB::Expr::from_canonical_u32(3));

        builder.when(local.is_fnctl_a1_1 + local.is_fnctl_a1_3).assert_zero(local.a1[1]);
        builder.when(local.is_fnctl_a1_1 + local.is_fnctl_a1_3).assert_zero(local.a1[2]);
        builder.when(local.is_fnctl_a1_1 + local.is_fnctl_a1_3).assert_zero(local.a1[3]);

        // ProjectZKM/Ziren#488:8: Result constraints for fnctl with a1==1 (F_GETFD).
        // Executor: a0 in {0,1,2} => result = a0; otherwise result = 0xFFFFFFFF.
        builder
            .when(local.is_fnctl_a1_1)
            .when(local.is_a0_0)
            .assert_word_zero(local.result);
        builder
            .when(local.is_fnctl_a1_1)
            .when(local.is_a0_1)
            .assert_word_eq(local.result, Word::<AB::Expr>::from(1u32));
        builder
            .when(local.is_fnctl_a1_1)
            .when(local.is_a0_2)
            .assert_word_eq(local.result, Word::<AB::Expr>::from(2u32));
        builder
            .when(local.is_fnctl_a1_1)
            .when_not(local.is_a0_0 + local.is_a0_1 + local.is_a0_2)
            .assert_word_eq(local.result, Word::<AB::Expr>::from(0xFFFFFFFFu32));

        // Result constraints for fnctl with a1==3 (F_GETFL)
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

        // Output constraints for fnctl with a1==1 or a1==3
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

        // ProjectZKM/Ziren#488:10: For SYS_WRITE, inorout is a read — value must equal prev_value.
        builder
            .when(local.is_write)
            .assert_word_eq(*local.inorout.value(), local.inorout.prev_value);

        builder.when(local.is_write).assert_word_eq(local.result, *local.inorout.value());
        builder.when(local.is_write).assert_word_zero(*local.output.value());
    }

    fn eval_nop<AB: ZKMAirBuilder>(&self, builder: &mut AB, local: &SysLinuxCols<AB::Var>) {
        builder.when(local.is_nop).assert_word_zero(*local.output.value());
        builder.when(local.is_nop).assert_word_zero(local.result);
    }
}
