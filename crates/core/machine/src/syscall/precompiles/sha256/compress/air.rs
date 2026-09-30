use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use zkm_core_executor::syscalls::SyscallCode;
use zkm_pcs::{
    air::{AirLookup, LookupScope, ZKMAirBuilder},
    LookupKind, Word,
};

use super::{
    columns::{ShaCompressCols, NUM_SHA_COMPRESS_COLS},
    ShaCompressChip, SHA_COMPRESS_K,
};
use crate::{
    air::{MemoryAirBuilder, WordAirBuilder},
    memory::MemoryCols,
    operations::{
        Add5Operation, AddOperation, AndOperation, FixedRotateRightOperation, NotOperation,
        XorOperation,
    },
};
use zkm_pcs::air::BaseAirBuilder;

impl<F> BaseAir<F> for ShaCompressChip {
    fn width(&self) -> usize {
        NUM_SHA_COMPRESS_COLS
    }
}

impl<AB> Air<AB> for ShaCompressChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &ShaCompressCols<AB::Var> = (*local).borrow();

        self.eval_control_flow_flags(builder, local);

        self.eval_memory(builder, local);

        self.eval_compression_ops(builder, local);

        self.eval_finalize_ops(builder, local);

        self.eval_state_bus(builder, local);
    }
}

impl ShaCompressChip {
    fn eval_control_flow_flags<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &ShaCompressCols<AB::Var>,
    ) {
        for i in 0..8 {
            builder.assert_bool(local.octet[i]);
        }

        let mut octet_sum = AB::Expr::ZERO;
        for i in 0..8 {
            octet_sum = octet_sum.clone() + local.octet[i].into();
        }
        builder.assert_one(octet_sum);

        for i in 0..10 {
            builder.assert_bool(local.octet_num[i]);
        }

        let mut octet_num_sum = AB::Expr::ZERO;
        for i in 0..10 {
            octet_num_sum = octet_num_sum.clone() + local.octet_num[i].into();
        }
        builder.assert_one(octet_num_sum);

        let mut computed_index = AB::Expr::ZERO;
        for i in 0..8 {
            computed_index = computed_index.clone() + local.octet[i] * AB::Expr::from_usize(i);
        }
        for j in 0..10 {
            computed_index =
                computed_index.clone() + local.octet_num[j] * AB::Expr::from_usize(8 * j);
        }
        builder.assert_eq(local.index, computed_index);

        builder.assert_eq(local.is_initialize, local.octet_num[0] * local.is_real);

        builder.assert_eq(
            local.is_compression,
            (local.octet_num[1]
                + local.octet_num[2]
                + local.octet_num[3]
                + local.octet_num[4]
                + local.octet_num[5]
                + local.octet_num[6]
                + local.octet_num[7]
                + local.octet_num[8])
                * local.is_real,
        );

        builder.assert_eq(local.is_finalize, local.octet_num[9] * local.is_real);

        builder.assert_bool(local.is_real);
    }

    /// Constrains that memory address is correct and that memory is correctly written/read.
    fn eval_memory<AB: ZKMAirBuilder>(&self, builder: &mut AB, local: &ShaCompressCols<AB::Var>) {
        builder.eval_memory_access(
            local.shard,
            local.clk + local.is_finalize,
            local.mem_addr,
            &local.mem,
            local.is_initialize + local.is_compression + local.is_finalize,
        );

        let mut cycle_num = AB::Expr::ZERO;
        for i in 0..10 {
            cycle_num = cycle_num.clone() + local.octet_num[i] * AB::Expr::from_usize(i);
        }

        let mut cycle_step = AB::Expr::ZERO;
        for i in 0..8 {
            cycle_step = cycle_step.clone() + local.octet[i] * AB::Expr::from_usize(i);
        }

        builder
            .when(local.is_initialize)
            .assert_eq(local.mem_addr, local.h_ptr + cycle_step.clone() * AB::Expr::from_u32(4));

        builder.when(local.is_compression).assert_eq(
            local.mem_addr,
            local.w_ptr
                + (((cycle_num - AB::Expr::ONE) * AB::Expr::from_u32(8)) + cycle_step.clone())
                    * AB::Expr::from_u32(4),
        );

        builder
            .when(local.is_finalize)
            .assert_eq(local.mem_addr, local.h_ptr + cycle_step.clone() * AB::Expr::from_u32(4));

        let vars = [local.a, local.b, local.c, local.d, local.e, local.f, local.g, local.h];
        for (i, var) in vars.iter().enumerate() {
            builder
                .when(local.is_initialize)
                .when(local.octet[i])
                .assert_word_eq(*var, *local.mem.prev_value());
            builder
                .when(local.is_initialize)
                .when(local.octet[i])
                .assert_word_eq(*var, *local.mem.value());
        }

        builder
            .when(local.is_compression)
            .assert_word_eq(*local.mem.prev_value(), *local.mem.value());

        builder
            .when(local.is_finalize)
            .assert_word_eq(*local.mem.value(), local.finalize_add.value);
    }

    fn eval_compression_ops<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &ShaCompressCols<AB::Var>,
    ) {
        for i in 0..64 {
            let octet_num = i / 8;
            let inner_index = i % 8;
            builder
                .when(local.octet_num[octet_num + 1] * local.octet[inner_index])
                .assert_all_eq(local.k, Word::<AB::F>::from(SHA_COMPRESS_K[i]));
        }

        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.e,
            6,
            local.e_rr_6,
            local.is_compression,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.e,
            11,
            local.e_rr_11,
            local.is_compression,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.e,
            25,
            local.e_rr_25,
            local.is_compression,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.e_rr_6.value,
            local.e_rr_11.value,
            local.s1_intermediate,
            local.is_compression,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.s1_intermediate.value,
            local.e_rr_25.value,
            local.s1,
            local.is_compression,
        );

        AndOperation::<AB::F>::eval(builder, local.e, local.f, local.e_and_f, local.is_compression);
        NotOperation::<AB::F>::eval(builder, local.e, local.e_not, local.is_compression);
        AndOperation::<AB::F>::eval(
            builder,
            local.e_not.value,
            local.g,
            local.e_not_and_g,
            local.is_compression,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.e_and_f.value,
            local.e_not_and_g.value,
            local.ch,
            local.is_compression,
        );

        Add5Operation::<AB::F>::eval(
            builder,
            &[local.h, local.s1.value, local.ch.value, local.k, local.mem.access.value],
            local.is_compression,
            local.temp1,
        );

        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.a,
            2,
            local.a_rr_2,
            local.is_compression,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.a,
            13,
            local.a_rr_13,
            local.is_compression,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.a,
            22,
            local.a_rr_22,
            local.is_compression,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.a_rr_2.value,
            local.a_rr_13.value,
            local.s0_intermediate,
            local.is_compression,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.s0_intermediate.value,
            local.a_rr_22.value,
            local.s0,
            local.is_compression,
        );

        AndOperation::<AB::F>::eval(builder, local.a, local.b, local.a_and_b, local.is_compression);
        AndOperation::<AB::F>::eval(builder, local.a, local.c, local.a_and_c, local.is_compression);
        AndOperation::<AB::F>::eval(builder, local.b, local.c, local.b_and_c, local.is_compression);
        XorOperation::<AB::F>::eval(
            builder,
            local.a_and_b.value,
            local.a_and_c.value,
            local.maj_intermediate,
            local.is_compression,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.maj_intermediate.value,
            local.b_and_c.value,
            local.maj,
            local.is_compression,
        );

        AddOperation::<AB::F>::eval(
            builder,
            local.s0.value,
            local.maj.value,
            local.temp2,
            local.is_compression.into(),
        );

        AddOperation::<AB::F>::eval(
            builder,
            local.d,
            local.temp1.value,
            local.d_add_temp1,
            local.is_compression.into(),
        );

        AddOperation::<AB::F>::eval(
            builder,
            local.temp1.value,
            local.temp2.value,
            local.temp1_add_temp2,
            local.is_compression.into(),
        );
    }

    fn eval_finalize_ops<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &ShaCompressCols<AB::Var>,
    ) {
        let add_operands = [local.a, local.b, local.c, local.d, local.e, local.f, local.g, local.h];
        let zero = AB::Expr::ZERO;
        let mut filtered_operand = Word([zero.clone(), zero.clone(), zero.clone(), zero]);
        for (i, operand) in local.octet.iter().zip(add_operands.iter()) {
            for j in 0..4 {
                filtered_operand.0[j] = filtered_operand.0[j].clone() + *i * operand.0[j];
            }
        }

        builder
            .when(local.is_finalize)
            .assert_word_eq(filtered_operand, local.finalized_operand.map(|x| x.into()));

        AddOperation::<AB::F>::eval(
            builder,
            local.mem.prev_value,
            local.finalized_operand,
            local.finalize_add,
            local.is_finalize.into(),
        );
    }

    /// `PrecompileChain` state bus.  Each real worker row RECEIVEs the current
    /// digest `a..h @ index` and SENDs the next digest `@ index + 1`: unchanged
    /// for initialize/finalize rows, and rotated for compression rows.  The
    /// `ShaCompressControlChip` seeds `@ index = 0` and drains `@ index = 80`,
    /// so the multiset only balances when the per-syscall chain telescopes
    /// `0 → 80`.  A leading `pid = SHA_COMPRESS.syscall_id()` isolates this
    /// chain from other precompiles on the shared `PrecompileChain` kind.
    fn eval_state_bus<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &ShaCompressCols<AB::Var>,
    ) {
        let pid = AB::Expr::from_u32(SyscallCode::SHA_COMPRESS.syscall_id());

        let header = |index: AB::Expr| -> Vec<AB::Expr> {
            vec![
                pid.clone(),
                local.shard.into(),
                local.clk.into(),
                local.w_ptr.into(),
                local.h_ptr.into(),
                index,
            ]
        };
        let push_state = |vals: &mut Vec<AB::Expr>, state: [Word<AB::Var>; 8]| {
            for word in state.iter() {
                for b in word.0.iter() {
                    vals.push((*b).into());
                }
            }
        };

        let mut recv = header(local.index.into());
        push_state(
            &mut recv,
            [local.a, local.b, local.c, local.d, local.e, local.f, local.g, local.h],
        );
        builder.receive(
            AirLookup::new(recv, local.is_real.into(), LookupKind::PrecompileChain),
            LookupScope::Local,
        );

        let mut send_carry = header(local.index.into() + AB::Expr::ONE);
        push_state(
            &mut send_carry,
            [local.a, local.b, local.c, local.d, local.e, local.f, local.g, local.h],
        );
        builder.send(
            AirLookup::new(
                send_carry,
                local.is_initialize + local.is_finalize,
                LookupKind::PrecompileChain,
            ),
            LookupScope::Local,
        );

        let mut send_comp = header(local.index.into() + AB::Expr::ONE);
        push_state(
            &mut send_comp,
            [
                local.temp1_add_temp2.value,
                local.a,
                local.b,
                local.c,
                local.d_add_temp1.value,
                local.e,
                local.f,
                local.g,
            ],
        );
        builder.send(
            AirLookup::new(send_comp, local.is_compression.into(), LookupKind::PrecompileChain),
            LookupScope::Local,
        );
    }
}
