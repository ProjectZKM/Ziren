use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use zkm_core_executor::syscalls::SyscallCode;
use zkm_pcs::{
    air::{AirLookup, LookupScope, ZKMAirBuilder},
    LookupKind,
};

use super::{ShaExtendChip, ShaExtendCols, NUM_SHA_EXTEND_COLS};
use crate::{
    air::{MemoryAirBuilder, WordAirBuilder},
    memory::MemoryCols,
    operations::{
        Add4Operation, FixedRotateRightOperation, FixedShiftRightOperation, XorOperation,
    },
};

use core::borrow::Borrow;

impl<F> BaseAir<F> for ShaExtendChip {
    fn width(&self) -> usize {
        NUM_SHA_EXTEND_COLS
    }
}

impl<AB> Air<AB> for ShaExtendChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &ShaExtendCols<AB::Var> = (*local).borrow();

        let i_start = AB::F::from_u32(16);
        let nb_bytes_in_word = AB::F::from_u32(4);

        builder.assert_bool(local.is_real);

        self.eval_state_bus(builder, local);

        builder.eval_memory_access(
            local.shard,
            local.clk + (local.i - i_start),
            local.w_ptr + (local.i - AB::F::from_u32(15)) * nb_bytes_in_word,
            &local.w_i_minus_15,
            local.is_real,
        );

        builder.eval_memory_access(
            local.shard,
            local.clk + (local.i - i_start),
            local.w_ptr + (local.i - AB::F::from_u32(2)) * nb_bytes_in_word,
            &local.w_i_minus_2,
            local.is_real,
        );

        builder.eval_memory_access(
            local.shard,
            local.clk + (local.i - i_start),
            local.w_ptr + (local.i - AB::F::from_u32(16)) * nb_bytes_in_word,
            &local.w_i_minus_16,
            local.is_real,
        );

        builder.eval_memory_access(
            local.shard,
            local.clk + (local.i - i_start),
            local.w_ptr + (local.i - AB::F::from_u32(7)) * nb_bytes_in_word,
            &local.w_i_minus_7,
            local.is_real,
        );

        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_15.value(),
            7,
            local.w_i_minus_15_rr_7,
            local.is_real,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_15.value(),
            18,
            local.w_i_minus_15_rr_18,
            local.is_real,
        );
        FixedShiftRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_15.value(),
            3,
            local.w_i_minus_15_rs_3,
            local.is_real.into(),
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.w_i_minus_15_rr_7.value,
            local.w_i_minus_15_rr_18.value,
            local.s0_intermediate,
            local.is_real,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.s0_intermediate.value,
            local.w_i_minus_15_rs_3.value,
            local.s0,
            local.is_real,
        );

        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_2.value(),
            17,
            local.w_i_minus_2_rr_17,
            local.is_real,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_2.value(),
            19,
            local.w_i_minus_2_rr_19,
            local.is_real,
        );
        FixedShiftRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_2.value(),
            10,
            local.w_i_minus_2_rs_10,
            local.is_real.into(),
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.w_i_minus_2_rr_17.value,
            local.w_i_minus_2_rr_19.value,
            local.s1_intermediate,
            local.is_real,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.s1_intermediate.value,
            local.w_i_minus_2_rs_10.value,
            local.s1,
            local.is_real,
        );

        Add4Operation::<AB::F>::eval(
            builder,
            *local.w_i_minus_16.value(),
            local.s0.value,
            *local.w_i_minus_7.value(),
            local.s1.value,
            local.is_real,
            local.s2,
        );

        builder.eval_memory_access(
            local.shard,
            local.clk + (local.i - i_start),
            local.w_ptr + local.i * nb_bytes_in_word,
            &local.w_i,
            local.is_real,
        );

        builder.assert_word_eq(*local.w_i.value(), local.s2.value);
    }
}

impl ShaExtendChip {
    /// `PrecompileChain` state bus.  Each real worker row RECEIVEs the current
    /// loop index `i` and SENDs `i + 1`.  The `ShaExtendControlChip` seeds
    /// `@ i = 16` and drains `@ i = 64`, so the multiset only balances when the
    /// per-syscall chain telescopes `16 → 64` across exactly 48 worker rows,
    /// pinning each row's `i` (and the constancy of `shard`/`clk`/`w_ptr`).  A
    /// leading `pid = SHA_EXTEND.syscall_id()` isolates this chain from other
    /// precompiles on the shared `PrecompileChain` kind.
    fn eval_state_bus<AB: ZKMAirBuilder>(&self, builder: &mut AB, local: &ShaExtendCols<AB::Var>) {
        let pid = AB::Expr::from_u32(SyscallCode::SHA_EXTEND.syscall_id());

        let tuple = |index: AB::Expr| -> Vec<AB::Expr> {
            vec![pid.clone(), local.shard.into(), local.clk.into(), local.w_ptr.into(), index]
        };

        builder.receive(
            AirLookup::new(
                tuple(local.i.into()),
                local.is_real.into(),
                LookupKind::PrecompileChain,
            ),
            LookupScope::Local,
        );

        builder.send(
            AirLookup::new(
                tuple(local.i.into() + AB::Expr::ONE),
                local.is_real.into(),
                LookupKind::PrecompileChain,
            ),
            LookupScope::Local,
        );
    }
}
