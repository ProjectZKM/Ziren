use p3_air::{WindowAccess, Air, BaseAir};
use p3_field::PrimeCharacteristicRing;
use zkm_core_executor::syscalls::SyscallCode;
use zkm_stark::{
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
        // Initialize columns.
        let main = builder.main();
        let local = main.current_slice();
        let local: &ShaExtendCols<AB::Var> = (*local).borrow();

        let i_start = AB::F::from_u32(16);
        let nb_bytes_in_word = AB::F::from_u32(4);

        // Assert that `is_real` is a bool.
        builder.assert_bool(local.is_real);

        // PrecompileChain state bus: receive `i`, send `i + 1`.  This pins the
        // per-row `i` sequencing (and the `shard`/`clk`/`w_ptr` constancy via the
        // matched tuple) that the legacy `cycle_16`/`cycle_48` flag machinery used
        // to enforce, without the row selectors the single-row BaseFold zerocheck
        // folder cannot evaluate.
        self.eval_state_bus(builder, local);

        // Read w[i-15].
        builder.eval_memory_access(
            local.shard,
            local.clk + (local.i - i_start),
            local.w_ptr + (local.i - AB::F::from_u32(15)) * nb_bytes_in_word,
            &local.w_i_minus_15,
            local.is_real,
        );

        // Read w[i-2].
        builder.eval_memory_access(
            local.shard,
            local.clk + (local.i - i_start),
            local.w_ptr + (local.i - AB::F::from_u32(2)) * nb_bytes_in_word,
            &local.w_i_minus_2,
            local.is_real,
        );

        // Read w[i-16].
        builder.eval_memory_access(
            local.shard,
            local.clk + (local.i - i_start),
            local.w_ptr + (local.i - AB::F::from_u32(16)) * nb_bytes_in_word,
            &local.w_i_minus_16,
            local.is_real,
        );

        // Read w[i-7].
        builder.eval_memory_access(
            local.shard,
            local.clk + (local.i - i_start),
            local.w_ptr + (local.i - AB::F::from_u32(7)) * nb_bytes_in_word,
            &local.w_i_minus_7,
            local.is_real,
        );

        // Compute `s0`.
        // w[i-15] rightrotate 7.
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_15.value(),
            7,
            local.w_i_minus_15_rr_7,
            local.is_real,
        );
        // w[i-15] rightrotate 18.
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_15.value(),
            18,
            local.w_i_minus_15_rr_18,
            local.is_real,
        );
        // w[i-15] rightshift 3.
        FixedShiftRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_15.value(),
            3,
            local.w_i_minus_15_rs_3,
            local.is_real.into(),
        );
        // (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18)
        XorOperation::<AB::F>::eval(
            builder,
            local.w_i_minus_15_rr_7.value,
            local.w_i_minus_15_rr_18.value,
            local.s0_intermediate,
            local.is_real,
        );
        // s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
        XorOperation::<AB::F>::eval(
            builder,
            local.s0_intermediate.value,
            local.w_i_minus_15_rs_3.value,
            local.s0,
            local.is_real,
        );

        // Compute `s1`.
        // w[i-2] rightrotate 17.
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_2.value(),
            17,
            local.w_i_minus_2_rr_17,
            local.is_real,
        );
        // w[i-2] rightrotate 19.
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_2.value(),
            19,
            local.w_i_minus_2_rr_19,
            local.is_real,
        );
        // w[i-2] rightshift 10.
        FixedShiftRightOperation::<AB::F>::eval(
            builder,
            *local.w_i_minus_2.value(),
            10,
            local.w_i_minus_2_rs_10,
            local.is_real.into(),
        );
        // (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19)
        XorOperation::<AB::F>::eval(
            builder,
            local.w_i_minus_2_rr_17.value,
            local.w_i_minus_2_rr_19.value,
            local.s1_intermediate,
            local.is_real,
        );
        // s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
        XorOperation::<AB::F>::eval(
            builder,
            local.s1_intermediate.value,
            local.w_i_minus_2_rs_10.value,
            local.s1,
            local.is_real,
        );

        // s2 := w[i-16] + s0 + w[i-7] + s1.
        Add4Operation::<AB::F>::eval(
            builder,
            *local.w_i_minus_16.value(),
            local.s0.value,
            *local.w_i_minus_7.value(),
            local.s1.value,
            local.is_real,
            local.s2,
        );

        // Write `s2` to `w[i]`.
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
            vec![
                pid.clone(),
                local.shard.into(),
                local.clk.into(),
                local.w_ptr.into(),
                index,
            ]
        };

        // Receive the current index `i`.
        builder.receive(
            AirLookup::new(tuple(local.i.into()), local.is_real.into(), LookupKind::PrecompileChain),
            LookupScope::Local,
        );

        // Send the next index `i + 1`.
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
