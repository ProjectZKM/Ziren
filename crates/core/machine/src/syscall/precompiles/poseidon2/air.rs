use std::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};

use crate::operations::poseidon2::air::{eval_external_round, eval_internal_rounds};
use crate::operations::poseidon2::permutation::Poseidon2Cols;
use crate::operations::poseidon2::{NUM_EXTERNAL_ROUNDS, WIDTH};
use crate::operations::KoalaBearWordRangeChecker;
use crate::syscall::precompiles::poseidon2::{
    columns::{Poseidon2MemCols, NUM_COLS},
    Poseidon2PermuteChip,
};
use crate::{
    air::{MemoryAirBuilder, WordAirBuilder},
    memory::MemoryCols,
};
use zkm_core_executor::syscalls::SyscallCode;
use zkm_core_executor::ByteOpcode;
use zkm_pcs::air::{LookupScope, ZKMAirBuilder};

impl<F> BaseAir<F> for Poseidon2PermuteChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

impl<AB> Air<AB> for Poseidon2PermuteChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &Poseidon2MemCols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);

        builder.slice_range_check_u8(&local.state_addr_word.0, local.is_real);
        builder.slice_range_check_u8(&local.last_addr_word.0, local.is_real);
        for (word, check) in [
            (local.state_addr_word, local.state_addr_range_check),
            (local.last_addr_word, local.last_addr_range_check),
        ] {
            KoalaBearWordRangeChecker::<AB::F>::range_check(
                builder,
                word,
                check,
                local.is_real.into(),
            );
        }
        builder
            .when(local.is_real)
            .assert_eq(local.state_addr, local.state_addr_word.reduce::<AB>());
        builder.when(local.is_real).assert_eq(
            local.state_addr_word[0],
            local.state_addr_low_div_four * AB::F::from_u32(4),
        );
        builder.send_byte(
            AB::Expr::from_u8(ByteOpcode::Range as u8),
            local.state_addr_low_div_four.into(),
            AB::Expr::from_u8(6),
            AB::Expr::ZERO,
            local.is_real.into(),
        );

        // Integer byte addition prevents the memory offsets from wrapping modulo p.
        // Both endpoints are canonical, so all intermediate word addresses are too.
        let offset = (((WIDTH - 1) * 4) as u32).to_le_bytes();
        let mut carry = AB::Expr::ZERO;
        let base_inv = AB::F::from_u32(256).inverse();
        for (i, byte) in offset.iter().take(4).enumerate() {
            carry = (local.state_addr_word[i] + AB::Expr::from_u8(*byte) + carry
                - local.last_addr_word[i])
                * base_inv;
            builder.when(local.is_real).assert_bool(carry.clone());
        }
        builder.when(local.is_real).assert_zero(carry);

        for i in 0..WIDTH {
            KoalaBearWordRangeChecker::<AB::F>::range_check(
                builder,
                *local.state_mem[i].prev_value(),
                local.pre_state_range_check_cols[i],
                local.is_real.into(),
            );
            let pre_state_word = local.state_mem[i].prev_value().0;
            let pre_state = pre_state_word
                .iter()
                .enumerate()
                .map(|(j, limb)| (*limb).into() * AB::Expr::from_u32(1 << (j * 8)))
                .sum::<AB::Expr>();
            builder.when(local.is_real).assert_eq(
                local.poseidon2.permutation.external_rounds_state()[0][i].into(),
                pre_state,
            );
        }

        for r in 0..NUM_EXTERNAL_ROUNDS {
            eval_external_round(builder, &local.poseidon2.permutation, r);
        }
        eval_internal_rounds(builder, &local.poseidon2.permutation);

        for i in 0..WIDTH {
            KoalaBearWordRangeChecker::<AB::F>::range_check(
                builder,
                *local.state_mem[i].value(),
                local.post_state_range_check_cols[i],
                local.is_real.into(),
            );
            let post_state_word = local.state_mem[i].value().0;
            let post_state = post_state_word
                .iter()
                .enumerate()
                .map(|(j, limb)| (*limb).into() * AB::Expr::from_u32(1 << (j * 8)))
                .sum::<AB::Expr>();
            builder
                .when(local.is_real)
                .assert_eq(local.poseidon2.permutation.perm_output()[i].into(), post_state);
        }

        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into(),
            local.state_addr,
            &local.state_mem,
            local.is_real,
        );

        builder.receive_syscall(
            local.shard,
            local.clk,
            AB::F::from_u32(SyscallCode::POSEIDON2_PERMUTE.syscall_id()),
            local.state_addr,
            AB::Expr::ZERO,
            local.is_real,
            LookupScope::Local,
        );
    }
}
