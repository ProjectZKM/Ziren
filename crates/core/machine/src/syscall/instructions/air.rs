use crate::frame::clk_from_r_type_frame;
use crate::memory::RegisterCols;
use std::borrow::Borrow;

use p3_air::{Air, AirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use zkm_core_executor::{syscalls::SyscallCode, Opcode};
use zkm_pcs::{
    air::{
        BaseAirBuilder, LookupScope, PublicValues, ZKMAirBuilder, POSEIDON_NUM_WORDS,
        PV_DIGEST_NUM_WORDS, ZKM_PROOF_NUM_PV_ELTS,
    },
    Word,
};

use crate::{
    air::WordAirBuilder,
    operations::{IsZeroOperation, KoalaBearWordRangeChecker},
};

use super::{columns::SyscallInstrColumns, SyscallInstrsChip};

impl<AB> Air<AB> for SyscallInstrsChip
where
    AB: ZKMAirBuilder,
    AB::Var: Sized,
{
    /// Constrains a `SYSCALL` row. It is sound because only the `SYSCALL`
    /// opcode is received (`is_real ∈ {0,1}`), `op_a_immutable = 0`,
    /// `is_syscall = 1`, `next_pc = is_halt ? 0 : pc + 4` (the halt row sends
    /// `(0, 4)` to the final endpoint), and `num_extra_cycles`, `op_a_val`,
    /// `is_halt` are fixed here, in `eval_syscall` and `eval_is_halt_syscall`.
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &SyscallInstrColumns<AB::Var> = (*local).borrow();

        let public_values_slice: [AB::PublicVar; ZKM_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| builder.public_values()[i]);
        let public_values: &PublicValues<Word<AB::PublicVar>, AB::PublicVar> =
            public_values_slice.as_slice().borrow();

        builder.assert_bool(local.is_real);

        self.eval_is_halt_syscall(builder, local);

        crate::frame::eval_r_type_frame(
            builder,
            &local.frame,
            local.is_real * Opcode::SYSCALL.as_field::<AB::F>(),
            local.pc.into(),
            local.next_pc.into(),
            local.next_pc + AB::Expr::from_u32(4),
            local.state_recv_next_pc.into(),
            local.num_extra_cycles.into(),
            local.is_real.into(),
        );
        builder.when(local.is_real).assert_zero(
            local.state_recv_next_pc
                - local.next_pc
                - local.is_halt * (local.pc + AB::Expr::from_u32(4) - local.next_pc),
        );
        builder
            .when(local.is_real)
            .when_not(local.frame.op_a_0)
            .assert_word_eq(local.op_a_value, *local.frame.op_a_access.value());

        builder.assert_eq::<AB::Var, AB::Expr>(
            local.num_extra_cycles,
            self.get_num_extra_syscall_cycles::<AB>(local),
        );

        self.eval_syscall(builder, local);

        self.eval_commit(
            builder,
            local,
            public_values.committed_value_digest,
            public_values.deferred_proofs_digest,
        );

        self.eval_halt_unimpl(builder, local, public_values);
    }
}

// The syscall code is the read-in value of op_a at the start of the instruction.
// We interpret the syscall_code as little-endian bytes and interpret each byte as a u8

#[inline(always)]
fn get_syscall_id<AB: ZKMAirBuilder>(local: &SyscallInstrColumns<AB::Var>) -> AB::Expr {
    let syscall_code = local.frame.op_a_access.prev_value;
    syscall_code[0] + syscall_code[1] * AB::Expr::from_u32(256)
}

#[inline(always)]
fn get_send_table<AB: ZKMAirBuilder>(local: &SyscallInstrColumns<AB::Var>) -> AB::Var {
    let syscall_code = local.frame.op_a_access.prev_value;
    syscall_code[2]
}

#[inline(always)]
fn get_num_extra_cycles<AB: ZKMAirBuilder>(local: &SyscallInstrColumns<AB::Var>) -> AB::Var {
    let syscall_code = local.frame.op_a_access.prev_value;
    syscall_code[3]
}

#[inline(always)]
fn is_send_table<AB: ZKMAirBuilder>(local: &SyscallInstrColumns<AB::Var>) -> AB::Expr {
    local.is_sys_linux + get_send_table::<AB>(local)
}

impl SyscallInstrsChip {
    /// Constraints related to the SYSCALL opcode.
    ///
    /// This method will do the following:
    /// 1. Send the syscall to the precompile table, if needed.
    /// 2. Check for valid op_a values.
    ///
    /// It is sound because `is_real = 0 ⇒ send_to_table = 0`, so padding rows
    /// send nothing, and on `HINT_LEN` the unconstrained `op_a_val` is still a
    /// valid word via the register lookup.
    pub(crate) fn eval_syscall<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &SyscallInstrColumns<AB::Var>,
    ) {
        let syscall_id = get_syscall_id::<AB>(local);
        let send_to_table = is_send_table::<AB>(local);

        builder.assert_bool(get_send_table::<AB>(local));
        builder.assert_bool(local.is_sys_linux);
        builder.assert_bool(send_to_table.clone());

        IsZeroOperation::<AB::F>::eval(
            builder,
            local.frame.op_a_access.prev_value[1].into(),
            local.is_prev_a1_zero,
            local.is_real.into(),
        );
        builder
            .when(local.is_real)
            .assert_eq(local.is_sys_linux, AB::Expr::one() - local.is_prev_a1_zero.result);

        builder.when(AB::Expr::ONE - local.is_real).assert_zero(send_to_table.clone());

        let send_to_precompile = get_send_table::<AB>(local);
        builder.assert_bool(local.op_b_check);
        builder.assert_bool(local.op_c_check);
        builder.when(send_to_precompile).assert_one(local.op_b_check);
        builder.when(local.is_halt).assert_one(local.op_b_check);
        builder.when(send_to_precompile).assert_one(local.op_c_check);
        builder.when(local.is_commit_deferred_proofs.result).assert_one(local.op_c_check);
        builder.when_not(local.is_real).assert_zero(local.op_b_check);
        builder.when_not(local.is_real).assert_zero(local.op_c_check);

        KoalaBearWordRangeChecker::<AB::F>::range_check::<AB>(
            builder,
            local.frame.op_b_val(),
            local.op_b_range_check,
            local.op_b_check.into(),
        );
        KoalaBearWordRangeChecker::<AB::F>::range_check::<AB>(
            builder,
            local.frame.op_c_val(),
            local.op_c_range_check,
            local.op_c_check.into(),
        );

        builder.send_syscall_halves(
            local.frame.shard,
            clk_from_r_type_frame::<AB>(&local.frame),
            syscall_id.clone(),
            AB::word_to_halves(local.frame.op_b_val()),
            AB::word_to_halves(local.frame.op_c_val()),
            local.is_sys_linux,
            send_to_table,
            LookupScope::Local,
        );

        builder.send_syscall_result(
            local.frame.shard,
            clk_from_r_type_frame::<AB>(&local.frame),
            local.op_a_value,
            local.frame.op_b_val(),
            local.frame.op_c_val(),
            local.is_sys_linux,
            LookupScope::Local,
        );

        let is_enter_unconstrained = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id.clone()
                    - AB::Expr::from_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
                local.is_enter_unconstrained,
                local.is_real.into(),
            );
            local.is_enter_unconstrained.result
        };

        builder
            .when(local.is_real)
            .when_not(is_enter_unconstrained)
            .assert_eq(local.syscall_id, syscall_id.clone());

        builder.when(local.is_real).when(is_enter_unconstrained).assert_eq(
            local.syscall_id,
            AB::Expr::from_u32(SyscallCode::EXIT_UNCONSTRAINED.syscall_id()),
        );

        let is_hint_len = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id.clone() - AB::Expr::from_u32(SyscallCode::SYSHINTLEN.syscall_id()),
                local.is_hint_len,
                local.is_real.into(),
            );
            local.is_hint_len.result
        };

        let zero_word = Word::<AB::F>::from(0);
        builder
            .when(local.is_real)
            .when(is_enter_unconstrained)
            .assert_word_eq(local.op_a_value, zero_word);

        builder
            .when(local.is_real)
            .when_not(is_enter_unconstrained + is_hint_len + local.is_sys_linux)
            .assert_word_eq(local.op_a_value, local.frame.op_a_access.prev_value);
    }

    /// Constraints related to the COMMIT and COMMIT_DEFERRED_PROOFS instructions.
    pub(crate) fn eval_commit<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &SyscallInstrColumns<AB::Var>,
        commit_digest: [Word<AB::PublicVar>; PV_DIGEST_NUM_WORDS],
        deferred_proofs_digest: [AB::PublicVar; POSEIDON_NUM_WORDS],
    ) {
        let (is_commit, is_commit_deferred_proofs) =
            self.get_is_commit_related_syscall(builder, local);

        let mut bitmap_sum = AB::Expr::ZERO;
        for bit in local.index_bitmap.iter() {
            builder.when(local.is_real).assert_bool(*bit);
            bitmap_sum = bitmap_sum.clone() + (*bit).into();
        }
        builder
            .when(local.is_real)
            .when(is_commit.clone() + is_commit_deferred_proofs.clone())
            .assert_one(bitmap_sum.clone());
        builder
            .when(local.is_real)
            .when(AB::Expr::ONE - (is_commit.clone() + is_commit_deferred_proofs.clone()))
            .assert_zero(bitmap_sum);

        for (i, bit) in local.index_bitmap.iter().enumerate() {
            builder
                .when(local.is_real)
                .when(*bit)
                .assert_eq(local.frame.op_b_val()[0], AB::Expr::from_u32(i as u32));
        }
        for i in 0..3 {
            builder
                .when(local.is_real)
                .when(is_commit.clone() + is_commit_deferred_proofs.clone())
                .assert_zero(local.frame.op_b_val()[i + 1]);
        }

        let expected_pv_digest_word = builder.index_word_array(&commit_digest, &local.index_bitmap);

        let digest_word = local.frame.op_c_val();

        builder
            .when(local.is_real)
            .when(is_commit.clone())
            .assert_word_eq(expected_pv_digest_word, digest_word);

        let expected_deferred_proofs_digest_element =
            builder.index_array(&deferred_proofs_digest, &local.index_bitmap);

        builder
            .when(local.is_real)
            .when(is_commit_deferred_proofs.clone())
            .assert_eq(expected_deferred_proofs_digest_element, digest_word.reduce::<AB>());
    }

    /// Constraint related to the halt and unimpl instruction.
    pub(crate) fn eval_halt_unimpl<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &SyscallInstrColumns<AB::Var>,
        public_values: &PublicValues<Word<AB::PublicVar>, AB::PublicVar>,
    ) {
        builder.when(local.is_halt).assert_zero(local.next_pc);

        builder
            .when(local.is_halt)
            .assert_eq(local.frame.op_b_val().reduce::<AB>(), public_values.exit_code);
    }

    /// Returns a boolean expression indicating whether the instruction is a HALT instruction.
    pub(crate) fn eval_is_halt_syscall<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &SyscallInstrColumns<AB::Var>,
    ) {
        let syscall_id = get_syscall_id::<AB>(local);

        let is_halt = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id.clone() - AB::Expr::from_u32(SyscallCode::HALT.syscall_id()),
                local.is_halt_check,
                local.is_real.into(),
            );
            local.is_halt_check.result
        };

        let is_exit_group = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id - AB::Expr::from_u32(SyscallCode::SYS_EXT_GROUP.syscall_id()),
                local.is_exit_group_check,
                local.is_real.into(),
            );
            local.is_exit_group_check.result
        };

        let is_halt_or_exit_group = is_halt + is_exit_group;

        builder.assert_eq(local.is_halt, is_halt_or_exit_group * local.is_real);
    }

    /// Returns two boolean expression indicating whether the instruction is a COMMIT or
    /// COMMIT_DEFERRED_PROOFS instruction.
    pub(crate) fn get_is_commit_related_syscall<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &SyscallInstrColumns<AB::Var>,
    ) -> (AB::Expr, AB::Expr) {
        let syscall_id = get_syscall_id::<AB>(local);

        let is_commit = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id.clone() - AB::Expr::from_u32(SyscallCode::COMMIT.syscall_id()),
                local.is_commit,
                local.is_real.into(),
            );
            local.is_commit.result
        };

        let is_commit_deferred_proofs = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id - AB::Expr::from_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id()),
                local.is_commit_deferred_proofs,
                local.is_real.into(),
            );
            local.is_commit_deferred_proofs.result
        };

        (is_commit.into(), is_commit_deferred_proofs.into())
    }

    /// Returns the number of extra cycles from an SYSCALL instruction.
    pub(crate) fn get_num_extra_syscall_cycles<AB: ZKMAirBuilder>(
        &self,
        local: &SyscallInstrColumns<AB::Var>,
    ) -> AB::Expr {
        let num_extra_cycles = get_num_extra_cycles::<AB>(local);

        num_extra_cycles * local.is_real
    }
}
