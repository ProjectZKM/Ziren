use crate::air::MemoryAirBuilder;
use crate::operations::{IsEqualWordOperation, XorOperation};
use crate::syscall::precompiles::boolean_circuit_garble::columns::{
    BooleanCircuitGarbleCols, NUM_BOOLEAN_CIRCUIT_GARBLE_COLS,
};
use crate::syscall::precompiles::boolean_circuit_garble::{
    BooleanCircuitGarbleChip, GATE_INFO_BYTES, OR_GATE_ID,
};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use std::borrow::Borrow;
use zkm_core_executor::syscalls::SyscallCode;
use zkm_stark::{LookupScope, ZKMAirBuilder};

impl<F> BaseAir<F> for BooleanCircuitGarbleChip {
    fn width(&self) -> usize {
        NUM_BOOLEAN_CIRCUIT_GARBLE_COLS
    }
}

impl<AB> Air<AB> for BooleanCircuitGarbleChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &BooleanCircuitGarbleCols<AB::Var> = (*local).borrow();
        let next: &BooleanCircuitGarbleCols<AB::Var> = (*next).borrow();

        builder.receive_syscall(
            local.shard,
            local.clk,
            AB::F::from_canonical_u32(SyscallCode::BOOLEAN_CIRCUIT_GARBLE.syscall_id()),
            local.input_address, // adjust for num_gates u32
            local.output_address,
            local.is_first_row,
            LookupScope::Local,
        );

        self.eval_flags(builder, local);
        self.eval_memory_access(builder, local);
        self.eval_logic_check(builder, local, next);
        self.eval_transition(builder, local, next);
    }
}

impl BooleanCircuitGarbleChip {
    fn eval_flags<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &BooleanCircuitGarbleCols<AB::Var>,
    ) {
        builder.assert_bool(local.is_real);
        builder.assert_bool(local.is_first_gate);
        builder.assert_bool(local.not_last_gate);
        builder.assert_bool(local.is_gate);
        builder.assert_zero(local.is_last_gate * local.is_first_gate);
        builder.when(local.is_gate).assert_one(local.is_last_gate + local.not_last_gate);
        builder.assert_bool(local.gate_type[0]);
        builder.assert_bool(local.gate_type[1]);
        builder.assert_eq(local.gate_type[0] + local.gate_type[1], local.is_gate);
        builder.when(local.is_real).assert_one(local.is_first_row + local.is_gate);
    }

    fn eval_memory_access<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &BooleanCircuitGarbleCols<AB::Var>,
    ) {
        // eval gate number read
        builder.eval_memory_access(
            local.shard,
            local.clk,
            local.input_address, // adjust for num_gates u32,
            &local.gates_input_mem[0],
            local.is_first_row,
        );

        // eval delta read
        for i in 0..4 {
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.input_address + AB::F::from_canonical_u32(4 + (i as u32) * 4),
                &local.gates_input_mem[i + 1],
                local.is_first_row,
            );
        }

        // eval gate info read
        for i in 0..GATE_INFO_BYTES {
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.input_address + AB::F::from_canonical_u32((i as u32) * 4),
                &local.gates_input_mem[i],
                local.is_gate,
            );
        }
        // eval result write
        builder.eval_memory_access(
            local.shard,
            local.clk,
            local.output_address,
            &local.result_mem,
            local.is_last_gate,
        );
    }

    fn eval_logic_check<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &BooleanCircuitGarbleCols<AB::Var>,
        next: &BooleanCircuitGarbleCols<AB::Var>,
    ) {
        // eval XOR operations
        for i in 0..4 {
            let h0_id = 1 + i;
            let h1_id = 5 + i;
            let label_b_id = 9 + i;

            XorOperation::<AB::F>::eval(
                builder,
                local.gates_input_mem[h0_id].access.value,
                local.gates_input_mem[h1_id].access.value,
                local.aux1[i],
                local.is_gate,
            );

            XorOperation::<AB::F>::eval(
                builder,
                local.aux1[i].value,
                local.gates_input_mem[label_b_id].access.value,
                local.aux2[i],
                local.is_gate,
            );

            XorOperation::<AB::F>::eval(
                builder,
                local.aux2[i].value,
                local.delta[i],
                local.aux3[i],
                local.is_gate,
            );
        }

        // eval check
        for i in 0..4 {
            let expected_id = 13 + i;
            IsEqualWordOperation::<AB::F>::eval(
                builder,
                local.aux2[i].value.map(|x| x.into()),
                local.gates_input_mem[expected_id].access.value.map(|x| x.into()),
                local.is_equal_words[i],
                local.gate_type[0].into(),
            );

            IsEqualWordOperation::<AB::F>::eval(
                builder,
                local.aux3[i].value.map(|x| x.into()),
                local.gates_input_mem[expected_id].access.value.map(|x| x.into()),
                local.is_equal_words[i],
                local.gate_type[1].into(),
            );
        }
        builder.when(local.is_gate).assert_eq(
            local.checks[0],
            local.is_equal_words[0].is_diff_zero.result
                * local.is_equal_words[1].is_diff_zero.result,
        );
        builder.when(local.is_gate).assert_eq(
            local.checks[1],
            local.is_equal_words[2].is_diff_zero.result * local.checks[0],
        );
        builder.when(local.is_gate).assert_eq(
            local.checks[2],
            local.is_equal_words[3].is_diff_zero.result * local.checks[1],
        );
        builder
            .when(local.not_last_gate)
            .assert_eq(next.checks[3], local.checks[3] * next.checks[2]);
    }

    fn eval_transition<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &BooleanCircuitGarbleCols<AB::Var>,
        next: &BooleanCircuitGarbleCols<AB::Var>,
    ) {
        let bytes_shift = AB::F::from_canonical_u32(256);
        let num_gates = local.gates_input_mem[0].access.value.0[0]
            + local.gates_input_mem[0].access.value.0[1] * bytes_shift
            + local.gates_input_mem[0].access.value.0[2] * bytes_shift * bytes_shift
            + local.gates_input_mem[0].access.value.0[3] * bytes_shift * bytes_shift * bytes_shift;
        builder.when_first_row().assert_eq(local.gates_num, num_gates.clone());

        for i in 0..4 {
            let delta_i = local.gates_input_mem[i + 1].access.value;
            for j in 0..4 {
                builder.when_first_row().assert_eq(local.delta[i][j], delta_i[j]);
            }
        }

        let gate_type_value = local.gate_type[0] * AB::Expr::zero() + local.gate_type[1];
        builder
            .when(local.is_gate)
            .assert_eq(gate_type_value * AB::Expr::from_canonical_u32(OR_GATE_ID), num_gates);

        builder.when(local.is_first_gate).assert_zero(local.gate_id);
        builder.when(local.is_last_gate).assert_eq(local.gates_num - AB::F::ONE, local.gate_id);
        builder.when(local.not_last_gate).assert_eq(local.gate_id + AB::F::ONE, next.gate_id);

        builder.when(local.not_last_gate * local.is_gate).assert_eq(
            local.input_address + AB::F::from_canonical_usize(GATE_INFO_BYTES * 4),
            next.input_address,
        );

        builder
            .when(local.not_last_gate * local.is_gate)
            .assert_eq(local.gates_num, next.gates_num);

        for i in 0..4 {
            for j in 0..4 {
                builder
                    .when(local.not_last_gate * local.is_gate)
                    .assert_eq(local.delta[i][j], next.delta[i][j]);
            }
        }
    }
}
