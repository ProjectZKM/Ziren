use crate::air::MemoryAirBuilder;
use crate::operations::{IsEqualWordOperation, XorOperation};
use crate::syscall::precompiles::boolean_circuit_garble::columns::{
    BooleanCircuitGarbleCols, NUM_BOOLEAN_CIRCUIT_GARBLE_COLS,
};
use crate::syscall::precompiles::boolean_circuit_garble::{
    BooleanCircuitGarbleChip, GATE_INFO_BYTES, OR_GATE_ID,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use std::borrow::Borrow;
use zkm_core_executor::syscalls::SyscallCode;
use zkm_stark::{air::AirLookup, LookupKind, LookupScope, ZKMAirBuilder};

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
        let local = main.current_slice();
        let local: &BooleanCircuitGarbleCols<AB::Var> = (*local).borrow();

        // Every real worker row is exactly one gate.
        builder.assert_bool(local.is_real);
        builder.assert_bool(local.gate_type[0]);
        builder.assert_bool(local.gate_type[1]);
        builder.assert_eq(local.gate_type[0] + local.gate_type[1], local.is_real);

        // PrecompileChain state bus: receive `(gate_id, input_address)` and send
        // `(gate_id + 1, input_address + GATE_INFO_BYTES*4)`, carrying the
        // per-syscall constants `gates_num`/`delta` so the matched tuple pins
        // them.  This replaces the legacy `next.*` gate chaining and the
        // `when_first_row` header logic (now in the control chip).
        self.eval_state_bus(builder, local);

        // Constrain memory (per-gate info reads).
        self.eval_memory_access(builder, local);
        // Constrain the gate logic (XORs + ciphertext equality checks).
        self.eval_logic_check(builder, local);
        // Bind the one-hot gate type to the gate-type byte read from memory.
        self.eval_gate_type(builder, local);
    }
}

impl BooleanCircuitGarbleChip {
    /// `PrecompileChain` state bus.  Each real worker row RECEIVEs its
    /// `(gate_id, input_address)` and SENDs `(gate_id + 1, input_address +
    /// GATE_INFO_BYTES*4)`.  The control chip seeds `@ gate_id = 0` and drains
    /// `@ gate_id = gates_num`, so the multiset only balances when the chain
    /// telescopes `0 → gates_num` across exactly `gates_num` worker rows,
    /// pinning each row's `gate_id`/`input_address` and the constancy of
    /// `shard`/`clk`/`gates_num`/`delta`.  A leading `pid =
    /// BOOLEAN_CIRCUIT_GARBLE.syscall_id()` isolates this chain on the shared
    /// `PrecompileChain` kind.
    fn eval_state_bus<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &BooleanCircuitGarbleCols<AB::Var>,
    ) {
        let pid = AB::Expr::from_u32(SyscallCode::BOOLEAN_CIRCUIT_GARBLE.syscall_id());

        let tuple = |gate_id: AB::Expr, input_address: AB::Expr| -> Vec<AB::Expr> {
            let mut vals = vec![
                pid.clone(),
                local.shard.into(),
                local.clk.into(),
                gate_id,
                local.gates_num.into(),
                input_address,
            ];
            for word in local.delta.iter() {
                for b in word.0.iter() {
                    vals.push((*b).into());
                }
            }
            vals
        };

        // Receive the current `(gate_id, input_address)`.
        builder.receive(
            AirLookup::new(
                tuple(local.gate_id.into(), local.input_address.into()),
                local.is_real.into(),
                LookupKind::PrecompileChain,
            ),
            LookupScope::Local,
        );

        // Send the next `(gate_id + 1, input_address + GATE_INFO_BYTES*4)`.
        builder.send(
            AirLookup::new(
                tuple(
                    local.gate_id.into() + AB::Expr::ONE,
                    local.input_address.into()
                        + AB::Expr::from_u32((GATE_INFO_BYTES * 4) as u32),
                ),
                local.is_real.into(),
                LookupKind::PrecompileChain,
            ),
            LookupScope::Local,
        );
    }

    fn eval_memory_access<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &BooleanCircuitGarbleCols<AB::Var>,
    ) {
        // Read this gate's 17-word info block at `input_address`.
        for i in 0..GATE_INFO_BYTES {
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.input_address + AB::Expr::from_u32((i as u32) * 4),
                &local.gates_input_mem[i],
                local.is_real,
            );
        }
    }

    fn eval_logic_check<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &BooleanCircuitGarbleCols<AB::Var>,
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
                local.is_real,
            );

            XorOperation::<AB::F>::eval(
                builder,
                local.aux1[i].value,
                local.gates_input_mem[label_b_id].access.value,
                local.aux2[i],
                local.is_real,
            );

            XorOperation::<AB::F>::eval(
                builder,
                local.aux2[i].value,
                local.delta[i],
                local.aux3[i],
                local.is_real,
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
        builder.when(local.is_real).assert_eq(
            local.checks[0],
            local.is_equal_words[0].is_diff_zero.result
                * local.is_equal_words[1].is_diff_zero.result,
        );
        builder.when(local.is_real).assert_eq(
            local.checks[1],
            local.is_equal_words[2].is_diff_zero.result * local.checks[0],
        );
        builder.when(local.is_real).assert_eq(
            local.checks[2],
            local.is_equal_words[3].is_diff_zero.result * local.checks[1],
        );
    }

    fn eval_gate_type<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &BooleanCircuitGarbleCols<AB::Var>,
    ) {
        // On a gate row `gates_input_mem[0]` is the gate-type byte read from
        // memory; bind the one-hot `gate_type` to it (`OR` → `OR_GATE_ID`,
        // `AND` → 0).
        let bytes_shift = AB::F::from_u32(256);
        let bs2 = bytes_shift.clone() * bytes_shift.clone();
        let bs3 = bs2.clone() * bytes_shift.clone();
        let mem_gate_type = local.gates_input_mem[0].access.value.0[0]
            + local.gates_input_mem[0].access.value.0[1] * bytes_shift
            + local.gates_input_mem[0].access.value.0[2] * bs2
            + local.gates_input_mem[0].access.value.0[3] * bs3;

        let gate_type_value: AB::Expr = local.gate_type[1].into();
        builder
            .when(local.is_real)
            .assert_eq(gate_type_value * AB::Expr::from_u32(OR_GATE_ID), mem_gate_type);
    }
}
