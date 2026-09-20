use crate::events::{BooleanCircuitGarbleEvent, PrecompileEvent};
use crate::syscalls::{Syscall, SyscallCode, SyscallContext};
use crate::ExecutionError;

pub(crate) struct BooleanCircuitGarbleSyscall;

// number of bytes for each gate input info.
pub const GATE_INFO_BYTES: usize = 17;

impl Syscall for BooleanCircuitGarbleSyscall {
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Result<Option<u32>, ExecutionError> {
        let start_clk = ctx.clk;
        let input_ptr = arg1;
        let output_ptr = arg2;

        let mut result = true;

        // read number of gates
        let (num_gates_read_record, num_gates_u32) = ctx.mr(input_ptr);

        let (delta_read_records, delta_u32s) = ctx.mr_slice(input_ptr + 4, 4);
        let delta: [u32; 4] = delta_u32s.try_into().unwrap();

        let gate_input_size = GATE_INFO_BYTES as u32 * num_gates_u32;
        let gates_base_ptr = input_ptr + 20;
        let (gate_read_records, gates_info) =
            ctx.mr_slice(gates_base_ptr, gate_input_size as usize);

        // for each gate info
        for i in 0..num_gates_u32 {
            let base = i as usize * GATE_INFO_BYTES;

            let gate_type_u32 = gates_info[base];
            let h0 = &gates_info[base + 1..base + 5];
            let h1 = &gates_info[base + 5..base + 9];
            let label_b = &gates_info[base + 9..base + 13];
            let expected_ciphertext = &gates_info[base + 13..base + 17];

            let computed_ciphertext = h0
                .iter()
                .zip(h1.iter().zip(label_b.iter().zip(delta.iter())))
                .map(|(&h0_i, (&h1_i, (&label_b_i, &delta_i)))| {
                    if gate_type_u32 == 0 {
                        // AND gate
                        h0_i ^ h1_i ^ label_b_i
                    } else {
                        // OR gate
                        h0_i ^ h1_i ^ label_b_i ^ delta_i
                    }
                })
                .collect::<Vec<u32>>();

            let checked = computed_ciphertext.as_slice() == expected_ciphertext;
            result = result && checked;
        }

        // write result to output
        let write_record = ctx.mw(output_ptr, result as u32);
        let shard = ctx.current_shard();
        let event = BooleanCircuitGarbleEvent {
            shard,
            clk: start_clk,
            input_addr: input_ptr,
            output_addr: output_ptr,
            num_gates: num_gates_u32,
            delta,
            gates_info: gates_info.clone(),
            output: result as u32,
            num_gates_read_record,
            delta_read_records: delta_read_records.try_into().unwrap(),
            gates_read_records: gate_read_records,
            output_write_record: write_record,
            local_mem_access: ctx.postprocess(),
        };
        let syscall_event = ctx.rt.syscall_event(
            start_clk,
            None,
            ctx.next_pc,
            syscall_code.syscall_id(),
            arg1,
            arg2,
        );
        ctx.add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::BooleanCircuitGarble(event),
        );
        Ok(None)
    }
}
