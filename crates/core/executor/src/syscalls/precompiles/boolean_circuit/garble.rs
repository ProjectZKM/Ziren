use crate::events::{BooleanCircuitGarbleEvent, PrecompileEvent};
use crate::syscalls::{Syscall, SyscallCode, SyscallContext};
use crate::ExecutionError;

pub(crate) struct BooleanCircuitGarbleSyscall;

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

        let mut gate_read_records = Vec::new();
        let mut gates_info: Vec<u32> = Vec::new();
        let mut result = true;

        // read number of gates
        let (num_gates_read_record, num_gates_u32) = ctx.mr(input_ptr);

        let (delta_read_records, delta_u32s) = ctx.mr_slice(input_ptr + 4, 4);
        let delta: [u32; 4] = delta_u32s.try_into().unwrap();

        // for each gate info
        let mut gate_info_ptr = input_ptr + 20;
        for _ in 0..num_gates_u32 {
            let (gate_type_record, gate_type_u32) = ctx.mr(gate_info_ptr);
            gate_read_records.push(gate_type_record);
            gates_info.push(gate_type_u32);

            let (h0_read_records, h0_u32s) = ctx.mr_slice(gate_info_ptr + 4, 4);
            gate_read_records.extend_from_slice(&h0_read_records);
            gates_info.extend_from_slice(&h0_u32s);

            let (h1_read_records, h1_u32s) = ctx.mr_slice(gate_info_ptr + 20, 4);
            gate_read_records.extend_from_slice(&h1_read_records);
            gates_info.extend_from_slice(&h1_u32s);

            let (label_b_read_records, label_b_u32s) = ctx.mr_slice(gate_info_ptr + 36, 4);
            gate_read_records.extend_from_slice(&label_b_read_records);
            gates_info.extend_from_slice(&label_b_u32s);

            let (expected_ciphertext, expected_ciphertext_u32s) =
                ctx.mr_slice(gate_info_ptr + 52, 4);
            gate_read_records.extend_from_slice(&expected_ciphertext);
            gates_info.extend_from_slice(&expected_ciphertext_u32s);

            // do the check
            let h0: [u32; 4] = h0_u32s.try_into().unwrap();
            let h1: [u32; 4] = h1_u32s.try_into().unwrap();
            let label_b: [u32; 4] = label_b_u32s.try_into().unwrap();
            let expected_ciphertext: [u32; 4] = expected_ciphertext_u32s.try_into().unwrap();

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

            let checked = computed_ciphertext.as_slice() == expected_ciphertext.as_slice();
            result = result && checked;
            gate_info_ptr += 68;
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
