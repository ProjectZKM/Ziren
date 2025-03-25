use crate::{
    syscalls::{Syscall, SyscallCode, SyscallContext},
};

use tiny_keccak::keccakf;
use crate::events::{KeccakSpongeEvent, PrecompileEvent};

pub(crate) const STATE_SIZE: usize = 25;
pub(crate) const GENERAL_BLOCK_SIZE_U32S: usize = 36;
pub(crate) const GENERAL_BLOCK_SIZE_U64S: usize = 18;
pub(crate) const KECCAK_GENERAL_OUTPUT_U64S: usize = 8;

pub(crate) struct KeccakSpongeSyscall;

impl Syscall for KeccakSpongeSyscall {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let start_clk = rt.clk;
        let input_ptr = arg1;
        let result_ptr = arg2;

        let mut input_read_records = Vec::new();
        let mut output_write_records = Vec::new();

        let mut state = [0_u64; STATE_SIZE];

        let (
            initial_records,
            initial_values
        ) = rt.mr_slice(result_ptr, 2);

        let [rate_len_bytes, input_len_u32s] = initial_values[0..2].try_into().unwrap();
        let [rate_length_record, input_length_record] = initial_records[0..2].try_into().unwrap();
        // General block size = 36 u32s
        assert_eq!(input_len_u32s as usize % GENERAL_BLOCK_SIZE_U32S, 0);

        // rate_len_bytes must be in {144, 136, 104, 72}
        assert!([144, 136, 104, 72].contains(&rate_len_bytes));

        let (input_records, input_values) = rt.mr_slice(input_ptr, input_len_u32s as usize);
        input_read_records.extend_from_slice(&input_records);

        let mut input_u64_values = Vec::new();
        for values in input_values.chunks_exact(2) {
            let least_sig = values[0];
            let most_sig = values[1];
            input_u64_values.push(least_sig as u64 + ((most_sig as u64) << 32));
        }

        // Perform
        for block in input_u64_values.chunks_exact(GENERAL_BLOCK_SIZE_U64S) {
            for (i, value) in block.iter().enumerate() {
                state[i] ^= *value;
            }
            keccakf(&mut state);
        }

        let saved_state = state.clone();

        // Increment the clk by 1 before writing because we read from memory at start_clk.
        rt.clk += 1;
        let mut values_to_write = Vec::new();
        for i in 0..KECCAK_GENERAL_OUTPUT_U64S {
            let most_sig = ((state[i] >> 32) & 0xFFFFFFFF) as u32;
            let least_sig = (state[i] & 0xFFFFFFFF) as u32;
            values_to_write.push(least_sig);
            values_to_write.push(most_sig);
        }

        let write_records = rt.mw_slice(result_ptr, values_to_write.as_slice());
        output_write_records.extend_from_slice(&write_records);

        // Push the Keccak permute event.
        let shard = rt.current_shard();
        let event = PrecompileEvent::KeccakSponge(KeccakSpongeEvent {
            shard,
            clk: start_clk,
            input: input_values,
            output: values_to_write.as_slice().try_into().unwrap(),
            input_len_u32s,
            rate_len_bytes,
            input_read_records,
            rate_length_record,
            input_length_record,
            output_write_records,
            input_addr: input_ptr,
            output_addr: result_ptr,
            local_mem_access: rt.postprocess(),
        });
        let syscall_event =
            rt.rt.syscall_event(start_clk, None, None, rt.next_pc, syscall_code.syscall_id(), arg1, arg2);
        rt.add_precompile_event(syscall_code, syscall_event, event);

        None
    }
}
