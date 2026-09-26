use crate::syscalls::{Syscall, SyscallCode, SyscallContext};

use crate::events::{KeccakSpongeEvent, PrecompileEvent};
use crate::ExecutionError;
use tiny_keccak::keccakf;

pub(crate) const STATE_SIZE_U64S: usize = 25;
pub(crate) const GENERAL_BLOCK_SIZE_U32S: usize = 36;
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
    ) -> Result<Option<u32>, ExecutionError> {
        let start_clk = rt.clk;
        let input_ptr = arg1;
        let result_ptr = arg2;

        let mut state = [0_u64; STATE_SIZE_U64S];

        let (input_length_record, input_len_u32s) = rt.mr(result_ptr + 16 * 4);

        assert_eq!(input_len_u32s as usize % GENERAL_BLOCK_SIZE_U32S, 0);

        let (input_read_records, input_values) = rt.mr_slice(input_ptr, input_len_u32s as usize);

        let mut xored_state_list = Vec::with_capacity(input_values.len() / GENERAL_BLOCK_SIZE_U32S);

        for block in input_values.as_chunks::<GENERAL_BLOCK_SIZE_U32S>().0 {
            for (lane, words) in block.as_chunks::<2>().0.iter().enumerate() {
                state[lane] ^= words[0] as u64 + ((words[1] as u64) << 32);
            }
            xored_state_list.push(state);

            keccakf(&mut state);
        }

        rt.clk += 1;
        let mut output = [0u32; 2 * KECCAK_GENERAL_OUTPUT_U64S];
        for (lane, words) in output.as_chunks_mut::<2>().0.iter_mut().enumerate() {
            words[0] = (state[lane] & 0xFFFFFFFF) as u32;
            words[1] = ((state[lane] >> 32) & 0xFFFFFFFF) as u32;
        }

        let output_write_records = rt.mw_slice(result_ptr, &output);

        let shard = rt.current_shard();
        let sponge_event = PrecompileEvent::KeccakSponge(KeccakSpongeEvent {
            shard,
            clk: start_clk,
            input: input_values,
            output,
            input_len_u32s,
            input_read_records,
            input_length_record,
            output_write_records,
            xored_state_list,
            input_addr: input_ptr,
            output_addr: result_ptr,
            local_mem_access: rt.postprocess(),
        });
        let sponge_syscall_event =
            rt.rt.syscall_event(start_clk, None, rt.next_pc, syscall_code.syscall_id(), arg1, arg2);
        rt.add_precompile_event(syscall_code, sponge_syscall_event, sponge_event);
        Ok(None)
    }
}
