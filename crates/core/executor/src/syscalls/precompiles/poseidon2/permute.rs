use crate::events::{Poseidon2PermuteEvent, PrecompileEvent};
use crate::syscalls::{Syscall, SyscallCode, SyscallContext};
use p3_field::{FieldAlgebra, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_symmetric::Permutation;
use zkm_primitives::poseidon2_init;

pub(crate) const STATE_SIZE: usize = 16;

pub(crate) struct Poseidon2PermuteSyscall;

impl Syscall for Poseidon2PermuteSyscall {
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let start_clk = ctx.clk;
        let state_ptr = arg1;
        if arg2 != 0 {
            panic!("Expected arg2 to be 0, got {arg2}");
        }
        if !state_ptr.is_multiple_of(4) {
            panic!("state_ptr must be aligned");
        }

        // First read the words for the state. We can read a slice_unsafe here because we write
        // the post-state to state_ptr later.
        let pre_state = ctx.slice_unsafe(state_ptr, STATE_SIZE);
        let pre_state: [u32; 16] = pre_state.as_slice().try_into().unwrap();

        let mut state = pre_state.map(KoalaBear::from_canonical_u32);

        let hasher = poseidon2_init();
        hasher.permute_mut(&mut state);

        let post_state = state.map(|x| x.as_canonical_u32());
        let state_records = ctx.mw_slice(state_ptr, &post_state);

        // Push the Poseidon2 permute event.
        let shard = ctx.current_shard();
        let event = PrecompileEvent::Poseidon2Permute(Poseidon2PermuteEvent {
            shard,
            clk: start_clk,
            pre_state,
            post_state,
            state_records,
            state_addr: state_ptr,
            local_mem_access: ctx.postprocess(),
        });

        let syscall_event = ctx.rt.syscall_event(
            start_clk,
            None,
            ctx.next_pc,
            syscall_code.syscall_id(),
            arg1,
            arg2,
        );
        ctx.add_precompile_event(syscall_code, syscall_event, event);

        None
    }
}
