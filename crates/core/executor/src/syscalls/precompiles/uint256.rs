use num::{BigUint, One, Zero};

use zkm_curves::edwards::WORDS_FIELD_ELEMENT;
use zkm_primitives::consts::{bytes_to_words_le, words_to_bytes_le_vec, WORD_SIZE};

use crate::{
    events::{PrecompileEvent, Uint256MulEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
    ExecutionError,
};

pub(crate) struct Uint256MulSyscall;

impl Syscall for Uint256MulSyscall {
    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Result<Option<u32>, ExecutionError> {
        let clk = rt.clk;

        let x_ptr = arg1;
        if !x_ptr.is_multiple_of(4) {
            panic!();
        }
        let y_ptr = arg2;
        if !y_ptr.is_multiple_of(4) {
            panic!();
        }

        let x = rt.slice_unsafe(x_ptr, WORDS_FIELD_ELEMENT);

        let (y_memory_records, y) = rt.mr_slice(y_ptr, WORDS_FIELD_ELEMENT);

        let modulus_ptr = y_ptr + WORDS_FIELD_ELEMENT as u32 * WORD_SIZE as u32;
        let (modulus_memory_records, modulus) = rt.mr_slice(modulus_ptr, WORDS_FIELD_ELEMENT);

        let uint256_x = BigUint::from_bytes_le(&words_to_bytes_le_vec(&x));
        let uint256_y = BigUint::from_bytes_le(&words_to_bytes_le_vec(&y));
        let uint256_modulus = BigUint::from_bytes_le(&words_to_bytes_le_vec(&modulus));

        let result: BigUint = if uint256_modulus.is_zero() {
            let modulus = BigUint::one() << 256;
            (uint256_x * uint256_y) % modulus
        } else {
            (uint256_x * uint256_y) % uint256_modulus
        };

        let mut result_bytes = result.to_bytes_le();
        result_bytes.resize(32, 0u8);

        let result = bytes_to_words_le::<8>(&result_bytes);

        rt.clk += 1;
        let x_memory_records = rt.mw_slice(x_ptr, &result);

        let shard = rt.current_shard();
        let event = PrecompileEvent::Uint256Mul(Uint256MulEvent {
            shard,
            clk,
            x_ptr,
            x,
            y_ptr,
            y,
            modulus,
            x_memory_records,
            y_memory_records,
            modulus_memory_records,
            local_mem_access: rt.postprocess(),
        });
        let sycall_event =
            rt.rt.syscall_event(clk, None, rt.next_pc, syscall_code.syscall_id(), arg1, arg2);
        rt.add_precompile_event(syscall_code, sycall_event, event);

        Ok(None)
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
