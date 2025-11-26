use super::{Syscall, SyscallCode, SyscallContext};
use crate::memory::Entry;
use crate::ExecutionError;

pub(crate) struct HintLenSyscall;

impl Syscall for HintLenSyscall {
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        _arg1: u32,
        _arg2: u32,
    ) -> Result<Option<u32>, ExecutionError> {
        if ctx.rt.state.input_stream_ptr >= ctx.rt.state.input_stream.len() {
            log::error!(
                "failed reading stdin due to insufficient input data: input_stream_ptr={}, input_stream_len={}",
                ctx.rt.state.input_stream_ptr,
                ctx.rt.state.input_stream.len()
            );
            return Err(ExecutionError::InvalidSyscallArgs());
        }
        Ok(Some(ctx.rt.state.input_stream[ctx.rt.state.input_stream_ptr].len() as u32))
    }
}

pub(crate) struct HintReadSyscall;

impl Syscall for HintReadSyscall {
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        ptr: u32,
        len: u32,
    ) -> Result<Option<u32>, ExecutionError> {
        if ctx.rt.state.input_stream_ptr >= ctx.rt.state.input_stream.len() {
            log::error!(
                "failed reading stdin due to insufficient input data: input_stream_ptr={}, input_stream_len={}",
                ctx.rt.state.input_stream_ptr,
                ctx.rt.state.input_stream.len()
            );
            return Err(ExecutionError::InvalidSyscallArgs());
        }
        let vec = &ctx.rt.state.input_stream[ctx.rt.state.input_stream_ptr];
        ctx.rt.state.input_stream_ptr += 1;
        if ctx.rt.unconstrained {
            log::error!("hint read should not be used in a unconstrained block");
            return Err(ExecutionError::ExceptionOrTrap());
        }

        if vec.len() as u32 != len || ptr % 4 != 0 {
            log::error!(
                "Invalid hint read syscall arguments: ptr={}, len={}, vec_len={}",
                ptr,
                len,
                vec.len()
            );
            return Err(ExecutionError::InvalidSyscallArgs());
        }

        // Iterate through the vec in 4-byte chunks
        for i in (0..len).step_by(4) {
            // Get each byte in the chunk
            let b1 = vec[i as usize];
            // In case the vec is not a multiple of 4, right-pad with 0s. This is fine because we
            // are assuming the word is uninitialized, so filling it with 0s makes sense.
            let b2 = vec.get(i as usize + 1).copied().unwrap_or(0);
            let b3 = vec.get(i as usize + 2).copied().unwrap_or(0);
            let b4 = vec.get(i as usize + 3).copied().unwrap_or(0);
            let word = u32::from_le_bytes([b1, b2, b3, b4]);

            // Save the data into runtime state so the runtime will use the desired data instead of
            // 0 when first reading/writing from this address.
            ctx.rt.uninitialized_memory_checkpoint.entry(ptr + i).or_insert_with(|| false);
            match ctx.rt.state.uninitialized_memory.entry(ptr + i) {
                Entry::Occupied(_entry) => {
                    log::error!("hint read address is initialized already");
                    return Err(ExecutionError::InvalidSyscallArgs());
                }
                Entry::Vacant(entry) => {
                    entry.insert(word);
                }
            }
        }
        Ok(None)
    }
}
