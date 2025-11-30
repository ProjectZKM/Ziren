use super::{Syscall, SyscallCode, SyscallContext};
use crate::ExecutionError;

pub(crate) struct CommitDeferredSyscall;

impl Syscall for CommitDeferredSyscall {
    #[allow(clippy::mut_mut)]
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        word_idx: u32,
        word: u32,
    ) -> Result<Option<u32>, ExecutionError> {
        let rt = &mut ctx.rt;

        if word_idx as usize >= rt.record.public_values.deferred_proofs_digest.len() {
            return Err(ExecutionError::InvalidSyscallArgs());
        }
        rt.record.public_values.deferred_proofs_digest[word_idx as usize] = word;

        Ok(None)
    }
}
