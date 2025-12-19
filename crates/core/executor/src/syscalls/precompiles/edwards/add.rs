use std::marker::PhantomData;

use zkm_curves::{edwards::EdwardsParameters, EllipticCurve};

use crate::{
    events::{create_ec_add_event, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
    ExecutionError,
};

pub(crate) struct EdwardsAddAssignSyscall<E: EllipticCurve + EdwardsParameters, const S: usize> {
    _phantom: PhantomData<E>,
}

impl<E: EllipticCurve + EdwardsParameters, const S: usize> EdwardsAddAssignSyscall<E, S> {
    /// Create a new instance of the [`EdwardsAddAssignSyscall`].
    pub const fn new() -> Self {
        Self { _phantom: PhantomData }
    }
}

impl<E: EllipticCurve + EdwardsParameters, const S: usize> Syscall for EdwardsAddAssignSyscall<E, S> {
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
        let event = create_ec_add_event::<E, S>(rt, arg1, arg2);
        let syscall_event =
            rt.rt.syscall_event(event.clk, None, rt.next_pc, syscall_code.syscall_id(), arg1, arg2);
        rt.add_precompile_event(syscall_code, syscall_event, PrecompileEvent::EdAdd(event));
        Ok(None)
    }
}
