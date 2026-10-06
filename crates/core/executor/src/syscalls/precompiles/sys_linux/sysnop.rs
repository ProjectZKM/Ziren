use crate::{
    events::{LinuxEvent, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext, ENOSYS},
    ExecutionError, Register,
};

/// A Linux call accepted as a no-op: it touches no memory and answers success with 0.
/// For the calls a runtime issues while starting and whose result carries nothing
/// (signal set-up, `prctl`, `madvise`, `munmap`, `close`, `gettid`, `nanosleep`, ...):
/// Go's runtime throws when `rt_sigaction` fails and crashes when `rt_sigprocmask` does,
/// so these must succeed. A call whose result a program consumes is `SysUnimplementedSyscall`.
pub(crate) struct SysNopSyscall;

/// A Linux call the machine does not implement, failed the way the kernel reports one:
/// `ENOSYS` in `$v0` with the error flag `$a3` set, no memory touched. For calls whose
/// result a program would consume (`open`, `openat`, `fstat64`, `clock_gettime`): the
/// program sees the failure through its C library instead of a value that means nothing.
pub(crate) struct SysUnimplementedSyscall;

impl Syscall for SysNopSyscall {
    fn num_extra_cycles(&self) -> u32 {
        0
    }

    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        a0: u32,
        a1: u32,
    ) -> Result<Option<u32>, ExecutionError> {
        linux_answer(rt, syscall_code, a0, a1, 0, 0)
    }
}

impl Syscall for SysUnimplementedSyscall {
    fn num_extra_cycles(&self) -> u32 {
        0
    }

    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        a0: u32,
        a1: u32,
    ) -> Result<Option<u32>, ExecutionError> {
        linux_answer(rt, syscall_code, a0, a1, ENOSYS, 1)
    }
}

/// Answers a Linux call that touches no memory: `v0` as the result, `a3` as the error flag.
fn linux_answer(
    rt: &mut SyscallContext,
    syscall_code: SyscallCode,
    a0: u32,
    a1: u32,
    v0: u32,
    a3: u32,
) -> Result<Option<u32>, ExecutionError> {
    {
        let start_clk = rt.clk;
        let a3_record = rt.rw_traced(Register::A3, a3);
        let shard = rt.current_shard();
        let event = PrecompileEvent::Linux(LinuxEvent {
            shard,
            clk: start_clk,
            a0,
            a1,
            v0,
            syscall_code: syscall_code.syscall_id(),
            read_records: vec![],
            write_records: vec![a3_record],
            local_mem_access: rt.postprocess(),
        });
        let syscall_event =
            rt.rt.syscall_event(start_clk, None, rt.next_pc, syscall_code.syscall_id(), a0, a1);
        rt.add_precompile_event(SyscallCode::SYS_LINUX, syscall_event, event);
        Ok(Some(v0))
    }
}
