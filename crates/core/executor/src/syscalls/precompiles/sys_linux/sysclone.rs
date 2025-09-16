use crate::{
    events::{LinuxEvent, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
    Register,
};

pub(crate) struct SysCloneSyscall;

impl Syscall for SysCloneSyscall {
    fn num_extra_cycles(&self) -> u32 {
        0
    }

    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        a0: u32,
        a1: u32,
    ) -> Option<u32> {
        let start_clk = rt.clk;
        let v0 = 1; // Simulate a successful clone operation
        let a3_record = rt.mw(Register::A3 as u32, 0);
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
        Some(v0)
    }
}
