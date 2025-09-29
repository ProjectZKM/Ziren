use std::vec;

use crate::{
    events::{LinuxEvent, PrecompileEvent},
    syscalls::{write::write_fd, Syscall, SyscallCode, SyscallContext},
    Register,
};

pub(crate) struct SysWriteSyscall;

impl Syscall for SysWriteSyscall {
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
        let a2 = Register::A2;
        let (record, v0) = rt.mr(a2 as u32);
        let fd = a0;
        let write_buf = a1;
        let nbytes = v0;
        let bytes = (0..nbytes).map(|i| rt.rt.byte(write_buf + i)).collect::<Vec<u8>>();
        let slice = bytes.as_slice();
        write_fd(rt, fd, slice);

        let a3_record = rt.mw(Register::A3 as u32, 0);
        let shard = rt.current_shard();
        let event = PrecompileEvent::Linux(LinuxEvent {
            shard,
            clk: start_clk,
            a0,
            a1,
            v0,
            syscall_code: syscall_code.syscall_id(),
            read_records: vec![record],
            write_records: vec![a3_record],
            local_mem_access: rt.postprocess(),
        });
        let syscall_event =
            rt.rt.syscall_event(start_clk, None, rt.next_pc, syscall_code.syscall_id(), a0, a1);
        rt.add_precompile_event(SyscallCode::SYS_LINUX, syscall_event, event);
        Some(v0)
    }
}
