use crate::{
    events::{LinuxEvent, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
    Register,
};

pub use zkm_primitives::consts::fd::*;

pub const MIPS_EBADF: u32 = 9;

pub(crate) struct SysFcntlSyscall;

impl Syscall for SysFcntlSyscall {
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
        let v0: u32; // Default return value for unsupported operations
        let a3_record = if a1 == 3 {
            // F_GETFL: get file descriptor flags
            match a0 {
                FD_STDIN => {
                    v0 = 0; // O_RDONLY
                    rt.mw(Register::A3 as u32, 0)
                }
                FD_STDOUT | FD_STDERR => {
                    v0 = 1; // O_WRONLY
                    rt.mw(Register::A3 as u32, 0)
                }
                _ => {
                    v0 = 0xffffffff;
                    rt.mw(Register::A3 as u32, MIPS_EBADF)
                }
            }
        } else if a1 == 1 {
            // GET_FD
            match a0 {
                FD_STDIN | FD_STDOUT | FD_STDERR => {
                    v0 = a0;
                    rt.mw(Register::A3 as u32, 0)
                }
                _ => {
                    v0 = 0xffffffff;
                    rt.mw(Register::A3 as u32, MIPS_EBADF)
                }
            }
        } else {
            v0 = 0xffffffff;
            rt.mw(Register::A3 as u32, MIPS_EBADF)
        };

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
