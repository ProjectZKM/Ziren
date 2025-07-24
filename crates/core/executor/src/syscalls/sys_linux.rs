use super::{context::SyscallContext, Syscall, SyscallCode};

use crate::Register;

pub use zkm_primitives::consts::fd::*;

pub const PAGE_ADDR_SIZE: usize = 12;
pub const PAGE_ADDR_MASK: usize = (1 << PAGE_ADDR_SIZE) - 1;
pub const PAGE_SIZE: usize = 1 << PAGE_ADDR_SIZE;

pub const MIPS_EBADF: u32 = 9;
pub(crate) struct SysMmapSyscall;

impl Syscall for SysMmapSyscall {
    fn execute(&self, ctx: &mut SyscallContext, _: SyscallCode, a0: u32, a1: u32) -> Option<u32> {
        let mut size = a1;
        if size & (PAGE_ADDR_MASK as u32) != 0 {
            // adjust size to align with page size
            size += PAGE_SIZE as u32 - (size & (PAGE_ADDR_MASK as u32));
        }
        let v0 = if a0 == 0 {
            let (_record, v0) = ctx.mr(Register::HEAP as u32);
            let _w_record = ctx.mw(Register::HEAP as u32, v0 + size);
            v0
        } else {
            a0
        };

        ctx.mw(Register::A3 as u32, 0);
        Some(v0)
    }
}

pub(crate) struct SysBrkSyscall;

impl Syscall for SysBrkSyscall {
    fn execute(&self, ctx: &mut SyscallContext, _: SyscallCode, a0: u32, _: u32) -> Option<u32> {
        let (_record, brk) = ctx.mr(Register::BRK as u32);
        let v0 = if a0 > brk { a0 } else { brk };
        ctx.mw(Register::A3 as u32, 0);
        Some(v0)
    }
}

pub(crate) struct SysCloneSyscall;

impl Syscall for SysCloneSyscall {
    fn execute(&self, ctx: &mut SyscallContext, _: SyscallCode, _: u32, _: u32) -> Option<u32> {
        ctx.mw(Register::A3 as u32, 0);
        Some(1)
    }
}

pub(crate) struct SysExitGroupSyscall;

impl Syscall for SysExitGroupSyscall {
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        exit_code: u32,
        _: u32,
    ) -> Option<u32> {
        println!("SysExitGroupSyscall: exit_code: {}", exit_code);
        ctx.set_next_pc(0);
        ctx.set_exit_code(exit_code);
        ctx.mw(Register::A3 as u32, 0);
        None
    }
}

pub(crate) struct SysReadSyscall;

impl Syscall for SysReadSyscall {
    fn execute(&self, ctx: &mut SyscallContext, _: SyscallCode, arg1: u32, _: u32) -> Option<u32> {
        let fd = arg1;
        let mut res = 0;
        if fd != FD_STDIN {
            res = 0xffffffff; // Return error for non-stdin reads.
            ctx.mw(Register::A3 as u32, MIPS_EBADF);
        } else {
            ctx.mw(Register::A3 as u32, 0);
        }
        Some(res)
    }
}

pub(crate) struct SysWriteSyscall;

impl Syscall for SysWriteSyscall {
    fn execute(&self, ctx: &mut SyscallContext, _: SyscallCode, _: u32, _: u32) -> Option<u32> {
        let a2 = Register::A2;
        let rt = &mut ctx.rt;
        let nbytes = rt.register(a2);
        ctx.mw(Register::A3 as u32, 0);
        Some(nbytes)
    }
}

pub(crate) struct SysFcntlSyscall;

impl Syscall for SysFcntlSyscall {
    fn execute(&self, ctx: &mut SyscallContext, _: SyscallCode, a0: u32, a1: u32) -> Option<u32> {
        let v0: u32;
        if a1 == 3 {
            // F_GETFL: get file descriptor flags
            match a0 {
                FD_STDIN => {
                    ctx.mw(Register::A3 as u32, 0);
                    v0 = 0 // O_RDONLY
                }
                FD_STDOUT | FD_STDERR => {
                    ctx.mw(Register::A3 as u32, 0);
                    v0 = 1 // O_WRONLY
                }
                _ => {
                    ctx.mw(Register::A3 as u32, MIPS_EBADF);
                    v0 = 0xffffffff;
                }
            }
        } else if a1 == 1 {
            // GET_FD
            match a0 {
                FD_STDIN | FD_STDOUT | FD_STDERR => {
                    ctx.mw(Register::A3 as u32, 0);
                    v0 = a0;
                },
                _ => {
                    ctx.mw(Register::A3 as u32, MIPS_EBADF);
                    v0 = 0xffffffff;
                }
            }
        } else {
            v0 = 0xffffffff;
            ctx.mw(Register::A3 as u32, MIPS_EBADF);
        }
        Some(v0)
    }
}

pub(crate) struct SysNopSyscall;

impl Syscall for SysNopSyscall {
    fn execute(&self, ctx: &mut SyscallContext, _: SyscallCode, _: u32, _: u32) -> Option<u32> {
        ctx.mw(Register::A3 as u32, 0);
        Some(0)
    }
}
