use crate::events::MemoryAccessPosition;
use super::{context::SyscallContext, Syscall, SyscallCode};

pub const PAGE_ADDR_SIZE: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_ADDR_SIZE;
pub const PAGE_ADDR_MASK: usize = PAGE_SIZE - 1;

pub const FD_STDIN: u32 = 0;
pub const FD_STDOUT: u32 = 1;
pub const FD_STDERR: u32 = 2;
pub const MIPS_EBADF: u32 = 9;

pub(crate) struct MmapSyscall;
impl Syscall for MmapSyscall {
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        hint: u32,
        size: u32,
    ) -> Option<(u32, u32)> {
        let mut v0 = 0;
        let mut final_size = size;
        if size & (PAGE_ADDR_MASK as u32) != 0 {
            // adjust size to align with page size
            final_size += PAGE_SIZE as u32 - (size & (PAGE_ADDR_MASK as u32));
        }
        if hint == 0 {
            v0 = ctx.rt.register(crate::Register::HEAP);
            ctx.rt.rw(crate::Register::HEAP, v0 + final_size, MemoryAccessPosition::S);
        } else {
            v0 = hint;
        }
        Some((v0, 0))
    }
}

pub(crate) struct CloneSyscall;
impl Syscall for CloneSyscall {
    fn execute(
        &self,
        _ctx: &mut SyscallContext,
        _: SyscallCode,
        _: u32,
        _: u32,
    ) -> Option<(u32, u32)> {
        Some((1, 0))
    }
}

pub(crate) struct BrkSyscall;
impl Syscall for BrkSyscall {
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        a0: u32,
        _: u32,
    ) -> Option<(u32, u32)> {
        let brk = ctx.rt.register(crate::Register::BRK);
        let v0 = if a0 > brk { a0 } else { brk };
        Some((v0, 0))
    }
}

pub(crate) struct ReadSyscall;
impl Syscall for ReadSyscall {
    fn execute(
        &self,
        _ctx: &mut SyscallContext,
        _: SyscallCode,
        a0: u32,
        _: u32,
    ) -> Option<(u32, u32)> {
        let mut v0 = 0u32;
        let mut v1 = 0u32;
        match a0 {
            FD_STDIN => {
                // leave v0 and v1 zero: read nothing, no error
            }
            _ => {
                v0 = 0xffffffff;
                v1 = MIPS_EBADF;
            }
        }
        Some((v0, v1))
    }
}

pub(crate) struct FcntlSyscall;
impl Syscall for FcntlSyscall {
    fn execute(
        &self,
        _ctx: &mut SyscallContext,
        _: SyscallCode,
        a0: u32,
        a1: u32,
    ) -> Option<(u32, u32)> {
        let mut v0 = 0u32;
        let mut v1 = 0u32;
        if a1 == 3 {
            // F_GETFL: get file descriptor flags
            match a0 {
                FD_STDIN => {
                    v0 = 0 // O_RDONLY
                }
                FD_STDOUT | FD_STDERR => {
                    v0 = 1 // O_WRONLY
                }
                _ => {
                    v0 = 0xffffffff;
                    v1 = MIPS_EBADF;
                }
            }
        } else if a1 == 1 {
            // GET_FD
            match a0 {
                FD_STDIN | FD_STDOUT | FD_STDERR => v0 = a0,
                _ => {
                    v0 = 0xffffffff;
                    v1 = MIPS_EBADF;
                }
            }
        } else {
            v0 = 0xffffffff;
            v1 = MIPS_EBADF;
        }
        Some((v0, v1))
    }
}

pub(crate) struct SetThreadAreaSyscall;
impl Syscall for SetThreadAreaSyscall {
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        a0: u32,
        _: u32,
    ) -> Option<(u32, u32)> {
        ctx.rt.rw(crate::Register::LOCAL_USER, a0, MemoryAccessPosition::S);
        Some((0, 0))
    }
}
