use crate::{
    events::{LinuxEvent, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
    Register,
};

pub(crate) struct SysMmapSyscall;

pub const PAGE_ADDR_SIZE: usize = 12;
pub const PAGE_ADDR_MASK: usize = (1 << PAGE_ADDR_SIZE) - 1;
pub const PAGE_SIZE: usize = 1 << PAGE_ADDR_SIZE;

impl Syscall for SysMmapSyscall {
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
        let mut size = a1;
        let start_clk = rt.clk;
        if size & (PAGE_ADDR_MASK as u32) != 0 {
            // adjust size to align with page size
            size += PAGE_SIZE as u32 - (size & (PAGE_ADDR_MASK as u32));
        }

        let a3_record = rt.mw(Register::A3 as u32, 0);

        let (v0, write_records) = if a0 == 0 {
            let v0 = rt.rt.register(Register::HEAP);
            let w_record = rt.mw(Register::HEAP as u32, v0 + size);
            (v0, vec![a3_record, w_record])
        } else {
            (a0, vec![a3_record])
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
            write_records,
            local_mem_access: rt.postprocess(),
        });
        let syscall_event =
            rt.rt.syscall_event(start_clk, None, rt.next_pc, syscall_code.syscall_id(), a0, a1);
        rt.add_precompile_event(SyscallCode::SYS_LINUX, syscall_event, event);
        Some(v0)
    }
}
