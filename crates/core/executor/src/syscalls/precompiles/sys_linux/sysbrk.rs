use crate::{
    events::{LinuxEvent, PrecompileEvent},
    program::MAX_MEMORY,
    syscalls::{Syscall, SyscallCode, SyscallContext},
    ExecutionError, Register,
};

pub(crate) struct SysBrkSyscall;

/// Maximum amount of heap growth allowed from the program's initial BRK value.
///
/// This is a prover-side safety bound to prevent guest-controlled `brk` values from
/// expanding memory usage without limit.
const MAX_HEAP_SIZE: u32 = 0x4000_0000;

fn max_brk(initial_brk: u32) -> Result<u32, ExecutionError> {
    let limit =
        initial_brk.checked_add(MAX_HEAP_SIZE).ok_or(ExecutionError::InvalidSyscallArgs())?;
    Ok(limit.min(MAX_MEMORY as u32))
}

fn resolve_brk(
    initial_brk: u32,
    current_brk: u32,
    requested_brk: u32,
) -> Result<u32, ExecutionError> {
    let limit = max_brk(initial_brk)?;
    let v0 = requested_brk.max(current_brk);
    if v0 > limit {
        return Err(ExecutionError::InvalidSyscallArgs());
    }
    Ok(v0)
}

impl Syscall for SysBrkSyscall {
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
        let start_clk = rt.clk;
        let (record, brk) = rt.rr_traced(Register::BRK);
        let initial_brk = rt.rt.program.image.get(&(Register::BRK as u32)).copied().unwrap_or(brk);
        let v0 = resolve_brk(initial_brk, brk, a0)?;
        let a3_record = rt.rw_traced(Register::A3, 0);
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
        Ok(Some(v0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_brk_keeps_current_value_when_request_is_lower() {
        assert_eq!(resolve_brk(0x1000, 0x2000, 0x1800).unwrap(), 0x2000);
    }

    #[test]
    fn resolve_brk_allows_growth_within_limit() {
        assert_eq!(resolve_brk(0x1000, 0x2000, 0x3000).unwrap(), 0x3000);
    }

    #[test]
    fn resolve_brk_rejects_growth_past_limit() {
        let initial_brk = 0x1000;
        let limit = max_brk(initial_brk).unwrap();
        assert!(matches!(
            resolve_brk(initial_brk, 0x2000, limit + 4),
            Err(ExecutionError::InvalidSyscallArgs())
        ));
    }

    #[test]
    fn max_brk_rejects_overflowing_initial_brk() {
        assert!(matches!(
            max_brk(u32::MAX - MAX_HEAP_SIZE + 1),
            Err(ExecutionError::InvalidSyscallArgs())
        ));
    }
}
