use zkm_primitives::consts::num_to_comma_separated;

use crate::{
    events::{LinuxEvent, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
    Executor, Register,
};

pub use zkm_primitives::consts::fd::*;

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
        let mut read_records = Vec::new();
        let mut write_records = Vec::new();
        let a2 = Register::A2;
        let (record, v0) = rt.mr(a2 as u32);
        read_records.push(record);

        let fd = a0;
        let write_buf = a1;
        let nbytes = v0;
        let bytes = (0..nbytes).map(|i| rt.rt.byte(write_buf + i)).collect::<Vec<u8>>();
        let slice = bytes.as_slice();
        if fd == FD_STDOUT {
            let s = core::str::from_utf8(slice).unwrap();
            match parse_cycle_tracker_command(s) {
                Some(command) => handle_cycle_tracker_command(rt.rt, command),
                None => {
                    // If the string does not match any known command, print it to stdout.
                    let flush_s = update_io_buf(rt, fd, s);
                    if !flush_s.is_empty() {
                        flush_s.into_iter().for_each(|line| println!("stdout: {line}"));
                    }
                }
            }
        } else if fd == FD_STDERR {
            let s = core::str::from_utf8(slice).unwrap();
            let flush_s = update_io_buf(rt, fd, s);
            if !flush_s.is_empty() {
                flush_s.into_iter().for_each(|line| println!("stderr: {line}"));
            }
        } else if fd == FD_PUBLIC_VALUES {
            rt.rt.state.public_values_stream.extend_from_slice(slice);
        } else if fd == FD_HINT {
            rt.rt.state.input_stream.push(slice.to_vec());
        } else if let Some(mut hook) = rt.rt.hook_registry.get(fd) {
            let res = hook.invoke_hook(rt.rt.hook_env(), slice);
            // Add result vectors to the beginning of the stream.
            let ptr = rt.rt.state.input_stream_ptr;
            rt.rt.state.input_stream.splice(ptr..ptr, res);
        } else {
            tracing::warn!("tried to write to unknown file descriptor {fd}");
        }

        let a3_record = rt.mw(Register::A3 as u32, 0);
        write_records.push(a3_record);
        let shard = rt.current_shard();
        let event = PrecompileEvent::Linux(LinuxEvent {
            shard,
            clk: start_clk,
            a0,
            a1,
            v0,
            syscall_code: syscall_code.syscall_id(),
            read_records,
            write_records,
            local_mem_access: rt.postprocess(),
        });
        let syscall_event =
            rt.rt.syscall_event(start_clk, None, rt.next_pc, syscall_code.syscall_id(), a0, a1);
        rt.add_precompile_event(SyscallCode::SYS_LINUX, syscall_event, event);
        Some(v0)
    }
}

/// An enum representing the different cycle tracker commands.
#[derive(Clone)]
enum CycleTrackerCommand {
    Start(String),
    End(String),
    ReportStart(String),
    ReportEnd(String),
}

/// Parse a cycle tracker command from a string. If the string does not match any known command,
/// returns None.
fn parse_cycle_tracker_command(s: &str) -> Option<CycleTrackerCommand> {
    let (command, fn_name) = s.split_once(':')?;
    let trimmed_name = fn_name.trim().to_string();

    match command {
        "cycle-tracker-start" => Some(CycleTrackerCommand::Start(trimmed_name)),
        "cycle-tracker-end" => Some(CycleTrackerCommand::End(trimmed_name)),
        "cycle-tracker-report-start" => Some(CycleTrackerCommand::ReportStart(trimmed_name)),
        "cycle-tracker-report-end" => Some(CycleTrackerCommand::ReportEnd(trimmed_name)),
        _ => None,
    }
}

/// Handle a cycle tracker command.
fn handle_cycle_tracker_command(rt: &mut Executor, command: CycleTrackerCommand) {
    match command {
        CycleTrackerCommand::Start(name) | CycleTrackerCommand::ReportStart(name) => {
            start_cycle_tracker(rt, &name);
        }
        CycleTrackerCommand::End(name) => {
            end_cycle_tracker(rt, &name);
        }
        CycleTrackerCommand::ReportEnd(name) => {
            // Attempt to end the cycle tracker and accumulate the total cycles in the fn_name's
            // entry in the ExecutionReport.
            if let Some(total_cycles) = end_cycle_tracker(rt, &name) {
                rt.report
                    .cycle_tracker
                    .entry(name.to_string())
                    .and_modify(|cycles| *cycles += total_cycles)
                    .or_insert(total_cycles);
            }
        }
    }
}

/// Start tracking cycles for the given name at the specific depth and print out the log.
fn start_cycle_tracker(rt: &mut Executor, name: &str) {
    let depth = rt.cycle_tracker.len() as u32;
    rt.cycle_tracker.insert(name.to_string(), (rt.state.global_clk, depth));
    let padding = "│ ".repeat(depth as usize);
    log::info!("{padding}┌╴{name}");
}

/// End tracking cycles for the given name, print out the log, and return the total number of cycles
/// in the span. If the name is not found in the cycle tracker cache, returns None.
fn end_cycle_tracker(rt: &mut Executor, name: &str) -> Option<u64> {
    if let Some((start, depth)) = rt.cycle_tracker.remove(name) {
        let padding = "│ ".repeat(depth as usize);
        let total_cycles = rt.state.global_clk - start;
        log::info!("{}└╴{} cycles", padding, num_to_comma_separated(total_cycles));
        return Some(total_cycles);
    }
    None
}

/// Update the io buffer for the given file descriptor with the given string.
#[allow(clippy::mut_mut)]
fn update_io_buf(ctx: &mut SyscallContext, fd: u32, s: &str) -> Vec<String> {
    let rt = &mut ctx.rt;
    let entry = rt.io_buf.entry(fd).or_default();
    entry.push_str(s);
    if entry.contains('\n') {
        // Return lines except for the last from buf.
        let prev_buf = std::mem::take(entry);
        let mut lines = prev_buf.split('\n').collect::<Vec<&str>>();
        let last = lines.pop().unwrap_or("");
        *entry = last.to_string();
        lines.into_iter().map(std::string::ToString::to_string).collect::<Vec<String>>()
    } else {
        vec![]
    }
}
