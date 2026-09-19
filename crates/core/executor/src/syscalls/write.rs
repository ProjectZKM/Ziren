use zkm_primitives::consts::num_to_comma_separated;

use crate::{ExecutionError, Executor, Register};

use super::{Syscall, SyscallCode, SyscallContext};

pub use zkm_primitives::consts::fd::*;

pub(crate) struct WriteSyscall;

impl Syscall for WriteSyscall {
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Result<Option<u32>, ExecutionError> {
        let a2 = Register::A2;
        let rt = &mut ctx.rt;
        let fd = arg1;
        let write_buf = arg2;
        let nbytes = rt.register(a2);
        // Read nbytes from memory starting at write_buf.
        let bytes = (0..nbytes).map(|i| rt.byte(write_buf + i)).collect::<Vec<u8>>();
        let slice = bytes.as_slice();
        write_fd(ctx, fd, slice)?;
        Ok(None)
    }
}

pub fn write_fd(ctx: &mut SyscallContext, fd: u32, slice: &[u8]) -> Result<(), ExecutionError> {
    let rt = &mut ctx.rt;
    if fd == FD_STDOUT {
        if let Ok(s) = core::str::from_utf8(slice) {
            match parse_cycle_tracker_command(s) {
                Some(command) => handle_cycle_tracker_command(rt, command),
                None => {
                    let flush_s = update_io_buf(ctx, fd, s);
                    if !flush_s.is_empty() {
                        // NOT `println!`: a multi-GPU core worker speaks its
                        // IPC frames on stdout, so one guest `print!` puts
                        // "stdout: ..." in the middle of a frame and the parent
                        // reads the text as a length prefix. That is a real
                        // reth block (23694455 emits guest stdout) aborting the
                        // parent with `memory allocation of 2322296605591762035
                        // bytes failed` -- 0x203a74756f647473, the eight bytes
                        // of "stdout: ".
                        flush_s.into_iter().for_each(|line| tracing::info!("stdout: {line}"));
                    }
                }
            }
        } else {
            eprintln!("Warning: Stdout Received invalid UTF-8 data in slice: {slice:?}");
        }
    } else if fd == FD_STDERR {
        if let Ok(s) = core::str::from_utf8(slice) {
            let flush_s = update_io_buf(ctx, fd, s);
            if !flush_s.is_empty() {
                // See the `FD_STDOUT` note above: never stdout from here.
                flush_s.into_iter().for_each(|line| tracing::info!("stderr: {line}"));
            }
        } else {
            eprintln!("Warning: Stderr Received invalid UTF-8 data in slice: {slice:?}");
        }
    } else if fd == FD_PUBLIC_VALUES {
        rt.state.public_values_stream.extend_from_slice(slice);
    } else if fd == FD_HINT {
        // On a replay seeded with the recorded stream this entry is already
        // there; pushing it again would double it and desync the cursor.
        if !rt.hint_stream_prerecorded {
            rt.state.input_stream.push(slice.to_vec());
        }
    } else if let Some(mut hook) = rt.hook_registry.get(fd) {
        // Likewise for hook results — and re-invoking the hook would repeat
        // its side effects once per parallel replay worker.
        if !rt.hint_stream_prerecorded {
            let res = hook.invoke_hook(rt.hook_env(), slice)?;
            // Add result vectors to the beginning of the stream.
            let ptr = rt.state.input_stream_ptr;
            rt.state.input_stream.splice(ptr..ptr, res);
        }
    } else {
        tracing::warn!("tried to write to unknown file descriptor {fd}");
    }
    Ok(())
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

/// Open a cycle-tracker scope.
///
/// Reopening a name that is already open is an instrumentation bug: as a
/// name-keyed map this overwrote the original start clock and the outer span's
/// cycles were lost. The scope is still pushed, so nesting stays consistent and
/// the matching ends line up -- the mistake is reported rather than absorbed.
fn start_cycle_tracker(rt: &mut Executor, name: &str) {
    if rt.cycle_tracker.iter().any(|(n, _)| n == name) {
        log::warn!(
            "cycle-tracker-start: {name:?} is already open; nested scopes must have distinct \
             names or their attribution is wrong"
        );
    }
    let depth = rt.cycle_tracker.len();
    rt.cycle_tracker.push((name.to_string(), rt.state.global_clk));
    let padding = "│ ".repeat(depth);
    log::info!("{padding}┌╴{name}");
}

/// Close a cycle-tracker scope, returning its cycle count.
///
/// Enforces LIFO. Closing an outer scope while an inner one is still open used
/// to succeed and leave the inner scope open forever; closing an unknown name
/// was ignored entirely. Both now say so: a non-LIFO close unwinds the scopes
/// above it (reporting each as unclosed) so later ends still align, and an
/// unknown close returns `None` with a warning.
fn end_cycle_tracker(rt: &mut Executor, name: &str) -> Option<u64> {
    let Some(pos) = rt.cycle_tracker.iter().rposition(|(n, _)| n == name) else {
        log::warn!("cycle-tracker-end: {name:?} was never opened");
        return None;
    };
    if pos + 1 != rt.cycle_tracker.len() {
        let inner: Vec<&str> =
            rt.cycle_tracker[pos + 1..].iter().map(|(n, _)| n.as_str()).collect();
        log::warn!(
            "cycle-tracker-end: {name:?} closed while {inner:?} still open; those scopes are \
             unclosed and their cycles are not reported"
        );
        rt.cycle_tracker.truncate(pos + 1);
    }
    let (_, start) = rt.cycle_tracker.pop()?;
    let padding = "│ ".repeat(rt.cycle_tracker.len());
    let total_cycles = rt.state.global_clk.saturating_sub(start);
    log::info!("{}└╴{} cycles", padding, num_to_comma_separated(total_cycles));
    Some(total_cycles)
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

#[cfg(test)]
mod tests {
    use super::{end_cycle_tracker, start_cycle_tracker};
    use crate::{Executor, Program};
    use zkm_pcs::ZKMCoreOpts;

    fn executor() -> Executor<'static> {
        let pc = 0x1000_0000u32;
        Executor::new(Program::new(Vec::new(), pc, pc), ZKMCoreOpts::default())
    }

    fn open(rt: &Executor<'_>) -> Vec<String> {
        rt.cycle_tracker.iter().map(|(n, _)| n.clone()).collect()
    }

    #[test]
    fn nested_scopes_close_innermost_first() {
        let mut rt = executor();
        start_cycle_tracker(&mut rt, "outer");
        rt.state.global_clk = 10;
        start_cycle_tracker(&mut rt, "inner");
        rt.state.global_clk = 30;
        assert_eq!(end_cycle_tracker(&mut rt, "inner"), Some(20));
        assert_eq!(open(&rt), ["outer"], "the outer scope stays open");
        rt.state.global_clk = 40;
        assert_eq!(end_cycle_tracker(&mut rt, "outer"), Some(40));
        assert!(rt.cycle_tracker.is_empty());
    }

    /// As a name-keyed map this OVERWROTE the first start clock, so the outer
    /// span silently measured from the inner one's start.
    #[test]
    fn a_repeated_name_does_not_lose_the_first_start() {
        let mut rt = executor();
        start_cycle_tracker(&mut rt, "dup");
        rt.state.global_clk = 100;
        start_cycle_tracker(&mut rt, "dup");
        assert_eq!(rt.cycle_tracker.len(), 2, "both opens are tracked");
        rt.state.global_clk = 150;
        // Innermost first: 150 - 100.
        assert_eq!(end_cycle_tracker(&mut rt, "dup"), Some(50));
        // ...and the FIRST open still has its own start clock.
        assert_eq!(end_cycle_tracker(&mut rt, "dup"), Some(150));
    }

    /// Closing an outer scope while an inner one is open used to succeed and
    /// leave the inner scope open forever.
    #[test]
    fn a_non_lifo_close_unwinds_rather_than_leaking() {
        let mut rt = executor();
        start_cycle_tracker(&mut rt, "outer");
        start_cycle_tracker(&mut rt, "inner");
        rt.state.global_clk = 60;
        assert_eq!(end_cycle_tracker(&mut rt, "outer"), Some(60));
        assert!(rt.cycle_tracker.is_empty(), "the abandoned inner scope is not left open");
    }

    #[test]
    fn closing_an_unopened_scope_is_reported_not_ignored() {
        let mut rt = executor();
        assert_eq!(end_cycle_tracker(&mut rt, "never-opened"), None);
        start_cycle_tracker(&mut rt, "real");
        assert_eq!(end_cycle_tracker(&mut rt, "other"), None, "a different name does not close it");
        assert_eq!(open(&rt), ["real"]);
    }

    #[test]
    fn depth_follows_nesting() {
        let mut rt = executor();
        start_cycle_tracker(&mut rt, "a");
        start_cycle_tracker(&mut rt, "b");
        start_cycle_tracker(&mut rt, "c");
        assert_eq!(rt.cycle_tracker.len(), 3, "depth is the stack index, so it cannot disagree");
        assert_eq!(open(&rt), ["a", "b", "c"]);
    }
}
