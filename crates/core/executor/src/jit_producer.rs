//! Native minimal-trace producer: the parent's `execute_minimal` runs the
//! guest as one program-wide JIT function instead of the interpreter.
//!
//! Native code executes the program, keeps the per-shard budgets in registers
//! and hands the executor exactly
//! the interpreter's side effects — the flat memory, the register records,
//! the clock, the oracle of pre-access values and the shard-split
//! accounting. This module is the executor half of that design; the native
//! half is [`zkm_core_jit::backends::x86::producer`].
//!
//! Division of labour:
//!
//! * **Native** (`build_producer`): every ALU / load / store / branch /
//!   jump / misc instruction whose lowering matches the interpreter bit for
//!   bit. Per instruction it stamps the registers the interpreter's
//!   `rr`/`rw` stamp, bumps the clock by 5, pushes the pre-access value of
//!   every memory word read or written to the oracle, charges the trace
//!   area / chip heights / touched addresses and fences the shard where
//!   [`Executor::inc_shard_if_need`] would.
//! * **Interpreter** (through [`producer_handler`]): syscalls, statically
//!   invalid encodings and operand forms the lowering does not model. The
//!   handler syncs the native state into the executor, runs
//!   [`Executor::execute_cycle`] for that one instruction and syncs back.
//! * **Host driver** ([`run`]): shard fences (`inc_shard_if_need` +
//!   `bump_record`, exactly the interpreter loop's bookkeeping), oracle
//!   growth, program end.
//!
//! The chunks the producer emits are byte-identical to the interpreter's
//! (`tests::producer_matches_interpreter_*`); the parent's `execute_minimal`
//! uses it whenever the executor is in the plain minimal-trace configuration
//! (see `platform::eligible`), with no switch.
//!
//! Known, deliberate divergences from the interpreter (all shared with the
//! block JIT, none reachable by a well-formed guest): a taken branch to pc 0
//! falls through instead of ending the program; per-opcode counts in the
//! `ExecutionReport` are folded into `ADD` (the total is exact); an
//! out-of-range load traps into the interpreter, which panics on the flat
//! memory bound like the interpreter alone would.

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
use crate::{ExecutionError, Executor};

/// Batches the producer has taken, for tests and for the one-line
/// `PRODUCER` census a caller can log. Not load-bearing.
///
/// `AtomicUsize`, not `AtomicU64`: a guest that verifies a proof of this
/// system inside the machine links this crate, and the guest target is
/// 32-bit with no `target_has_atomic = "64"`.  The counter is a batch
/// count, so pointer width is ample.
#[doc(hidden)]
pub static PRODUCER_BATCHES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod platform;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub(crate) use platform::run;

/// No native producer on this platform: the interpreter runs everything.
#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
pub(crate) fn run(
    _exec: &mut Executor<'_>,
    _num_shards_executed: &mut u32,
) -> Result<Option<bool>, ExecutionError> {
    Ok(None)
}
