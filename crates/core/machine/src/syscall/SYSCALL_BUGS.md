# Syscall Bug Tracker

This file tracks syscall-related AIR issues found during manual review and Picus analysis.

## Picus Findings

### 1. `SyscallInstrs`: `is_sys_linux` is only constrained in one direction

- Location:
  - `crates/core/machine/src/syscall/instructions/air.rs`
- Current constraint:
  - `when_not(is_sys_linux) => prev_a_value[1] = 0`
- Missing reverse direction:
  - `is_sys_linux = 1 => prev_a_value[1] != 0`
  - or more precisely `prev_a_value[1] = linux byte for this syscall`
- Why this matters:
  - A prover can flip `is_sys_linux` from `0` to `1` on rows where `prev_a_value[1] = 0`.
  - This disables the `op_a` unchanged check and routes the row into `SysLinux`.
- Picus symptom:
  - Same row admitted two behaviors:
    - `op_a = prev_a`
    - `op_a = 0`
  - The second behavior came from the `SysLinux -> nop` path.
- Likely fix:
  - Add the reverse implication in `SyscallInstrs`.
  - Long-term better fix: constrain the full syscall metadata bytes canonically from `syscall_id`.

### 2. `SysLinux`: known syscall ids are not forced onto their matching branch

- Location:
  - `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs`
- Current structure:
  - One-way implications such as:
    - `when(is_clone) => syscall_id = SYS_CLONE`
    - `when(is_read) => syscall_id = SYS_READ`
  - One-hot sum:
    - `is_mmap + is_clone + is_exit_group + is_brk + is_fnctl + is_read + is_write + is_nop = 1`
- Missing reverse direction:
  - `syscall_id = SYS_CLONE => is_clone = 1`
  - similarly for the other recognized linux syscall ids
- Why this matters:
  - A recognized linux syscall id can still choose `is_nop = 1`.
  - This makes the result follow the `nop` semantics instead of the intended syscall semantics.
- Picus symptom:
  - For `syscall_id = 4120` (`SYS_CLONE`), two valid outputs were found:
    - `result = 1` via `is_clone`
    - `result = 0` via `is_nop`
- Likely fix:
  - For each recognized linux syscall id, add the reverse implication to the corresponding flag.
  - Restrict `is_nop` to the "unknown linux syscall id" case.

### 3. `SysLinux`: `is_mmap_a0_0` is only constrained in one direction

- Location:
  - `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs`
- Current constraint:
  - `when(is_mmap_a0_0) => is_mmap * is_a0_0 = 1`
- Missing reverse direction:
  - `is_mmap * is_a0_0 = 1 => is_mmap_a0_0 = 1`
  - equivalently `is_mmap_a0_0 = is_mmap * is_a0_0`
- Why this matters:
  - For `mmap`/`mmap2` with `a0 = 0`, the prover can set:
    - `is_mmap = 1`
    - `is_a0_0 = 1`
    - `is_mmap_a0_0 = 0`
  - This skips the guarded `HEAP` memory access and the `result = inorout.prev_value` linkage.
- Picus symptom:
  - For `syscall_id = 4090` (`SYS_MMAP2`) and `a0 = 0`, two different `result` values were admitted.
- Likely fix:
  - Constrain `is_mmap_a0_0` exactly as the product `is_mmap * is_a0_0`.

### 4. `Syscall` bridge still reduces `arg1`/`arg2` modulo the base field

- Locations:
  - `crates/core/machine/src/syscall/instructions/air.rs`
  - `crates/core/machine/src/syscall/chip.rs`
  - `crates/stark/src/word.rs`
- Current behavior:
  - `send_syscall` sends `op_b_value.reduce()` and `op_c_value.reduce()`
  - The syscall table chip also uses reduced `arg1`/`arg2`
- Why this matters:
  - Distinct 32-bit words can collide modulo the KoalaBear prime `0x7f000001`.
  - The later `send_syscall_result` fix helps local byte-level linkage to `SysLinux`, but the older reduced `Syscall` interaction still exists.
- Example collision:
  - `0x80000000`
  - `0x00ffffff`
  - both reduce to the same field element modulo `0x7f000001`
- Status:
  - Still looks like a real structural issue unless the reduced bridge is no longer relied on for soundness.

### 5. `SysLinux::mmap`: `A3` / output write is unconstrained

- Location:
  - `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs`
- Current behavior:
  - `eval_mmap` constrains `result` and the optional `HEAP` write through `local.inorout`
  - but it never constrains `local.output.value()`

### 6. `SysLinux::mmap`: weak `page_offset` / `upper_address` decomposition

- Location:
  - `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs`
- Current constraints:
  - `when(is_offset_0) => page_offset = 0`
  - `page_offset + upper_address = a1.reduce()`
- Missing constraints:
  - `page_offset = a1 & 0xfff`
  - `upper_address = a1 & !0xfff`
  - `page_offset < 4096`
  - `upper_address` page-aligned
  - `is_offset_0 <=> page_offset == 0`

### 7. `SysLinux::exit_group`: unconstrained result

- Current behavior:
  - `SysExitGroupSyscall::execute` returns `Ok(None)` and records `LinuxEvent.v0 = 0`
  - the executor keeps `V0 = syscall_id` whenever a syscall returns `None`
  - the `SysLinux` trace sets `cols.result = event.v0`
  - the syscall-result bridge in `SyscallChip` uses `linux_event.v0` on the precompile side




## Picus Notes

- Current extracted module under investigation:
  - `crates/picus/picus_out/SyscallInstrs.picus`
- Useful variable names from the current extraction:
  - `x_6` = `is_sys_linux`
  - `x_7` = internal `syscall_id`
  - `x_20..x_23` = `prev_a_value[0..3]`
  - `x_127` = `is_mmap`
  - `x_132` = `is_clone`
  - `x_133` = `is_exit_group`
  - `x_134` = `is_brk`
  - `x_142` = `is_fnctl`
  - `x_147` = `is_read`
  - `x_148` = `is_write`
  - `x_149` = `is_nop`
  - `x_124` = `is_a0_0`
  - `x_128` = `is_mmap_a0_0`
