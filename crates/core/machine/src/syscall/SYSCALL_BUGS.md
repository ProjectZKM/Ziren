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
- Picus symptom:
  - Adding KoalaBear-word postconditions for `op_b` / `op_c` fails.
  - Picus finds a model with:
    - `is_sys_linux = 1`
    - unknown linux syscall id, so the `SysLinux -> nop` path is taken
    - `op_b` / `op_c` bytes that are not valid KoalaBear words
  - This shows the extracted bridge still admits non-KoalaBear `arg1` / `arg2` values.
- Example collision:
  - `0x80000000`
  - `0x00ffffff`
  - both reduce to the same field element modulo `0x7f000001`
- Likely fix:
  - Add explicit KoalaBear word checks for `op_b_value` and `op_c_value` on the syscall bridge path.
  - Use `send_to_table` as the multiplicity/enable for the syscall-table interaction, rather than a weaker selector such as `is_sys_linux`.
  - If the reduced `send_syscall` interaction is still kept, it should only be active on rows where those KoalaBear word checks hold.

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

- Location:
  - `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs`
- Current behavior:
  - `eval_exit_group` only constrains `local.output.value()` and does not constrain `local.result`
- Picus symptom:
  - With `x_7 = 4246`, `x_133 = 1`, and `x_149 = 0`, Picus finds two valid models with:
    - the same `A3` write (`x_115..x_118 = 0`)
    - different result bytes (`x_8..x_11`), and therefore different top-level outputs `x_67..x_70`
- Likely fix:
  - Add `assert_word_zero(local.result)` on the `is_exit_group` branch

### 8. `SysLinux::fnctl(a1 == 1)`: missing result constraints

- Locations:
  - `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs`
  - `crates/core/executor/src/syscalls/precompiles/sys_linux/sysfcntl.rs`
- Current behavior:
  - `eval_fnctl` constrains `result` for:
    - `a1 == 3`
    - unsupported `a1`
  - but does not constrain `result` for the supported `a1 == 1` (`F_GETFD`) case
- Executor semantics:
  - for `a1 == 1`:
    - `a0 = 0 => result = 0`
    - `a0 = 1 => result = 1`
    - `a0 = 2 => result = 2`
    - otherwise `result = 0xffffffff`
- Likely fix:
  - Add `result` constraints for the `is_fnctl_a1_1` branch mirroring the executor logic
  - Separately tighten the `is_a0_0` / `is_a0_1` / `is_a0_2` classifiers if exact subcase routing is intended

### 9. `SysLinux`: `is_a0_0` / `is_a0_1` / `is_a0_2` are only constrained in one direction

- Location:
  - `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs`
- Current behavior:
  - the AIR only enforces:
    - `is_a0_0 => a0 == 0`
    - `is_a0_1 => a0 == 1`
    - `is_a0_2 => a0 == 2`
  - but not the reverse implications
- Why this matters:
  - multiple syscall branches use these flags as exact subcase classifiers:
    - `mmap` / `mmap2` branch on `is_a0_0`
    - `read` branches on `is_a0_0`
    - `fnctl` branches on `is_a0_0`, `is_a0_1`, `is_a0_2`
- Picus symptom:
  - For `x_7 = 4090` (`SYS_MMAP2`) with `a0 = 0`, Picus finds two valid models:
    - `is_a0_0 = 1`, which enables the heap path and emits a `HEAP` write
    - `is_a0_0 = 0`, which disables the heap path and falls through to `result = a0 = 0`
  - The same issue also appears in `fnctl`:
    - for `x_7 = 4055` with `a1 = 3` and `a0 = 1`, Picus finds:
      - `is_a0_1 = 0`, which routes to the unsupported-fd branch (`result = 0xffffffff`, `A3 = 9`)
      - `is_a0_1 = 1`, which routes to the supported `F_GETFL` branch (`result = 1`, `A3 = 0`)
- Likely fix:
  - Constrain the `is_a0_*` flags to exactly match the byte word `a0`
  - at minimum, add the missing reverse implications for the `0`, `1`, and `2` cases

### 10. `SysLinux::write`: read value is not tied to previous value

- Locations:
  - `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs`
  - `crates/core/machine/src/syscall/precompiles/sys_linux/trace.rs`
  - `crates/core/machine/src/memory/consistency/trace.rs`
- Current behavior:
  - `eval_write` uses `local.inorout` in `eval_memory_access(...)`
  - then constrains `result = *local.inorout.value()`
  - but does not constrain `local.inorout.value() = local.inorout.prev_value`
- Why this matters:
  - for `SYS_WRITE`, `local.inorout` is populated from a read of register `A2`
  - honest trace generation sets `prev_value = value` for reads
  - the AIR does not enforce that equality for this read-shaped `MemoryReadWriteCols`
- Picus symptom:
  - For `x_7 = 4004` (`SYS_WRITE`) and `x_148 = 1`, Picus finds two valid models with:
    - the same `A3` write (`x_115..x_118 = 0`)
    - different `x_102..x_105 = local.inorout.value()`
    - and therefore different `result` bytes `x_8..x_11`
- Likely fix:
  - On the `is_write` branch, assert `local.inorout.value() = local.inorout.prev_value`
  - or use a read-only memory witness type for the `A2` access instead of `MemoryReadWriteCols`

### 11. `SysLinux::mmap`: new heap value is only constrained through `reduce()`

- Location:
  - `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs`
- Current behavior:
  - on the `mmap(a0 = 0)` path, the AIR constrains:
    - `local.inorout.value().reduce() = size + local.inorout.prev_value.reduce()`
  - but it does not constrain the new heap word `local.inorout.value()` bytewise
- Why this matters:
  - distinct 32-bit words can share the same reduced field element
  - so the new heap value can vary while preserving the reduced equality
- Picus symptom:
  - With `x_7 = 4090`, `x_127 = 1`, `x_124 = 1`, `x_128 = 1`, and the `a1` decomposition fixed,
    Picus still finds two valid models with:
    - the same `result` bytes `x_8..x_11`
    - the same `A3` write
    - different new heap bytes `x_102..x_105`, and therefore different propagated `HEAP` writes `x_202..x_206`
- Likely fix:
  - Constrain the new heap word bytewise rather than only via `reduce()`
  - or add enough range/injectivity constraints so the reduced equality uniquely determines the word

### 12. `SysLinux`: `is_a1_1` / `is_a1_3` are only constrained in one direction

- Location:
  - `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs`
- Current behavior:
  - the AIR only enforces:
    - `is_a1_1 => a1 == 1`
    - `is_a1_3 => a1 == 3`
  - but not the reverse implications
- Why this matters:
  - the `fnctl` logic uses `is_a1_1` / `is_a1_3` as exact subcase classifiers
  - so even when `a1 == 1` or `a1 == 3`, the prover can clear those flags and route the row into the unsupported-op branch
- Picus symptom:
  - For `x_7 = 4055` (`SYS_FCNTL`) with `a1 = 1`, Picus finds two valid models:
    - one with `is_a1_1 = 0`, which takes the unsupported-`a1` branch
    - one with `is_a1_1 = 1`, which takes the supported `F_GETFD` branch
  - the same witness also benefits from the already-known `is_a0_*` and `fnctl(a1 == 1)` result issues
- Likely fix:
  - Constrain `is_a1_1` and `is_a1_3` exactly from the `a1` word
  - at minimum, add the reverse implications for the `1` and `3` cases




## Picus Notes

- Current extracted module under investigation:
  - `crates/picus/picus_out/SyscallInstrs3.picus`
- Useful variable names from the current extraction:
  - `x_6` = `is_sys_linux`
  - `x_7` = internal `syscall_id`
  - `x_20..x_23` = `prev_a_value[0..3]`
  - `x_127` = `is_mmap`
  - `x_132` = `is_clone`
  - `x_133` = `is_exit_group`
  - `x_134` = `is_brk`
  - `x_142` = `is_fnctl`
  - `x_143` = `is_a1_1`
  - `x_144` = `is_a1_3`
  - `x_145` = `is_fnctl_a1_1`
  - `x_146` = `is_fnctl_a1_3`
  - `x_147` = `is_read`
  - `x_148` = `is_write`
  - `x_149` = `is_nop`
  - `x_124` = `is_a0_0`
  - `x_125` = `is_a0_1`
  - `x_126` = `is_a0_2`
  - `x_128` = `is_mmap_a0_0`
