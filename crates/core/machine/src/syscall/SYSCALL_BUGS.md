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
- Current behavior:
  - the `mmap` path tries to decompose `a1` into:
    - a low 12-bit `page_offset`
    - a page-aligned `upper_address`
  - but the low-byte side of the decomposition is still too weak
- Concrete issue:
  - `page_offset` is modeled as:
    - `page_offset = page_offset_lo + 256 * page_offset_hi`
    - with 4 boolean bits for `page_offset_hi`
  - however `page_offset_lo` is range-checked with `ByteOpcode::U16Range` instead of an 8-bit range check
  - so `page_offset_lo` is allowed to be any 16-bit value, not a byte
- Why this matters:
  - the AIR no longer pins `page_offset` to the actual low 12 bits of `a1`
  - so different decompositions of the same `a1` can still satisfy the constraints
  - that in turn changes the computed `mmap_size` and the propagated `HEAP` write
- Picus symptom:
  - On the `mmap2(a0 = 0)` heap path, Picus finds two valid models with:
    - the same syscall id and the same `a1`
    - the same old heap value / syscall result
    - different heap-update outputs
  - in the witness, the low-byte witness differs as:
    - `x_134 = 65412` in one model
    - `x_134 = 20` in the other
  - that should be impossible if this were really an 8-bit limb
- Missing constraints:
  - `page_offset_lo < 256`
  - `page_offset = a1 & 0xfff`
  - `upper_address = a1 & !0xfff`
  - `is_offset_0 <=> page_offset == 0`
- Likely fix:
  - replace the `U16Range` check on `page_offset_lo` with an 8-bit range check (`U8Range` / `slice_range_check_u8`-equivalent)
  - keep the 4-bit boolean decomposition for the high nibble of the 12-bit offset
  - ensure the resulting `page_offset + upper_address = a1.reduce()` relation is tied to that canonical 12-bit decomposition

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

### 11. `SysLinux::mmap`: new heap value and is only constrained through `reduce()`

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

### 12. `SysLinux::mmap`: `mmap_size` is only constrained through `reduce()`

- Location:
  - `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs`
- Current behavior:
  - on the `mmap(a0 = 0)` path, the AIR constrains:
    - `local.mmap_size.reduce::<AB>() = size_field`
  - and separately byte-range-checks `local.mmap_size`
  - but it does not constrain `local.mmap_size` to be the canonical KoalaBear-word encoding of `size_field`
- Why this matters:
  - distinct 32-bit words can share the same reduced field element modulo the KoalaBear prime
  - so multiple bytewise encodings of `mmap_size` can satisfy the same `reduce()` equality
  - the later heap update is bytewise, so this directly produces different heap writes
- Picus symptom:
  - On the `mmap2(a0 = 0)` heap path, Picus finds two valid models with:
    - the same syscall id, same `a1`, same old heap value, and same syscall result
    - the same fixed decomposition values:
      - `x_131 = 1024`
      - `x_133 = 805302272`
    - but different `mmap_size` bytes:
      - `x_142..x_145 = (1,0,0,175)` in one model
      - `x_142..x_145 = (0,0,0,48)` in the other
  - those two words differ by the KoalaBear prime `0x7f000001`
  - the heap write then diverges accordingly:
    - `x_217..x_220 = (196,162,0,191)` in one model
    - `x_217..x_220 = (195,162,0,64)` in the other
- Likely fix:
  - Constrain `local.mmap_size` as the canonical KoalaBear-word encoding of `size_field`, not just by `reduce()`
  - for example, add an explicit KoalaBear-word validity check for `local.mmap_size`
  - or derive `mmap_size` directly from a canonical byte/word decomposition of `size_field`

### 13. `SysLinux`: `is_a1_1` / `is_a1_3` are only constrained in one direction

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

### 14. `SysLinux::brk`: read value is not tied to previous value

- Locations:
  - `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs`
  - `crates/core/machine/src/syscall/precompiles/sys_linux/trace.rs`
- Current behavior:
  - `eval_brk` uses `local.inorout` in `eval_memory_access(...)`
  - then compares `a0` against `*local.inorout.value()`
  - but the fallback result branch uses `local.inorout.prev_value`
  - and the AIR never constrains `*local.inorout.value() = local.inorout.prev_value`
- Why this matters:
  - for `SYS_BRK`, `local.inorout` is populated from a read of register `BRK`
  - for a read access, the `value` and `prev_value` should agree
  - if they do not, the prover can change the comparison outcome without changing the traced previous `BRK` value
- Picus symptom:
  - For `x_7 = 4045` (`SYS_BRK`) and `x_155 = 1`, Picus finds two valid models with:
    - the same `result` bytes `x_10..x_13`
    - the same `A3` write (`x_117..x_120 = 0`)
    - different promoted `local.inorout.value()` bytes (`x_104..x_107` / `x_193..x_196`)
  - This is the same structural issue previously seen on `SYS_WRITE`, but on the `BRK` register read.
- Likely fix:
  - On the `is_brk` branch, assert `*local.inorout.value() = local.inorout.prev_value`
  - or use a read-only memory witness type for the `BRK` access instead of `MemoryReadWriteCols`

### 15. SysLinux::brk + `GtColsBytes`: selected comparison byte need not be unequal

- Locations:
  - `crates/core/machine/src/operations/cmp.rs`
  - surfaced in `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs` through `SysLinux::brk`
- Classification:
  - functional correctness bug in a shared comparison gadget
- Current behavior:
  - `GtColsBytes` uses one-hot byte flags to choose the comparison byte
  - it enforces that bytes before the selected flag are equal
  - and it sends one `LTU` lookup on the selected bytes
  - but it does not enforce that the selected bytes are actually different
- Why this matters:
  - the prover can select an earlier equal byte as the comparison byte
  - `LTU(a, a) = 0`, so this can force the gadget result to `0` even when a later byte proves `a > b`
  - callers that rely on the gadget result can therefore branch incorrectly
- Picus symptom:
  - On `SysLinux::brk`, Picus finds two valid models with the same `a0` and the same traced `BRK` value, but different comparison witnesses and different syscall results
  - the visible manifestation is in `SysLinux`, but the root cause is in the shared `GtColsBytes` gadget
- Likely fix:
  - keep the existing `LTU(b, a)` lookup for the selected bytes
  - add the complementary gated `LTU(a, b)` lookup when any comparison-byte flag is set
  - this makes equality on the selected byte impossible, because the selected byte must satisfy either `a > b` or `a < b`
  - Concretely, in `GtColsBytes::eval` in `crates/core/machine/src/operations/cmp.rs`, keep the existing:
    ```rust
    builder.send_byte(
        ByteOpcode::LTU.as_field::<AB::F>(),
        cols.result,
        cols.b_comparison_byte,
        cols.a_comparison_byte,
        is_real,
    );
    ```
    and then add:
    ```rust
    builder.send_byte(
        ByteOpcode::LTU.as_field::<AB::F>(),
        AB::Expr::one() - cols.result,
        cols.a_comparison_byte,
        cols.b_comparison_byte,
        is_real.into() * sum_flags.clone(),
    );
    ```
    This rules out choosing an equal byte as the selected comparison byte.

### 16. `SysLinux::mmap`: low-limb range check fix is incorrect (bad fix attempt for item 6)

- Location:
  - `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs`
- Current behavior:
  - the attempted fix for the `mmap` `page_offset` decomposition adds a range check on `page_offset_lo`
  - but it uses `ByteOpcode::U16Range`
  - `page_offset_lo` is not a full byte: it is the low nibble of `a1[1]`
  - so the AIR needs to enforce `page_offset_lo < 16` / a 4-bit constraint
  - even `U8Range` would still be too weak; `U16Range` is much too weak
- Picus symptom:
  - On the `mmap2(a0 = 0)` heap path, Picus finds two valid models with:
    - the same syscall id and the same `a1`
    - the same old heap value / syscall result
    - different heap-update outputs
  - the concrete witness shows:
    - `x_134 = 65412` in one model
    - `x_134 = 20` in the other
  - that should be impossible if `x_134` were really the low nibble of `a1[1]`
- Likely fix:
  - replace the `U16Range` check on `page_offset_lo` with a true `<16` / 4-bit constraint
  - for example, decompose `page_offset_lo` into 4 boolean bits or use an equivalent nibble-range lookup
  - keep the 4-bit boolean decomposition for the high nibble
  - then recheck that item 6 is fully closed

### 17. `SysLinux::mmap`: `upper_address` page alignment is only enforced modulo the field

- Location:
  - `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs`
- Current behavior:
  - `upper_address` is a single field element column, not a canonical 32-bit word decomposition
  - the AIR only enforces:
    - `upper_address = upper_address_pages * 4096`
    - `page_offset + upper_address = a1.reduce()`
  - both constraints are field equations
- Why this matters:
  - in KoalaBear, `4096` is invertible
  - so `upper_address = upper_address_pages * 4096` does **not** prove that `upper_address` is a page-aligned 32-bit integer chunk
  - it only proves that `upper_address` is some field element with a multiplicative witness
  - combined with the modular `page_offset + upper_address = a1.reduce()` relation, this allows non-canonical decompositions of the same `a1`
  - this remains true even if the low-limb range issue from items 6 / 15 is fixed
- Picus symptom:
  - On the `mmap2(a0 = 0)` heap path, Picus finds two valid models with:
    - the same syscall id and the same `a1`
    - the same old heap value / syscall result
    - different `upper_address` / heap-update outputs
  - relevant witness lines:
    - `x_9 = 4090`, `x_129 = 1`, `x_126 = 1`, `x_130 = 1`
    - `x_131 = 4093` in one model vs `x_131 = 2` in the other
    - `x_133 = 2130702596` in one model vs `x_133 = 254` in the other
    - `x_217..x_220 = (5,1,194,128)` in one model vs `(0,17,194,128)` in the other
  - those two decompositions should not both be valid for the same `a1 = 256`
- Likely fix:
  - derive `page_offset` and `upper_address` canonically from the bytes of `a1`, not from a field-multiple witness
  - or decompose `upper_address` into a word / byte form and enforce:
    - low 12 bits are zero
    - the remaining bytes match the aligned upper chunk of `a1`
  - equivalently, constrain `upper_address_pages` as the canonical integer quotient of `a1 >> 12`, then reconstruct `upper_address` from that quotient

### 18. `SyscallPrecompile`: packed syscall-result halves for `arg1` / `arg2` are not canonical

- Locations:
  - `crates/core/machine/src/syscall/chip.rs`
  - `crates/picus/picus_out/SyscallPrecompile.picus`
- Current behavior:
  - `SyscallPrecompile` stores:
    - `arg1`, `arg2`
    - `arg1_lo`, `arg1_hi`
    - `arg2_lo`, `arg2_hi`
  - and only enforces:
    - `arg1 = arg1_lo + 65536 * arg1_hi` in the field
    - `arg2 = arg2_lo + 65536 * arg2_hi` in the field
  - it does not enforce that `(arg1_lo, arg1_hi)` and `(arg2_lo, arg2_hi)` are the canonical half-word decomposition of KoalaBear words
- Why this matters:
  - distinct half-word pairs can encode different 32-bit words with the same field reduction modulo the KoalaBear prime
  - so the precompile shard can emit a different packed `SyscallResult` witness than the canonical CPU-side arguments, while preserving the same reduced `arg1` / `arg2`
- Picus symptom:
  - In the standalone `SyscallPrecompile` extraction, Picus finds models with:
    - the same global syscall payload `x_27..x_36`
    - the same local `send_syscall` payload `x_14..x_18`
    - but different local `send_syscall_result_packed` halves `x_23..x_26`
  - example witness family:
    - one model uses `x_23..x_26 = (2, 65024, 65535, 24319)`
    - another uses `x_23..x_26 = (0, 0, 0, 56832)`
    - while `x_14..x_18` and `x_27..x_36` remain fixed
- Likely fix:
  - Constrain the half-word pairs to be the canonical decomposition of KoalaBear words.
  - Better: carry `arg1_lo`, `arg1_hi`, `arg2_lo`, and `arg2_hi` (or all bytes) through the global syscall bridge so the exact 32-bit arguments are verified cross-shard.

## Manual

### 1. `Syscall results are not linked through GlobalChip`

- Location:
  - `crates/core/machine/src/syscall/chip/air.rs`
- Current behavior:
  - The SysLinux and SysPrecompile chips are in one shard, the SysCore and SysInstrs chips are in another shard. Local events only propagate in the same shard.
  - The syscall instruction chip sends a syscall result and syscall event to the core chip.
  - The core chip receives the syscall event and the result and then sends a global event with the same syscall id and arguments but not the result.
  - The precompile chip sends a syscall event and receives the result from the SysLinux chip.
- Why this matters:
  - The syscall results are not necessarily consistent across the two shards. The result of the syscall is not shared in the global chip. 
- Likely fix:
  - add the `result` to the global chip to link the two shards.
  - The design of this interaction should be reconsidered

### 2. `SyscallPrecompile` can reinterpret `arg1` / `arg2` as different 32-bit words than the CPU shard

- Locations:
  - `crates/core/machine/src/syscall/chip.rs`
  - `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs`
- Current behavior:
  - The global syscall bridge only carries `arg1` and `arg2` as single field elements.
  - On the precompile shard, `SyscallChip` stores:
    - `arg1`, `arg2`
    - `arg1_lo`, `arg1_hi`
    - `arg2_lo`, `arg2_hi`
  - and only enforces:
    - `arg1 = arg1_lo + 65536 * arg1_hi` in the field
    - `arg2 = arg2_lo + 65536 * arg2_hi` in the field
  - There is no constraint that these `(lo, hi)` pairs encode canonical KoalaBear words, and the global bridge does not carry the halves/bytes.
  - `SysLinux` then consumes:
    - reduced `a0` / `a1` on the local `Syscall` interaction
    - packed half-words for `result`, `a0`, `a1` on the local `SyscallResult` interaction
- Why this matters:
  - Distinct 32-bit words can have the same field reduction modulo the KoalaBear prime.
  - So the precompile shard can choose non-canonical half-word decompositions whose packed 32-bit word is different from the CPU shard's canonical word, while still matching the same reduced `arg1` / `arg2` globally.
  - This means the CPU shard and the precompile/SysLinux shard can agree on the global syscall bridge but disagree on the exact 32-bit syscall arguments being executed.
- Concrete attack scenario:
  1. In the CPU/core shard, the prover emits a linux syscall with canonical 32-bit arguments `(syscall_id, arg1, arg2)`.
  2. The global syscall bridge only checks the reduced field values of `arg1` and `arg2`, so the precompile shard reuses those same field elements.
  3. In `SyscallPrecompile`, the prover chooses a non-canonical half-word decomposition for one argument. For example, they can witness:
     - `arg2 = 0`
     - `arg2_lo = 2`
     - `arg2_hi = 65024`
     because `2 + 65536 * 65024 = 2 * 0x7f000001`, so this still equals `0` in KoalaBear.
  4. The local `send_syscall` interaction to `SysLinux` still uses the reduced field element `arg2 = 0`, so the core/precompile bridge balances.
  5. But the local `send_syscall_result_packed` interaction uses `(arg2_lo, arg2_hi) = (2, 65024)`, so `SysLinux` can witness `a1` as the byte word `0xfe000002`, which is a different 32-bit value that also reduces to `0`.
  6. `SysLinux` then executes the syscall semantics on those altered bytes and returns a result consistent with that altered witness.
  7. The prover uses the same packed result on the core side, so all local/global interactions balance even though the precompile shard executed the syscall on different 32-bit arguments than the CPU shard.
- Picus symptom:
  - The standalone `SyscallPrecompile` extraction admits multiple half-word witnesses for the same full reduced arguments.
  - In particular, Picus finds models with:
    - the same global inputs `x_27..x_36`
    - the same local `send_syscall` payload `x_14..x_18`
    - but different packed `send_syscall_result` argument halves `x_23..x_26`
  - This is exactly the witness freedom needed for the attack above.
- Likely fix:
  - Extend the global syscall bridge to carry `arg1_lo`, `arg1_hi`, `arg2_lo`, and `arg2_hi` (or all argument bytes), not just the reduced field elements.
  - Enforce that the packed halves/bytes encode canonical KoalaBear words.
  - Preferably use the same packed representation throughout the `SyscallCore` / `SyscallPrecompile` / `SysLinux` bridge so the exact 32-bit arguments are verified cross-shard.

### 3. `send_syscall` / `receive_syscall` use a lossy request encoding

- Locations:
  - `crates/stark/src/air/builder.rs`
  - `crates/core/machine/src/syscall/instructions/air.rs`
  - `crates/core/machine/src/syscall/chip.rs`
  - `crates/core/machine/src/syscall/precompiles/sys_linux/air.rs`
- Current behavior:
  - The syscall request bridge currently carries:
    - `shard`
    - `clk`
    - `syscall_id`
    - reduced `arg1`
    - reduced `arg2`
  - It does not carry the exact 32-bit byte/half-word representation of the syscall arguments.
- Why this matters:
  - This makes the request bridge fundamentally lossy for any precompile that later needs exact 32-bit syscall arguments.
  - As a result, each precompile has to reconstruct byte/half-word structure locally and independently prove canonicality.
  - If any precompile fails to do that perfectly, the same overflow/collision issue can reappear there.
  - So this is not just a `SysLinux` bug; it is a bridge-design issue that can affect other precompiles too.
- Recommended fix:
  - Change `send_syscall` / `receive_syscall` to carry canonical argument limbs, preferably:
    - `arg1_lo`, `arg1_hi`
    - `arg2_lo`, `arg2_hi`
    - or all argument bytes
  - Use that same exact representation:
    - in `SyscallInstrs -> SyscallCore`
    - across the global `SyscallCore -> SyscallPrecompile` bridge
    - and in `SyscallPrecompile -> SysLinux` / other precompile chips
  - In other words, the syscall request bridge should verify exact 32-bit words end-to-end, not only their field reductions.


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
