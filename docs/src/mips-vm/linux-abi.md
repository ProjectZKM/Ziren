# Linux ABI Support

This document describes how Ziren supports the Linux ABI inside its MIPS zkVM, covering execution, proving, and cross-shard verification.

## Overview

Ziren runs MIPS guest programs compiled against a Linux userspace ABI. The guest issues `SYSCALL` instructions just like a real MIPS/Linux process. The zkVM intercepts these and either:

1. **Executes** the syscall in the host executor (producing a concrete result), then
2. **Proves** that the result is correct via AIR constraints in the `SysLinuxChip`.

The guest never touches real kernel code. The zkVM emulates a minimal Linux kernel that supports memory management, basic I/O, and process lifecycle — enough to run programs compiled with standard C/Go/Rust toolchains targeting MIPS.

## Architecture

```
                        Guest Program (MIPS binary)
                                  |
                          SYSCALL (V0 = syscall number)
                                  |
                                  v
                  +-------------------------------+
                  |           Executor            |
                  |                               |
                  |  execute_operation()          |
                  |    -> SyscallCode::from_u32() |
                  |    -> get_syscall()           |
                  |    -> handler.execute()       |
                  |    -> emit_syscall_event()    |
                  +-------------------------------+
                          |               |
                    LinuxEvent       LinuxEvent
                          |               |
                          v               v
           +--------------------+     +------------------------+
           |    Core Shard      |     |   Precompile Shard     |
           |                    |     |                        |
           | SyscallInstrsChip  |     | SyscallChip(Precompile)|
           |   send_syscall()   |     |   receive_syscall()    |
           |        |           |     |         |              |
           | SyscallChip(Core)  |     |    SysLinuxChip        |
           |  receive_syscall() |     |    (81 columns)        |
           +--------|-----------+     +---------|------------- +
                    |                           |
                    |   global lookup message:  |
                    |   [shard, clk,            |
                    |    syscall_id,            |
                    |    arg1, arg2,            |
                    |    result_lo, result_hi]  |
                    |                           |
                    v                           v
                +--------------------------------------+
                |            GlobalChip                |
                |  Verify send/receive multiplicities  |
                |  Ensure result consistency           |
                +--------------------------------------+
```

## Register Convention (MIPS ABI)

All registers are 32-bit (`u32`). In the AIR, each is represented as `Word<T>` = 4 x `u8` (little-endian, each byte range-checked to [0, 255]).

| Register | Width | Role |
|----------|-------|------|
| `V0` | 32-bit | Syscall number (input) / return value (output) |
| `A0` | 32-bit | First argument |
| `A1` | 32-bit | Second argument |
| `A2` | 32-bit | Third argument (read via memory when needed) |
| `A3` | 32-bit | Error code output (0 = success, 9 = EBADF) |

## Supported Linux Syscalls

### SYS_MMAP (4210) / SYS_MMAP2 (4090) — Memory Mapping

Used by the guest allocator to request memory pages.

| Arg | Width | Semantics |
|-----|-------|-----------|
| `a0` | 32-bit | Requested address. `0` = allocate from heap. |
| `a1` | 32-bit | Size in bytes. Rounded up to page boundary. |
| **return** `v0` | 32-bit | Allocated address (heap pointer when `a0 == 0`, or `a0` itself). |
| **output** `A3` | 32-bit | Always `0x00000000`. |

**Execution logic:**
- `a0 == 0`: returns current heap pointer, increments heap by page-aligned size.
- `a0 != 0`: returns `a0` (reuse existing mapping).

**Page alignment in the AIR:**

The 32-bit size `a1` is decomposed at the byte level to separate the 12-bit page offset from the 20-bit page-aligned upper address:

```
a1 = [byte0 : 8-bit] [byte1 : 8-bit] [byte2 : 8-bit] [byte3 : 8-bit]
                       ├── lo nibble: 4-bit (boolean bit decomposition)
                       └── hi nibble: 4-bit (boolean bit decomposition)

page_offset   = byte0 + lo_nibble * 256          (12-bit, range [0, 4095])
upper_address = hi_nibble * 4096 + byte2 * 65536 + byte3 * 16777216
```

The `mmap_size` is constrained **byte-by-byte** (not via field `reduce()`) to avoid KoalaBear prime collisions:

```
mmap_size[0] = 0
mmap_size[1] = hi_nibble * 16 + 16 * not_aligned - carry[0] * 256
mmap_size[2] = a1[2] + carry[0] - carry[1] * 256
mmap_size[3] = a1[3] + carry[1]
```

Where `not_aligned = 1` when `page_offset != 0` (round up to next page). The carry bits handle byte overflow from the `+0x1000` addition. Page alignment (low 12 bits = 0) is structural: `byte0 = 0` and every term in `byte1` is a multiple of 16.

Heap update uses bytewise `AddOperation` (4 x u8 + 3 carry bits):
`new_heap = old_heap + mmap_size`.

### SYS_BRK (4045) — Program Break

| Arg | Width | Semantics |
|-----|-------|-----------|
| `a0` | 32-bit | New break address. |
| `a1` | 32-bit | Unused. |
| **return** `v0` | 32-bit | `max(a0, current_brk)`. |
| **output** `A3` | 32-bit | Always `0x00000000`. |

AIR uses `GtColsBytes` (bytewise greater-than with complementary LTU lookups) to compare `a0` against the BRK register.

### SYS_CLONE (4120) — Process Clone (Simulated)

| Arg | Width | Semantics |
|-----|-------|-----------|
| `a0` | 32-bit | Clone flags (ignored). |
| `a1` | 32-bit | Child stack (ignored). |
| **return** `v0` | 32-bit | Always `0x00000001`. |
| **output** `A3` | 32-bit | Always `0x00000000`. |

Threading is not implemented. The syscall always returns 1 (simulated parent PID).

### SYS_EXIT_GROUP (4246) — Terminate Execution

| Arg | Width | Semantics |
|-----|-------|-----------|
| `a0` | 32-bit | Exit code. |
| `a1` | 32-bit | Unused. |
| **return** `v0` | 32-bit | Always `0x00000000`. |
| **output** `A3` | 32-bit | Always `0x00000000`. |

Sets `next_pc = 0` and records the exit code. Equivalent to `HALT`.

### SYS_READ (4003) — Read from File Descriptor

| Arg | Width | Semantics |
|-----|-------|-----------|
| `a0` | 32-bit | File descriptor. Only `0` (stdin) is valid. |
| `a1` | 32-bit | Buffer address. |
| **return** `v0` | 32-bit | Bytes read, or `0xFFFFFFFF` on error. |
| **output** `A3` | 32-bit | `0x00000000` on success, `0x00000009` (EBADF) on invalid fd. |

Only stdin (fd 0) is supported. All other fds return -1 with EBADF.

### SYS_WRITE (4004) — Write to File Descriptor

| Arg | Width | Semantics |
|-----|-------|-----------|
| `a0` | 32-bit | File descriptor. |
| `a1` | 32-bit | Buffer address. |
| `A2` (implicit) | 32-bit | Byte count (read from A2 register via memory). |
| **return** `v0` | 32-bit | Bytes written (= A2 value). |
| **output** `A3` | 32-bit | Always `0x00000000`. |

AIR constrains `inorout.value == inorout.prev_value` (read-only guard on A2 memory access).

### SYS_FCNTL (4055) — File Control

| Arg | Width | Semantics |
|-----|-------|-----------|
| `a0` | 32-bit | File descriptor (0/1/2 valid). |
| `a1` | 32-bit | Command: `1` = F_GETFD, `3` = F_GETFL. |
| **return** `v0` | 32-bit | Flags/fd value, or `0xFFFFFFFF` on error. |
| **output** `A3` | 32-bit | `0x00000000` on success, `0x00000009` on error. |

Full case matrix:

| cmd (`a1`) | fd (`a0`) | result (`v0`) | error (`A3`) |
|------------|-----------|---------------|--------------|
| 1 (F_GETFD) | 0 | `0x00000000` | `0x00000000` |
| 1 (F_GETFD) | 1 | `0x00000001` | `0x00000000` |
| 1 (F_GETFD) | 2 | `0x00000002` | `0x00000000` |
| 1 (F_GETFD) | other | `0xFFFFFFFF` | `0x00000009` |
| 3 (F_GETFL) | 0 | `0x00000000` (O_RDONLY) | `0x00000000` |
| 3 (F_GETFL) | 1 | `0x00000001` (O_WRONLY) | `0x00000000` |
| 3 (F_GETFL) | 2 | `0x00000001` (O_WRONLY) | `0x00000000` |
| 3 (F_GETFL) | other | `0xFFFFFFFF` | `0x00000009` |
| other | any | `0xFFFFFFFF` | `0x00000009` |

AIR uses bidirectional `IsZeroOperation` decoders on `a0` (3 decoders) and `a1` (2 decoders) with exhaustive branch constraints.

### NOP Syscalls — No Operation

| Arg | Width | Semantics |
|-----|-------|-----------|
| `a0` | 32-bit | Ignored. |
| `a1` | 32-bit | Ignored. |
| **return** `v0` | 32-bit | Always `0x00000000`. |
| **output** `A3` | 32-bit | Always `0x00000000`. |

| Syscall | Number |
|---------|--------|
| SYS_OPEN | 4005 |
| SYS_CLOSE | 4006 |
| SYS_MUNMAP | 4091 |
| SYS_NANOSLEEP | 4166 |
| SYS_RT_SIGACTION | 4194 |
| SYS_RT_SIGPROCMASK | 4195 |
| SYS_SIGALTSTACK | 4206 |
| SYS_FSTAT64 | 4215 |
| SYS_MADVISE | 4218 |
| SYS_GETTID | 4222 |
| SYS_SCHED_GETAFFINITY | 4240 |
| SYS_CLOCK_GETTIME | 4263 |
| SYS_OPENAT | 4288 |
| SYS_PRLIMIT64 | 4338 |

Any unrecognized Linux syscall ID also falls into the NOP path.

## Cross-Shard Verification

Linux syscalls execute across two shards:

- **Core shard**: CPU decodes `SYSCALL`, writes `(shard, clk, syscall_id, arg1, arg2)` to `SyscallChip(Core)`.
- **Precompile shard**: `SysLinuxChip` computes the result, receives the same tuple from `SyscallChip(Precompile)`.

Both `SyscallChip` instances send a **global lookup message** that includes the result:

```
[shard, clk, syscall_id, arg1, arg2, result_lo, result_hi]
```

The `GlobalChip` verifies that send/receive multiplicities match. This ensures the Core shard and Precompile shard agree on the syscall result — a malicious prover cannot compute one result in the Precompile shard but write a different value into the CPU register in the Core shard.

The result is packed as two half-words (`result_lo = byte0 + byte1 * 256`, `result_hi = byte2 + byte3 * 256`) to keep the global message at degree 1.

## Syscall ID Detection

The `SYSCALL` instruction stores the syscall code in register `V0`. The system distinguishes Linux syscalls from precompile syscalls by examining `prev_a_value[1]` (byte 1 of the syscall code):

- `byte[1] != 0` → **Linux syscall** (MIPS syscall numbers like 4003, 4045, etc. all have non-zero byte 1)
- `byte[1] == 0` → **Precompile syscall** (Ziren precompile codes have byte 1 = 0)

This is enforced bidirectionally via an `IsZeroOperation` in `SyscallInstrsChip`, preventing a malicious prover from misrouting a precompile call into the Linux path or vice versa.

## AIR Soundness Properties

The `SysLinuxChip` enforces these key properties (all proven bidirectionally):

1. **Syscall routing**: Each Linux syscall ID maps to exactly one handler branch. Bidirectional `IsZeroOperation` decoders prevent misrouting (e.g., CLONE cannot be routed to NOP).

2. **Argument decoding**: `a0 == 0/1/2` and `a1 == 1/3` flags are bidirectional — when the argument matches a known value, the flag MUST be set.

3. **Result correctness**: Every branch constrains both `result` (V0) and `output` (A3) to specific values matching the executor semantics.

4. **Memory consistency**: Read-only memory accesses (BRK read, A2 read) enforce `value == prev_value`. Write accesses (HEAP update) use bytewise `AddOperation`.

5. **Page alignment**: MMAP size is constrained byte-by-byte. Low 12 bits of `mmap_size` are structurally zero (byte0 = 0, byte1 is always a multiple of 16). No field `reduce()` is used.

6. **Cross-shard linkage**: Syscall results are included in the global lookup message, preventing result forgery across shards.
