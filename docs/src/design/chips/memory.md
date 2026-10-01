# Memory

Registers and memory share one address space and one memory argument. The 36 registers (the 32 general-purpose registers, `LO`, `HI` and two internal registers for the program break and heap) occupy addresses 0 to 35, and memory instructions may not address them. Every access is a pair of tuples on the `Memory` bus: the accessing row sends the previous access `(prev_shard, prev_clk, addr, prev_value)` and receives the current one `(shard, clk, addr, value)`, and asserts that the current timestamp is strictly larger. The argument is described in [Memory Consistency Checking](../memory-checking.md). This page describes the chips.

The memory chips are the five memory-instruction chips, `MemoryBump`, `MemoryLocal`, `MemoryGlobalInit` and `MemoryGlobalFinal`. The sources are in `crates/core/machine/src/memory/`.

## Memory instructions

The load and store opcodes are split by width and direction so that each chip carries only the columns its opcodes need:

| Chip | Opcodes |
|---|---|
| `LoadWord` | `LW`, `LL` |
| `LoadNarrow` | `LB`, `LBU`, `LH`, `LHU` |
| `StoreWord` | `SW`, `SC` |
| `StoreNarrow` | `SB`, `SH` |
| `MemoryUnaligned` | `LWL`, `LWR`, `SWL`, `SWR` |

Each chip embeds the I-type instruction frame and a common block that constrains:

1. The effective address \\( addr = op_b + op_c \\), computed inline with an addition gadget (value and carries).
2. That the address word is a canonical KoalaBear value with byte-checked limbs, and that \\( addr \ge 36 \\), so a memory instruction cannot touch a register.
3. The two low address bits, and the memory access at the aligned address \\( addr - (addr \bmod 4) \\), at timestamp \\( clk + 0 \\).
4. \\( next\\_next\\_pc = next\\_pc + 4 \\): memory instructions are sequential.

Per chip:

- `LoadWord` and `StoreWord` pin the low address bits to zero. A load's value is `op_a`; a store's memory value is `op_a`.
- `SC` stores the previous value of `op_a` and sets `op_a` to 1. The machine is single-threaded, so a store-conditional always succeeds and `LL` is an ordinary load.
- `LoadNarrow` selects the byte or half-word with three offset flags and extends it. For a signed load whose top bit is set, the bytes above the loaded value are `0xFF`. This is a byte constraint, not an ALU lookup.
- `StoreNarrow` uses the offset flags to replace one byte or half-word of the previous memory word.
- `MemoryUnaligned` combines the memory word with the previous value of `op_a` according to the offset, as `LWL`/`LWR`/`SWL`/`SWR` specify.

The memory-instruction chips do not range-check the bytes of the loaded or stored word. A stored word comes from a register, and a loaded word goes to one. Values written into memory from any other source (global initialization, precompiles) are byte-checked where they enter.

## MemoryBump

A register access compares only clocks, not shards. To make that sound, `MemoryBump` has one row per (register, shard) for every register the shard touches: a *shadow read* of the register at timestamp `(shard, 0)`. Its previous access may be in any earlier shard, so this row uses the full access columns with a shard comparison. Because `clk` restarts at 0 in every shard and real register accesses sit at \\( clk + 1 \\) to \\( clk + 4 \\), the shadow read is always the first access of the shard to that register. Every other register access then has `prev_shard = shard`. This reduces each register access to six columns (value, previous clock and one 16-bit limb of the clock difference) instead of nine.

## MemoryLocal

`MemoryLocal` has one row per address the shard accesses. The row opens and closes the shard's chain for that address:

- It receives the initial tuple `(initial_shard, initial_clk, addr, initial_value)` on the `Memory` bus, where the shard's first access sends it as its "previous" access. It also sends the same tuple to the `Global` bus as a receive message.
- It sends the final tuple `(final_shard, final_clk, addr, final_value)`, matching the shard's last access, and sends it to the `Global` bus as a send message.

The initial side is otherwise a free witness, so the row range-checks both shards to 16 bits, both clocks to 26 bits (a 16-bit and a 10-bit limb) and every value limb to a byte.

On the `Global` bus, a shard's final value for an address cancels against the next accessing shard's initial value (see [Memory Consistency Checking](../memory-checking.md)).

## MemoryGlobalInit and MemoryGlobalFinal

These chips cover the lifetime of an address across the whole execution:

- `MemoryGlobalInit` has a row for each address the program touches that is not in the program image. It sends `(0, 0, addr, value)` on the `Global` bus with its initial value.
- `MemoryGlobalFinal` has a row for each touched address. It receives the last `(shard, clk, addr, value)` from the `Global` bus.

Initial values of the program image do not have rows. They are folded into the verifying key as `initial_global_cumulative_sum`, which the leaf of the first shard adds to the global sum.

Each address may be initialized and finalized once. Both chips enforce it the same way:

- The value is witnessed as 32 bits and the address is bit-decomposed.
- Consecutive rows are chained on a control bus (`MemoryGlobalInitControl` or `MemoryGlobalFinalizeControl`) carrying `(index, addr, valid)`.
- Each row asserts `prev_addr < addr` with a 32-bit comparison.

The chain continues across shards: each shard's first row receives the previous shard's last address from the public values (`previous_init_addr_bits`, `last_init_addr_bits` and the finalize equivalents), and the leaf checks that the ranges of consecutive shards join. The only row exempt from the comparison is the genesis row, index 0 with previous address 0, which initializes and finalizes address 0 to zero.
