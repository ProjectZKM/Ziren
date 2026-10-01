# State Machine

The Ziren state machine is the MIPS32r2 machine as a set of chips (tables) connected by buses. A chip is a fixed-width table over KoalaBear whose constraints are local to one row. Everything that relates two rows, or two chips, is an interaction: a row *sends* or *receives* a tuple on a named bus, and the lookup argument proves that on every bus the sent and received multisets are equal.

The chip set is the `MipsAir` enum in `crates/core/machine/src/mips/mod.rs`. The families are:

- **Program**

  A preprocessed table of the program image: one row per instruction, pinning `pc = pc_base + 4·index` and the decoded instruction. Instruction rows fetch their instruction from it on the program bus.

- **Instruction chips**

  One chip per opcode family, each row one executed instruction:
  - ALU: `AddSub`, `AddSubImm`, `Bitwise`, `BitwiseImm`, `Mul`, `DivRem`, `Lt`, `LtImm`, `CloClz`, `ShiftLeft`, `ShiftLeftImm`, `ShiftRight`, `ShiftRightImm` (see [ALU](./alu.md));
  - control flow: `Branch`, `Jump` (see [Flow Control](./flow-ctrl.md));
  - memory instructions: `LoadWord`, `LoadNarrow`, `StoreWord`, `StoreNarrow`, `MemoryUnaligned` (see [Memory](./memory.md));
  - others: `MovCond` (MOVZ/MOVN and WSBH), `MiscInstrs` (INS, EXT, SEB/SEH, MADD/MADDU/MSUB/MSUBU, TEQ) and `SyscallInstrs` (the `syscall` instruction, including halt).

  Each instruction chip embeds the instruction frame described in [CPU](./cpu.md): there is no separate CPU table.

- **Memory**

  `MemoryLocal`, `MemoryGlobalInit`, `MemoryGlobalFinal` and `MemoryBump` (see [Memory](./memory.md) and [Memory Consistency Checking](../memory-checking.md)).

- **Global**

  The `Global` chip turns every message that crosses a shard boundary (memory hand-offs, syscalls sent to a precompile shard) into a point on a septic elliptic curve and accumulates the points into the shard's digest.

- **Lookup tables**

  `ByteLookup`, a preprocessed table of byte operations over all byte pairs (AND, OR, XOR, NOR, SLL, LTU, MSB, shift-carry, u8 and u16 range checks), and `RangeLookup`, a preprocessed table of `(a, bits)` for `a < 2^bits`, `bits ≤ 10`.

- **Syscalls and precompiles**

  `SyscallCore` records each syscall made in an execution shard, `SyscallPrecompile` receives it in the precompile shard that proves it, and `SysLinux` computes the results of the supported Linux syscalls. Precompile chips cover SHA-256 extend and compress, the Keccak sponge, the Poseidon2 permutation, Weierstrass and Edwards curve operations, BN254 and BLS12-381 field arithmetic and 256-bit multiplication. SHA-256 and Keccak, whose operations span several rows, split into a worker chip and a control chip chained on the `PrecompileChain` bus. See [Precompiles](../../dev/precompiles.md).

## The state bus

Instead of a transition constraint between consecutive rows, the machine's control state travels on the `State` bus. Every instruction row receives `(shard, clk, pc, next_pc)` and sends `(shard, clk + 5 + extra, next_pc, next_next_pc)`, where `extra` is the number of additional cycles a syscall takes. The shard's public values send the initial state and receive the final one. Because each real row receives exactly one tuple and sends exactly one with a strictly larger `clk`, bus balance forces the rows to form a single chain from the shard's initial state to its final state, in any order in the tables.

Two program counters travel on the bus because MIPS has a branch delay slot: `next_pc` is the address of the instruction after the current one, and `next_next_pc` the one after that, which a taken branch or a jump sets to its target.

## Buses

| Bus | Carries |
|---|---|
| `Program` | `(pc, instruction)` fetches against the program table |
| `State` | `(shard, clk, pc, next_pc)` from one instruction to the next |
| `Memory` | timestamped `(shard, clk, addr, value)` accesses |
| `Byte`, `Range` | byte-operation and range-check lookups |
| `Syscall`, `SyscallResult` | syscall arguments and results between the syscall chips |
| `Global` | messages that cross shards, consumed by the `Global` chip |
| `GlobalAccumulation` | the running sum of the `Global` chip's points |
| `MemoryGlobalInitControl`, `MemoryGlobalFinalizeControl` | the ordered chain of initialized and finalized addresses |
| `PrecompileChain` | the per-row state of multi-row precompiles |

The `State`, `GlobalAccumulation` and the two global-memory control buses are closed by endpoints the shard's public values supply; every other bus balances within the shard's traces.
