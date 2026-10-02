# CPU

Ziren V2.0 has no CPU chip. The work a CPU table used to do (fetch the instruction, read and write registers, advance the clock and the program counter) is done by an *instruction frame*: a fixed group of columns and constraints that every instruction chip embeds in its rows. An executed instruction therefore costs one row in the chip of its opcode family and nothing else. The frame is defined in `crates/core/machine/src/frame/mod.rs`.

## Frame columns

`InstructionFrameCols` has:

- `shard`: the shard number, range-checked to 16 bits.
- `clk_16bit_limb`, `clk_high_limb`: the per-shard clock \\( clk = clk_{16} + 2^{16} \cdot clk_{high} \\). The low limb is range-checked to 16 bits and the high limb to 10 bits, so timestamps are 26-bit values.
- `instruction`: the decoded instruction (`opcode`, `op_a`, `op_b`, `op_c`, the immediate flags `imm_b`, `imm_c`, and `op_a_0`, which marks a write to `$zero`).
- `op_a_access`, `op_b_access`, `op_c_access`: the three register accesses. `op_a` is a read-write access (previous and new value), `op_b` and `op_c` are reads.

`Jump`, `MovCond` and `MiscInstrs` use this full frame. Narrower variants save columns where the instruction format allows it:

- `ITypeFrameCols`: `op_a` and `op_b` registers and an immediate `op_c` word. Used by `AddSubImm`, `BitwiseImm`, `LtImm`, `CloClz`, `Branch` and the memory-instruction chips.
- `RTypeFrameCols`: three registers, with the opcode and operand indices stored as single columns. Used by `AddSub`, `Bitwise`, `Lt`, `Mul`, `DivRem`, `ShiftLeft`, `ShiftRight` and `SyscallInstrs`.
- `ShamtFrameCols`: `op_a` and `op_b` registers and a 5-bit shift amount held in one column. Used by `ShiftLeftImm` and `ShiftRightImm`.

Each register access holds the value, the clock of the previous access to that register, and one 16-bit limb of the clock difference: six columns. The previous access is always in the same shard because the `MemoryBump` chip inserts a read of every touched register at `(shard, 0)` (see [Memory](./memory.md)).

## Frame constraints

`eval_instruction_frame` constrains, for a real row:

1. **Program fetch.** The row sends `(pc, instruction)` on the `Program` bus, so the instruction must be the one the preprocessed program table stores at `pc`. The instruction's opcode must equal the chip's opcode, which the chip computes from its own selector columns.
2. **Clock.** The shard and the two clock limbs are range-checked.
3. **Immediates.** If `imm_b` (or `imm_c`) is set, the operand value equals the immediate in the instruction and no register is read.
4. **Registers.** The accesses happen at fixed sub-cycle offsets: `op_c` at \\( clk + 1 \\), `op_b` at \\( clk + 2 \\), `op_a` at \\( clk + 3 \\). A memory access, where there is one, uses \\( clk + 0 \\), and the `HI` register written by `Mul`, `DivRem` and the multiply-accumulate instructions of `MiscInstrs` uses \\( clk + 4 \\). If `op_a_0` is set, the written value is zero. The written value's four bytes are range-checked.
5. **State hand-off.** The row receives `(shard, clk, pc, next_pc)` on the `State` bus and sends `(shard, clk + 5 + extra, next_pc, next_next_pc)`, where `extra` is the number of extra cycles a syscall takes (zero for every other chip).

The chip supplies `pc`, `next_pc` and `next_next_pc` as expressions. `pc` and `next_pc` are whatever the row receives from its predecessor; in particular a delay-slot instruction receives a branch target as its `next_pc`. A sequential chip only fixes \\( next\\_next\\_pc = next\\_pc + 4 \\). The branch and jump chips carry `next_pc` and `next_next_pc` as range-checked words and compute the target. The halt row of the syscall chip receives its predecessor's `pc + 4` as `next_pc` and sends `next_pc = 0`, the exit marker.

Because every instruction advances `clk` by at least 5 and consumes one `State` tuple while producing one, balancing the `State` bus forces the rows of all instruction chips to form one chain from the shard's initial state to its final state (see [State Machine](./state-machine.md)).

## Program counters and the delay slot

MIPS executes the instruction after a branch or jump (the delay slot) before the target. The frame carries two program counters:

- `next_pc` is the address of the next instruction to execute; for a branch or jump this is the delay slot.
- `next_next_pc` is the address after that. For sequential instructions it is `next_pc + 4`; a branch or jump sets it to the taken target or the fall-through address.

The delay-slot instruction receives `(next_pc, next_next_pc)` and passes the target on as its own `next_pc`.

The shard's public values carry both pairs, `(start_pc, start_next_pc)` and `(next_pc, next_next_pc)`, but a pending branch target never crosses a shard boundary. The executor never closes a shard in front of a delay slot, and the recursion leaf enforces it: for a shard that executes instructions it asserts `start_next_pc = start_pc + 4` and `next_next_pc = next_pc + 4`, so both boundaries are sequential. The recursion then chains only `pc`: each shard's `start_pc` must equal the previous shard's `next_pc`.
