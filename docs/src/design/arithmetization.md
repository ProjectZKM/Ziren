# Arithmetization

Ziren expresses the execution of a MIPS program as an Algebraic Intermediate Representation (AIR): a set of tables whose cells are KoalaBear field elements, together with polynomial constraints and bus interactions that the tables satisfy exactly when the execution is valid.

## Key concepts

- **Chips.** The trace is split into chips (see [State Machine](./chips/state-machine.md)). A chip is a table with a fixed number of columns and a height that depends on the execution, typically one row per event (an executed instruction, a memory address, a precompile call). Some chips also have *preprocessed* columns, which are fixed by the program and committed once at setup. The program table and the byte and range tables are preprocessed.
- **Row constraints.** Each chip has polynomial constraints over the columns of a single row, the public values and, for preprocessed chips, the row's preprocessed columns. Every constraint has degree at most 3. Constraints do not refer to the next row: there are no transition constraints and no first-row or last-row selectors.
- **Interactions.** A row may send or receive tuples of column expressions on named buses, each with a multiplicity expression. A shard is valid when every chip's constraints hold on every row and every bus balances. The relations that a classic AIR states between consecutive rows, such as the program counter moving from one instruction to the next, are bus interactions in Ziren (see the `State` bus in [CPU](./chips/cpu.md)). The balance of all buses is proved by the lookup argument described in [Lookup Arguments](./lookup-arguments.md).
- **Padding.** Traces are padded with rows whose selectors are zero. Every constraint and multiplicity is gated by those selectors, so padding rows satisfy the constraints and send nothing.

The constraints are proved with a zerocheck over the multilinear extensions of the columns, not by dividing by a vanishing polynomial (see [STARK Protocol](./stark.md)).

## The AddSub chip as an example

### Instructions

The `AddSub` chip proves the register forms of addition and subtraction. The decoder maps both the trapping and the non-trapping MIPS forms to one opcode each, so the chip needs no overflow logic. The immediate forms (`ADDI`, `ADDIU`) are proved by the `AddSubImm` chip in the same way.

| instruction | op [31:26] | rs [25:21] | rt [20:16] | rd [15:11] | shamt [10:6] | func [5:0] | function | opcode |
|---|---|---|---|---|---|---|---|---|
| ADD  | 000000 | rs | rt | rd | 00000 | 100000 | rd = rs + rt | `ADD` |
| ADDU | 000000 | rs | rt | rd | 00000 | 100001 | rd = rs + rt | `ADD` |
| SUB  | 000000 | rs | rt | rd | 00000 | 100010 | rd = rs - rt | `SUB` |
| SUBU | 000000 | rs | rt | rd | 00000 | 100011 | rd = rs - rt | `SUB` |

### Columns

```rust
pub struct AddSubCols<T> {
    pub pc: T,
    pub next_pc: T,
    pub add_gate: T,             // is_add * (1 - op_a_0)
    pub sub_gate: T,             // is_sub * (1 - op_a_0)
    pub is_add: T,
    pub is_sub: T,
    pub frame: RTypeFrameCols<T>,
}
```

The R-type frame holds the shard, the two clock limbs, the opcode, the three register indices, `op_a_0`, and the three register accesses. `op_a` is a read-write access (previous value, value, previous clock, clock-difference limb); `op_b` and `op_c` are reads (value, previous clock, clock-difference limb). With 4-byte words the chip has 36 columns: 6 of its own and 30 in the frame. The chip needs no columns for the result or the carries. The result is the value of the `op_a` access, whose bytes the frame range-checks, and the carries are expressions.

### Constraints

Write \\( a_i, b_i, c_i \\) for byte \\( i \\) of the values of `op_a`, `op_b` and `op_c`. For addition, the carry out of byte \\( i \\) is

\\[ k_i = (b_i + c_i - a_i + k_{i-1}) \cdot 256^{-1}, \qquad k_{-1} = 0, \\]

a degree-1 expression in the columns. \\( a = b + c \bmod 2^{32} \\) holds exactly when every \\( k_i \\) is 0 or 1, so the chip asserts

\\[ add\\_gate \cdot k_i \cdot (k_i - 1) = 0, \qquad i = 0, \dots, 3. \\]

Subtraction \\( a = b - c \\) is checked as the addition \\( a + c = b \\), with carries \\( k'_i = (a_i + c_i - b_i + k'_{i-1}) \cdot 256^{-1} \\) and \\( sub\\_gate \cdot k'_i \cdot (k'_i - 1) = 0 \\).

The gate is a column rather than the product \\( is\\_add \cdot (1 - op\\_a\\_0) \\): with the product inline the constraint would have degree 4. The chip asserts \\( add\\_gate = is\\_add \cdot (1 - op\\_a\\_0) \\) separately. When the destination is `$zero` the frame forces the written value to 0, which need not equal \\( b + c \\), so the check is switched off.

The remaining constraints are that `is_add`, `is_sub` and their sum `is_real` are boolean, and the frame's interactions with `is_real` as multiplicity:

- the `Program` fetch of `(pc, ADD or SUB, op_a, op_b, op_c, ...)`;
- the three register accesses on the `Memory` bus;
- the `U16Range`, `Range` and `U8Range` byte lookups for the shard, the clock and the result bytes;
- the `State` receive of `(shard, clk, pc, next_pc)` and send of `(shard, clk + 5, next_pc, next_pc + 4)`.

### Example trace

Consider this fragment:

| pc | instruction | effect |
|---|---|---|
| 0x100 | `addu $7, $5, $6` | \\( 13 + 13685 = 13698 \\) |
| 0x104 | `slt $2, $6, $7` | (proved by the `Lt` chip) |
| 0x108 | `subu $5, $7, $4` | \\( 13698 - 10 = 13688 \\) |

The `AddSub` chip gets two rows. The `slt` goes to the `Lt` chip, and the `State` bus connects the rows of the two chips. The value columns in little-endian bytes:

| pc | next_pc | is_add | is_sub | add_gate | sub_gate | op_a_0 | a (value of op_a) | b | c |
|---|---|---|---|---|---|---|---|---|---|
| 0x100 | 0x104 | 1 | 0 | 1 | 0 | 0 | [130, 53, 0, 0] | [13, 0, 0, 0] | [117, 53, 0, 0] |
| 0x108 | 0x10c | 0 | 1 | 0 | 1 | 0 | [120, 53, 0, 0] | [130, 53, 0, 0] | [10, 0, 0, 0] |

In the first row \\( k_0 = (13 + 117 - 130) / 256 = 0 \\) and \\( k_1 = (0 + 53 - 53 + 0)/256 = 0 \\). In the second row \\( k'_0 = (120 + 10 - 130)/256 = 0 \\). All carries are boolean and the rows are valid. Had the prover put 131 in \\( a_0 \\) of the first row, \\( k_0 = -1/256 \\) would be neither 0 nor 1 and the constraint would fail.

The rows the chip has beyond the executed instructions are padding: all selectors are 0, so every gated constraint holds and every interaction has multiplicity 0.

## Preprocessed traces

Tables that do not depend on the execution (the program image, the byte table, the range table) are preprocessed. Their columns are committed during setup, the commitment is part of the verifying key, and the prover only supplies the multiplicity columns in the main trace. A proof for a different program therefore fails against the verifying key, because the program table's commitment differs.
