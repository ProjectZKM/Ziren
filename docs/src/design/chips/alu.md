# ALU

Each arithmetic and logic opcode family has its own chip, and most families have a second chip for the immediate form. A row is one executed instruction: it embeds an instruction frame (see [CPU](./cpu.md)), which reads the operands and writes the result register, and adds only the columns needed to prove that result. The ALU chips are sequential: each sends \\( next\\_next\\_pc = next\\_pc + 4 \\). There is no ALU bus: an ALU row proves its own result and receives nothing from other instruction chips. The sources are in `crates/core/machine/src/alu/`.

| Chip | Frame | Opcodes (MIPS instructions) |
|---|---|---|
| `AddSub` | R-type | `ADD` (ADD, ADDU), `SUB` (SUB, SUBU) |
| `AddSubImm` | I-type | `ADD`, `SUB` with an immediate (ADDI, ADDIU, LUI) |
| `Bitwise` | R-type | `AND`, `OR`, `XOR`, `NOR` |
| `BitwiseImm` | I-type | `AND`, `OR`, `XOR` with an immediate (ANDI, ORI, XORI) |
| `Lt` | R-type | `SLT`, `SLTU` |
| `LtImm` | I-type | `SLT`, `SLTU` with an immediate (SLTI, SLTIU) |
| `Mul` | R-type | `MUL`, `MULT`, `MULTU` |
| `DivRem` | R-type | `DIV`, `DIVU`, `MOD`, `MODU` |
| `CloClz` | I-type | `CLO`, `CLZ` |
| `ShiftLeft` | R-type | `SLL` by a register (SLLV) |
| `ShiftLeftImm` | shift-amount | `SLL` by an immediate |
| `ShiftRight` | R-type | `SRL`, `SRA`, `ROR` by a register (SRLV, SRAV, ROTRV) |
| `ShiftRightImm` | shift-amount | `SRL`, `SRA`, `ROR` by an immediate |

The decoder also maps some instructions onto these opcodes: `MFHI`, `MTHI`, `MFLO` and `MTLO` become `ADD` with `HI` (register 33) or `LO` (register 32) as an operand and zero as the other, and `LUI` becomes `ADD` of `$zero` and the shifted immediate.

## Techniques

- **Addition and subtraction.** `AddSub` does not witness carries. With byte limbs \\( a_i, b_i, c_i \\), the carry out of limb \\( i \\) is the expression \\( carry_i = (b_i + c_i - a_i + carry_{i-1}) \cdot 256^{-1} \\), and the chip asserts that each carry is boolean. The bytes of \\( a \\) are range-checked by the frame. Subtraction is checked as the addition \\( a + c = b \\). See [Arithmetization](../arithmetization.md) for the full column layout.
- **Bitwise.** One byte lookup per byte, `(op, a_i, b_i, c_i)`, against the byte table. The lookups are skipped when the destination is `$zero`.
- **Comparison.** `Lt` locates the most significant byte where the operands differ, using one-hot byte flags and an inverse witness, and compares that byte pair with the `LTU` byte lookup. For `SLT` the top byte is first masked to 7 bits with an `AND 0x7f` lookup, and the result is combined with the two sign bits.
- **Multiplication.** Both operands are extended to 64 bits (sign-extended for `MULT`) and the product is checked limb by limb with witnessed carries. `MUL` writes the low word to the destination; `MULT` and `MULTU` write the low word to `LO` and the high word to `HI`, the second write at \\( clk + 4 \\).
- **Division.** `DivRem` witnesses the quotient and remainder and checks \\( b = c \cdot q + r \\) in 64-bit arithmetic with an inline multiplication. It asserts that \\( r \\) has the sign of \\( b \\) and that \\( |r| < |c| \\), and handles the overflow case \\( b = -2^{31}, c = -1 \\). Division by zero traps in the executor, and the chip rejects \\( c = 0 \\). `DIV` and `DIVU` write the quotient to `LO` and the remainder to `HI`; `MOD` and `MODU` write the remainder to the destination register.
- **Shifts.** The 5-bit shift amount is split into a byte shift \\( \lfloor c/8 \rfloor \\) and a bit shift \\( c \bmod 8 \\). Left shifts multiply by \\( 2^{c \bmod 8} \\) and move bytes. Right shifts use the `ShrCarry` byte lookup for the bit part and extend the operand to 64 bits so that `SRA` fills with the sign bit; `ROR` also feeds the shifted-out bits back in at the top.
- **Leading bits.** `CLZ` witnesses the result \\( n \\) and checks it with a right shift: \\( b = 0 \\) gives \\( n = 32 \\), and otherwise \\( b \gg (31 - n) = 1 \\). `CLO` is computed as `CLZ` of \\( \lnot b \\).
