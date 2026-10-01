# Flow Control

Branches and jumps are proved by the `Branch` and `Jump` chips (`crates/core/machine/src/control_flow/`). Both set the post-delay-slot address `next_next_pc` that the instruction frame sends on the `State` bus. The instruction in the delay slot at `next_pc` runs first and passes that address on as its own `next_pc` (see [CPU](./cpu.md)). Both chips carry `next_pc` and `next_next_pc` as 32-bit words and range-check them to canonical KoalaBear values. Neither chip can end a shard: the executor never closes a shard before a delay slot, and the recursion leaf requires sequential shard boundaries.

## Branch chip

`Branch` proves `BEQ`, `BNE`, `BLTZ`, `BLEZ`, `BGTZ` and `BGEZ`. It uses the I-type frame. `op_a` and `op_b` are the compared registers; for the compare-with-zero branches `op_b` is `$zero`. `op_c` is the sign-extended offset shifted left by two.

Columns, besides the frame: `pc`, `next_pc` and `next_next_pc` with their range checkers, an addition gadget `target_add`, the six opcode selectors, `is_branching`, the equality witnesses (`eq_lo`, `eq_hi` and their inverses, `a_eq_b`), `msb_a` and `a_gt_0`.

Constraints:

- **Selectors.** The six selectors are boolean and their sum is `is_real`, so a real row has exactly one. The opcode passed to the frame is their weighted sum. The register `op_a` is only read: its written value equals its previous value.
- **Next address.** If `is_branching`, \\( next\\_next\\_pc = next\\_pc + op_c \\), proved by `target_add`. Otherwise \\( next\\_next\\_pc = next\\_pc + 4 \\). `is_branching` is boolean and zero on padding rows.
- **Equality.** With \\( d_{lo} \\) and \\( d_{hi} \\) the differences of the low and high 16-bit halves of `op_a` and `op_b`, the chip checks \\( eq_{lo} \cdot d_{lo} = 0 \\) and \\( eq_{lo} = 1 - d_{lo} \cdot inv_{lo} \\) (and the same for the high half), so \\( a\\_eq\\_b = eq_{lo} \cdot eq_{hi} \\) is 1 exactly when the registers are equal.
- **Sign.** For the compare-with-zero branches, `msb_a` is the top bit of `op_a`, taken from the `MSB` byte lookup, and \\( a\\_gt\\_0 = (1 - msb\\_a)(1 - a\\_eq\\_b) \\).
- **Condition.** `is_branching` must equal the branch condition: `a_eq_b` for `BEQ`, its negation for `BNE`, `msb_a` for `BLTZ`, its negation for `BGEZ`, `a_gt_0` for `BGTZ` and its negation for `BLEZ`.

## Jump chip

`Jump` proves the three jump opcodes the decoder produces:

| Opcode | MIPS instructions | Target |
|---|---|---|
| `Jump` | `JR`, `JALR` | the register `op_b` |
| `Jumpi` | `J`, `JAL` | the immediate `op_b`, the 26-bit index shifted left by two |
| `JumpDirect` | `BAL` | \\( next\\_pc + op_b \\), with `op_b` the shifted offset |

The chip uses the full instruction frame. Its columns are `pc`, `next_pc` and `next_next_pc` with range checkers, an addition gadget `target_add`, a range checker for the link value, and the selectors `is_jump`, `is_jumpi` and `is_jumpdirect`.

Constraints:

- **Selectors.** The selectors are boolean and their sum is `is_real`. The opcode passed to the frame is their weighted sum.
- **Link.** Unless the destination is `$zero` (`op_a_0`), the value written to `op_a` is \\( next\\_pc + 4 \\), the address after the delay slot. The value is range-checked to a canonical word. `JR` and `J` decode with `$zero` as the destination, so they link nothing.
- **Target.** For `Jump` and `Jumpi`, \\( next\\_next\\_pc = op_b \\). For `JumpDirect`, `target_add` proves \\( next\\_next\\_pc = next\\_pc + op_b \\).
