# Flow Control

Ziren enforces MIPS32r2 control flow verification via dedicated Branch and Jump chips, ensuring precise execution of program control instructions.

 ## Branch Chip

MIPS branch instructions execute conditional jumps through register comparisons (BEQ/BNE for equality, BGTZ/BLEZ etc. for sign checks). They calculate targets using 16-bit offsets shifted left twice (enabling ±128KB jumps) and feature a mandatory branch delay slot that always executes the next instruction—simplifying pipelining by allowing compiler-controlled optimizations. 

### Structure Description
Branch chip uses columns to record the following information.
- ​Control Flow Management​​
  - Tracks current and future program counter states across sequential and branching execution paths (`pc, next_pc,target_pc,next_next_pc`).
  - Implements 32-bit address validation through dedicated range-checking components(`next_pc_range_checker, target_pc_range_checker, next_next_pc_range_checker`).
- ​Operand Handling System​​
  - Stores three register/immediate values following MIPS three-operand convention (`op_a_value, op_b_value, op_c_value`).
  - Contains special flag detection for zero-register operand scenarios (`op_a_0`).
- ​​Instruction Semantics Encoding​​

  Embeds five mutually exclusive flags corresponding to MIPS branch opcodes (`is_beq, is_bltz, is_blez, is_bgtz, is_bgez`).
- ​Execution State Tracking​​

  Maintains dual execution path indicators for taken/not-taken branch conditions(`is_branching, not_branching`). 
- ​Comparison Logic Core​​

  Evaluates signed integer relationships between primary operands, generating equality, greater-than, and less-than condition flags (`a_eq_b, a_gt_b, a_lt_b`). 

### Major Constraints

We use the following key constraints to validate the branch chip:

- Program Counter Validation

  - Range check for all PC values (`pc`, `next_pc`, `target_pc`, `next_next_pc`, etc.).
  - Branching case: `next_pc` must equal `target_pc`.
  - Non-branching case: `next_next_pc` must equal `next_pc + 4`.
  - `is_branching` and `not_branching` are mutually exclusive and exhaustive for real instructions.

- Instruction Validity
  - Exactly one branch instruction flag must be active per row (`1 = is_beq + ... + is_bgtz`).
  - Instruction flags are strictly boolean values (0/1).
  - Opcode validity is enforced through linear combination verification.

- Branch Condition Logic
  `is_branching` and `not_branching` consistent whti condition flags.

## Jump Chip

MIPS jump instructions force unconditional PC changes via absolute or register-based targets. They calculate 256MB-range addresses by combining PC's upper bits with 26-bit immediates or use full 32-bit register values. All jumps enforce a ​mandatory delay slot executing the next instruction—enabling compiler-driven pipeline optimizations without speculative execution. 

### Structure Description
Jump chip uses columns to record the following information:

- ​Control Flow Management​​

  - Tracks current program counter and jump targets (`pc, next_pc, target_pc`).
  - Implements 32-bit address validation via dedicated range checkers (`next_pc_range_checker, target_pc_range_checker, op_a_range_checker`).
- ​​Operand System​​
  - Stores three operands for jump address calculation (`op_a_value, op_b_value, op_c_value`).
  - Contains zero-register flag detection for first operand register (`op_a_0`).
- ​​Instruction Semantics​​
  
  Embeds three mutually exclusive jump-type flags (`is_jump, is_jumpi, is_jumpdirect`).

### Major Constraints

We use the following key constraints to validate the jump chip:

- Instruction Validity
  - Exactly one jump instruction flag must be active per row:

    ```rust
    1 = is_jump + is_jumpi + is_jumpdirect
    ```
  - Instruction flags are strictly boolean (0/1).
  - Opcode validity enforced through linear combination verification:
    ```rust
    opcode = is_jump*JUMP + is_jumpi*JUMPI + is_jumpdirect*JUMPDIRECT
    ```
- Return Address Handling
  - For non-X0 register targets (`op_a_0` = 0):
    ```rust
    op_a_value = next_pc + 4
    ```
  - When jumping to X0 (`op_a_0` = 1), return address validation is skipped.
- Range Checking
  
  All critical values (`op_a_value, next_pc, target_pc`) are range-checked, ensuring values are valid 32-bit words.
- PC Transition Logic

  - Target_pc calculation via ALU operation:
    ```rust
    send_alu(
      Opcode::ADD,
      target_pc = next_pc + op_b_value, 
      is_jumpdirect
    )
    ```
  - Direct jumps (`is_jumpdirect`) use immediate operand addition.

