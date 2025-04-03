# Flow Control

 ZKM2 uses ​the Branch Chip and Jump Chip to handle branch instructions and jump instructions ​respectively within MIPS32r2.

 ## Branch Chip

MIPS branch instructions execute conditional jumps through register comparisons (BEQ/BNE for equality, BGTZ/BLEZ etc. for sign checks). They calculate targets using 16-bit offsets shifted left twice (enabling ±128KB jumps) and feature a mandatory branch delay slot that always executes the next instruction—simplifying pipelining by allowing compiler-controlled optimizations. Requiring explicit compare operations rather than status flags, this design reflects MIPS' RISC focus on hardware simplicity and predictable timing through fixed-length instructions.

Below is the branch chip designed in ZKM2 to emulate branch instructions:

 ```rust
 /// Branch instruction constraints with PC management and condition evaluation
pub struct BranchColumns<T> {
    // region: Program Counter Management
    /// Current & derived program counters with range checks
    pub pc: T,
    pub next_pc: Word<T>,                  // Sequential execution target
    pub target_pc: Word<T>,                 // Branch jump target  
    pub next_next_pc: Word<T>,               // Fall-through PC (next_pc + 4)
    pub next_pc_range_checker: KoalaBearWordRangeChecker<T>,
    pub target_pc_range_checker: KoalaBearWordRangeChecker<T>,
    pub next_next_pc_range_checker: KoalaBearWordRangeChecker<T>,

    // region: Operand System
    /// 3-operand values (A/B/C) and register 0 flag
    pub op_a_value: Word<T>,
    pub op_b_value: Word<T>, 
    pub op_c_value: Word<T>,
    pub op_a_0: T,                          // 1 when operand A is register 0

    // region: Branch Instruction Flags
    /// MIPS branch opcode indicators (mutually exclusive)
    pub is_beq: T,  // Branch Equal
    pub is_bne: T,  // Branch Not Equal
    pub is_bltz: T, // Branch Less Than Zero
    pub is_blez: T, // Branch Less or Equal Zero
    pub is_bgtz: T, // Branch Greater Than Zero 
    pub is_bgez: T, // Branch Greater or Equal Zero

    // region: Branch Condition State
    /// Active when branch condition met (see docs for logic)
    pub is_branching: T,
    /// Active when branch condition failed (see docs for logic) 
    pub not_branching: T,

    // region: Condition Flags
    /// Operand comparison results (A vs B)
    pub a_eq_b: T,  // A == B
    pub a_gt_b: T,  // A > B (signed)
    pub a_lt_b: T,  // A < B (signed)
}
```
We use the following key constraints to validate the branch chip:

- Program Counter Validation

  
  - Range check for all PC values (`pc`, `next_pc`, `target_pc`, `next_next_pc`, etc.).
  - Branching case: `next_pc` must equal `target_pc`.
  - Non-branching case: `next_next_pc` must equal `next_pc + 4`.
  - `is_branching` and `not_branching` are mutually exclusive and exhaustive for real instructions.

- Instruction Validity
  - Exactly one branch instruction flag must be active per row (`is_real = is_beq + ... + is_bgtz`).
  - Instruction flags are strictly boolean values (0/1).
  - Opcode validity is enforced through linear combination verification.

- Branch Condition Logic
```rust
is_branching = 
    (is_beq & a_eq_b) |
    (is_bne & !a_eq_b) | 
    (is_bltz & a_lt_b) | 
    (is_bgtz & a_gt_b) |
    (is_blez & (a_lt_b | a_eq_b)) |
    (is_bgez & (a_gt_b | a_eq_b))
```


## Jump Chip

MIPS jump instructions force unconditional PC changes via absolute or register-based targets. They calculate 256MB-range addresses by combining PC's upper bits with 26-bit immediates or use full 32-bit register values. All jumps enforce a ​mandatory delay slot executing the next instruction—enabling compiler-driven pipeline optimizations without speculative execution. Their fixed 32-bit encoding (6-bit opcode + 26-bit target) and absence of condition checks embody RISC principles through hardware simplicity and timing predictability, particularly optimizing function calls and large-scale control flow.

Below is the jump chip designed in ZKM2 to emulate jump instructions:
 ```rust
/// Circuit constraints for MIPS jump instruction verification
pub struct JumpColumns<T> {
    // region: Program Counter Management
    /// Current PC and derived addresses with validity checks
    pub pc: T,                              // Current Program Counter
    pub next_pc: Word<T>,                   // Sequential execution address (PC + 4)
    pub next_pc_range_checker: KoalaBearWordRangeChecker<T>,
    pub target_pc: Word<T>,                 // Jump target address 
    pub target_pc_range_checker: KoalaBearWordRangeChecker<T>,

    // region: Operand System
    /// 3-operand values (A: jump base, B/C: offset/condition)
    pub op_a_value: Word<T>,                // Base address operand
    pub op_b_value: Word<T>,                 // Offset/condition operand  
    pub op_c_value: Word<T>,                 // Auxiliary operand
    pub op_a_0: T,                          // Flag when base is register $zero

    // region: Instruction Identification
    /// Jump opcode indicators (mutually exclusive)
    pub is_jump: T,    // J-type absolute jump
    pub is_jumpi: T,   // I-type conditional jump
    pub is_jumpdirect: T, // Pseudo-direct jump

    // region: Address Validation
    /// Range check for PC-relative calculations (e.g. JAL return address)
    pub op_a_range_checker: KoalaBearWordRangeChecker<T>,
}
 ```
We use the fllowing key constraints to valid the jump chip:


- Instruction Validity
  - Exactly one jump instruction flag must be active per row:

    ```rust
    is_real = is_jump + is_jumpi + is_jumpdirect
    ```
  - Instruction flags are strictly boolean (0/1).
  - Opcode validity enforced through linear combination verification:
    ```rust
    opcode = is_jump*JUMP + is_jumpi*JUMPI + is_jumpdirect*JUMPDIRECT
    ```
- Return Address Handling
  For non-X0 register targets (op_a_0 = 0):
  ```rust
  op_a_value = next_pc + 4
  ```
  When jumping to X0 (op_a_0 = 1), return address validation is skipped.
- Range Checking
  
  All critical values (op_a_value, next_pc, target_pc) are range-checked, ensuring values are valid 32-bit words.
- PC Transition Logic

  target_pc calculation via ALU operation:
  ```rust
  send_alu(
    Opcode::ADD,
    target_pc = next_pc + op_b_value, 
    is_jumpdirect
  )
  ```
  Direct jumps (is_jumpdirect) use immediate operand addition.

