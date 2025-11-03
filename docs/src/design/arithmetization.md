# Arithmetization

Algebraic Intermediate Representation (AIR) serves as the arithmetization foundation in the Ziren system, bridging computation and succinct cryptographic proofs. AIR provides a structured method to represent computations through polynomial constraints over execution traces.

## Key Concepts of AIR
- Execution Trace
  
  A tabular structure where each row represents system's state at a computation step, with columns corresponding to registers/variables. 

- Transition Constraints
  
  Algebraic relationships enforced between consecutive rows, expressed as low-degree polynomials (e.g., \\(P(state_i, state_{i+1}) = 0\\)).

- Boundary Constraints
  
  Ensure valid initial/final states (e.g., \\(state_0 = initial\\_value\\)).

These constraints utilize low-degree polynomials for efficient proof generation/verification. Ziren mandates degree-3 polynomial constraints within its AIR framework, establishing a formally verifiable equilibrium between proof generation efficiency and trace column representation compactness. [See AIR paper](https://eprint.iacr.org/2023/661.pdf) for rigorous technical details.

## AIR Implementation in Ziren Chips

Having introduced various chip/table structures in Ziren, we note that building a chip involves:
- Matrix Population - Filling values into a matrix structure.
- Constraint Construction - Establishing relationships between values, particularly across consecutive rows.

This process aligns with AIR's core functionality by:
- Treating column values as polynomial evaluations.
- Encoding value constraints as polynomial relationships.

## AddSub Chip Example

### Supported MIPS Instructions

| instruction | Op [31:26] | rs [25:21]  | rt [20:16]  | rd [15:11]  | shamt [10:6] | func [5:0]  | function                                                     |
| ----------- | ---------- | ----------- | ----------- | ----------- | ------------ | ----------- | ------------------------------------------------------------ |
| ADD         | 000000     | rs          | rt          | rd          | 00000        | 100000      | rd = rs+rt                                                   |
| ADDI        | 001000     | rs          | rt          | imm         | imm          | imm         | rt = rs + sext(imm)                                          |
| ADDIU       | 001001     | rs          | rt          | imm         | imm          | imm         | rt = rs + sext(imm)                                          |
| ADDU        | 000000     | rs          | rt          | rd          | 00000        | 100001      | rd = rs+rt                                                   |
| SUB         | 000000     | rs          | rt          | rd          | 00000        | 100010      | rd = rs - rt                                                 |
| SUBU        | 000000     | rs          | rt          | rd          | 00000        | 100011      | rd = rs - rt |


### Column Structure

```rust
pub struct AddSubCols<T> {
    // Program flow
    pub pc: T,          
    pub next_pc: T,    
    
    // Core operation
    pub add_operation: AddOperation<T>,  // Shared adder for both ops (a = b + c)
    
    // Input operands (context-sensitive):
    // - ADD: operand_1 = b, operand_2 = c 
    // - SUB: operand_1 = a, operand_2 = c
    pub operand_1: Word<T>,  
    pub operand_2: Word<T>,
    
    // Validation flags
    pub op_a_not_0: T,  // Non-zero guard for first operand
    pub is_add: T,      // ADD opcode flag
    pub is_sub: T,      // SUB opcode flag
}

pub struct AddOperation<T> {
    pub value: Word<T>,
    pub carry: [T; 3],
}
// 32-bit word structure
pub struct Word<T>(pub [T; WORD_SIZE]); // WORD_SIZE = 4
```

The AddSub Chip implementation utilizes 20 columns：
- `operand_1.[0-3], operand_2.[0-3]`: 4-byte operands (8 columns), 
- `add_operation.value.[0-3]`: 4-byte results (4 columns),
- `add_operation.carry.[0-2]`: Carry flags (3 columns),
- `pc, next_pc, op_a_not_0, is_add, is_sub`: Control signals (5 columns).

### Computational Validity Constraints 

The corresponding constraints support (we use op_1, op_2, add_op for short of operand_1, operand_2 and add_operation respectively):
- Zero Constraints

  Enforces add/sub validity for each byte, e.g., for addition \\(op\\_1.0 + op\\_2.0 - add\\_op.value.0 = 0 \\) or \\(op\\_1.0 + op\\_2.0 - add\\_op.value.0 = 256 \\).
- bool constraints
 
  carry values are bool, e.g., \\( add\\_op.carry.0 \in \\{0,1\\} \\).
- range check
  8-bits values for op_1.i, op_2.i, add_op.value.i. e.g., \\(op\\_1.0 \in \\{0,1,2,\cdots,255\\}\\).

### Matrix Population

Sample register state evolution:

| program count | instruction | description | ....  | r1  | r2  | r3 | r4 | r5| r6| r7|                                                   
|------| ---------- | ----------- | ------- | ----|---|--- | ---|----|----- | -----------| 
| 0        |      | initial        | ......      | x     | 30|10|9|13|13685| 21| 
| 1        | add $r5 $r6 $r7   | r7 = r5 + r6 | ...... | x   | 30|10|9|13|13685| 13698| 
| 2        | addi $r6 $r5 0    | r5 = r6 + 0  | ...... | x   | 30|10|9|13685|13685| 13698| 
| 3        | addi $r7 $r6 0    | r6 = r7 + 0  | ...... | x   | 30|10|9|13685|13698|13698 | 
| 4        | addi $r4 $r4 1    | r4 = r4 + 1  | ...... | x   | 30|10|10|13685|13698| 13698| 
| 5        | slt $r2 $r6 $r7   | r2 = r6 < r7? 1:0| ......| x| 0|10|10|13685|13698| 13698| 
| 6        | sub $r6 $r4 $r5  | r5 = r6 - r4 | ...... |    x | 0|10|10|13688|13698| 13698| 

Instructions 1, 2, 3, 4, and 6 are integrated with the AddSub Chip. The trace matrix (illustrated below, with the final row highlighting polynomial constraints) delineates their computational pathways.

| pc|next_pc | add_op.value.0 | add_op.value.1 |add_op.value.2|add_op.value.3| add_op.carry.0  | add_op.carry.1  |add_op.carry.2| op_1.0 | op_1.1 | op_1.2|op_1.3|  op_2.0 | op_2.1 | op_2.2|op_1.3|op_a_not_0|is_add|is_sub|                                                   
|--|--|---|---- |---- |---|----| --|--|---|---| ---|----|---|-- |--|--|--|--|--|
|1|2|130|53|0|0|0|0|0|13|0|0|0|117|53|0|0|1|1|0|
|2|3|119|53|0|0|0|0|0|119|53|0|0|0|0|0|0|1|1|0| 
|3|4|130|53|0|0|0|0|0|130|53|0|0|0|0|0|0|1|1|0| 
|4|5|10|0|0|0|0|0|0|9|0|0|0|1|0|0|0|1|1|0| 
|6|7|120|53|0|0|0|0|0|130|53|0|0|10|0|0|0|1|0|1| 
|a(x)|b(x)|c(x)|d(x)|e(x)|f(x)|g(x)|h(x)|i(x)|j(x)|k(x)|l(x)|m(x)|n(x)|o(x)|p(x)|q(x)|r(x)|s(x)|t(x)|

### AIR Transformation Example

Each column is represented as a polynomial defined over a ​​2-adic subgroup​​ within the ​​KoalaBear prime field​​. To demonstrate AIR expression, we analyze the ​​first-byte computation​​ in the addition operation: 

\\[P_{add}(x) := (j(x) + n(x) - c(x))(j(x) + n(x) - c(x)-256) = 0.\\]

And for sub operation, 
\\[P_{sub}(x) := (j(x) + n(x) - c(x))(j(x) + n(x) - c(x)-256) = 0.\\]

Using operation selectors \\(s(x), t(x)\\),  the derived polynomila constraint is 
\\[ s(x)\cdot P_{add}(x) + t(x) \cdot P_{sub}(x) = 0.\\]

Where:
- s(x): Add operation selector,
- t(x): Sub operation selector,
- j(x): First byte of op_1, 
- n(x): First byte of op_2,
- c(x): First byte of result value add_op.value.

###  Preprocessed AIR

For invariant components (e.g., Program/Bytes chips), Ziren precomputes commitments to invariant data columns and predefines fixed AIR constraints among them during setup to establish the Preprocessed AIR framework. By removing redundant recomputation of preprocessed AIR constraints in proofs, PAIR reduces ZKP proving time.

### Conclusion

The AIR framework transforms trace constraints into polynomial identities, where increased rows only expand the evaluation domain rather than polynomial complexity. Ziren also enhances efficiency through:
- Lookup Tables for range checks.
- Multiset Hashing for memory consistency.
- FRI for polynomial interactive oracle proofs (IOP).


These components constitute the foundational architecture of Ziren and will be elaborated in subsequent sections. 
