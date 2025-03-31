# ALU

The Arithmetic Logic Unit (ALU) chips comprises specialized verification circuits that enforce correctness for arithmetic and bitwise operations. These circuits implement cross-table lookups with the main CPU table to maintain instruction-execution integrity across the processor pipeline.

## Modular Design
The ALU is decomposed into dedicated verification units corresponding to MIPS instruction classes:

- ​AddSub Chip - Validates addition and subtion instructions, e.g., ADD,ADDI,SUB,SUBU, etc.
- ​Bitwise Chip - Verifies bitwise instructions, e.g., AND, ANDI, OR, XOR, NOR, etc.
- ​Mul Chip - Handles multiplication and division instruction, e.g., MUL, MULT, DIV, DIVU, etc.
- ShiftRight Chip - Processes logical/arithmetic shifts, e.g., SLL, SRA, SRL, etc.
- Lt Chip - Enforces SLT/SLTI comparisons.

Each chip establishes correct calculation of corresponding instructions and constraint relationships with CPU table columns through Plookup-based verification, ensuring operational results match programmed instructions.

Taking the AddSub Chip as an example, introduce its composition.

## AddSub Chip
The AddSub module provides formal verification for MIPS integer addition and subtraction operations through constrained algebraic relationships.

```rust
pub struct AddSubCols<T> {
    /// Execution context identifier for table joins
    pub shard: T,
    
    /// Additive operation constraints (a = b + c, a in ADD, b in SUB)
    pub add_operation: AddOperation<T>,
    
    /// Primary operand (b in ADD, a in SUB)
    pub operand_1: Word<T>,
    
    /// Secondary operand (c in both operations)
    pub operand_2: Word<T>,
    
    /// Opcode verification flags
    pub is_add: T,  // ADD/ADDI assertion
    pub is_sub: T   // SUB assertion
}
```
The ​AddSub Chip enforces computational validity for addition/subtraction operations. Using lookup-based verification, CPU table entries corresponding to ADD/SUB instructions establish constrained connections with the AddSub Chip. All these ALU chips collectively implement a ​modular verification framework for MIPS instructions' execution.


