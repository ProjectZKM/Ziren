# ALU
The Arithmetic Logic Unit (ALU) chips comprise ​​specialized verification circuits​​ designed to enforce computational correctness for all arithmetic and bitwise operations. These circuits implement ​​cross-table lookup protocols​​ with the main CPU table, ensuring instruction-execution integrity throughout the processor pipeline.

## Modular Design

The ALU employs a ​​hierarchical verification architecture​​ organized by MIPS instruction class:

- ​AddSub Chip​​ - Validates addition/subtraction instructions (ADD, ADDI, SUB, SUBU).
- ​Bitwise Chip​​ - Verifies logical operations (AND, ANDI, OR, XOR, NOR).
- ​​CloClz Chip​​ - Processes count-leading-ones/zeros operations (CLO/CLZ).
- ​​DivRem Chip​​ - Implements division/remainder operations (DIV/REM).
- ​​Lt Chip​​ - Enforces signed/unsigned comparisons (SLT, SLTI, SLTU).
- ​​Mul Chip​​ - Handles multiplication operations (MUL, MULT, MULTU).
- ​​ShiftLeft Chip​​ - Executes logical left shifts (SLL, SLLI).
- ​​ShiftRight Chip​​ - Manages logical/arithmetic right shifts (SRL, SRA).
​

Each chip employs domain-specific verification to ensure accurate execution of programmed instructions and [LogUp](https://eprint.iacr.org/2023/1518)-based proper alignment with CPU table constraints, thereby guaranteeing consistency between computational results and predefined operational logic.

In Section [arithmetization](../arithmetization.md), we analyze the AddSub Chip to demonstrate its ​​column architecture​​ and ​​constraint system implementation​​, providing concrete insights into ALU verification mechanisms.
