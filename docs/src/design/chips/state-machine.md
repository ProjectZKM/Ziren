# State Machine

The ZKM2 state machine is a ​MIPS-compatible, register-based virtual machine designed for zero-knowledge verification of general-purpose computations. It operates as a modular system of interconnected chips/tables (terms used interchangeably), each specializing in distinct computational tasks.

Core Components:
- Program Chip

  Manages program counter (PC) and instruction stream decoding while enforcing strict PC progression aligned with MIPS pipeline stages. The program table is preprocessed and constrains the program counter, instructions and selectors for the program. The CPU Chip looks up its instructions in the Program Chip.

- ​CPU Chip

  The CPU chip serves as the central processing unit for MIPS instruction execution. Each clock cycle corresponds to a table row, indexed via the pc column from the Program Chip. We constrain the transition of the pc, clk and operands in this table according to the cycle’s instruction. Each MIPS instruction has three operands: a, b, and c, and the CPU table has a separate column for the value of each of these three operands. The CPU table has no constraints for the proper execution of the instruction, nor does the table itself check that operand values originate from (or write to) correct memory addresses. ZKM2 relies on cross-table lookups to verify these constraints.


- ALU Chips
   
  The ALU Chips manage common field operations and bitwise operations. These chips are responsible for verifying correctness of arithmetic and bitwise operations and throug corss-table lookups from the main CPU Chip to make sure executing the correct instructions.

- ​Memory Chips
  
  Memory chips are responsible for the values in the a, b, and c operand columns in CPU chip come from (or write to) the right memory addresses specified in the instruction. ZKM2 use multiset hashing based offline memory consistnecy checking in the main operation of its memory argument with 4 memory tables.  

- Custom Chips
  
  Several Custom Chips are used for accelecating proving time in ZKM2's proof system: Poseidon2 hash, STARK compression and STARK-to-SNARK adapter.

- Precompile Chips:

  Precompile chips are custom-designed chips for accelerating non-MIPS cryptographic operations in ZKM2. They are recommended for handling common yet computationally intensive cryptographic tasks, such as SHA-256/Keccak hashing, elliptic curve operations (e.g., BN254, Secp256k1), and pairing-based cryptography.


Each chip consists of an AIR (Algebraic Intermediate Representation) to enforce functional correctness and received/sent signal vectors to connect with other chips. This modular design enables collaborative verification of MIPS instruction execution with full computational completeness, cryptographic security, and ​optimized proving performance featuring parallelizable constraint generation and sublinear verification complexity.