# State Machine

The Ziren state machine is a ​MIPS-compatible, register-based virtual machine designed for zero-knowledge verification of general-purpose computations. It operates as a modular system of interconnected chips/tables (terms used interchangeably), each specializing in distinct computational tasks.

Core Components:
- Program Chip

  Manages program counter (PC) and instruction stream decoding while enforcing strict PC progression aligned with MIPS pipeline stages. The program table is preprocessed and constrains the program counter, instructions and selectors for the program. The CPU chip looks up its instructions in the Program chip.

- ​CPU Chip

  The CPU chip serves as the central processing unit for MIPS instruction execution. Each clock cycle corresponds to a table row, indexed via the pc column from the Program chip. We constrain the transition of the pc, clk and operands in this table according to the cycle’s instruction. Each MIPS instruction has three operands: a, b, and c, and the CPU table has a separate column for the value of each of these three operands. The CPU table has no constraints for the proper execution of the instruction, nor does the table itself check that operand values originate from (or write to) correct memory addresses. Ziren relies on cross-table lookups to verify these constraints.


- ALU Chips
   
  The ALU chips manage common field operations and bitwise operations. These chips are responsible for verifying correctness of arithmetic and bitwise operations and throug corss-table lookups from the main CPU chip to make sure executing the correct instructions.

- Flow-Control Chips
  
  Flow control mechanisms are ​fundamental components in modern computer programs, ​enhancing program functionality and execution flexibility by providing structured control mechanisms. In the Ziren, ​dedicated modules — ​the Branch chip and Jump chip — ​are implemented to handle branch instructions and jump instructions ​respectively within the MIPS Instruction Set Architecture (ISA).
  
- ​Memory Chips
  
  Memory chips are responsible for the values in the a, b, and c operand columns in CPU chip come from (or write to) the right memory addresses specified in the instruction. Ziren use multiset hashing based offline memory consistency checking in the main operation of its memory argument with several memory tables.  

- Global Chip

  Global chip in Ziren is responsible for processing and verifying global lookup events (such as memory accesses, system calls), ensuring compliance with predefined rules and generating cryptographic proof data.

- Custom Chips
  
  Several Custom chips are used to accelecate proving time in Ziren's proof system: Poseidon2 hash, STARK compression and STARK-to-SNARK adapter.

- Precompiled Chips:

  Precompiled chips are custom-designed chips for accelerating non-MIPS cryptographic operations in Ziren. They are recommended for handling common yet computationally intensive cryptographic tasks, such as SHA-256/Keccak hashing, elliptic curve operations (e.g., BN254, Secp256k1), and pairing-based cryptography.


Each chip consists of an AIR (Algebraic Intermediate Representation) to enforce functional correctness and received/sent signal vectors to connect with other chips. This modular design enables collaborative verification of MIPS instruction execution with full computational completeness, cryptographic security, and ​optimized proving performance featuring parallelizable constraint generation and sublinear verification complexity.
