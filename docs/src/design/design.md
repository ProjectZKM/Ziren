# Design


As ​MIPS instruction set based zkVM, Ziren is designed to generate efficient zero-knowledge proofs for complex computations (e.g., smart contract execution). Its architecture integrates a ​modular state machine, ​custom chip design, and a ​hybrid proof system (STARK + SNARK). 

- Modular State Machine

  The state machine serves as the central control unit, simulating MIPS instruction execution through ​multi-chip collaboration to ensure all state transitions are verifiable in zero-knowledge. Key submodules include the Program Chip, CPU Chip, Memory Chips, ALU Chips, Global Chip and Bytes Chip. Together they enforce equivalence between MIPS program execution and Ziren VM constraints. 

- Custom Chip Design

  Ziren translates MIPS execution traces into a polynomial constraint system. To efficiently encode MIPS instructions:
  - Dedicated constraint circuits are implemented for each MIPS opcode to accelerate proof generation.
  - Precompiled chips handle ​common yet computationally intensive cryptographic operations (e.g., hashing, field arithmetic) for optimal performance.


- Hybrid Proof System

  Ziren employs a three-stage proof workflow to balance modularity and efficiency:
  - Sharded STARK Proofs:

    MIPS instructions are partitioned into fixed-length shards, each verified via fast STARK proofs. 
  - Recursive Aggregation:

    Shard proofs are compressed using a recursive STARK composition scheme.
  - SNARK Finalization:

    The aggregated proof is wrapped into a Groth16-compatible SNARK for efficient on-chain verification.
  - Proof Composition
    
    Proof composition enables developers to implement recursive proof verification, allowing cryptographic proofs to be nested within zkVM programs.
    


