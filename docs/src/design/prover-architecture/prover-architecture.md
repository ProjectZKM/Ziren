# Prover Architecture

Ziren's prover architecture employs a multi-stage proof composition strategy to achieve scalable zero-knowledge computation. The system combines novel constraint reduction techniques with optimized polynomial commitment schemes and constraint construction schemes, delivering 10x faster proving speeds compared to previous ZKM, and outperforming other zkVM implementations to date.

## Core Components
The Ziren proving system implements a hierarchical verification model through four key components.

- Runtime Executor
  
  Processes program instructions, partitions execution into verifiable shards, and generates cryptographic execution records:
  - Instruction-level parallelism through pipelined execution for different shards.
  - Multiset hashing based memory state transitions.
  - Event-based constraint generation.

- Machine Prover
  
  Generates [STARK](../stark.md) proofs for individual execution shards using:

  - STARK config with KoalaBear field optimization.
  - Merkle Matrix Commitment Scheme (MMCS) with Poseidon2 hash algorithm.
  - FRI-based low-degree proofs.

- STARK Aggregation
  
  Recursively composes proofs across execution shards with custom recursive constraint chip over KoalaBear field.

- STARK-to-SNARK Adapter
  
  Converts aggregation proof to Ethereum-compatible format with:

  - BN254 field adaptation, compressing the STARK verifying circuit using Groth16-friendly field expression.
  - Groth16 circuit wrapping.

The final output is a ​Groth16 proof with corresponding verification key, compatible with Ethereum's Layer 1 verification infrastructure.
