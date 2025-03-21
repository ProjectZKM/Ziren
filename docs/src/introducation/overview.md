# Overview
ZKM2 is an optimized iteration of the [ZKM](https://docs.zkm.io/introduction) protocol, introducing a novel [​zkMIPS](https://github.com/zkMIPS)-based virtual machine that transforms [MIPS](https://en.wikipedia.org/wiki/MIPS_architecture) instructions into arithmetic circuits for STARK-powered zero-knowledge proofs. Designed for high-performance and trust-minimized computation, ZKM2 integrates cutting-edge cryptographic techniques and architectural improvements to address scalability bottlenecks in universal zkVMs.

## Architectural Workflow

The workfolw of ZKM2 is as follows:
- ​Frontend Compilation:
Source code (Rust/Go) → MIPS assembly → Optimized MIPS instructions for algebraic representation.
- ​Constrained Execution:
Emulates MIPS instructions while generating execution traces with embedded constraints (ALU, memory consistency, range checks, etc.) and treating columns of execution traces as polynomials.
- ​STARK Proof Generation:
Compiles traces into Plonky3 AIR (Algebraic Intermediate Representation), and prove the constraints using the Fast Reed-Solomon Interactive Oracle Proof of Proximity (FRI) technique.
- STARK Compression and STARK to SNARK:
To produce a constant-size proof, ZKM2 supports first generating a recursive argument to compress STARK proofs and then wrapping the compressed proof into a final, Groth16-compatible proof for ​efficient on-chain verification.
- Verification:
On-chain verification of Groth16-compatible proof.

## Core Innovations
Building on ZKM's full functionality, ZKM2 optimizes the entire ​workflow to achieve industry-leading performance: 
- ​MIPS-to-Circuit Compiler: 
Converts standard MIPS binaries into constraint systems with deterministic execution traces using proof-system-friendly compilation configuration with existing toolchains (GCC/LLVM).
- Multiset Hasing for Memory Consistency Checking:
Replaces Merkle-Patricia trees with multiset hashing for memory consistency checks, largely reducing witness data and enabling parallel verification.
- ​KoalaBear Prime Field:
Using KoalaBear Prime \\(2^{31} - 2^{24} + 1\\) instead of 64-bit Goldilock Prime, accelerating algebraic operations in proofs.
- Integrateting Cutting-edge Industry Advancements:
Adopts [Plonky3](https://github.com/Plonky3/Plonky3)'s optimized FRI implementation and ​adapts [SP1](https://github.com/succinctlabs/sp1)'s RISC-V primitives for MIPS.

## Target Use Cases
ZKM2 enables ​universal verifiable computation via STARK proofs, including:
- Hybrid Rollups: Combines optimistic rollup’s cost efficiency with validity proof verifiability, allowing users to choose withdrawal modes (fast/high-cost vs. slow/low-cost) while enhancing cross-chain capital efficiency. [Goat](https://www.goat.network/), a Bitcoin L2 ​built on ZKM2, leverages Taproot scripts to validate computations, enabling ​non-EVM chains like Bitcoin to achieve Turing completeness while ​maintaining transaction finality via Bitcoin. 
- Entangled Rollup: Uses entangled rollups for trustless cross-chain communication, with universal L2 extension resolving fragmented liquidity via proof-of-burn mechanisms (e.g., cross-chain asset transfers).
- zkML Verification: Protects sensitive ML model/data privacy (e.g., healthcare), allowing result verification without exposing raw inputs (e.g., doctors validating diagnoses without patient ECG data).
