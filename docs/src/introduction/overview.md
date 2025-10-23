# Overview

[Ziren](https://github.com/ProjectZKM/Ziren) is an open-source, simple, stable, and universal zero-knowledge virtual machine on MIPS32r2 instruction set architecture(ISA).


Ziren is the industry's first zero-knowledge proof virtual machine supporting the MIPS instruction set, developed by the ZKM team, enabling zero-knowledge proof generation for general-purpose computation. Ziren is fully open-source and comes equipped with a comprehensive developer toolkit and an efficient proof network. The Entangled Rollup protocol, designed specifically to utilize Ziren, is a native asset cross-chain circulation protocol, with typical application cases including the Metis Hybrid Rollup design and the GOAT Network Bitcoin L2.

## Architectural Workflow

The workflow of Ziren is as follows:
- Frontend Compilation
  
  Source code (Rust) → MIPS assembly → Optimized MIPS instructions for algebraic representation.
- Arithmetization

  Emulates MIPS instructions while generating execution traces with embedded constraints (ALU, memory consistency, range checks, etc.) and treating columns of execution traces as polynomials.
- STARK Proof Generation

  Compiles traces into Plonky3 AIR (Algebraic Intermediate Representation), and proves the constraints using the Fast Reed-Solomon Interactive Oracle Proof of Proximity (FRI) technique.
- STARK Compression and STARK-to-SNARK Proof Recursion
  
  To produce a constant-size proof, Ziren supports first generating a recursive argument to compress STARK proofs, and then wrapping the compressed proof into a SNARK for efficient on-chain verification.
- Verification
  
  The SNARK proof can be verified on-chain. The STARK proof can be verified on any verification layer for faster optimistic finalization.

## Core Innovations


Ziren is the world's first MIPS-based zkVM, achieving the industry-leading performance through the following core innovations:

- Ziren Compiler
   
  Implement the first zero-knowledge compiler for [MIPS32r2](/mips-vm/mips-vm.md). Convert standard MIPS binaries into constraint systems with deterministic execution traces using proof-system-friendly compilation and PAIR builder.

- "Area Minimization" Chip Design

  Ziren partitions circuit constraints into highly segmented chips, strategically minimizing the total layout area while preserving logical completeness. This fine-grained decomposition enables compact polynomial representations with reduced commitment and evaluation overhead, thereby directly optimizing ZKP proof generation efficiency.

- Multiset Hashing for Memory Consistency Checking

  Replaces MerkleTree hashing with [Multiset Hashing](/design/memory-checking.md) for memory consistency checks, significantly reducing witness data and enabling parallel verification.
 
- KoalaBear Prime Field

  Using KoalaBear Prime \\(2^{31} - 2^{24} + 1\\) instead of 64-bit Goldilocks Prime, accelerating algebraic operations in proofs.

- Hardware Acceleration

  Ziren supports AVX2/512 and GPU acceleration. The GPU prover can achieve 30x faster for Core proof, 15x for Aggregation proof and 30x for BN254 Wrapping proof than CPU prover. 
 
- Integrating Cutting-edge Industry Advancements

  Ziren constructs its zero-knowledge proof system by integrating [Plonky3](https://github.com/Plonky3/Plonky3)'s optimized Fast Reed-Solomon IOP (FRI) protocol and adapting [SP1](https://github.com/succinctlabs/sp1)'s circuit builder, recursion compiler, and precompiles for the MIPS architecture.

## Target Use Cases
Ziren enables universal verifiable computation via STARK proofs, including:
- Bitcoin L2
 
  [GOAT Network](https://www.goat.network/) is a Bitcoin L2 built on Ziren and BitVM2 to improve the scalability and interoperability of Bitcoin. 
  
- ZK-OP (HybridRollups) 
  
  Combines optimistic rollup’s cost efficiency with validity proof verifiability, allowing users to choose withdrawal modes (fast/high-cost vs. slow/low-cost) while enhancing cross-chain capital efficiency. 
- Entangled Rollup

  Entanglement of rollups for trustless cross-chain communication, with universal L2 extension resolving fragmented liquidity via proof-of-burn mechanisms (e.g. cross-chain asset transfers).
 
- zkML Verification
  Protects sensitive ML model/data privacy (e.g. healthcare), allowing result verification without exposing raw inputs (e.g. doctors validating diagnoses without patient ECG data).