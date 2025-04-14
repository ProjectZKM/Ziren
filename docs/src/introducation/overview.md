# Overview

zkMIPS is an open-source, simple, stable, and universal zero-knowledge virtual machine on MIPS32r2 instruction set architecture(ISA).

zkMIPS is the industry's first zero-knowledge proof virtual machine supporting the MIPS instruction set, developed by the ZKM team, enabling zero-knowledge proof generation for general-purpose computation. zkMIPS is fully open-source and comes equipped with a comprehensive developer toolkit and an efficient proof network. The Entangled Rollup protocol, built on zkMIPS, is a native asset cross-chain circulation protocol, with typical application cases including Metis Hybrid Rollup and GOAT Network.

## Architectural Workflow

The workflow of zkMIPS is as follows:
- Frontend Compilation:
  
  Source code (Rust) → MIPS assembly → Optimized MIPS instructions for algebraic representation.
- Constrained Execution:

  Emulates MIPS instructions while generating execution traces with embedded constraints (ALU, memory consistency, range checks, etc.) and treating columns of execution traces as polynomials.
- STARK Proof Generation:

  Compiles traces into Plonky3 AIR (Algebraic Intermediate Representation), and proves the constraints using the Fast Reed-Solomon Interactive Oracle Proof of Proximity (FRI) technique.
- STARK Compression and STARK to SNARK:
  
  To produce a constant-size proof, zkMIPS supports first generating a recursive argument to compress STARK proofs and then wrapping the compressed proof into a SNARK proof for efficient on-chain verification.
- Verification:
  
  On-chain verification of the SNARK proof.

## Core Innovations

zkMIPS is the world first MIPS zkVM, and achieve the industry-leading performance with the core innovations as below. 

- zkMIPS Compiler
   
  Implement the first zero-knowledge compiler for [MIPS32r2 instruction set](/mips-vm/mips-vm.md). Converts standard MIPS binaries into constraint systems with deterministic execution traces using proof-system-friendly compilation and PAIR builder.
 
- Multiset Hashing for Memory Consistency Checking

  Replaces Merkle-Patricia trees with multiset hashing for memory consistency checks, significantly reducing witness data and enabling parallel verification.
 
- KoalaBear Prime Field

  Using KoalaBear Prime \\(2^{31} - 2^{24} + 1\\) instead of 64-bit Goldilock Prime, accelerating algebraic operations in proofs.

- Hardware Acceleration

  zkMIPS supports AVX2/512 and GPU acceleration.
 
- Integrating Cutting-edge Industry Advancements

  zkMIPS constructs its zero-knowledge verification system by integrating [Plonky3](https://github.com/Plonky3/Plonky3)'s optimized Fast Reed-Solomon IOP (FRI) protocol and adapting [SP1](https://github.com/succinctlabs/sp1)'s circuit builder, recursion compiler, and precompiles for the MIPS architecture.

## Target Use Cases
zkMIPS enables universal verifiable computation via STARK proofs, including:
- Bitcoin L2
 
  [GOAT Network](https://www.goat.network/), a Bitcoin L2 built on zkMIPS and BitVM2 to improve the interoperability of Bitcoin.
  
- ZK-OP(HybridRollups) 
  
  Combines optimistic rollup’s cost efficiency with validity proof verifiability, allowing users to choose withdrawal modes (fast/high-cost vs. slow/low-cost) while enhancing cross-chain capital efficiency. 
- Entangled Rollup

  Uses entangled rollups for trustless cross-chain communication, with universal L2 extension resolving fragmented liquidity via proof-of-burn mechanisms (e.g., cross-chain asset transfers).
 
- zkML Verification
  Protects sensitive ML model/data privacy (e.g., healthcare), allowing result verification without exposing raw inputs (e.g., doctors validating diagnoses without patient ECG data).