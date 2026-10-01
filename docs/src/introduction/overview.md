# Overview

[Ziren](https://github.com/ProjectZKM/Ziren) is an open-source zero-knowledge virtual machine (zkVM) for the MIPS32r2 instruction set architecture (ISA), developed by ZKM. A program compiled for MIPS32r2, for example from Rust or Go, runs inside Ziren, and Ziren produces a proof that the execution was correct. A verifier checks the proof far faster than it could replay the execution, either natively or on-chain after the proof is wrapped into a SNARK.

Ziren proves the complete user-mode integer instruction set of MIPS32r2, branch-delay slot included, and proves Ethereum mainnet blocks end to end in production. It is used by the Entangled Rollup protocol for native cross-chain asset circulation, with deployments including the GOAT Network Bitcoin L2 and the Metis Hybrid Rollup.

This documentation describes Ziren V2.0.

## Architectural Workflow

- **Compilation.** Guest source code (Rust, or Go) is compiled by the Ziren toolchain for the `mipsel-zkm-zkvm-elf` target into a MIPS32r2 ELF binary. The ELF image, loaded into memory, fixes the program the proof is about.

- **Execution.** The executor runs the ELF, either with an interpreter or with a just-in-time compiler, and cuts the run into shards. For each shard it records the events (instructions, memory accesses, syscalls and precompile calls) the prover needs.

- **Arithmetization.** Every executed instruction becomes one row of the chip for its opcode family; there is no central CPU table. The branch-delay slot is carried in the machine state as a pair `(pc, next_pc)`. Chips exchange values over buses (program fetch, register and memory accesses, byte lookups, syscalls), which are checked by a lookup argument.

- **Shard proving.** Each shard is proved with one LogUp-GKR lookup argument for all of its buses and one zerocheck for all of its constraints, over the 31-bit KoalaBear field. A jagged polynomial commitment reduces the claims on the shard's columns, which have differing heights, to a single evaluation that is opened by one batched WHIR proof. Hashing uses Poseidon2.

- **Recursion and compression.** A recursion tree composes the shard proofs: a leaf program verifies one shard proof, and compose programs merge contiguous ranges of proofs up to a single root. Every recursion program's verifying key must belong to an enumerated allowlist, committed to as a Merkle root (the vk root). The result is a compressed proof whose size does not grow with the execution.

- **SNARK wrapping.** For on-chain verification the compressed proof is shrunk and wrapped into a Groth16 or PLONK proof over BN254.

- **Verification.** Groth16 and PLONK proofs are verified by Solidity contracts or by the `zkm-verifier` crate; core and compressed proofs are verified natively by the SDK.

## Design Choices

- **MIPS32r2 execution.** The guest executes the MIPS32r2 integer instructions listed in [MIPS ISA](../mips-vm/mips-isa.md), including the branch-delay slot, with a minimal Linux ABI for runtimes such as Go (see [Linux ABI](../mips-vm/linux-abi.md)).

- **Per-opcode chips.** Instructions are proved by narrow per-family chips rather than one wide table, so a common instruction pays only for its own columns. An addition or bitwise operation costs 33 to 37 committed cells per row, of which 29 to 32 are the shared instruction frame.

- **Cross-shard memory consistency by multiset hashing.** Accesses to memory that crosses shard boundaries are accumulated as points on an elliptic curve over a degree-7 extension of KoalaBear (see [Memory Consistency Checking](../design/memory-checking.md)), rather than by Merkle hashing.

- **KoalaBear field.** Arithmetic is over the prime \\(2^{31} - 2^{24} + 1\\), with a degree-4 extension for challenges.

- **GPU proving.** A CUDA implementation of the same protocol generates traces and proves shards on the GPU; the host only executes the guest and coordinates.

- **Formal determinism.** A Lean 4 statement that each core chip's outputs are determined by its inputs is extracted mechanically from the chip's constraints (`crates/fv`).

- **Foundations.** Ziren builds on [Plonky3](https://github.com/Plonky3/Plonky3) and adapts [SP1](https://github.com/succinctlabs/sp1)'s circuit builder, recursion compiler and precompiles for MIPS32.

## Target Use Cases

Ziren enables verifiable computation for general programs, including:

- **Bitcoin L2.** [GOAT Network](https://www.goat.network/) is a Bitcoin L2 built on Ziren and BitVM2 to improve the scalability and interoperability of Bitcoin. See [Use Cases](./use-cases.md).

- **ZK-OP (hybrid rollups).** Combines an optimistic rollup's cost with validity-proof verifiability, letting users choose between a fast, higher-cost withdrawal and a slow, lower-cost one.

- **Entangled Rollup.** Entangles rollups for trustless cross-chain communication, with a universal L2 extension that addresses fragmented liquidity through proof-of-burn (for example, cross-chain asset transfers).

- **zkML verification.** Verifies the result of a machine-learning computation without exposing the model or its inputs (for example, validating a diagnosis without revealing patient data).
