# Other Components

Except for CPU chip, Memory chips, and ALU chips, we also have Program chip, Bytes chip, customized Poseidon2 chip, STARK Compression chip, STARK-to-SNARK chip, and Precompiled chips.

In addition to the CPU, Memory, and ALU chips, Ziren incorporates several specialized components:

- ​Program Chip - Manages instruction preprocessing
- Global Chip - Processes global cross-table lookups
- Bytes Chip - Handles byte operations and u16 range check
- Poseidon2 Hash Chip - Cryptographic primitive implementation
- ​STARK Compression/SNARK-to-SNARK Adapter - Proof system optimization
- ​Precompiled Chips - Accelerated cryptographic operations


## Program Chip

Program chip establishes program execution constraints through preprocessed instruction verification. The CPU chip performs lookups against this verified instruction set.

## Global Chip
Global chip in Ziren is responsible for processing and verifying global lookup events (such as memory accesses, system calls), ensuring compliance with predefined rules and generating zero-knowledge data commitments.

## Bytes Chip
The Bytes chip is a preprocessed table that performs 8/16-bit unsigned integer range checks and  byte logic/arithmetic operations.

## Poseidon2 Hash Chip

[Poseidon2](https://eprint.iacr.org/2023/323) enhances the original Poseidon sponge function architecture with dual operational modes: maintaining sponge construction for general hashing while incorporating domain-specific compression mechanisms. Core optimizations include:
- Matrix-based linear layer substitutions replacing partial rounds.
- Configurable function width/rate parameters.

's implementation integrates specialized permutation logic with KoalaBear field arithmetic optimizations, critical for proof compression layers and STARK-to-SNARK proof system interoperability.

## ​STARK Compression/SNARK-to-SNARK Adapter

Three proofs are used in Ziren
- Shard Proofs: Used to verify correct execution of patched MIPS instructions (i.e., shard).
- STARK Compressed Proof: Compress shard proofs into one STARK proof.
- STARK-to-SNARK Adapter: Transform final STARK proof into Groth16-compatible SNARK proof.

After emulating MIPS instructions into STARK circuits, where each circuit processes fixed-length instruction shards, and after deriving the corresponding shard STARK proofs, these proofs are first compressed into a single STARK proof. This consolidated proof is then transformed into a SNARK proof. The chips responsible for STARK compression and the STARK-to-SNARK adapter are custom-designed specifically for proof verification over the KoalaBear field.

## Precompiled Chips

Another category of chips extensively utilized in Ziren is Precompiled chips. These chips are specifically designed to handle widely used but computationally intensive cryptographic operations, such as hash functions and signature schemes. 

Unlike the approach of emulating MIPS instructions, Ziren delegates these computations to dedicated precompiled tables. The CPU table then performs lookups to retrieve the appropriate values from these tables (precompiled operations are activated via syscalls). Precompiles have the capability to directly read from and write to memory through the memory argument. They are typically provided with a clock (clk) value and pointers to memory addresses, which specify the locations for reading or writing data during the operation. For a comprehensive list of precompiled tables, refer to [this section](../../../mips-vm/mips-isa.md).

