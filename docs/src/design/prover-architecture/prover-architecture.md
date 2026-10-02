# Prover Architecture

The Ziren prover turns one execution of a guest ELF into a proof in four stages. Each stage is a function of `ZKMProver` in `crates/prover/src/lib.rs`, and the SDK calls them in this order:

1. **Execute and prove shards** (`prove_core`). The executor runs the program and cuts the execution into shards. Each shard's events become chip traces, and each shard gets its own shard proof (see [STARK Protocol](../stark.md)). The result is a `ZKMCoreProof`, a list of shard proofs.
2. **Compress** (`compress`). A recursion tree verifies all shard proofs, and any deferred proofs, and reduces them to one recursion proof over the whole execution (see [STARK Aggregation](./stark-aggregation.md) and [Recursive STARK](./recursive-stark.md)).
3. **Shrink and wrap** (`shrink`, `wrap_bn254`). The compressed proof is verified by a fixed-shape shrink program and then by a wrap program. The wrap program is proved with a BN254-friendly hash so that a SNARK can verify it.
4. **SNARK** (`wrap_groth16_bn254`, `wrap_plonk_bn254`, `wrap_dvsnark_bn254`). A gnark circuit verifies the wrap proof and produces a Groth16, PLONK or designated-verifier SNARK over BN254 (see [STARK to SNARK](./stark-to-snark.md)).

The SDK proof kinds stop at different stages: `core` after stage 1, `compressed` after stage 2, and `groth16`, `plonk` or `dvsnark` after stage 4.

## Execution and sharding

The executor (`crates/core/executor`) interprets the MIPS32r2 program and records events: one per executed instruction, memory access, syscall and precompile call. It closes the current shard and starts a new one when any of these limits is reached:

- the cycle budget (`shard_size`);
- the per-shard clock, so that every timestamp stays below the \\( 2^{26} \\) range the memory argument checks;
- the estimated trace area of the shard, in cells;
- the height of the tallest chip, which must stay below \\( 2^{22} \\) rows, the size the recursion verifier is built for.

A shard is never closed in front of a delay slot. Precompile events are moved into separate precompile shards, and the memory initialization and finalization events of the whole execution are placed in the last shards. Each shard records its public values: start and end `pc`, shard and execution-shard numbers, the memory address ranges it initialized and finalized, the committed-value and deferred-proof digests, the exit code and its global digest.

## Shard proofs

Shard proofs are independent of each other, so they are generated in parallel. Every constraint between shards is a public value or a message on the global bus, and the recursion checks them. Trace generation and proving can run on the CPU prover or on GPUs.

## Recursion and SNARK

The recursion machine is a separate STARK machine (`RecursionAir`) over KoalaBear. It runs recursion programs, which are verifiers of shard proofs compiled to the recursion machine's instruction set, and proves their execution with the same shard argument. Each proof it produces is again a shard proof, so recursion proofs can be verified recursively. The final wrap proof uses the same machine with a Poseidon2 hash over BN254, which the gnark circuit can check.
