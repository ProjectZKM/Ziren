# Recursive STARK

This page follows one execution through the proving pipeline and names the code for each step. [STARK Aggregation](./stark-aggregation.md) describes what the recursion tree checks, and [STARK Protocol](../stark.md) describes the shard argument that every proof in the pipeline uses.

## Shard proof generation

### 1. Setup

- `ZKMProver::get_program(elf)` loads the ELF into a `Program`: the instruction image, `pc_start` and the initial memory image.
- `ZKMProver::setup(elf)` builds the proving and verifying keys. The verifying key holds:
  - the commitment to the preprocessed traces (the program table, the byte and range tables);
  - `pc_start`;
  - `initial_global_cumulative_sum`, the global digest of the initial memory image;
  - the chip layout.

  Its digest (`zkm_vk_digest`) identifies the program in every later proof.

### 2. Execution and trace generation

`ZKMProver::prove_core(pk, program, stdin, opts, context)` runs the executor, which cuts the execution into shards (see [Continuation](../continuation.md)), and generates the traces of each shard. The machine is `MipsAir` (`crates/core/machine/src/mips/mod.rs`), an enum with one variant per chip: the instruction chips (each with its instruction frame, see [CPU](../chips/cpu.md)), the memory chips, the lookup tables, the syscall and precompile chips and the `Global` chip. A chip with no events in a shard is left out of that shard's proof.

### 3. Shard proofs

Each shard is proved with the shard argument: jagged commitment, LogUp-GKR, zerocheck and WHIR. The result, `ZKMCoreProof`, is a list of `ShardProof`s. Each holds the main commitment, the public values, the chip heights, the LogUp-GKR and zerocheck proofs, the opened values and the jagged evaluation proof.

## Recursive aggregation

### RecursionAir

Recursion programs run on a small virtual machine over KoalaBear whose execution is proved by `RecursionAir` (`crates/recursion/core/src/machine.rs`). Its chips are:

| Chip | Role |
|---|---|
| `MemoryConst`, `MemoryVar` | the program's memory: constants and variables |
| `BaseAlu`, `ExtAlu` | arithmetic in KoalaBear and in its degree-4 extension |
| `Poseidon2Wide` | the Poseidon2 permutation, for Merkle paths and the transcript |
| `Select` | conditional selection |
| `Ext2Felt` | decomposition of an extension element into base-field coefficients |
| `PublicValues` | the program's public values |

The chips have no special gates for FRI or sumcheck. The recursion verifier's sumchecks, Merkle path checks and WHIR folding are compiled to these operations. The machine is instantiated at three constraint degrees: `CompressAir` and `ShrinkAir` at degree 3 and `WrapAir` at degree 9. The degree changes only the Poseidon2 column layout.

### Recursion programs

The recursion compiler (`crates/recursion/compiler`) builds each program from the verifier code in `crates/recursion/circuit`:

| Program | Built by | Verifies |
|---|---|---|
| normalize | `recursion_program_basefold` | one core shard proof |
| compose | `compose_program_basefold` | one to three adjacent recursion proofs |
| deferred | `deferred_program_basefold` | a batch of deferred compressed proofs |
| shrink | `shrink_program_basefold` | the compressed proof |
| wrap | `wrap_bn254_program_basefold` | the shrink proof, for the BN254 SNARK |

The program is fixed by the shape of the proofs it verifies. A normalize program depends on the chip set of the shard and its height class. A compose program depends only on its arity, since every recursion proof has the same shape. The prover caches programs and their keys.

### Verifying-key set

Programs are generated, not written by hand, so the set of valid recursion keys is enumerated in advance: the normalize programs for every shard shape, the compose programs of every arity, and the deferred programs. Their hashes form a Merkle tree of height 14 (`VK_MERKLE_TREE_HEIGHT`) whose root, `vk_root`, is a public value of every recursion proof and a public input of the SNARK. The enumeration ships with the prover as `vk_map.bin`. The compose and deferred programs check a Merkle proof that the key of each proof they verify is in the set, and the shrink program checks it for the compressed proof. Without this check, a prover could verify a proof of an arbitrary program in place of a normalize proof.

### Compression

`ZKMProver::compress(vk, core_proof, deferred_proofs, opts)`:

1. builds the leaf inputs with `get_first_layer_inputs`: one normalize input per shard (`get_recursion_core_inputs_basefold`) and the deferred batches (`get_recursion_deferred_inputs_basefold`);
2. runs the range-keyed reduction tree of compose programs (`compress_tree.rs`) until one proof covers the whole execution;
3. returns the root proof as a `ZKMReduceProof`.

`shrink` and `wrap_bn254` continue from there (see [STARK to SNARK](./stark-to-snark.md)).

## Source mapping

| Stage | Functions | Machine |
|---|---|---|
| Setup | `get_program`, `setup` | `MipsAir` |
| Execution, traces, shard proofs | `prove_core` | `MipsAir` |
| Leaf inputs | `get_first_layer_inputs`, `get_recursion_core_inputs_basefold`, `get_recursion_deferred_inputs_basefold` | |
| Compression | `compress`, `compose_program_basefold`, `deferred_program_basefold` | `CompressAir` |
| Shrink | `shrink`, `shrink_program_basefold` | `ShrinkAir` |
| Wrap | `wrap_bn254`, `wrap_bn254_program_basefold` | `WrapAir` over `OuterSC` |
| SNARK | `wrap_groth16_bn254`, `wrap_plonk_bn254`, `wrap_dvsnark_bn254` | gnark over BN254 |
