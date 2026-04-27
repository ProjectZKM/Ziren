# D2 cutover plan — Legacy recursion → basefold recursion

Task #35. Drive the feat/upgrade-plonky3 prover fully onto the basefold recursion programs so compress VKs become cluster-parametrized and `test_e2e_compress_fibonacci` passes with `VERIFY_VK=true`.

## Current state (pre-cutover)

- `prove_core` → `Vec<ShardProof<CoreSC>>` (legacy FRI shard proofs)
- `ZKMCircuitWitness::{Core, Deferred, Compress}` carries legacy `ZKMRecursionWitnessValues` / `ZKMDeferredWitnessValues` / `ZKMCompressWitnessValues`
- `ZKMProver::{recursion_program, compress_program, deferred_program, shrink_program, wrap_program}` call legacy circuit builders (`ZKMRecursiveVerifier::verify` etc.)
- `_basefold` program builders exist at `crates/recursion/circuit/src/machine/basefold_programs.rs` and the matching witness types exist at `*_basefold.rs`, but are **not wired** into any prover path
- `prove_shard_to_basefold` exists at `crates/stark/src/shard_level/prover.rs` but is exercised only by shard-level unit tests — `prove_core` does NOT call it
- VK map is 30 stacked-shape VKs (after task #32) or HEAD's stale 50MB legacy map; neither matches fibonacci's legacy compress_vk because legacy circuit is per-chip while enumerator is cluster

## Target state

- `prove_core_basefold` produces `Vec<BasefoldShardProof>` per shard
- `ZKMCircuitWitness` carries basefold variants
- `ZKMProver` program methods dispatch to `build_*_basefold_program`
- `compress` / `shrink` / `wrap` orchestration runs basefold proofs through basefold programs end-to-end
- Legacy files deleted: `core.rs`, `compress.rs`, `deferred.rs`, `wrap.rs`, legacy witness structs, `compress_program_from_input`
- VK map regenerated with basefold programs → stacked-shape (~13 clusters) covers every real program

## Execution steps

### Step A — prover-side shard proofs
Make `prove_core` (or a new `prove_core_basefold`) call `prove_shard_to_basefold` per shard. Produce `Vec<BasefoldShardProof<KoalaBear, Challenge>>`. New type `ZKMCoreBasefoldProof` = `Vec<BasefoldShardProof>`.

Files: `crates/core/machine/src/utils/prove.rs`, `crates/prover/src/lib.rs`, `crates/prover/src/types.rs`.

### Step B — witness construction
Update `get_first_layer_inputs` / `get_recursion_core_inputs` / `get_recursion_deferred_inputs` to produce `ZKMCoreBasefoldWitnessValues` / `ZKMDeferredBasefoldWitnessValues` / `ZKMCompressBasefoldWitnessValues`.

Files: `crates/prover/src/lib.rs`.

### Step C — witness enum + dispatch
`ZKMCircuitWitness` gets basefold variants; the match arm at lib.rs:708-728 dispatches to the basefold program builders.

Files: `crates/prover/src/types.rs`, `crates/prover/src/lib.rs`.

### Step D — ZKMProver program methods
Replace `recursion_program` / `compress_program` / `deferred_program` / `shrink_program` / `wrap_program` with basefold counterparts calling `build_normalize_basefold_program` / `build_compose_basefold_program` / `build_deferred_basefold_program` / `build_wrap_basefold_program`.

Files: `crates/prover/src/lib.rs`.

### Step E — compress/shrink/wrap orchestration
Update the thread-scoped pipeline in `compress` / `shrink` / `wrap` to stream basefold proofs through basefold programs.

Files: `crates/prover/src/lib.rs`.

### Step F — verify path
Update `ZKMProver::verify_compressed` / `verify_shrink` / `verify_wrap` to accept basefold-compressed proofs and verify with basefold verifier.

Files: `crates/prover/src/verify.rs`.

### Step G — VK generation
`build_compress_vks` uses basefold programs. `ZKMCompressProgramShape::from_proof_shape` maps Recursion → basefold normalize, Compress → basefold compose, etc. `program_from_shape` dispatches to basefold builders.

Files: `crates/prover/scripts/build_compress_vks.rs`, `crates/prover/src/shapes.rs`, `crates/prover/src/lib.rs`.

### Step H — delete legacy
Remove `core.rs`, `compress.rs`, `deferred.rs`, `wrap.rs`, legacy witness types `ZKMRecursionWitnessValues` / `ZKMDeferredWitnessValues` / `ZKMCompressWitnessValues`, `compress_program_from_input`, `ZKMRecursiveVerifier` / `ZKMCompressVerifier` / `ZKMDeferredVerifier` / `ZKMCompressRootVerifierWithVKey`. Update `machine/mod.rs` accordingly.

Files: `crates/recursion/circuit/src/machine/*.rs`, `crates/prover/src/lib.rs`.

### Step I — regenerate VK map
Full regen on ant-5090-2 with basefold programs. Expect ~13 unique VKs (one per cluster). vk_map.bin should shrink to ~500 bytes.

### Step J — run test_e2e_compress_fibonacci
VERIFY_VK=true. Expect pass.

## Dependencies / ordering

A blocks B-J. B blocks C. C blocks D-E. D blocks E. E blocks F-G. G blocks I-J.

## Blockers / open questions

- Does `prove_shard_to_basefold` need per-shard context (deferred state, is_first_shard, is_complete) the way legacy prove_shard does?
- Witness struct `ZKMCoreBasefoldWitnessValues` uses `InnerVal, InnerChallenge` — does that match what shard-level prover produces for `CoreSC` (= KoalaBearPoseidon2)?
- Does `fix_shape(&mut program)` still work for basefold programs, or does shape-fixing need a basefold-aware variant?
