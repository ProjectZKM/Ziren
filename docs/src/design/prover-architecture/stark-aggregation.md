# STARK Aggregation

`ZKMProver::compress` reduces the shard proofs of an execution, together with any deferred proofs, to a single recursion proof. It does this with a tree of recursion programs whose leaves are shard proofs.

## Leaves: normalize

Each core shard proof is verified by a *normalize* program, one shard per program. The program:

- runs the shard verifier (LogUp-GKR, zerocheck, jagged WHIR opening) against the program's verifying key;
- checks the conditions that depend on the shard alone;
- outputs the shard's public values in the recursion format (`RecursionPublicValues`), which covers a shard *range* `[start_shard, next_shard)`.

The first shard must start at the verifying key's `pc_start` and contributes the key's initial global digest. An execution shard must have sequential boundaries (`start_next_pc = start_pc + 4`, `next_next_pc = next_pc + 4`) and exit code 0.

Deferred proofs are verified by a separate *deferred* program in batches. A deferred batch covers a range placed after the last execution shard (see [Proof Composition](./proof-composition.md)).

## Inner nodes: compose

A *compose* program verifies up to three (`REDUCE_BATCH_SIZE`) recursion proofs of adjacent ranges and outputs the public values of their union. It checks that each input starts where the previous one ends:

- `start_pc` equals the previous `next_pc`;
- shard and execution-shard numbers continue;
- the initialized and finalized address ranges join;
- the deferred-proof digest chain continues;
- the committed-value and deferred-proof digests agree.

It also adds the inputs' global digests. Each input's verifying key must be in the enumerated set of recursion keys: the program checks a Merkle proof of the key's hash against `vk_root`, a tree of height 14. The check is compiled into the program when `VERIFY_VK` is true, the default.

## Scheduling

The tree is keyed by shard range, not by depth (`crates/prover/src/compress_tree.rs`). When a proof completes, the scheduler looks for an adjacent range. Once a contiguous run reaches three proofs, it is dispatched to a compose program; a shorter run waits. Levels therefore overlap: a range is reduced as soon as its neighbours are ready. The compose program asserts continuity between its inputs, so every batch must be a contiguous run in order.

A leaf is never the root. An execution of one shard is closed by a compose of arity one.

## Root

The compose that covers the whole execution runs with `is_complete` set and checks that the proof describes a complete, successful run:

- the execution starts at shard 1 and contains an execution shard;
- it ends with `next_pc = 0`;
- the reconstructed deferred digest starts at zero and ends at the digest the guest committed;
- the sum of all global digests is the neutral digest, so every cross-shard memory and syscall message was consumed.

The output is a `ZKMReduceProof`, the *compressed* proof, which the SDK can verify directly or pass on to the SNARK stages.
