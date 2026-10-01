# Continuation

Ziren proves an execution of any length by splitting it into shards, proving each shard on its own, and joining the shard proofs in the recursion. This has three advantages:

- **Bounded proofs.** Each shard proof has a bounded size and cost, however long the execution.
- **Parallelism.** Shards are proved independently, on many cores, GPUs or machines.
- **State continuity.** The recursion checks that each shard starts where the previous one ended, and [memory consistency checking](./memory-checking.md) across shards ensures that every shard sees the memory the previous shards left.

## Sharding

The executor runs the whole program and closes a shard when any of these limits is reached (see [Prover Architecture](./prover-architecture/prover-architecture.md)): the cycle budget, the per-shard clock limit, the estimated trace area, or the height of the tallest chip. It never closes a shard in front of a branch delay slot. Precompile calls are proved in separate precompile shards, which the execution shards reach through syscall messages on the global bus.

The per-shard clock `clk` restarts at 0 in every shard, and a timestamp is the pair `(shard, clk)`.

## Shard state

A shard's proof exposes its interface as public values:

| Public values | Meaning |
|---|---|
| `start_pc`, `start_next_pc`, `next_pc`, `next_next_pc` | the program counters on entry and exit |
| `shard`, `execution_shard` | the shard's number and its number among execution shards |
| `previous_init_addr_bits`, `last_init_addr_bits`, `previous_finalize_addr_bits`, `last_finalize_addr_bits` | the range of addresses whose global initialization and finalization the shard covers |
| `committed_value_digest`, `deferred_proofs_digest` | the guest's public output digest and deferred-proof digest, once committed |
| `exit_code` | the exit code on halt |
| `global_cumulative_sum` | the sum of the shard's cross-shard messages on the septic curve |

No register file or memory image is passed between shards. Registers are memory addresses 0 to 35. The last value of each address a shard touches leaves the shard as a message on the global bus, and the next shard that touches the address takes it from there (see [Memory Consistency Checking](./memory-checking.md)).

## Key constraints

- **Shard validity.** Each shard proof verifies against the program's verifying key.
- **Initial state.** The first shard starts at `pc_start` from the verifying key, and its global digest is added to the key's digest of the initial memory image.
- **Transitions.** Each shard's `start_pc` equals the previous shard's `next_pc`. Shard boundaries are sequential (`start_next_pc = start_pc + 4`, `next_next_pc = next_pc + 4`), so no pending branch target crosses them. Shard numbers increase by one, and the initialized and finalized address ranges of consecutive shards join.
- **Completion.** The last shard ends with `next_pc = 0` and exit code 0. The sum of all shards' global digests and the initial digest is the neutral digest, so every memory value handed from one shard to another was consumed exactly once.

The normalize programs check the conditions on single shards, the compose programs check the transitions, and the root checks completion (see [STARK Aggregation](./prover-architecture/stark-aggregation.md)).
