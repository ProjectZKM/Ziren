# Memory Consistency Checking

[Offline memory checking](https://georgwiese.github.io/crypto-summaries/Concepts/Protocols/Offline-Memory-Checking) lets a prover show that a read/write memory was used correctly: every read returns the value most recently written to that address. Unlike online checking with Merkle paths, it checks nothing per access. Each access adds tuples to two multisets, and one equality check between the multisets at the end covers all accesses. Ziren uses it for registers and memory alike, within a shard through the lookup argument and across shards through a multiset hash on an elliptic curve.

## Read set and write set

The read set \\( RS \\) and write set \\( WS \\) are multisets of tuples \\( (a, v, c) \\): an address, a value and a timestamp.

- **Initialization.** \\( RS = WS = \emptyset \\). For every address \\( a_i \\) with initial value \\( v_i \\), add \\( (a_i, v_i, 0) \\) to \\( WS \\).
- **Access.** To access address \\( a \\) at time \\( c_{now} \\), take the last tuple \\( (a, v, c) \\) written for \\( a \\), add it to \\( RS \\), and add \\( (a, v', c_{now}) \\) to \\( WS \\). For a read \\( v' = v \\); for a write \\( v' \\) is the new value.
- **Post-processing.** For every address, add its last tuple in \\( WS \\) to \\( RS \\).

The memory was used correctly if:

1. the sets were initialized correctly;
2. at every access \\( c < c_{now} \\), so the timestamps of an address strictly increase;
3. a read adds the same value to \\( RS \\) and \\( WS \\);
4. after post-processing, \\( RS = WS \\).

Suppose the first incorrect read of address \\( a \\) returns \\( (a, v', c') \\) instead of the last written \\( (a, v, c) \\). All tuples in \\( WS \\) are distinct because timestamps strictly increase, and \\( (a, v', c') \\) was never written. So \\( RS \\) contains a tuple that \\( WS \\) does not contain, and no later step can remove it. Then \\( RS \neq WS \\).

## Within a shard

A shard's accesses are tuples `(shard, clk, addr, value)` on the `Memory` bus. The timestamp is the pair `(shard, clk)`.

- An access sends its previous tuple `(prev_shard, prev_clk, addr, prev_value)` (the read) and receives its new tuple (the write). It asserts that `(shard, clk)` is strictly larger than `(prev_shard, prev_clk)`. When the shards are equal, the difference `clk - prev_clk - 1` is split into a 16-bit and a 10-bit limb and both are range-checked, which proves `clk > prev_clk` because both clocks are below \\( 2^{26} \\). Otherwise the same check is applied to the shards.
- `MemoryLocal` has one row per address the shard touches. The row supplies the address's first tuple in the shard and consumes its last one.
- Registers are addresses 0 to 35. `MemoryBump` inserts a read of every touched register at `(shard, 0)`, so the check for every other register access compares clocks only (see [Memory](./chips/memory.md)).

The `Memory` bus balances when the sends equal the receives, which is condition 4 for the shard. The LogUp-GKR argument proves it together with all other buses (see [Lookup Arguments](./lookup-arguments.md)).

## Across shards

The first and last tuple of each address in a shard must also match the neighbouring shards. These tuples are *global* lookups: lookups whose two sides may lie in different shards.

- `MemoryLocal` *receives* the address's initial tuple and *sends* its final tuple, on the local `Memory` bus and again as global lookups.
- `MemoryGlobalInit` sends the initial value of each address outside the program image, at timestamp `(0, 0)`.
- `MemoryGlobalFinal` receives the final value of each touched address.
- `MemoryProgram` is a preprocessed table of the program image, part of the verifying key. Every shard includes it; its multiplicity is 1 on the image's rows in the first shard and 0 in every other shard, so the first shard sends the initial value of every image word.

The same mechanism carries syscalls from an execution shard to the precompile shard that proves them (`SyscallCore` and `SyscallPrecompile`).

## Global challenge

Within a shard, LogUp balances a bus with challenges \\( (\alpha, \beta) \\) drawn after the shard's trace is committed. A global lookup cannot be balanced that way, since its other side is in another shard, proved with other challenges. Ziren instead proves every shard's global lookups under one challenge pair \\( (\alpha_g, \beta_g) \\) for the whole execution, drawn only after every shard has committed the rows that carry global lookups.

1. **Global round.** The chips with global lookups (`MemoryLocal`, `MemoryGlobalInit`, `MemoryGlobalFinal`, `SyscallCore`, `SyscallPrecompile` and `MemoryProgram`) are committed in a round of their own, between the preprocessed round and the main round.
2. **Hash chain.** The chain starts at \\( g_0 \\), sampled from a challenger that has observed the verifying key. Shard \\( i \\) extends it, \\( g_i = H(g_{i-1}, C_i, \mathit{shape}_i) \\), with its global round's commitment \\( C_i \\) and the name and height of each chip in the round; a shard without a global round extends it with a fixed tag. The chain's end is \\( g^\star \\).
3. **Challenge.** \\( (\alpha_g, \beta_g) \\) is derived from \\( g^\star \\) alone. \\( \beta_g \\) is the eq table of a seed of dimension \\( d \\), the log of the widest global message (its values plus the lookup kind), so a message is fingerprinted alike in every shard.
4. **Shard proof.** Each shard's transcript observes \\( g^\star \\) first. Its LogUp-GKR circuit evaluates the shard's global lookups under \\( (\alpha_g, \beta_g) \\) and all other lookups under the shard's own \\( (\alpha, \beta) \\), and outputs the sum \\( S_i \\) of the shard's global fractions; the local fractions must still sum to zero.
5. **Recursion.** The first shard's leaf checks that its chain starts at \\( g_0 \\) of the verifying key. Each leaf computes one chain step over its shard's global round and publishes the chain before and after it, \\( g^\star \\) and \\( S_i \\). Compress nodes check that their children's chains meet and agree on \\( g^\star \\), and add the sums. The root checks that the chain ends at \\( g^\star \\) and that \\( \sum_i S_i = 0 \\).

A matching send and receive give opposite fractions and cancel. Because \\( g^\star \\) binds every global row of every shard before \\( (\alpha_g, \beta_g) \\) is drawn, an unbalanced set of global lookups sums to zero only with probability about \\( (d + 1) N_g / |\mathbb{F}_{p^4}| \\), where \\( N_g \\) is the number of global lookups in the execution. This requires \\( N_g < p \\), so that the count of one message cannot wrap around.

The price is order: every shard must commit its global round before any shard is proved. The prover runs a bind pass that executes the program, commits each shard's global round and builds the chain, and then a proving pass under \\( (\alpha_g, \beta_g) \\).
