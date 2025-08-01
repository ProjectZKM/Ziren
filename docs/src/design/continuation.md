# Continuation

Ziren implements an advanced continuation framework within its zkVM architecture, combining recursive proof composition with ​multi-shard execution capabilities. This design enables unbounded computational scalability with cryptographically verifiable state transitions while minimizing resource overhead. It has the following advantages:
- Scalability
​
  Shards avoid single proof size explosion for long computations.
- Parallelism

  Independent shard proving enables distributed proof generation.

- ​State Continuity

  Overall [memory consistency checking](../design/memory-checking.md) and consecutive program counter verifying ensures protocol-level execution integrity beyond individual shards.

## Session-Shard Structure

A program execution forms a ​Session, which is dynamically partitioned into atomic ​shards based on cycle consumption. Each shard operates as an independent local execution with its own proof/receipt, while maintaining global consistency through cryptographic state binding. 

**Key Constraints**
- Shard Validity

  Each shard's proof must be independently verifiable.
- Initial State Consistency

  First shard's start state must match verifier-specific program constraints (i.e., code integrity and entry conditions).

- Inter-Shard Transition

  Subsequent shards must begin at the previous shard's terminal state. 


## Proof Overflow

- Shard Execution Environment

  Shards operate with isolated execution contexts defined by:
  - ​Initial Memory Image: Compressed memory snapshots with Merkle root verification.
  - Register File State: Including starting PC value and memory image.

- Shard Proof

  Prove all instructions' execution in this shard, collecting all reading memory and writing memory records.

- Session Proof Aggregation

  Global session validity requires ​sequential consistency proof chaining:
  - Overall memory consistency checking.
  - Program counters consistency checking.
  - Combine shard proofs via folding scheme.

