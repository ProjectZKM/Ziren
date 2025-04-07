# Continuation

ZKM2 implements an advanced continuation framework within its zkVM architecture, combining recursive proof composition with ​multi-segment execution capabilities. This design enables unbounded computational scalability with cryptographically verifiable state transitions while minimizing resource overhead. It has the following advantage:
- Scalability
​
  Segmentation avoids single proof size explosion for long computations.
- Parallelism

  Independent segment proving enables distributed proof generation.

- ​State Continuity

  Overall [memory consistency checking](../offline_memory_consistency_checking.md) and consective program counter verifying ensures protocol-level execution integrity beyond individual segments.

## Session-Segment Structure

A program execution forms a ​Session, which is dynamically partitioned into atomic ​segments based on cycle consumption. Each segment operates as an independent local execution with its own proof/receipt, while maintaining global consistency through cryptographic state binding. 

**Key Constraints**
- Segment Validity

  Each segment's proof must be independently verifiable.
- Initial State Consistency

  First segment's start state must match verifier-specific program constraints (i.e., code integrity and entry conditions).

- Inter-Segment Transition

  Subsequent segments must begin at the previous segment's terminal state. 


## Proof Overflow

- Segment Execution Environment

  Segments operate with isolated execution contexts defined by:
  - ​Initial Memory Image: Compressed memory snapshots with Merkle root verification.
  - Register File State: Including starting PC value and memory image.

- Segment Proof

  Prove all instructions' execution in this segment, collecting all reading memory and writing memory records.

- Session Proof Aggregation

  Global session validity requires ​sequential consistency proof chaining:
  - Overall memory consistency checking.
  - Program counters consistency checking.
  - Combine segment proofs via folding scheme.

