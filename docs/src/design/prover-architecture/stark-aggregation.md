# STARK Aggregation

Ziren's STARK aggregation system decomposes complex program proofs into parallelizable shard proofs and recursively compresses them into a single STARK proof. 

## Shard Proof Generation

Ziren processes execution trace proofs for shards through three key phases:
- ​Execution Shard

  Splits program execution (compiled ELF binaries) into fixed-size batches and maintains execution context continuity across shards.
- ​Trace Generation​​
  
  Converts each shard's execution into constrained polynomial traces and encodes register states, memory operations, and instruction flows.
- Shard ​Proof 
  
  Generates STARK proofs for each shard independently using FRI with Merkle tree-based polynomial commitments.

The proving pipeline coordinates multiple parallel proving units to process shards simultaneously, significantly reducing total proof generation time compared to linear processing.

## Recursive Aggregation

Recursive aggregations are used to recursively compress multiple shard proofs into one. The aggregation system processes verification artifacts through:

- ​Proof Normalization​​

  Converts shard proofs into recursive-friendly format.
- ​Context Bridging​​

  Maintains execution state continuity between shards.
- ​Batch Optimization​​

  Groups proofs for optimal parallel processing.

The aggregation engine implements a multi-phase composition:
- Base Layer​​
  
  Processes raw shard proofs through initial verification circuits and generates first-layer aggregation certificates.
- ​Intermediate Layers​​
  
  Recursively combines certificates "2-to-1" using recursive-circuit. 
- ​Final Compression​​
  
  Produces single STARK proof through final composition step.


