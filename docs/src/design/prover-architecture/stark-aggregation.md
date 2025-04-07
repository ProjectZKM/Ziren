# STARK Aggregation

ZKM2's STARK aggregation system decomposes complex program proofs into parallelizable segment proofs and recursively compresses them into a single STARK proof. 

## Segment Proof Generation

ZKM2 processes execution trace proofs for segments through three key phases:
- ​Execution Segmentation​​

  Splits program execution (compiled ELF binaries) into fixed-size batches and maintains execution context continuity across segments.
- ​Trace Generation​​
  
  Converts each segment's execution into constrained polynomial traces and encodes register states, memory operations, and instruction flows.
- Segment ​Proof 
  
  Generates STARK proofs for each segment independently using FRI with Merkle-tree based polynomial commitments.

The proving pipeline coordinates multiple parallel proving units to process segments simultaneously, significantly reducing total proof generation time compared to linear processing.

## Recursive Aggregation

Recursive aggregations are used to recursively compress multiple segment proofs into one. The aggregation system processes verification artifacts through:

- ​Proof Normalization​​

  Converts segment proofs into recursive-friendly format.
- ​Context Bridging​​

  Maintains execution state continuity between segments.
- ​Batch Optimization​​

  Groups proofs for optimal parallel processing.

And the aggregation engine implements a multi-phase composition:
- Base Layer​​
  
  Processes raw segment proofs through initial verification circuits and generates first-layer aggregation certificates.
- ​Intermediate Layers​​
  
  Recursively combines certificates "2-to-1" using recursive-circuit. 
- ​Final Compression​​
  
  Produces single STARK proof through final composition step.


