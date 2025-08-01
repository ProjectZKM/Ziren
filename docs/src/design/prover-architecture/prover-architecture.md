# Prover Architecture

Ziren zkVM’s prover is built on a scalable, modular, and highly parallelizable architecture that reimagines end-to-end zero-knowledge proof generation for complex programs. The system leverages four tightly-coupled components—**Runtime Executor**, **Machine Prover**, **STARK Aggregation**, and **STARK-to-SNARK Adapter**—to deliver high-throughput proving, succinct on-chain verification, and exceptional developer flexibility.

### 1. Runtime Executor

At the heart of the Ziren prover is the **Runtime Executor**, which orchestrates program execution, manages state transitions, and partitions computation into shards for efficient parallel processing. The workflow consists of:

- **Instruction Stream Partitioning**:
    
    The executor splits compiled program binaries (ELF files) into fixed-size execution shards. Each shard represents a self-contained computation slice, enabling pipelined, parallelized execution.
    
- **Event-Driven Constraint Generation**:
    
    As each instruction executes, the runtime dynamically emits algebraic constraints capturing the semantics of register states, memory operations, control flow, and system events.
    
- **Multiset Hash State Transitions**:
    
    Memory consistency and integrity are preserved across shards through cryptographically secure multiset hashing, ensuring tamper-proof execution continuity.
    
- **Checkpoint & Trace Management**:
    
    The executor periodically checkpoints the global execution state, allowing for robust recovery, trace replay, and efficient shard-wise proof generation.
    

This parallelism and modularity provide a robust foundation for high-performance zero-knowledge proof workflows.

### 2. Machine Prover

Once shards and execution traces are produced, the **Machine Prover** takes over, generating STARK proofs for each shard in isolation. This stage features:

- **KoalaBear Field Optimization**:
    
    All arithmetic and constraint evaluations are performed in a custom, highly efficient field (KoalaBear), minimizing circuit complexity and maximizing throughput.
    
- **Poseidon2-based Merkle Matrix Commitment**:
    
    The system commits to all polynomial traces using a Merkle Matrix Commitment Scheme (MMCS), leveraging the Poseidon2 hash for both speed and post-quantum security.
    
- **FRI-based Low-Degree Testing**:
    
    Soundness is guaranteed by advanced Fast Reed-Solomon IOPP (FRI) protocols, providing strong assurance of trace integrity with compact commitments.
    
- **Concurrent Proof Generation**:
    
    Proving tasks for all shards are executed in parallel, fully utilizing available CPU cores and significantly reducing end-to-end proving time compared to sequential approaches.
    

Together, these components deliver high-speed, secure, and scalable zero-knowledge proof generation for arbitrary program logic.

### 3. STARK Aggregation

Following independent proof generation, **STARK Aggregation** recursively compresses multiple shard proofs into a single, compact STARK proof. The aggregation process involves:

- **Proof Normalization & Context Bridging**:
    
    Shard proofs are converted into a uniform, recursion-friendly format, with mechanisms to preserve and bridge execution context across shard boundaries.
    
- **Recursive Composition Engine**:
    
    The aggregation system recursively combines proofs in multiple layers. The base layer ingests raw shard proofs, performing initial verification and aggregation. Intermediate layers employ “2-to-1” recursive circuits to further compress certificates, and the final composition step yields a single, globally-valid STARK proof.
    
- **Batch Optimization**:
    
    Proofs are batched for optimal parallel processing, minimizing aggregation time and maximizing throughput for large-scale computations.
    

This multi-phase approach ensures that even highly parallel and fragmented computations can be succinctly and efficiently verified as a single cryptographic object.

### 4. STARK-to-SNARK Adapter

To enable efficient and universally compatible on-chain verification, Ziren incorporates a **STARK-to-SNARK Adapter** that transforms the final STARK proof into a Groth16-based SNARK. This pipeline includes:

- **Field Adaptation & Circuit Shrinkage**:
    
    Aggregated STARK proofs, originally constructed over the KoalaBear field, are recursively transformed into the BN254-friendly field suitable for Groth16. The proof is compressed and converted in a way that preserves validity while optimizing for size.
    
- **SNARK Wrapping**:
    
    The SNARK wrapping process generates a Groth16-compatible circuit, packages the transformed proof using BN254 elliptic curve primitives, and produces both the final proof and its verification key.
    
- **On-Chain Optimization**:
    
    The resulting Groth16 proof is succinct, supports constant-time verification (O(1)), and can be directly verified by Ethereum and other EVM-based blockchains using standard pairing checks.
    

This dual-proof pipeline enables Ziren to combine the scalability and transparency of STARKs with the succinctness and universality of SNARKs, making advanced cryptographic verifiability available for all blockchain applications.