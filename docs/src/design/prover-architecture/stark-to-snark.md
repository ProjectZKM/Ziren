# STARK to SNARK 

Ziren’s proof pipeline does not stop at scalable STARK aggregation. To enable **fast, cost-efficient on-chain verification**, Ziren recursively transforms large STARK proofs into succinct SNARKs (Plonk or Groth16), achieving **O(1) verification time** independent of the original program’s size or complexity.
## 1. Field Adaptation & Circuit Shrinkage

### **Purpose**

The core challenge in going from STARK to SNARK lies in **field compatibility**: STARKs natively operate over a large extension field (quartic over KoalaBear Prime), while efficient SNARKs (e.g., Plonk, Groth16) require proofs to be expressed over the BN254 curve field.

Ziren addresses this with a **two-phase cryptographic transformation**:

### a. **Proof Compression**

- **What it does**: Recursively compresses the (potentially massive) aggregated STARK proof into a much shorter proof, maintaining all necessary soundness and context.
- **How**: The compression step leverages FRI-based recursion and context-aware aggregation circuits.
- **Key function**:
    - `ZKMProver::shrink(reduced_proof, opts)`
        - Internally creates a new aggregation circuit (the “shrink” circuit), which operates over a compressed field representation.

### b. **Recursive Field Conversion**

- **What it does**: Transforms the compressed proof from the KoalaBear quartic extension field to the SNARK-friendly BN254 field.
- **How**: Wraps the shrunken STARK proof inside a “wrapping” circuit specifically designed to fit within the constraints and arithmetic of BN254.
- **Key function**:
    - `ZKMProver::wrap_bn254(shrinked_proof, opts)`
        - Internally creates and executes the wrap circuit, outputting a proof whose public inputs and commitments are fully compatible with SNARKs (Plonk/Groth16).

**Engineering Insight**

- This two-stage transformation ensures that the final proof is not only succinct, but also verifiable on any EVM-compatible chain or zero-knowledge SNARK circuit.

## 2. SNARK Wrapping

After adapting the proof to the BN254 field, Ziren applies a final **SNARK wrapping** step, producing a Groth16 or Plonk proof that is maximally efficient for blockchain verification.

### a. **Circuit Specialization**

- **What it does**: Specializes the constraint system for the target SNARK protocol, mapping the BN254-adapted proof to a form Groth16/Plonk can consume.
- **How**: Generates a custom constraint system and witness for the chosen SNARK, reflecting the final state and commitments from the STARK pipeline.
- **Key function**:
    - `ZKMProver::wrap_plonk_bn254(proof, build_dir)`
    - `ZKMProver::wrap_groth16_bn254(proof, build_dir)`
        - These invoke circuit synthesis, key generation, and proof construction for the chosen SNARK system.

### b. **Proof Packaging**

- **What it does**: Encodes and serializes the proof using BN254 elliptic curve primitives, including public input encoding and elliptic curve commitments.
- **How**: Utilizes efficient encoding routines and cryptographic libraries for serialization and EVM compatibility.
- **Key function**:
    - Still within the above `wrap_*_bn254` functions, which return a ready-to-verify SNARK proof object.

### c. **On-Chain Optimization**

- **What it does**: Ensures the final proof is optimized for low-cost, constant-time verification on EVM or other smart contract platforms.
- **How**: Outputs are structured for native use in Solidity and similar VMs, supporting direct on-chain pairing checks (using BN254 curve operations).
- **Key output**:
    - The returned `PlonkBn254Proof` or `Groth16Bn254Proof` can be immediately used for on-chain verification via Ethereum precompiles or standard verification contracts.

## **Source Mapping Table**

| Pipeline Stage | Core Implementation Functions/Structs |
| --- | --- |
| Proof Compression | `shrink` |
| Field Conversion/Wrap | `wrap_bn254` |
| SNARK Circuit Specialize | `wrap_plonk_bn254`, `wrap_groth16_bn254` |
| Proof Packaging | `PlonkBn254Proof`, `Groth16Bn254Proof` |
| On-Chain Verification | Output proof objects for EVM/BN254 verification |