# STARK to SNARK 
ZKM2's STARK-to-SNARK conversion enables efficient on-chain verification by transforming STARK proofs into SNARK-compatible formats through a two-phase cryptographic pipeline. This process reduces proof size​ while achieving constant verification time \\(O(1)\\) independent of circuit complexity.


## Field Shrinkage: Converting to SNARK-Friendly Field BN254

The `shrink` function converts STARK proofs into SNARK-compatible representations through:
- ​Proof Compression:

  Reduces proof length via a recursive composition method.

- Recursive Field Conversion:
  
  Transforms proofs from STARK's native field (quartic  extension field over KoalaBear Prime) to BN254-friendly format.



The `shrink` function converts the STARK aggregated proof into a field that is friendly for SNARKs. This process involves running a recursive program that “shrinks” the proof, making it more compact and easier to handle in SNARK systems.

The shrink phase reduces the size and complexity of the aggregated STARK proof by “compressing” it into a smaller representation in a different field. This field is more amenable for conversion into a SNARK format. The function uses a recursive runtime environment to run a custom designed circuit (the shrink program) that outputs a compact proof.

```rust
pub fn shrink(
    &self,
    reduced_proof: ZKMReduceProof<InnerSC>,  // Aggregated STARK proof
    opts: ZKMProverOpts,                     // Prover options with recursion config
) -> Result<ZKMReduceProof<InnerSC>, ZKMRecursionProverError> 
```

## SNARK Wrapping

The `wrap_bn254` function finalizes SNARK compatibility through:

- ​Circuit Specialization

  Generates Groth16-specific constraint system.
- ​Proof Packaging

  Encodes proofs with BN254 elliptic curve primitives.

- ​On-Chain Optimization

  Implements optimized on-chain pairing verification.



```rust
pub fn wrap_bn254(
    &self,
    compressed_proof: ZKMReduceProof<InnerSC>,  // Shrink-processed proof
    opts: ZKMProverOpts,
) -> Result<ZKMReduceProof<OuterSC>, ZKMRecursionProverError> 
```


To conclude, the system transforms aggregated STARK proofs through:
- Shrink Phase
  - Proof size reduction: Recursive reduces proof length.
  - Field isomorphism: From native quartic  extension field over KoalaBear Prime to BN254-friendly format.

- ​Wrap Phase
  - Groth16 circuit instantiation.
  - On-chain verification gas optimization.