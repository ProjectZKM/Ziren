# STARK to SNARK 
zkMIPS's STARK-to-SNARK conversion enables efficient on-chain verification by transforming STARK proofs into SNARK-compatible formats through a two-stage cryptographic transformation pipeline. This process reduces proof size​ while achieving constant verification time \\(O(1)\\) independent of circuit complexity.


## Field Adaptation and Circuit Shrinkage

This stage transforms proofs from STARK's native field (quartic  extension field over KoalaBear Prime) to BN254-friendly format through:
- ​Proof Compression:

  Reduces proof length via a recursive compressing method.

- Recursive Field Conversion:
  
  Transforms proofs from STARK's native field (quartic  extension field over KoalaBear Prime) to BN254-friendly format.

## SNARK Wrapping

This stage finalizes SNARK compatibility through:

- ​Circuit Specialization

  Generates Groth16-specific constraint system.
- ​Proof Packaging

  Encodes proofs with BN254 elliptic curve primitives.

- ​On-Chain Optimization

  Implements optimized on-chain pairing verification.

