# Trusted Setup

The zk-SNARK protocols often require a trusted setup to generate a CRS (Common Reference String), proving key and verification key.

Groth16 requires sampling five random field elements to generate the proving and verifying keys: τ, α, β, γ, and σ. These are considered toxic waste and should be discarded and completely forgotten once the keys have been generated, as they could be used to create fake proofs that the verifier would accept. The main solution to this deployment issue is to run the setup through an MPC (multi-party computation).

## Example

The generated proving key (pk), verifying key (vk), and verifier contract will be stored at the path indicated by `build_dir`.

```rust
use zkm2_recursion_gnark_ffi::groth16_bn254::Groth16Bn254Prover

Groth16Bn254Prover::build(constraints, witness, build_dir)
```

For more details, please refer to document [TRUSTED_SETUP](https://github.com/zkMIPS/zkm2/blob/dev/init/crates/prover/TRUSTED_SETUP.md).
