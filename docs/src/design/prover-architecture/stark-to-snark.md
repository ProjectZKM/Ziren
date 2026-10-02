# STARK to SNARK

A compressed proof is a KoalaBear STARK. Verifying it on a blockchain would cost too much, so Ziren verifies it inside a SNARK over BN254. There are two recursion steps before the SNARK and then the SNARK itself.

## 1. Shrink

`ZKMProver::shrink(reduced_proof, opts)` runs the *shrink* program. The program verifies the compressed proof, including the Merkle proof that its verifying key is in the recursion key set, and is proved with the recursion machine (`ShrinkAir`) at a fixed shape. The compressed proof's shape depends on the execution; the shrink proof's does not. This gives the next step a single input shape. The shrink proof still uses the inner configuration: KoalaBear, Poseidon2 over KoalaBear and jagged WHIR.

## 2. Wrap

`ZKMProver::wrap_bn254(shrink_proof, opts)` runs the *wrap* program, which verifies the shrink proof. The wrap program is proved with a different configuration (`OuterSC` in `crates/recursion/core/src/stark/config.rs`), chosen to be cheap to verify in a BN254 circuit:

- the field is still KoalaBear with its degree-4 extension, but Merkle trees and the transcript use Poseidon2 over the BN254 scalar field (width 3). The transcript is a `MultiField32Challenger`, which packs KoalaBear elements into BN254 elements;
- the dense polynomial commitment under the jagged layer is BaseFold at rate \\( 2^{-3} \\), with 94 queries and 26 bits of query grinding (`ZIREN_WRAP_QUERY_GRINDING_BITS`);
- the wrap machine (`WrapAir`) allows constraints of degree 9, so its Poseidon2 chip uses the degree-9 column layout with fewer intermediate columns than the degree-3 layout of the compress and shrink machines.

## 3. SNARK

The wrap proof is verified by a gnark circuit. `build_outer_circuit` in `crates/prover/src/build.rs` compiles the wrap verifier into constraints over BN254, and the circuit is proved with one of:

- `wrap_groth16_bn254`: Groth16, the smallest proof and cheapest on-chain verification;
- `wrap_plonk_bn254`: PLONK, with a universal setup;
- `wrap_dvsnark_bn254`: a designated-verifier SNARK.

The circuit has three public inputs:

| Input | Meaning |
|---|---|
| `vkey_hash` | the digest of the guest program's verifying key (`zkm_vk_digest`) |
| `committed_values_digest` | the digest of the guest's public outputs (SHA-256; BLAKE3 when the guest is built with the `imm-wrap-vk` feature), as 32 bytes packed into one BN254 element |
| `vk_root` | the root of the recursion verifying-key set |

The circuit also pins the wrap verifying key: in the standard build it asserts the wrap key's preprocessed commitment and `pc_start` against the values the circuit was built from, so a change to the recursion programs requires a new circuit and setup. The build with `ZKM_IMM_WRAP_VK` instead folds the wrap key into `vkey_hash` with Poseidon2, so the circuit does not change when the wrap key does.

A verifier of the SNARK proof takes the program's `vkey_hash` and the public values, recomputes `committed_values_digest` from the public values, and checks the proof against those inputs and the expected `vk_root`.
