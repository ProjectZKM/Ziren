# Proof Composition

## What is a receipt?

A receipt gives the results of your program along with proof that they were produced honestly.

## What is Proof Composition

You can verify other receipts in the guest use `zkm_zkvm::lib::verify::verify_zkm_proof()`

## Example: [Aggregation](https://github.com/ProjectZKM/Ziren/tree/main/examples/aggregation)

### Host

```rust
//! A simple example showing how to aggregate proofs of multiple programs with ZKM.

use zkm_sdk::{
    include_elf, HashableKey, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin,
    ZKMVerifyingKey,
};

/// A program that aggregates the proofs of the simple program.
const AGGREGATION_ELF: &[u8] = include_elf!("aggregation");

/// A program that just runs a simple computation.
const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci");

/// An input to the aggregation program.
///
/// Consists of a proof and a verification key.
struct AggregationInput {
    pub proof: ZKMProofWithPublicValues,
    pub vk: ZKMVerifyingKey,
}

fn main() {
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (aggregation_pk, _) = client.setup(AGGREGATION_ELF);
    let (fibonacci_pk, fibonacci_vk) = client.setup(FIBONACCI_ELF);

    // Generate the fibonacci proofs.
    let proof_1 = tracing::info_span!("generate fibonacci proof n=10").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&10);
        client.prove(&fibonacci_pk, stdin).compressed().run().expect("proving failed")
    });
    let proof_2 = tracing::info_span!("generate fibonacci proof n=20").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&20);
        client.prove(&fibonacci_pk, stdin).compressed().run().expect("proving failed")
    });
    let proof_3 = tracing::info_span!("generate fibonacci proof n=30").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&30);
        client.prove(&fibonacci_pk, stdin).compressed().run().expect("proving failed")
    });

    // Setup the inputs to the aggregation program.
    let input_1 = AggregationInput { proof: proof_1, vk: fibonacci_vk.clone() };
    let input_2 = AggregationInput { proof: proof_2, vk: fibonacci_vk.clone() };
    let input_3 = AggregationInput { proof: proof_3, vk: fibonacci_vk.clone() };
    let inputs = vec![input_1, input_2, input_3];

    // Aggregate the proofs.
    tracing::info_span!("aggregate the proofs").in_scope(|| {
        let mut stdin = ZKMStdin::new();

        // Write the verification keys.
        let vkeys = inputs.iter().map(|input| input.vk.hash_u32()).collect::<Vec<_>>();
        stdin.write::<Vec<[u32; 8]>>(&vkeys);

        // Write the public values.
        let public_values =
            inputs.iter().map(|input| input.proof.public_values.to_vec()).collect::<Vec<_>>();
        stdin.write::<Vec<Vec<u8>>>(&public_values);

        // Write the proofs.
        //
        // Note: this data will not actually be read by the aggregation program, instead it will be
        // witnessed by the prover during the recursive aggregation process inside Ziren itself.
        for input in inputs {
            let ZKMProof::Compressed(proof) = input.proof.proof else { panic!() };
            stdin.write_proof(*proof, input.vk.vk);
        }

        // Generate the plonk bn254 proof.
        client.prove(&aggregation_pk, stdin).plonk().run().expect("proving failed");
    });
}
```

### Guest

```rust
//! A simple program that aggregates the proofs of multiple programs proven with the zkVM.

#![no_main]
zkm_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};

pub fn main() {
    // Read the verification keys.
    let vkeys = zkm_zkvm::io::read::<Vec<[u32; 8]>>();

    // Read the public values.
    let public_values = zkm_zkvm::io::read::<Vec<Vec<u8>>>();

    // Verify the proofs.
    assert_eq!(vkeys.len(), public_values.len());
    for i in 0..vkeys.len() {
        let vkey = &vkeys[i];
        let public_values = &public_values[i];
        let public_values_digest = Sha256::digest(public_values);
        zkm_zkvm::lib::verify::verify_zkm_proof(vkey, &public_values_digest.into());
    }

    // TODO: Do something interesting with the proofs here.
    //
    // For example, commit to the verified proofs in a merkle tree. For now, we'll just commit to
    // all the (vkey, input) pairs.
    let commitment = commit_proof_pairs(&vkeys, &public_values);
    zkm_zkvm::io::commit_slice(&commitment);
}

pub fn words_to_bytes_le(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let word_bytes = words[i].to_le_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }
    bytes
}

/// Encode a list of vkeys and committed values into a single byte array. In the future this could
/// be a merkle tree or some other commitment scheme.
///
/// ( vkeys.len() || vkeys || committed_values[0].len as u32 || committed_values[0] || ... )
pub fn commit_proof_pairs(vkeys: &[[u32; 8]], committed_values: &[Vec<u8>]) -> Vec<u8> {
    assert_eq!(vkeys.len(), committed_values.len());
    let mut res = Vec::with_capacity(
        4 + vkeys.len() * 32
            + committed_values.len() * 4
            + committed_values.iter().map(|vals| vals.len()).sum::<usize>(),
    );

    // Note we use big endian because abi.encodePacked in solidity does also
    res.extend_from_slice(&(vkeys.len() as u32).to_be_bytes());
    for vkey in vkeys.iter() {
        res.extend_from_slice(&words_to_bytes_le(vkey));
    }
    for vals in committed_values.iter() {
        res.extend_from_slice(&(vals.len() as u32).to_be_bytes());
        res.extend_from_slice(vals);
    }

    res
}
```
