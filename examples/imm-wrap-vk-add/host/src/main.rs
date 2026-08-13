use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use zkm_sdk::{include_elf, utils, ProverClient, ZKMProof, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
///
/// Build it in BLAKE3 mode with `ZKM_IMM_WRAP_VK=1 cargo run --release`, or in the default
/// SHA256 mode by leaving `ZKM_IMM_WRAP_VK` unset.
const ELF: &[u8] = include_elf!("imm-wrap-vk-add");

fn main() {
    utils::setup_logger();

    let imm_wrap_vk_mode = std::env::var("ZKM_IMM_WRAP_VK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    println!(
        "guest built in {} mode",
        if imm_wrap_vk_mode { "imm-wrap-vk (BLAKE3)" } else { "default (SHA256)" }
    );

    let a = 5u32;
    let b = 7u32;

    let mut stdin = ZKMStdin::new();
    stdin.write(&a);
    stdin.write(&b);

    let client = ProverClient::new();

    let (_, report) = client.execute(ELF, &stdin).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    let (pk, vk) = client.setup(ELF);
    let proof = client.prove(&pk, stdin).groth16().run().unwrap();
    println!("generated proof");

    let mut public_values = proof.public_values.clone();
    let a_out = public_values.read::<u32>();
    let b_out = public_values.read::<u32>();
    let sum = public_values.read::<u32>();
    println!("{a_out} + {b_out} = {sum}");
    assert_eq!(sum, a + b);

    client.verify(&proof, &vk).expect("verification failed");

    // Also pull the committed-values digest out of the Groth16 proof's own public inputs, and
    // compare it against an independently computed hash of the raw public values, using whichever
    // algorithm this guest build should have used. This checks the guest hasher itself directly,
    // in addition to the host-side verification path above (rather than reusing
    // `ZKMPublicValues::hash_bn254()`, which is the same function under test).
    let ZKMProof::Groth16(groth16_proof) = &proof.proof else {
        panic!("expected a groth16 proof");
    };
    let committed_value_digest = &groth16_proof.public_inputs[1];

    let raw_public_values = proof.public_values.as_slice();
    let mut hash: [u8; 32] = if imm_wrap_vk_mode {
        blake3::hash(raw_public_values).into()
    } else {
        Sha256::digest(raw_public_values).into()
    };
    // Mask the top 3 bits, matching the BN254 scalar field encoding used for Groth16 public
    // inputs (same masking `ZKMPublicValues::hash_bn254()` applies internally).
    hash[0] &= 0b00011111;
    let expected_digest = BigUint::from_bytes_be(&hash).to_string();

    assert_eq!(
        *committed_value_digest, expected_digest,
        "committed public-values digest does not match {} of the raw public values",
        if imm_wrap_vk_mode { "BLAKE3" } else { "SHA256" }
    );
    println!(
        "committed public-values digest matches {} of the raw public values",
        if imm_wrap_vk_mode { "BLAKE3" } else { "SHA256" }
    );

    println!("successfully generated and verified proof for the program!")
}