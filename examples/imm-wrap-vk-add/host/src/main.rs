use core::borrow::Borrow;

use p3_field::PrimeField32;
use sha2::{Digest, Sha256};
use zkm_sdk::{include_elf, utils, ProverClient, ZKMProof, ZKMStdin};
use zkm_stark::{air::PublicValues, Word};

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
    let proof = client.prove(&pk, stdin).compressed().run().unwrap();
    println!("generated proof");

    let mut public_values = proof.public_values.clone();
    let a_out = public_values.read::<u32>();
    let b_out = public_values.read::<u32>();
    let sum = public_values.read::<u32>();
    println!("{a_out} + {b_out} = {sum}");
    assert_eq!(sum, a + b);

    client.verify(&proof, &vk).expect("verification failed");

    // Also pull the digest the guest actually committed to out of the proof, and compare it
    // against an independently computed hash of the raw public values, using whichever
    // algorithm this guest build should have used. This checks the guest hasher itself directly,
    // in addition to the host-side verification path above.
    let ZKMProof::Compressed(compressed_proof) = &proof.proof else {
        panic!("expected a compressed proof");
    };
    let proof_public_values: &PublicValues<Word<_>, _> =
        compressed_proof.proof.public_values.as_slice().borrow();
    let committed_value_digest: Vec<u8> = proof_public_values
        .committed_value_digest
        .iter()
        .flat_map(|w| w.0.iter().map(|x| x.as_canonical_u32() as u8))
        .collect();

    let raw_public_values = proof.public_values.as_slice();
    let expected_digest: Vec<u8> = if imm_wrap_vk_mode {
        blake3::hash(raw_public_values).as_bytes().to_vec()
    } else {
        Sha256::digest(raw_public_values).to_vec()
    };

    assert_eq!(
        committed_value_digest, expected_digest,
        "committed public-values digest does not match {} of the raw public values",
        if imm_wrap_vk_mode { "BLAKE3" } else { "SHA256" }
    );
    println!(
        "committed public-values digest matches {} of the raw public values",
        if imm_wrap_vk_mode { "BLAKE3" } else { "SHA256" }
    );

    println!("successfully generated and verified proof for the program!")
}