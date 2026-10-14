//! Copy into examples/fibonacci/host/bin and add a Cargo bin entry plus bincode.
//! Run with ZKM_PROVER=cuda and VERIFY_VK=true on both client and server.
use std::{fs, time::Instant};
use zkm_sdk::{include_elf, ProverClient, ZKMProof, ZKMStdin};

fn main() {
    assert_eq!(std::env::var("VERIFY_VK").as_deref(), Ok("true"));
    let client = ProverClient::new();
    assert!(client.prover.zkm_prover().vk_verification);
    let elf = include_elf!("fibonacci");
    let (pk, vk) = client.setup(elf);
    let mut stdin = ZKMStdin::new();
    stdin.write(&500u32);
    let proof = client.prove(&pk, stdin).compressed().run().unwrap();
    client.verify(&proof, &vk).unwrap(); // Warm the native verifier.
    let ZKMProof::Compressed(reduce) = &proof.proof else { panic!("expected compressed proof") };
    let raw = bincode::serialize(reduce).unwrap();
    fs::write("compressed-reduce-proof.bin", &raw).unwrap();
    proof.save("compressed-proof-with-pis.bin").unwrap();
    let mut times = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        client.verify(&proof, &vk).unwrap();
        times.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    println!("{{\"guest\":\"fibonacci\",\"stdin_u32\":500,\"verify_vk\":true,\"raw_reduce_bytes\":{},\"stark_wire_bytes\":{},\"sdk_container_bytes\":{},\"verify_ms\":{:?}}}",
        raw.len(), proof.bytes().unwrap().len(), bincode::serialize(&proof).unwrap().len(), times);
}
