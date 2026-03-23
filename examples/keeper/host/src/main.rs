mod payload;

use std::env;
use std::fs::File;
use std::io::Read;
use std::time::Instant;
use zkm_sdk::{utils, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/keeper.elf"));

fn load_payload(args: &[String]) -> Vec<u8> {
    let (mut rpc, mut block, mut file_path) = (None, None, None);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rpc" => {
                rpc = Some(args.get(i + 1).expect("--rpc requires a value").clone());
                i += 2;
            }
            "--block" => {
                block = Some(args.get(i + 1).expect("--block requires a value").clone());
                i += 2;
            }
            _ => {
                file_path = Some(args[i].clone());
                i += 1;
            }
        }
    }

    if let Some(rpc_url) = rpc {
        let block_arg = block.as_deref().unwrap_or("latest");
        payload::fetch_payload(&rpc_url, block_arg).expect("failed to fetch payload from RPC")
    } else if let Some(path) = file_path {
        println!("Loading payload from file: {path}");
        let mut file = File::open(&path).unwrap_or_else(|e| panic!("unable to open {path}: {e}"));
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .unwrap_or_else(|e| panic!("unable to read {path}: {e}"));
        data
    } else {
        eprintln!(
            "Usage: {} [--rpc <url> [--block <block>]] [<payload_file>]",
            env::args().next().unwrap()
        );
        std::process::exit(1);
    }
}

fn prove_keeper(data: Vec<u8>) {
    let mut stdin = ZKMStdin::new();
    stdin.write(&data);

    let client = ProverClient::new();

    let start = Instant::now();
    let (_, report) = client.execute(ELF, &stdin).run().unwrap();
    let duration = start.elapsed();

    println!(
        "executed program with {} cycles, {} seconds",
        report.total_instruction_count(),
        duration.as_secs_f64()
    );

    let (pk, vk) = client.setup(ELF);
    let proof = client.prove(&pk, stdin).compressed().run().unwrap();

    println!("generated proof");
    if let Err(err) = client.verify(&proof, &vk) {
        panic!("verification error: {err:?}");
    }

    proof
        .save("proof-with-pis.bin")
        .expect("saving proof failed");
    let deserialized_proof =
        ZKMProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    client
        .verify(&deserialized_proof, &vk)
        .expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}

fn main() {
    dotenv::dotenv().ok();
    utils::setup_logger();

    let args: Vec<String> = env::args().skip(1).collect();
    let data = load_payload(&args);
    prove_keeper(data);
}
