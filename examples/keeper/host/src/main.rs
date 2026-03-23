mod payload;

use std::env;
use std::fs::File;
use std::io::Read;
use std::time::Instant;
use zkm_sdk::{utils, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/keeper.elf"));

struct Args {
    rpc: Option<String>,
    block: Option<String>,
    file_path: Option<String>,
    save: bool,
    follow: bool,
    poll_interval_secs: u64,
}

fn parse_args(args: &[String]) -> Args {
    let mut parsed = Args {
        rpc: None,
        block: None,
        file_path: None,
        save: false,
        follow: false,
        poll_interval_secs: 5,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rpc" => {
                parsed.rpc = Some(args.get(i + 1).expect("--rpc requires a value").clone());
                i += 2;
            }
            "--block" => {
                parsed.block = Some(args.get(i + 1).expect("--block requires a value").clone());
                i += 2;
            }
            "--save" => {
                parsed.save = true;
                i += 1;
            }
            "--follow" => {
                parsed.follow = true;
                i += 1;
            }
            "--poll-interval" => {
                let val = args.get(i + 1).expect("--poll-interval requires a value");
                parsed.poll_interval_secs = val
                    .trim_end_matches('s')
                    .parse()
                    .expect("--poll-interval must be a number (in seconds)");
                i += 2;
            }
            _ => {
                parsed.file_path = Some(args[i].clone());
                i += 1;
            }
        }
    }
    parsed
}

fn fetch_one(rpc_url: &str, block_arg: &str, save: bool) -> Vec<u8> {
    let (_block_num, data) =
        payload::fetch_payload(rpc_url, block_arg, save).expect("failed to fetch payload from RPC");
    data
}

fn load_from_file(path: &str) -> Vec<u8> {
    println!("Loading payload from file: {path}");
    let mut file = File::open(path).unwrap_or_else(|e| panic!("unable to open {path}: {e}"));
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .unwrap_or_else(|e| panic!("unable to read {path}: {e}"));
    data
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

fn print_usage() -> ! {
    eprintln!(
        "Usage: {} [options] [<payload_file>]\n\
         \n\
         Options:\n\
         \x20 --rpc <url>              Ethereum JSON-RPC endpoint\n\
         \x20 --block <block>          Block number (hex/decimal) or \"latest\" (default: latest)\n\
         \x20 --save                   Save payload to file only, skip proving\n\
         \x20 --follow                 Continuously process new blocks\n\
         \x20 --poll-interval <secs>   Poll interval in seconds for --follow (default: 5)",
        env::args().next().unwrap()
    );
    std::process::exit(1);
}

fn run_follow(rpc_url: &str, start_block: &str, save_only: bool, poll_interval: u64) {
    let mut next_block = if start_block.eq_ignore_ascii_case("latest") {
        payload::latest_block_number(rpc_url).expect("failed to get latest block number")
    } else if start_block.starts_with("0x") || start_block.starts_with("0X") {
        u64::from_str_radix(start_block.trim_start_matches("0x").trim_start_matches("0X"), 16)
            .expect("invalid hex block number")
    } else {
        start_block.parse::<u64>().expect("invalid block number")
    };

    println!("Follow mode: starting from block 0x{next_block:x}, poll interval {poll_interval}s");

    loop {
        let latest =
            payload::latest_block_number(rpc_url).expect("failed to get latest block number");

        if next_block > latest {
            std::thread::sleep(std::time::Duration::from_secs(poll_interval));
            continue;
        }

        while next_block <= latest {
            let block_tag = format!("0x{next_block:x}");
            println!("\n=== Processing block {block_tag} ===");

            let data = fetch_one(rpc_url, &block_tag, save_only || true);

            if !save_only {
                prove_keeper(data);
            }

            next_block += 1;
        }
    }
}

fn main() {
    dotenv::dotenv().ok();
    utils::setup_logger();

    let args: Vec<String> = env::args().skip(1).collect();
    let args = parse_args(&args);

    if args.follow {
        let rpc_url = args.rpc.as_deref().unwrap_or_else(|| {
            eprintln!("--follow requires --rpc");
            std::process::exit(1);
        });
        let block_arg = args.block.as_deref().unwrap_or("latest");
        run_follow(rpc_url, block_arg, args.save, args.poll_interval_secs);
        return;
    }

    if let Some(rpc_url) = &args.rpc {
        let block_arg = args.block.as_deref().unwrap_or("latest");
        let data = fetch_one(rpc_url, block_arg, args.save);
        if args.save {
            println!("Payload saved, skipping prove.");
            return;
        }
        prove_keeper(data);
    } else if let Some(path) = &args.file_path {
        let data = load_from_file(path);
        prove_keeper(data);
    } else {
        print_usage();
    }
}
