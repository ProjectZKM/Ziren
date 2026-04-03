mod payload;

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Instant;
use zkm_sdk::{utils, ExecutionReport, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/keeper.elf"));

struct Args {
    rpc: Option<String>,
    block: Option<String>,
    file_path: Option<String>,
    save: bool,
    execute_only: bool,
    follow: bool,
    poll_interval_secs: u64,
    report_path: Option<PathBuf>,
}

fn parse_args(args: &[String]) -> Args {
    let mut parsed = Args {
        rpc: None,
        block: None,
        file_path: None,
        save: false,
        execute_only: false,
        follow: false,
        poll_interval_secs: 5,
        report_path: None,
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
            "--execute" => {
                parsed.execute_only = true;
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
            "--report-path" => {
                parsed.report_path = Some(PathBuf::from(
                    args.get(i + 1).expect("--report-path requires a value").clone(),
                ));
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

fn fetch_one(rpc_url: &str, block_arg: &str, save: bool) -> (String, Vec<u8>) {
    let (block_num, data) =
        payload::fetch_payload(rpc_url, block_arg, save).expect("failed to fetch payload from RPC");
    (format!("0x{block_num:x}"), data)
}

fn load_from_file(path: &str) -> Vec<u8> {
    println!("Loading payload from file: {path}");
    let mut file = File::open(path).unwrap_or_else(|e| panic!("unable to open {path}: {e}"));
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .unwrap_or_else(|e| panic!("unable to read {path}: {e}"));
    data
}

/// Write execution report to CSV file (append mode, write header if empty).
fn write_report(path: &PathBuf, block_tag: &str, report: &ExecutionReport, exec_secs: f64) {
    use strum::IntoEnumIterator;
    use zkm_core_executor::syscalls::SyscallCode;

    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .expect("failed to open report file");
    let file_is_empty = file.metadata().map(|m| m.len() == 0).unwrap_or(true);
    let mut wtr = file;

    if file_is_empty {
        let hdr = vec![
            "block", "total_cycles", "total_syscalls", "executed_seconds",
        ];
        let syscall_names: Vec<String> = SyscallCode::iter()
            .map(|s| format!("{s}").to_lowercase())
            .collect();
        let all: Vec<&str> = hdr.iter().copied()
            .chain(syscall_names.iter().map(|s| s.as_str()))
            .collect();
        writeln!(wtr, "{}", all.join(",")).unwrap();
    }

    let mut row = vec![
        block_tag.to_string(),
        report.total_instruction_count().to_string(),
        report.total_syscall_count().to_string(),
        format!("{exec_secs:.6}"),
    ];
    for s in SyscallCode::iter() {
        row.push(report.syscall_counts[s].to_string());
    }
    writeln!(wtr, "{}", row.join(",")).unwrap();
}

fn execute_keeper(data: &Vec<u8>, block_tag: &str, report_path: &Option<PathBuf>) -> bool {
    let mut stdin = ZKMStdin::new();
    stdin.write(data);

    let client = ProverClient::new();

    let start = Instant::now();
    let result = client.execute(ELF, &stdin).run();
    let duration = start.elapsed();

    let (_, report) = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("execution failed for {block_tag}: {e}");
            return false;
        }
    };

    println!(
        "executed program with {} cycles, {} syscalls, {} seconds",
        report.total_instruction_count(),
        report.total_syscall_count(),
        duration.as_secs_f64()
    );
    println!("{}", report);

    if let Some(path) = report_path {
        write_report(path, block_tag, &report, duration.as_secs_f64());
        println!("Report appended to {}", path.display());
    }
    true
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

fn run_data(data: Vec<u8>, execute_only: bool, block_tag: &str, report_path: &Option<PathBuf>) -> bool {
    println!("Run with execution_mode: {execute_only:?}");
    if execute_only {
        execute_keeper(&data, block_tag, report_path)
    } else {
        prove_keeper(data);
        true
    }
}

fn print_usage() -> ! {
    eprintln!(
        "Usage: {} [options] [<payload_file>]\n\
         \n\
         Options:\n\
         \x20 --rpc <url>              Ethereum JSON-RPC endpoint\n\
         \x20 --block <block>          Block number (hex/decimal) or \"latest\" (default: latest)\n\
         \x20 --save                   Save payload to file only, skip proving\n\
         \x20 --execute                Execute only (no proving)\n\
         \x20 --follow                 Continuously process new blocks\n\
         \x20 --poll-interval <secs>   Poll interval in seconds for --follow (default: 5)\n\
         \x20 --report-path <path>     Append execution report CSV to this file",
        env::args().next().unwrap()
    );
    std::process::exit(1);
}

fn run_follow(rpc_url: &str, start_block: &str, save_only: bool, execute_only: bool, poll_interval: u64, report_path: &Option<PathBuf>) {
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

            let (_, data) = fetch_one(rpc_url, &block_tag, save_only || true);

            if !save_only {
                if !run_data(data, execute_only, &block_tag, report_path) {
                    eprintln!("block {block_tag} failed, skipping");
                }
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
        run_follow(rpc_url, block_arg, args.save, args.execute_only, args.poll_interval_secs, &args.report_path);
        return;
    }

    if let Some(rpc_url) = &args.rpc {
        let block_arg = args.block.as_deref().unwrap_or("latest");
        let (block_tag, data) = fetch_one(rpc_url, block_arg, args.save);
        if args.save {
            println!("Payload saved, skipping prove.");
            return;
        }
        if !run_data(data, args.execute_only, &block_tag, &args.report_path) {
            std::process::exit(1);
        }
    } else if let Some(path) = &args.file_path {
        let data = load_from_file(path);
        let block_tag = std::path::Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");
        if !run_data(data, args.execute_only, block_tag, &args.report_path) {
            std::process::exit(1);
        }
    } else {
        print_usage();
    }
}
