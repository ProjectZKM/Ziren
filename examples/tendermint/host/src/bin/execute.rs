//! Execute-only tendermint runner — no prove/verify.  Exercises the
//! JIT-by-default path through ProverClient::execute over the
//! tendermint guest with the canonical block_2279100 + block_2279130
//! inputs.

use std::time::{Duration, Instant};

use serde::Deserialize;
use tendermint_light_client_verifier::types::LightBlock;
use zkm_sdk::{include_elf, utils, ProverClient, ZKMStdin};

const TENDERMINT_ELF: &[u8] = include_elf!("tendermint");

fn load_light_block(height: u64) -> LightBlock {
    // Resolve relative to this crate's host directory so `cargo run`
    // works regardless of cwd.
    let crate_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{crate_dir}/files/block_{height}.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"));
    let mut deser = serde_json::Deserializer::from_str(&raw);
    LightBlock::deserialize(&mut deser).expect("deserialize LightBlock")
}

fn main() {
    utils::setup_logger();

    let block_1 = load_light_block(2279100);
    let block_2 = load_light_block(2279130);
    let encoded_1 = serde_cbor::to_vec(&block_1).unwrap();
    let encoded_2 = serde_cbor::to_vec(&block_2).unwrap();

    // Optionally dump the encoded stdin for the JIT bisect helper
    // to consume (set DUMP_STDIN=path to enable).  Format: bincode
    // Vec<Vec<u8>> with little-endian u64 length prefixes.
    if let Ok(path) = std::env::var("DUMP_STDIN") {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(2u64).to_le_bytes());
        buf.extend_from_slice(&(encoded_1.len() as u64).to_le_bytes());
        buf.extend_from_slice(&encoded_1);
        buf.extend_from_slice(&(encoded_2.len() as u64).to_le_bytes());
        buf.extend_from_slice(&encoded_2);
        std::fs::write(&path, &buf).expect("dump stdin");
        eprintln!("[tendermint] stdin dumped to {path}");
    }

    let runs: usize = std::env::var("RUNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);

    let client = ProverClient::new();
    let mut last_pvs: Option<Vec<u8>> = None;
    let mut last_cycles = 0u64;

    for run in 1..=runs {
        let mut stdin = ZKMStdin::new();
        stdin.write_vec(encoded_1.clone());
        stdin.write_vec(encoded_2.clone());

        let started = Instant::now();
        let (mut public_values, report) = match client.execute(TENDERMINT_ELF, &stdin).run() {
            Ok(o) => o,
            Err(e) => {
                eprintln!("[run {run}] execute failed: {e:?}");
                std::process::exit(1);
            }
        };
        let dur: Duration = started.elapsed();
        let pvs = public_values.as_slice().to_vec();
        let cycles = report.total_instruction_count() + report.total_syscall_count();
        eprintln!(
            "[tendermint run {run}] OK cycles={cycles} pvs_len={} dur={dur:?} first16={:02x?}",
            pvs.len(),
            &pvs[..pvs.len().min(16)],
        );
        match last_pvs {
            None => {
                last_pvs = Some(pvs);
                last_cycles = cycles;
            }
            Some(ref prev) => {
                assert_eq!(prev, &pvs, "run {run} pvs differs from run 1");
                assert_eq!(cycles, last_cycles, "run {run} cycle count differs from run 1");
            }
        }
    }
    eprintln!("All {runs} runs succeeded.");
}
