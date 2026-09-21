use zkm_sdk::{include_elf, utils, ProverClient, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const REPORT_ELF: &[u8] = include_elf!("report");
const NORMAL_ELF: &[u8] = include_elf!("normal");

fn main() {
    utils::setup_logger();

    let client = ProverClient::new();
    let (_, _) = client.execute(NORMAL_ELF, &ZKMStdin::new()).run().expect("proving failed");

    let (_, report) = client.execute(REPORT_ELF, &ZKMStdin::new()).run().expect("proving failed");

    let setup_cycles = report.cycle_tracker.get("setup").unwrap();
    println!(
        "Using cycle-tracker-report saves the number of cycles to the cycle-tracker mapping in the report.\nHere's the number of cycles used by the setup: {}",
        setup_cycles
    );
}
