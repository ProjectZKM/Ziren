//! Time how long `ZKMProver::new()` takes.

use std::time::Instant;
use zkm_core_machine::utils::setup_cli_logger;
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::ZKMProver;

fn main() {
    setup_cli_logger();
    tracing::info!("[time-prover-new] VERIFY_VK={:?}", std::env::var("VERIFY_VK").ok(),);
    let t = Instant::now();
    let _prover = ZKMProver::<DefaultProverComponents>::new();
    tracing::info!("[time-prover-new] new() took {:?}", t.elapsed());
    let t = Instant::now();
    let _prover = ZKMProver::<DefaultProverComponents>::uninitialized();
    tracing::info!("[time-prover-new] uninitialized() took {:?}", t.elapsed());
}
