//! Time how long `ZKMProver::new()` takes with VK verification on.
//!
//! Useful for diagnosing slow startup when `VERIFY_VK=true` —
//! `new()` builds N compress programs upfront, where N is the
//! `multi_cartesian_product` of the allowed_shapes raised to
//! `REDUCE_BATCH_SIZE`.  With 4 shapes and batch_size=2, that's
//! 16 compress programs each compiled via `compress_program_from_input`.

use std::time::Instant;
use zkm_core_machine::utils::setup_logger;
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::ZKMProver;

fn main() {
    setup_logger();
    eprintln!(
        "[time-prover-new] VERIFY_VK={:?}",
        std::env::var("VERIFY_VK").ok(),
    );
    let t = Instant::now();
    let _prover = ZKMProver::<DefaultProverComponents>::new();
    eprintln!("[time-prover-new] new() took {:?}", t.elapsed());
}
