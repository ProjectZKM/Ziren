//! # ZKM2 SDK Utilities
//!
//! A collection of utilities for the ZKM2 SDK.

use zkm2_core_machine::io::ZKMStdin;
pub use zkm2_core_machine::utils::setup_logger;

/// Dump the program and stdin to files for debugging if `ZKM_DUMP` is set.
pub(crate) fn zkm_dump(elf: &[u8], stdin: &ZKMStdin) {
    if std::env::var("ZKM_DUMP").map(|v| v == "1" || v.to_lowercase() == "true").unwrap_or(false) {
        std::fs::write("program.bin", elf).unwrap();
        let stdin = bincode::serialize(&stdin).unwrap();
        std::fs::write("stdin.bin", stdin.clone()).unwrap();
    }
}
