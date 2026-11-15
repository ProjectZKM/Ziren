//! A simple example showing how to aggregate proofs of multiple programs with ZKM.
//!
//! Aggregation verifies compressed proofs inside a guest as deferred proofs,
//! which the binary compress does not support yet.

fn main() {
    zkm_sdk::utils::setup_logger();
    tracing::error!(
        "aggregation needs deferred proofs, which the binary compress does not support yet"
    );
    std::process::exit(1);
}
