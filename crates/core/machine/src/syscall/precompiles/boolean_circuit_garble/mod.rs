mod air;
mod columns;
mod trace;

/// A chip that computes non-free-gate ciphertexts and verifies them against the received ones.
pub struct BooleanCircuitGarbleChip;

impl BooleanCircuitGarbleChip {
    pub const fn new() -> Self {
        Self {}
    }
}
