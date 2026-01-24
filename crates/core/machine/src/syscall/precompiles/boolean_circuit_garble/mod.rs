mod air;
mod columns;
mod trace;

// number of bytes for each gate input info.
pub const GATE_INFO_BYTES: usize = 17;
// OR gate id
pub const OR_GATE_ID: u32 = 7;
/// A chip that computes non-free-gate ciphertexts and verifies them against the received ones.
#[derive(Default)]
pub struct BooleanCircuitGarbleChip;
