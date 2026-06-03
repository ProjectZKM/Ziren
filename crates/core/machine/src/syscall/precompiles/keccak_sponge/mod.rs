mod air;
mod columns;
mod constants;
mod control;
mod trace;
mod utils;

pub use control::{
    KeccakSpongeControlChip, KeccakSpongeControlCols, NUM_KECCAK_SPONGE_CONTROL_COLS,
};

pub const KECCAK_GENERAL_RATE_U32S: usize = 36;
pub const KECCAK_STATE_U32S: usize = 50;
pub const KECCAK_GENERAL_OUTPUT_U32S: usize = 16;
/// Bits per `p3_keccak` u64 limb (16-bit limbs → 4 limbs/u64, 100 limbs/state).
pub const BITS_PER_LIMB: usize = 16;

/// The keccak-sponge **worker** chip: one row per keccak-f round, with the
/// round-to-round and block-to-block hand-off carried on the `PrecompileChain`
/// buses (see `air` and the `control` chip).
#[derive(Default)]
pub struct KeccakSpongeChip;

impl KeccakSpongeChip {
    pub const fn new() -> Self {
        Self {}
    }
}
#[cfg(test)]
pub mod sponge_tests {
    use crate::utils::{self, run_test};
    use test_artifacts::KECCAK_SPONGE_ELF;
    use zkm_core_executor::Program;
    use zkm_stark::CpuProver;
    #[test]
    fn test_keccak_sponge_program_prove() {
        utils::setup_logger();
        let program = Program::from(KECCAK_SPONGE_ELF).unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }
}
