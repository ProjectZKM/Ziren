mod air;
mod columns;
mod trace;
mod utils;

pub const KECCAK_GENERAL_RATE_U32S: usize = 36;
pub const KECCAK_STATE_U32S: usize = 50;
pub const KECCAK_GENERAL_OUTPUT_U32S: usize = 16;

#[derive(Default)]
pub struct KeccakSpongeChip;

impl KeccakSpongeChip {
    pub const fn new() -> Self {
        Self {}
    }
}
#[cfg(test)]
pub mod sponge_tests {
    use test_artifacts::KECCAK_SPONGE_ELF;
    use zkm2_core_executor::Program;
    use zkm2_stark::CpuProver;
//
    use crate::utils::{self, run_test};
    #[test]
    fn test_keccak_sponge_program_prove() {
        utils::setup_logger();
        let program = Program::from(KECCAK_SPONGE_ELF).unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }
}
