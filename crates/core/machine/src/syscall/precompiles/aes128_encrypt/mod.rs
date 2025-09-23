mod air;
mod columns;
mod trace;

#[derive(Default)]
pub struct AES128EncryptChip;

impl AES128EncryptChip {
    pub const fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod tests {
    use crate::utils::{self, run_test};
    use test_artifacts::AES128_ENCRYPT_ELF;
    use zkm_core_executor::Program;
    use zkm_stark::CpuProver;
    #[test]
    fn test_aes128_encrypt_program_prove() {
        utils::setup_logger();
        let program = Program::from(AES128_ENCRYPT_ELF).unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }
}
