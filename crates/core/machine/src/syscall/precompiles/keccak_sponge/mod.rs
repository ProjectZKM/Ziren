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
    use zkm_pcs::CpuProver;
    #[test]
    fn trace_preserves_event_rows() {
        use p3_koala_bear::KoalaBear;
        use p3_matrix::{dense::RowMajorMatrix, Matrix};
        use zkm_core_executor::{
            events::PrecompileEvent, syscalls::SyscallCode, ExecutionRecord, Executor,
        };
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::ZKMCoreOpts;

        let mut runtime =
            Executor::new(Program::from(KECCAK_SPONGE_ELF).unwrap(), ZKMCoreOpts::default());
        runtime.run().unwrap();
        let chip = super::KeccakSpongeControlChip;
        let mut block_count = 0;
        for record in &runtime.records {
            let events = record.get_precompile_events(SyscallCode::KECCAK_SPONGE);
            if events.is_empty() {
                continue;
            }
            let blocks: usize = events
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::KeccakSponge(event) => event.num_blocks(),
                    _ => unreachable!(),
                })
                .sum();
            block_count += blocks;
            let trace: RowMajorMatrix<KoalaBear> =
                chip.generate_trace(record, &mut ExecutionRecord::default()).unwrap();
            assert!(trace.height() >= blocks);
            assert_eq!(
                trace.height(),
                <super::KeccakSpongeControlChip as MachineAir<KoalaBear>>::num_rows(&chip, record)
                    .unwrap()
            );
        }
        assert!(block_count > 0);
    }

    #[test]
    fn test_keccak_sponge_program_prove() {
        utils::setup_logger();
        let program = Program::from(KECCAK_SPONGE_ELF).unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }
}
