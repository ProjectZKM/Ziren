pub mod air;
pub mod columns;
pub mod trace;

use zkm2_core_executor::MipsAirId;

/// The maximum log degree of the CPU chip to avoid lookup multiplicity overflow.
pub const MAX_CPU_LOG_DEGREE: usize = 22;

/// A chip that implements the CPU.
#[derive(Default)]
pub struct CpuChip;

impl CpuChip {
    pub fn id(&self) -> MipsAirId {
        MipsAirId::Cpu
    }
}
