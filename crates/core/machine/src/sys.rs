use p3_koala_bear::KoalaBear;
use zkm_core_executor::events::{
    AluEvent, BranchEvent, CpuEventFfi, JumpEvent, MemInstrEvent, MemoryInitializeFinalizeEvent,
    MemoryLocalEvent, MiscEvent, MovCondEvent, SyscallEvent,
};
use zkm_core_executor::InstructionFfi;

use crate::alu::{BitwiseCols, CloClzCols};
use crate::memory::columns::MemoryInstructionsColumns;
use crate::{
    alu::{AddSubCols, LtCols, ShiftLeftCols},
    control_flow::{BranchColumns, JumpColumns},
    cpu::columns::CpuCols,
    memory::{MemoryInitCols, SingleMemoryLocal},
    misc::columns::MiscInstrColumns,
    misc::mov_cond::MovCondCols,
    syscall::chip::SyscallCols,
};

#[link(name = "zkm-core-machine-sys", kind = "static")]
extern "C-unwind" {
    pub fn cpu_event_to_row_koalabear(
        event: CpuEventFfi,
        shard: u32,
        instruction: InstructionFfi,
        cols: &mut CpuCols<KoalaBear>,
    );
    pub fn add_sub_event_to_row_koalabear(event: &AluEvent, cols: &mut AddSubCols<KoalaBear>);
    pub fn memory_local_event_to_row_koalabear(
        event: &MemoryLocalEvent,
        cols: &mut SingleMemoryLocal<KoalaBear>,
    );
    pub fn memory_global_event_to_row_koalabear(
        event: &MemoryInitializeFinalizeEvent,
        is_receive: bool,
        cols: &mut MemoryInitCols<KoalaBear>,
    );
    pub fn syscall_event_to_row_koalabear(
        event: &SyscallEvent,
        is_receive: bool,
        cols: &mut SyscallCols<KoalaBear>,
    );
    pub fn mem_instrs_event_to_row_koalabear(
        event: &MemInstrEvent,
        is_receive: bool,
        cols: &mut MemoryInstructionsColumns<KoalaBear>,
    );
    pub fn lt_event_to_row_koalabear(event: &AluEvent, cols: &mut LtCols<KoalaBear>);
    pub fn bitwise_event_to_row_koalabear(event: &AluEvent, cols: &mut BitwiseCols<KoalaBear>);
    pub fn clo_clz_event_to_row_koalabear(event: &AluEvent, cols: &mut CloClzCols<KoalaBear>);
    pub fn branch_event_to_row_koalabear(event: &BranchEvent, cols: &mut BranchColumns<KoalaBear>);
    pub fn jump_event_to_row_koalabear(event: &JumpEvent, cols: &mut JumpColumns<KoalaBear>);
    pub fn misc_instrs_event_to_row_koalabear(
        event: &MiscEvent,
        cols: &mut MiscInstrColumns<KoalaBear>,
    );
    pub fn mov_cond_event_to_row_koalabear(event: &MovCondEvent, cols: &mut MovCondCols<KoalaBear>);
    pub fn shift_left_event_to_row_koalabear(event: &AluEvent, cols: &mut ShiftLeftCols<KoalaBear>);

    pub fn test_mul();
    pub fn test_inv();
    pub fn test_sqrt();
    pub fn test_curve_formula();
}

#[cfg(test)]
mod tests {
    use crate::sys::{test_curve_formula, test_inv, test_mul, test_sqrt};

    #[test]
    fn test_septic() {
        unsafe { test_mul() };
        unsafe { test_inv() };
        unsafe { test_sqrt() };
        unsafe { test_curve_formula() };
    }
}
