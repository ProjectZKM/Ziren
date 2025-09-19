use p3_koala_bear::KoalaBear;
use zkm_core_executor::events::{AluEvent, MemoryInitializeFinalizeEvent, MemoryLocalEvent, SyscallEvent};

use crate::{alu::AddSubCols, memory::{MemoryInitCols, SingleMemoryLocal}, syscall::chip::SyscallCols};

#[link(name = "zkm-core-machine-sys", kind = "static")]
extern "C-unwind" {
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
}
