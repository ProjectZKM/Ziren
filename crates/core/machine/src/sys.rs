use p3_koala_bear::KoalaBear;
use zkm_core_executor::events::{AluEvent, MemoryLocalEvent, MemoryInitializeFinalizeEvent};

use crate::{alu::AddSubCols, memory::{MemoryInitCols, SingleMemoryLocal}};

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
}
