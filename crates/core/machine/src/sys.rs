use crate::{alu::AddSubCols, memory::SingleMemoryLocal};
use p3_koala_bear::KoalaBear;

use zkm_core_executor::events::{AluEvent, MemoryLocalEvent};

#[link(name = "zkm-core-machine-sys", kind = "static")]
extern "C-unwind" {
    pub fn add_sub_event_to_row_koalabear(event: &AluEvent, cols: &mut AddSubCols<KoalaBear>);
    pub fn memory_local_event_to_row_koalabear(
        event: &MemoryLocalEvent,
        cols: &mut SingleMemoryLocal<KoalaBear>,
    );
}
