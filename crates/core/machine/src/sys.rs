use crate::alu::AddSubCols;
use p3_koala_bear::KoalaBear;

use zkm_core_executor::events::AluEvent;

#[link(name = "zkm-core-machine-sys", kind = "static")]
extern "C-unwind" {
    pub fn add_sub_event_to_row_koalabear(event: &AluEvent, cols: &mut AddSubCols<KoalaBear>);
}
