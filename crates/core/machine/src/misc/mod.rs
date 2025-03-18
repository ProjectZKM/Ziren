use columns::NUM_MISC_INSTR_COLS;
use p3_air::BaseAir;

pub mod air;
pub mod columns;
pub mod trace;

#[derive(Default)]
pub struct MiscInstrsChip;

impl<F> BaseAir<F> for MiscInstrsChip {
    fn width(&self) -> usize {
        NUM_MISC_INSTR_COLS
    }
}
