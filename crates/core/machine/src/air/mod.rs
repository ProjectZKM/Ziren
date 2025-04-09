mod memory;
mod program;
mod word;

pub use memory::*;
pub use program::*;
pub use word::*;

use zkm_stark::air::{BaseAirBuilder, ZKMAirBuilder};

/// A trait which contains methods related to memory lookups in an AIR.
///
pub trait ZKMCoreAirBuilder:
    ZKMAirBuilder + WordAirBuilder + MemoryAirBuilder + ProgramAirBuilder
{
}

impl<AB: BaseAirBuilder> MemoryAirBuilder for AB {}
impl<AB: BaseAirBuilder> ProgramAirBuilder for AB {}
impl<AB: BaseAirBuilder> WordAirBuilder for AB {}
impl<AB: BaseAirBuilder + ZKMAirBuilder> ZKMCoreAirBuilder for AB {}
