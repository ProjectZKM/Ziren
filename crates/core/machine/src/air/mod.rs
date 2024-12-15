use zkm2_stark::air::{BaseAirBuilder, ZKMAirBuilder};

mod word;

pub use word::*;


/// A trait which contains methods related to memory interactions in an AIR.

pub trait ZKMCoreAirBuilder:
    ZKMAirBuilder + WordAirBuilder
{
}

impl<AB: BaseAirBuilder> WordAirBuilder for AB {}
impl<AB: BaseAirBuilder + ZKMAirBuilder> ZKMCoreAirBuilder for AB {}


