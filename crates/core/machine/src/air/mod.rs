use zkm2_stark::BaseAirBuilder;

mod word;

pub use word::*;

impl<AB: BaseAirBuilder> WordAirBuilder for AB {}
