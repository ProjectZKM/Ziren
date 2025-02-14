use p3_koala_bear::KoalaBear;
use p3_bn254_fr::Bn254Fr;
use p3_field::extension::BinomialExtensionField;
use zkm2_stark::{InnerChallenge, InnerVal};

use crate::{circuit::AsmConfig, prelude::Config};

pub type InnerConfig = AsmConfig<InnerVal, InnerChallenge>;

#[derive(Clone, Default, Debug)]
pub struct OuterConfig;

impl Config for OuterConfig {
    type N = Bn254Fr;
    type F = KoalaBear;
    type EF = BinomialExtensionField<KoalaBear, 4>;
}
