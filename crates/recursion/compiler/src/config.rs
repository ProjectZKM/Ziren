use p3_bn254_fr::Bn254;
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_koala_bear::KoalaBear;
use zkm_stark::{Inner128Challenge, InnerChallenge, InnerVal};

use crate::{circuit::AsmConfig, prelude::Config};

pub type InnerConfig = AsmConfig<InnerVal, InnerChallenge>;
pub type Inner128Config = AsmConfig<InnerVal, Inner128Challenge>;

#[derive(Clone, Default, Debug)]
pub struct OuterConfig;

impl Config for OuterConfig {
    type N = Bn254;
    type F = KoalaBear;
    type EF = BinomialExtensionField<KoalaBear, 4>;
}

#[derive(Clone, Default, Debug)]
pub struct OuterD5Config;

impl Config for OuterD5Config {
    type N = Bn254;
    type F = KoalaBear;
    type EF = QuinticTrinomialExtensionField<KoalaBear>;
}
