#[cfg(feature = "bls12381")]
use p3_bls12381_fr::Bls12381Fr as FR;
#[cfg(feature = "bn254")]
use p3_bn254_fr::Bn254Fr as FR;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::KoalaBear;
use zkm_stark::{InnerChallenge, InnerVal};

use crate::{circuit::AsmConfig, prelude::Config};

pub type InnerConfig = AsmConfig<InnerVal, InnerChallenge>;

#[derive(Clone, Default, Debug)]
pub struct OuterConfig;

impl Config for OuterConfig {
    type N = FR;
    type F = KoalaBear;
    type EF = BinomialExtensionField<KoalaBear, 4>;
}
