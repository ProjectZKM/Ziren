//! Empty record and program types for test chips.

use crate::air::MachineProgram;
use crate::record::MachineRecord;
use crate::septic_digest::SepticDigest;
use crate::InnerVal;
use p3_field::PrimeCharacteristicRing;

#[derive(Clone, Default)]
pub(crate) struct MockRecord;

impl MachineRecord for MockRecord {
    type Config = ();

    fn stats(&self) -> hashbrown::HashMap<String, usize> {
        hashbrown::HashMap::new()
    }

    fn append(&mut self, _other: &mut Self) {}

    fn public_values<FF: PrimeCharacteristicRing>(&self) -> Vec<FF> {
        Vec::new()
    }
}

#[derive(Clone, Default)]
pub(crate) struct MockProgram;

impl MachineProgram<InnerVal> for MockProgram {
    fn pc_start(&self) -> InnerVal {
        InnerVal::ZERO
    }

    fn initial_global_cumulative_sum(&self) -> SepticDigest<InnerVal> {
        SepticDigest::<InnerVal>::zero()
    }
}
