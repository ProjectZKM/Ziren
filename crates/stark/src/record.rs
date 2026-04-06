use hashbrown::HashMap;

use p3_field::PrimeCharacteristicRing;

/// A record that can be proven by a machine.
pub trait MachineRecord: Default + Sized + Send + Sync + Clone {
    /// The configuration of the machine.
    type Config: 'static + Copy + Send + Sync;

    /// The statistics of the record.
    fn stats(&self) -> HashMap<String, usize>;

    /// Appends two records together.
    fn append(&mut self, other: &mut Self);

    /// Returns the public values of the record.
    fn public_values<F: PrimeCharacteristicRing>(&self) -> Vec<F>;
}
