use hashbrown::HashMap;

use p3_field::PrimeCharacteristicRing;

/// A record that can be proven by a machine.
pub trait MachineRecord: Default + Sized + Send + Sync + Clone {
    /// The configuration of the machine.
    type Config: 'static + Copy + Send + Sync;

    /// The statistics of the record.
    fn stats(&self) -> HashMap<String, usize>;

    /// The area pins a proof of this record commits under, when the record
    /// knows its program and the program names a pin class
    /// (`MachineProgram::area_pins`); `None` leaves it to the machine.
    fn area_pins(&self) -> Option<crate::jagged::RecursionPins> {
        None
    }

    /// Appends two records together.
    fn append(&mut self, other: &mut Self);

    /// Returns the public values of the record.
    fn public_values<F: PrimeCharacteristicRing>(&self) -> Vec<F>;

    /// The byte-table multiplicities this record's byte lookups scatter to,
    /// laid out as the Byte and Range chips' traces are: `NUM_BYTE_OPS`
    /// planes of 2^16 rows (plane = opcode, row = `b << 8 | c`, or `a1` for
    /// `U16Range`) and one plane of 2^17 rows (`(1 << b) + a1`) for the range
    /// checks.  A prover that counts these on the device compares against
    /// them; records without byte lookups return `None`.
    fn byte_multiplicity_planes(&self) -> Option<(Vec<u32>, Vec<u32>)> {
        None
    }
}
