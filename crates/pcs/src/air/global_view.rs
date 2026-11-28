//! A chip's global lookups as a table of their own.

use core::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use super::MachineAir;

/// The main columns of a chip of the machine `A`, without its constraints:
/// the table a global proof reads the chip's global lookups from.
///
/// The chip's own shard proof constrains the columns and commits them in the
/// shard's global round. A global proof opens that commitment again, under
/// the global challenge drawn after every shard has committed, and proves
/// only the sum of the lookups' fractions.
pub struct GlobalView<A> {
    name: String,
    width: usize,
    _air: PhantomData<fn() -> A>,
}

impl<A> GlobalView<A> {
    /// The view named `name` of a chip whose main trace has `width` columns.
    pub const fn new(name: String, width: usize) -> Self {
        Self { name, width, _air: PhantomData }
    }

    /// The name of the view of the chip `chip` in the table slot `slot` of a
    /// global proof. Slots order first, so the views of one slot keep the
    /// name order of their chips.
    pub fn name_in_slot(slot: usize, chip: &str) -> String {
        assert!(slot < 100, "a global proof holds fewer than 100 table slots");
        format!("{slot:02}.{chip}")
    }

    /// The table slot and the chip of a view named by [`Self::name_in_slot`];
    /// `None` for any other name.
    pub fn slot_and_chip(view: &str) -> Option<(usize, &str)> {
        let (slot, chip) = view.split_once('.')?;
        if slot.len() != 2 || !slot.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some((slot.parse().ok()?, chip))
    }

    /// The chip a view named by [`Self::name_in_slot`] is a view of.
    pub fn chip_name(view: &str) -> &str {
        view.split_once('.').map_or(view, |(_, chip)| chip)
    }
}

impl<F, A> BaseAir<F> for GlobalView<A> {
    fn width(&self) -> usize {
        self.width
    }
}

impl<AB: AirBuilder, A> Air<AB> for GlobalView<A> {
    fn eval(&self, _builder: &mut AB) {}
}

impl<F: Field, A: MachineAir<F>> MachineAir<F> for GlobalView<A> {
    type Record = A::Record;
    type Program = A::Program;
    type Error = A::Error;

    fn name(&self) -> String {
        self.name.clone()
    }

    fn generate_trace(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        unreachable!("a global view reads the trace its chip committed")
    }

    fn generate_dependencies(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn included(&self, _shard: &Self::Record) -> bool {
        true
    }
}
