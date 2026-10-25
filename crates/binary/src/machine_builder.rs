//! One builder trait for every folder the stage drives an AIR through.
//!
//! The multi-STARK evaluates an AIR through several builders: symbolic ones
//! at setup, multilinear folders in the zerocheck, bit-sliced folders in the
//! sliced kernels.  Some record bus declarations and some hold no bus, and
//! which concrete types exist depends on the target's vector units.  An AIR
//! here is written once against [`MachineBuilder`], whose [`declare_bus`]
//! forwards to a builder that records buses and is a no-op on one that does
//! not; the blanket impls below cover each builder family generically, so
//! no concrete type is named twice.
//!
//! [`declare_bus`]: MachineBuilder::declare_bus

use p3_air::symbolic::SymbolicAirBuilder;
use p3_air::{AirBuilder, DebugConstraintBuilder};
use p3_bus::{
    BusActivation, BusDirection, BusInteractionBuilder, BusInteractionRecorder, BusName,
    BusSymbolicBuilder,
};
use p3_field::{ExtensionField, Field};
use p3_lookup::{IndexedLookupBuilder, InteractionSymbolicBuilder, TraceWindow};
use p3_multi_stark::folder::{InteractionMultilinearFolder, MultilinearFolder};
use p3_multi_stark::sliced::{SlicedFolder, SlicedQuadraticFolder};

/// An AIR builder that may or may not record bus declarations.
pub trait MachineBuilder: AirBuilder {
    /// Declare one tuple on `bus`, where the builder records buses.
    fn declare_bus(
        &mut self,
        bus: BusName<'_>,
        direction: BusDirection,
        fields: Vec<Self::Expr>,
        activation: BusActivation<Self::Expr>,
    );

    /// Pull the `payload` columns out of `table` at the entry the `bits`
    /// columns name, least significant first, where the builder records
    /// lookups.
    fn read_table(&mut self, table: &str, bits: Vec<usize>, payload: Vec<usize>);

    /// Provide `table` from the `columns` of `window`, where the builder
    /// records lookups.
    fn provide_table(&mut self, table: &str, window: TraceWindow, columns: Vec<usize>);
}

/// The lookup declarations, forwarded where the builder records them.
macro_rules! records_lookups {
    () => {
        fn read_table(&mut self, table: &str, bits: Vec<usize>, payload: Vec<usize>) {
            self.push_indexed_read_bits(table, bits, payload);
        }

        fn provide_table(&mut self, table: &str, window: TraceWindow, columns: Vec<usize>) {
            self.push_indexed_table(table, window, columns);
        }
    };
}

macro_rules! records_buses {
    ($($ty:ty),* $(,)?) => {$(
        impl<'a, F: Field, EF: ExtensionField<F>> MachineBuilder for $ty
        where
            Self: BusInteractionRecorder + IndexedLookupBuilder,
        {
            fn declare_bus(
                &mut self,
                bus: BusName<'_>,
                direction: BusDirection,
                fields: Vec<Self::Expr>,
                activation: BusActivation<Self::Expr>,
            ) {
                self.push_bus_interaction(bus, direction, fields, activation);
            }

            records_lookups!();
        }
    )*};
}

records_buses!(
    BusSymbolicBuilder<F, EF>,
    InteractionSymbolicBuilder<F, EF>,
    DebugConstraintBuilder<'a, F, EF>,
);

impl<'a, F, Var, Acc> MachineBuilder for MultilinearFolder<'a, F, Var, Acc>
where
    Self: BusInteractionRecorder + IndexedLookupBuilder,
{
    fn declare_bus(
        &mut self,
        bus: BusName<'_>,
        direction: BusDirection,
        fields: Vec<Self::Expr>,
        activation: BusActivation<Self::Expr>,
    ) {
        self.push_bus_interaction(bus, direction, fields, activation);
    }

    records_lookups!();
}

impl<'a, F, Var, Acc> MachineBuilder for InteractionMultilinearFolder<'a, F, Var, Acc>
where
    Self: BusInteractionRecorder + IndexedLookupBuilder,
{
    fn declare_bus(
        &mut self,
        bus: BusName<'_>,
        direction: BusDirection,
        fields: Vec<Self::Expr>,
        activation: BusActivation<Self::Expr>,
    ) {
        self.push_bus_interaction(bus, direction, fields, activation);
    }

    records_lookups!();
}

/// A builder that holds no bus still asserts a selecting activation to be
/// boolean, as the recording builders do, so that every builder counts the
/// same constraints.
fn assert_selector_bool<AB: AirBuilder>(builder: &mut AB, activation: BusActivation<AB::Expr>) {
    if let BusActivation::Boolean(selector) = activation {
        builder.assert_bool(selector);
    }
}

/// The sliced kernels evaluate constraints only; the bus is reduced elsewhere.
impl<'a, F, S, R> MachineBuilder for SlicedFolder<'a, F, S, R>
where
    Self: AirBuilder + IndexedLookupBuilder,
{
    fn declare_bus(
        &mut self,
        _bus: BusName<'_>,
        _direction: BusDirection,
        _fields: Vec<Self::Expr>,
        activation: BusActivation<Self::Expr>,
    ) {
        assert_selector_bool(self, activation);
    }

    records_lookups!();
}

impl<'a, F, R> MachineBuilder for SlicedQuadraticFolder<'a, F, R>
where
    Self: AirBuilder + IndexedLookupBuilder,
{
    fn declare_bus(
        &mut self,
        _bus: BusName<'_>,
        _direction: BusDirection,
        _fields: Vec<Self::Expr>,
        activation: BusActivation<Self::Expr>,
    ) {
        assert_selector_bool(self, activation);
    }

    records_lookups!();
}

/// The plain symbolic builder sees constraints only.
impl<F: Field, EF: ExtensionField<F>> MachineBuilder for SymbolicAirBuilder<F, EF> {
    fn declare_bus(
        &mut self,
        _bus: BusName<'_>,
        _direction: BusDirection,
        _fields: Vec<Self::Expr>,
        activation: BusActivation<Self::Expr>,
    ) {
        assert_selector_bool(self, activation);
    }

    fn read_table(&mut self, _table: &str, _bits: Vec<usize>, _payload: Vec<usize>) {}

    fn provide_table(&mut self, _table: &str, _window: TraceWindow, _columns: Vec<usize>) {}
}
