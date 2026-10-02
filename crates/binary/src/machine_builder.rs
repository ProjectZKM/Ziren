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
use p3_lookup::InteractionSymbolicBuilder;
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
}

macro_rules! records_buses {
    ($($ty:ty),* $(,)?) => {$(
        impl<'a, F: Field, EF: ExtensionField<F>> MachineBuilder for $ty
        where
            Self: BusInteractionRecorder,
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
    Self: BusInteractionRecorder,
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
}

impl<'a, F, Var, Acc> MachineBuilder for InteractionMultilinearFolder<'a, F, Var, Acc>
where
    Self: BusInteractionRecorder,
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
}

/// The sliced kernels evaluate constraints only; the bus is reduced elsewhere.
impl<'a, F, S, R> MachineBuilder for SlicedFolder<'a, F, S, R>
where
    Self: AirBuilder,
{
    fn declare_bus(
        &mut self,
        _bus: BusName<'_>,
        _direction: BusDirection,
        _fields: Vec<Self::Expr>,
        _activation: BusActivation<Self::Expr>,
    ) {
    }
}

impl<'a, F, R> MachineBuilder for SlicedQuadraticFolder<'a, F, R>
where
    Self: AirBuilder,
{
    fn declare_bus(
        &mut self,
        _bus: BusName<'_>,
        _direction: BusDirection,
        _fields: Vec<Self::Expr>,
        _activation: BusActivation<Self::Expr>,
    ) {
    }
}

/// The plain symbolic builder sees constraints only.
impl<F: Field, EF: ExtensionField<F>> MachineBuilder for SymbolicAirBuilder<F, EF> {
    fn declare_bus(
        &mut self,
        _bus: BusName<'_>,
        _direction: BusDirection,
        _fields: Vec<Self::Expr>,
        _activation: BusActivation<Self::Expr>,
    ) {
    }
}
