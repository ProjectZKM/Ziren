//! AIR bounds shared by the binary machine's proving backends.
use crate::F;
use p3_air::{Air, BaseAir};
use p3_binary_field::{BinaryField2, Ghash128};
use p3_bus::BusSymbolicBuilder;
use p3_lookup::InteractionSymbolicBuilder;
use p3_multi_stark::folder::{InteractionMultilinearFolder, MultilinearFolder};
use p3_multi_stark::packed_ext::{PackedExt, PackedRepr};
use p3_multi_stark::sliced::{SlicedFolder, SlicedQuadraticFolder};
use p3_multi_stark::subfield::{SubfieldAcc, SubfieldVar};
pub trait BinaryAir:
    BaseAir<F>
    + Air<InteractionSymbolicBuilder<F, F>>
    + Air<BusSymbolicBuilder<F, F>>
    + for<'a> Air<MultilinearFolder<'a, F, F, F>>
    + for<'a> Air<MultilinearFolder<'a, F, PackedExt<F, F>, PackedExt<F, F>>>
    + for<'a> Air<InteractionMultilinearFolder<'a, F, F, F>>
    + for<'a> Air<InteractionMultilinearFolder<'a, F, PackedExt<F, F>, PackedExt<F, F>>>
    + for<'a> Air<
        MultilinearFolder<'a, F, SubfieldVar<F, BinaryField2>, SubfieldAcc<F, BinaryField2>>,
    > + for<'a> Air<SlicedFolder<'a, F, BinaryField2, F>>
    + for<'a> Air<SlicedFolder<'a, F, BinaryField2, Ghash128>>
    + for<'a> Air<SlicedQuadraticFolder<'a, F, Ghash128>>
    + for<'a> Air<MultilinearFolder<'a, F, Ghash128, Ghash128>>
    + for<'a> Air<InteractionMultilinearFolder<'a, F, Ghash128, Ghash128>>
    + for<'a> Air<MultilinearFolder<'a, F, PackedRepr<F, Ghash128>, PackedRepr<F, Ghash128>>>
    + for<'a> Air<
        InteractionMultilinearFolder<'a, F, PackedRepr<F, Ghash128>, PackedRepr<F, Ghash128>>,
    >
{
}

impl<A> BinaryAir for A where
    A: BaseAir<F>
        + Air<InteractionSymbolicBuilder<F, F>>
        + Air<BusSymbolicBuilder<F, F>>
        + for<'a> Air<MultilinearFolder<'a, F, F, F>>
        + for<'a> Air<MultilinearFolder<'a, F, PackedExt<F, F>, PackedExt<F, F>>>
        + for<'a> Air<InteractionMultilinearFolder<'a, F, F, F>>
        + for<'a> Air<InteractionMultilinearFolder<'a, F, PackedExt<F, F>, PackedExt<F, F>>>
        + for<'a> Air<
            MultilinearFolder<'a, F, SubfieldVar<F, BinaryField2>, SubfieldAcc<F, BinaryField2>>,
        > + for<'a> Air<SlicedFolder<'a, F, BinaryField2, F>>
        + for<'a> Air<SlicedFolder<'a, F, BinaryField2, Ghash128>>
        + for<'a> Air<SlicedQuadraticFolder<'a, F, Ghash128>>
        + for<'a> Air<MultilinearFolder<'a, F, Ghash128, Ghash128>>
        + for<'a> Air<InteractionMultilinearFolder<'a, F, Ghash128, Ghash128>>
        + for<'a> Air<MultilinearFolder<'a, F, PackedRepr<F, Ghash128>, PackedRepr<F, Ghash128>>>
        + for<'a> Air<
            InteractionMultilinearFolder<'a, F, PackedRepr<F, Ghash128>, PackedRepr<F, Ghash128>>,
        >
{
}
