use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::{
    extension::{BinomialExtensionField, BinomiallyExtendable},
    Field, FieldAlgebra, FieldExtensionAlgebra, PackedField, PrimeField64,
};

use crate::evaluation_frame::StarkEvaluationFrame;

pub trait Stark<F: PrimeField64 + BinomiallyExtendable<D>, const D: usize>: Sync {
    /// The `Target` version of `Self::EvaluationFrame`, used to evaluate constraints recursively.
    type EvaluationFrameTarget: StarkEvaluationFrame<BinomialExtensionField<F, D>>;
}
