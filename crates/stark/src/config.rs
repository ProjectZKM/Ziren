use core::marker::PhantomData;

use p3_challenger::{CanObserve, CanSample, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{ExtensionField, Field, PrimeField};

pub type PcsError<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Error;

pub type Domain<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Domain;

pub type Val<SC> = <Domain<SC> as PolynomialSpace>::Val;

pub type PackedVal<SC> = <Val<SC> as Field>::Packing;

pub type Challenge<SC> = <SC as StarkGenericConfig>::Challenge;
pub type Challenger<SC> = <SC as StarkGenericConfig>::Challenger;
pub type Com<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Commitment;
pub type OpeningProof<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Proof;

// FIXME: dumplicated with Domain
pub type Dom<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Domain;
pub type PcsProverData<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::ProverData;

pub type PackedChallenge<SC> =
    <<SC as StarkGenericConfig>::Challenge as ExtensionField<Val<SC>>>::ExtensionPacking;

pub trait StarkGenericConfig {
    type Val: Field;
    /// The PCS used to commit to trace polynomials.
    type Pcs: Pcs<Self::Challenge, Self::Challenger>;

    /// The field from which most random challenges are drawn.
    type Challenge: ExtensionField<Val<Self>>;

    /// The challenger (Fiat-Shamir) implementation used.
    type Challenger: FieldChallenger<Val<Self>>
        + CanObserve<<Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Commitment>
        + CanSample<Self::Challenge>;

    fn pcs(&self) -> &Self::Pcs;
}

#[derive(Debug)]
pub struct StarkConfig<Pcs, Challenge, Challenger> {
    pcs: Pcs,
    _phantom: PhantomData<(Challenge, Challenger)>,
}

impl<Pcs, Challenge, Challenger> StarkConfig<Pcs, Challenge, Challenger> {
    pub const fn new(pcs: Pcs) -> Self {
        Self {
            pcs,
            _phantom: PhantomData,
        }
    }
}

impl<Pcs, Challenge, Challenger> StarkGenericConfig for StarkConfig<Pcs, Challenge, Challenger>
where
    Challenge: ExtensionField<<Pcs::Domain as PolynomialSpace>::Val>,
    Pcs: p3_commit::Pcs<Challenge, Challenger>,
    Challenger: FieldChallenger<<Pcs::Domain as PolynomialSpace>::Val>
        + CanObserve<<Pcs as p3_commit::Pcs<Challenge, Challenger>>::Commitment>
        + CanSample<Challenge>,
{
    type Pcs = Pcs;
    type Val = <Pcs::Domain as PolynomialSpace>::Val;
    type Challenge = Challenge;
    type Challenger = Challenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }
}
