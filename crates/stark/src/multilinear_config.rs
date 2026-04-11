//! Configuration trait for multilinear STARK proving with WHIR PCS.
//!
//! This is the multilinear counterpart of [`StarkGenericConfig`], designed
//! to work with [`MultilinearPcs`] (e.g., WHIR) instead of the univariate
//! [`Pcs`] trait used by the FRI-based pipeline.
//!
//! The key architectural difference:
//! - Univariate: traces are committed as polynomials over roots-of-unity domains
//! - Multilinear: traces are committed as multilinear extensions over the Boolean hypercube

use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::MultilinearPcs;
use p3_field::{ExtensionField, PrimeField, TwoAdicField};
use serde::{de::DeserializeOwned, Serialize};

/// Configuration trait for multilinear STARK proving.
///
/// Analogous to [`super::StarkGenericConfig`] but parameterized over
/// [`MultilinearPcs`] instead of [`p3_commit::Pcs`].
pub trait MultilinearStarkConfig: 'static + Send + Sync + Clone {
    /// Base field for trace values.
    type Val: PrimeField + TwoAdicField;

    /// The multilinear PCS (e.g., WHIR).
    type Pcs: MultilinearPcs<Self::Challenge, Self::Challenger, Val = Self::Val> + Sync;

    /// Extension field for challenges and openings.
    type Challenge: ExtensionField<Self::Val> + TwoAdicField;

    /// Fiat-Shamir challenger.
    type Challenger: FieldChallenger<Self::Val>
        + CanObserve<<Self::Pcs as MultilinearPcs<Self::Challenge, Self::Challenger>>::Commitment>
        + Clone;

    /// Get the PCS instance.
    fn pcs(&self) -> &Self::Pcs;

    /// Create a fresh challenger.
    fn challenger(&self) -> Self::Challenger;

    /// Number of variables (log2 of max trace height).
    fn num_vars(&self) -> usize;
}

// ── Type aliases for ergonomic access ──────────────────────────────────

pub type MlVal<MC> = <MC as MultilinearStarkConfig>::Val;

pub type MlChallenge<MC> = <MC as MultilinearStarkConfig>::Challenge;

pub type MlChallenger<MC> = <MC as MultilinearStarkConfig>::Challenger;

pub type MlCom<MC> = <<MC as MultilinearStarkConfig>::Pcs as MultilinearPcs<
    <MC as MultilinearStarkConfig>::Challenge,
    <MC as MultilinearStarkConfig>::Challenger,
>>::Commitment;

pub type MlProof<MC> = <<MC as MultilinearStarkConfig>::Pcs as MultilinearPcs<
    <MC as MultilinearStarkConfig>::Challenge,
    <MC as MultilinearStarkConfig>::Challenger,
>>::Proof;

pub type MlProverData<MC> = <<MC as MultilinearStarkConfig>::Pcs as MultilinearPcs<
    <MC as MultilinearStarkConfig>::Challenge,
    <MC as MultilinearStarkConfig>::Challenger,
>>::ProverData;

pub type MlError<MC> = <<MC as MultilinearStarkConfig>::Pcs as MultilinearPcs<
    <MC as MultilinearStarkConfig>::Challenge,
    <MC as MultilinearStarkConfig>::Challenger,
>>::Error;
