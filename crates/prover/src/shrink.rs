//! Select a shrink strategy for a native compressed recursion proof.
//!
//! [`NativeShrink`] preserves the existing frozen shape and BN254 wrap path.
//! Optional compact strategies prove the same child-verification computation
//! with a different output PCS/transcript; they are not implicitly wrappable.

use crate::{
    components::ZKMProverComponents, CompressedSC, ShrinkSC, ZKMProver, ZKMRecursionProverError,
};
use zkm_core_executor::ZKMReduceProof;
use zkm_pcs::{StarkGenericConfig, ZKMProverOpts};

#[cfg(feature = "compact-shrink")]
pub mod adapter;
#[cfg(feature = "compact-shrink")]
mod compact;
#[cfg(feature = "compact-shrink")]
pub use compact::compact_shrink_prover;

/// Selects an output proof configuration and its proving implementation.
///
/// Implementations must prove verification of the native compressed input,
/// preserving its key admission and application/public-value statement. Merely
/// converting proof elements or relabeling a proof is not a shrink strategy.
pub trait ShrinkStrategy {
    type Config: StarkGenericConfig;

    fn shrink<C: ZKMProverComponents>(
        prover: &ZKMProver<C>,
        reduced_proof: ZKMReduceProof<CompressedSC>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<Self::Config>, ZKMRecursionProverError>;
}

/// The existing Poseidon2 shrinker with its frozen, wrap-compatible shape.
/// Available without the `compact-shrink` feature.
///
/// ```no_run
/// use zkm_core_executor::ZKMReduceProof;
/// use zkm_pcs::ZKMProverOpts;
/// use zkm_prover::{
///     components::ZKMProverComponents, CompressedSC, NativeShrink, OuterSC,
///     ZKMProver, ZKMRecursionProverError,
/// };
///
/// fn shrink_then_wrap<C: ZKMProverComponents>(
///     prover: &ZKMProver<C>,
///     compressed: ZKMReduceProof<CompressedSC>,
///     opts: ZKMProverOpts,
/// ) -> Result<ZKMReduceProof<OuterSC>, ZKMRecursionProverError> {
///     let shrunk = prover.shrink_with::<NativeShrink>(compressed, opts)?;
///     prover.wrap_bn254(shrunk, opts)
/// }
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeShrink;

impl ShrinkStrategy for NativeShrink {
    type Config = ShrinkSC;

    fn shrink<C: ZKMProverComponents>(
        prover: &ZKMProver<C>,
        reduced_proof: ZKMReduceProof<CompressedSC>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<Self::Config>, ZKMRecursionProverError> {
        prover.shrink_native(reduced_proof, opts)
    }
}

/// A byte-hash compact strategy supported by the compact verifier and adapter.
/// Native shrink proofs use the existing `verify_shrink` and BN254 wrap APIs.
/// A compact output cannot be passed to the existing native wrapper:
///
/// ```compile_fail,E0308
/// use zkm_core_executor::ZKMReduceProof;
/// use zkm_pcs::ZKMProverOpts;
/// use zkm_prover::{
///     components::ZKMProverComponents, CompactShrink, Keccak256Suite, ZKMProver,
/// };
///
/// fn unsupported_wrap<C: ZKMProverComponents>(
///     prover: &ZKMProver<C>,
///     compact: ZKMReduceProof<CompactShrink<Keccak256Suite>>,
///     opts: ZKMProverOpts,
/// ) {
///     prover.wrap_bn254(compact, opts).unwrap();
/// }
/// ```
#[cfg(feature = "compact-shrink")]
pub trait CompactShrinkStrategy:
    ShrinkStrategy<Config = crate::CompactShrink<Self::Suite>>
{
    type Suite: zkm_pcs::shrink::HashSuite;
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// Prove verification of a native compressed proof using the selected strategy.
    /// The output type determines which verification and wrap APIs accept it.
    pub fn shrink_with<T: ShrinkStrategy>(
        &self,
        reduced_proof: ZKMReduceProof<CompressedSC>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<T::Config>, ZKMRecursionProverError> {
        T::shrink(self, reduced_proof, opts)
    }

    /// Compatibility alias for `shrink_with::<NativeShrink>`.
    pub fn shrink(
        &self,
        reduced_proof: ZKMReduceProof<CompressedSC>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<ShrinkSC>, ZKMRecursionProverError> {
        self.shrink_with::<NativeShrink>(reduced_proof, opts)
    }
}
