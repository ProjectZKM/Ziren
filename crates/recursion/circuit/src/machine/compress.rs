//! Compose-stage compress witness/value/shape **data-type carriers** + the
//! basefold-shaped `dummy()` factory used by the shape enumerator pipeline.
//!
//! ## Task #397 (May 19 2026) — FRI compose-body deletion
//!
//! The legacy in-circuit `ZKMCompressVerifier::verify` body (the FRI-shaped
//! compose verifier originally inherited from SP1) has been retired. The
//! production compose verifier lives in
//! [`super::compress_basefold::verify_compress_basefold`]; the recursion-AIR
//! variant lives in [`super::compress_basefold_recursion`]. Both consume the
//! basefold-shaped witness layouts from those modules — they do NOT consume
//! [`ZKMCompressWitnessVariable`] anymore.
//!
//! What remains in this module (the load-bearing surface for the HYBRID
//! wrap-stays-on-FRI decision):
//!
//! - [`PublicValuesOutputDigest`] — still imported by all basefold compose
//!   builders (`compress_basefold.rs`, `compress_basefold_recursion.rs`,
//!   `basefold_programs.rs`) to select between
//!   [`super::recursion_public_values_digest`] and
//!   [`super::root_public_values_digest`] in the public-values output stream.
//! - [`ZKMCompressWitnessValues`] / [`ZKMCompressWitnessVariable`] /
//!   [`ZKMCompressShape`] — data-type carriers retained because
//!   [`super::wrap`] (the legacy outer-circuit FRI verifier consumed by
//!   `build_outer_circuit` and ultimately by the gnark / Groth16 / PLONK
//!   bn254 backend) still takes a [`ZKMCompressWitnessVariable`] input.
//! - `ZKMCompressWitnessValues::dummy` — wires the shape-enumerator pipeline
//!   to `dummy_recursion_basefold_vk_and_shard_proof` (the only dummy still
//!   alive post-Phase-3e).

use p3_air::Air;
use p3_koala_bear::KoalaBear;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zkm_recursion_compiler::ir::Felt;

use zkm_stark::{
    air::MachineAir,
    koala_bear_poseidon2::KoalaBearPoseidon2,
    shape::OrderedShape,
    Dom, ShardProof, StarkGenericConfig, StarkMachine, StarkVerifyingKey,
};

use crate::{
    stark::{dummy_recursion_basefold_vk_and_shard_proof, ShardProofVariable},
    CircuitConfig, KoalaBearFriParameters, KoalaBearFriParametersVariable, VerifyingKeyVariable,
};

/// Selector tag passed to the basefold compose verifiers to choose between
/// [`super::recursion_public_values_digest`] (the standard reduce digest used
/// at intermediate compress layers) and [`super::root_public_values_digest`]
/// (used at the root layer, which is wrap's input).
pub enum PublicValuesOutputDigest {
    Reduce,
    Root,
}

/// Witness layout for the compress stage verifier.
///
/// Consumed by [`super::wrap::ZKMWrapVerifier::verify`] (the outer-circuit
/// FRI verifier — wrap stays on FRI per the HYBRID memo). The basefold
/// compose path uses
/// [`super::compress_basefold::ZKMCompressBasefoldWitnessVariable`] instead.
pub struct ZKMCompressWitnessVariable<
    C: CircuitConfig<F = KoalaBear>,
    SC: KoalaBearFriParametersVariable<C>,
> {
    /// The shard proofs to verify.
    pub vks_and_proofs: Vec<(VerifyingKeyVariable<C, SC>, ShardProofVariable<C, SC>)>,
    pub is_complete: Felt<C::F>,
}

/// An input layout for the reduce verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "ShardProof<SC>: Serialize, Dom<SC>: Serialize"))]
#[serde(bound(deserialize = "ShardProof<SC>: Deserialize<'de>, Dom<SC>: DeserializeOwned"))]
pub struct ZKMCompressWitnessValues<SC: StarkGenericConfig> {
    pub vks_and_proofs: Vec<(StarkVerifyingKey<SC>, ShardProof<SC>)>,
    pub is_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZKMCompressShape {
    pub(crate) proof_shapes: Vec<OrderedShape>,
}

impl<SC: KoalaBearFriParameters> ZKMCompressWitnessValues<SC> {
    pub fn shape(&self) -> ZKMCompressShape {
        let proof_shapes = self.vks_and_proofs.iter().map(|(_, proof)| proof.shape()).collect();
        ZKMCompressShape { proof_shapes }
    }
}

impl ZKMCompressWitnessValues<KoalaBearPoseidon2> {
    /// Step 5 Phase 3e (May 19 2026): the env-gated dispatcher seam
    /// was retired with the rest of Phase 3e.  Basefold is the only
    /// recursion-shard shape now, so this calls
    /// `dummy_recursion_basefold_vk_and_shard_proof` directly.
    /// The trait bound `A: Air<VerifierConstraintFolder>` propagates
    /// from `dummy_basefold_vk_and_shard_proof` (which drives
    /// `prove_shard_to_basefold`).  Both `MipsAir` and
    /// `RecursionAir<F, DEGREE>` satisfy this via the standard
    /// `MachineAir` derive.
    pub fn dummy<A>(
        machine: &StarkMachine<KoalaBearPoseidon2, A>,
        shape: &ZKMCompressShape,
    ) -> Self
    where
        A: MachineAir<KoalaBear>
            + for<'b> Air<zkm_stark::folder::VerifierConstraintFolder<'b, KoalaBearPoseidon2>>,
    {
        let vks_and_proofs = shape
            .proof_shapes
            .iter()
            .map(|proof_shape| {
                let (vk, proof) =
                    dummy_recursion_basefold_vk_and_shard_proof(machine, proof_shape);
                (vk, proof)
            })
            .collect();

        Self { vks_and_proofs, is_complete: false }
    }
}

impl From<Vec<OrderedShape>> for ZKMCompressShape {
    fn from(proof_shapes: Vec<OrderedShape>) -> Self {
        Self { proof_shapes }
    }
}
