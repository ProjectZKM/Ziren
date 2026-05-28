//! Deferred-stage witness/value/shape **data-type carriers**.
//!
//! ## Task #397 (May 19 2026) — FRI deferred-body deletion
//!
//! The legacy in-circuit `ZKMDeferredVerifier::verify` body (the FRI-shaped
//! deferred-shard verifier originally inherited from SP1) has been retired.
//! The production deferred verifier lives in
//! [`super::deferred_basefold::verify_deferred_basefold`]; the recursion-AIR
//! variant lives in [`super::deferred_basefold_recursion`].
//!
//! The data types in this module are retained because:
//!
//! - [`ZKMDeferredWitnessValues`] is the concrete struct hosted by
//!   `ZKMCircuitWitness::Deferred` and round-tripped through the prover's
//!   shape enumerator + serde wire format. It carries a
//!   [`super::ZKMMerkleProofWitnessValues`] which still has a live consumer
//!   under the basefold compose path (`compress_basefold.rs:212`).
//! - [`ZKMDeferredShape`] is similarly the shape-enumeration carrier on the
//!   compress branch, and references [`super::ZKMCompressShape`] from
//!   [`super::compress`].
//!
//! [`ZKMDeferredWitnessVariable`] is the in-circuit binding for the
//! `Witnessable` impl in [`super::witness`]; the read/write half is
//! preserved so the witness stream stays back-compat with downstream proof
//! payloads.

use p3_air::Air;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use zkm_recursion_compiler::ir::Felt;
use zkm_stark::{
    air::{MachineAir, POSEIDON_NUM_WORDS},
    koala_bear_poseidon2::KoalaBearPoseidon2,
    Dom, ShardProof, StarkMachine, StarkVerifyingKey, Word,
};

use zkm_recursion_core::{air::PV_DIGEST_NUM_WORDS, DIGEST_SIZE};

use crate::{
    hash::{FieldHasher, FieldHasherVariable},
    stark::ShardProofVariable,
    CircuitConfig, KoalaBearFriParameters, KoalaBearFriParametersVariable, VerifyingKeyVariable,
};

use super::{
    ZKMCompressShape, ZKMCompressWitnessValues, ZKMMerkleProofWitnessValues,
    ZKMMerkleProofWitnessVariable,
};

#[derive(Debug, Clone, Hash)]
pub struct ZKMDeferredShape {
    pub(crate) inner: ZKMCompressShape,
    pub(crate) height: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "SC::Challenger: Serialize, ShardProof<SC>: Serialize, Dom<SC>: Serialize, [SC::Val; DIGEST_SIZE]: Serialize, SC::Digest: Serialize"
))]
#[serde(bound(
    deserialize = "SC::Challenger: Deserialize<'de>, ShardProof<SC>: Deserialize<'de>, Dom<SC>: DeserializeOwned, [SC::Val; DIGEST_SIZE]: Deserialize<'de>, SC::Digest: Deserialize<'de>"
))]
pub struct ZKMDeferredWitnessValues<SC: KoalaBearFriParameters + FieldHasher<KoalaBear>> {
    pub vks_and_proofs: Vec<(StarkVerifyingKey<SC>, ShardProof<SC>)>,
    pub vk_merkle_data: ZKMMerkleProofWitnessValues<SC>,
    pub start_reconstruct_deferred_digest: [SC::Val; POSEIDON_NUM_WORDS],
    pub zkm_vk_digest: [SC::Val; DIGEST_SIZE],
    pub committed_value_digest: [Word<SC::Val>; PV_DIGEST_NUM_WORDS],
    pub deferred_proofs_digest: [SC::Val; POSEIDON_NUM_WORDS],
    pub end_pc: SC::Val,
    pub end_shard: SC::Val,
    pub end_execution_shard: SC::Val,
    pub init_addr_bits: [SC::Val; 32],
    pub finalize_addr_bits: [SC::Val; 32],
    pub is_complete: bool,
}

pub struct ZKMDeferredWitnessVariable<
    C: CircuitConfig<F = KoalaBear>,
    SC: FieldHasherVariable<C> + KoalaBearFriParametersVariable<C>,
> {
    pub vks_and_proofs: Vec<(VerifyingKeyVariable<C, SC>, ShardProofVariable<C, SC>)>,
    pub vk_merkle_data: ZKMMerkleProofWitnessVariable<C, SC>,
    pub start_reconstruct_deferred_digest: [Felt<C::F>; POSEIDON_NUM_WORDS],
    pub zkm_vk_digest: [Felt<C::F>; DIGEST_SIZE],
    pub committed_value_digest: [Word<Felt<C::F>>; PV_DIGEST_NUM_WORDS],
    pub deferred_proofs_digest: [Felt<C::F>; POSEIDON_NUM_WORDS],
    pub end_pc: Felt<C::F>,
    pub end_shard: Felt<C::F>,
    pub end_execution_shard: Felt<C::F>,
    pub init_addr_bits: [Felt<C::F>; 32],
    pub finalize_addr_bits: [Felt<C::F>; 32],
    pub is_complete: Felt<C::F>,
}

impl ZKMDeferredWitnessValues<KoalaBearPoseidon2> {
    /// Step 5 Phase 3b (May 19 2026) bound widening — see the matching
    /// note on `ZKMCompressWitnessValues::dummy`.
    pub fn dummy<A>(
        machine: &StarkMachine<KoalaBearPoseidon2, A>,
        shape: &ZKMDeferredShape,
        log2_combined_leaves: Option<usize>,
    ) -> Self
    where
        A: MachineAir<KoalaBear>
            + for<'b> Air<zkm_stark::folder::VerifierConstraintFolder<'b, KoalaBearPoseidon2>>,
    {
        let inner_witness = ZKMCompressWitnessValues::<KoalaBearPoseidon2>::dummy(
            machine,
            &shape.inner,
            log2_combined_leaves,
        );
        let vks_and_proofs = inner_witness.vks_and_proofs;

        let vk_merkle_data = ZKMMerkleProofWitnessValues::dummy(vks_and_proofs.len(), shape.height);

        Self {
            vks_and_proofs,
            vk_merkle_data,
            is_complete: true,
            zkm_vk_digest: [KoalaBear::ZERO; DIGEST_SIZE],
            start_reconstruct_deferred_digest: [KoalaBear::ZERO; POSEIDON_NUM_WORDS],
            committed_value_digest: [Word::default(); PV_DIGEST_NUM_WORDS],
            deferred_proofs_digest: [KoalaBear::ZERO; POSEIDON_NUM_WORDS],
            end_pc: KoalaBear::ZERO,
            end_shard: KoalaBear::ZERO,
            end_execution_shard: KoalaBear::ZERO,
            init_addr_bits: [KoalaBear::ZERO; 32],
            finalize_addr_bits: [KoalaBear::ZERO; 32],
        }
    }
}

impl ZKMDeferredShape {
    pub const fn new(inner: ZKMCompressShape, height: usize) -> Self {
        Self { inner, height }
    }
}
