//! VK-merkle-proof verifier + compress-with-vkey **data-type carriers**.
//!
//! ## Task #397 (May 19 2026) — FRI compose-with-vkey body deletion
//!
//! The legacy `ZKMCompressWithVKeyVerifier::verify` body (which performed
//! the VK merkle check and then re-entered the FRI compose verifier) has
//! been removed. The vkey check is now inlined at the head of the basefold
//! compose verifier (see `compress_basefold.rs:212`,
//! `deferred_basefold.rs:168`, `wrap_basefold.rs:128`), which calls
//! [`ZKMMerkleProofVerifier::verify`] directly.
//!
//! Retained surface (still on live import paths):
//!
//! - [`ZKMMerkleProofVerifier`] — the actual basefold-path vkey verifier,
//!   live in three call sites.
//! - [`ZKMMerkleProofWitnessValues`] / [`ZKMMerkleProofWitnessVariable`] —
//!   the witness carriers for the merkle proof, consumed by
//!   `compress_basefold::ZKMCompressBasefoldWitnessValues::vk_merkle_data`
//!   and the deferred/wrap basefold variants.
//! - [`ZKMCompressWithVKeyWitnessValues`] / [`ZKMCompressWithVkeyShape`] /
//!   [`ZKMCompressWithVKeyWitnessVariable`] — data-type carriers used by
//!   the prover (`crates/prover/src/lib.rs:1582-1620`) when assembling the
//!   pre-compose witness payload.
//! - `ZKMCompressWithVKeyWitnessValues::dummy` — used by the shape
//!   enumerator pipeline.

use std::marker::PhantomData;

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use serde::{Deserialize, Serialize};
use zkm_recursion_compiler::ir::{Builder, Felt};
use zkm_recursion_core::DIGEST_SIZE;
use zkm_stark::{
    air::MachineAir, koala_bear_poseidon2::KoalaBearPoseidon2, Com, InnerChallenge, OpeningProof,
    StarkGenericConfig, StarkMachine,
};

use crate::{
    hash::{FieldHasher, FieldHasherVariable},
    merkle_tree::{verify, MerkleProof},
    stark::MerkleProofVariable,
    witness::{WitnessWriter, Witnessable},
    CircuitConfig, FriProofVariable, KoalaBearFriParameters, KoalaBearFriParametersVariable,
};

use super::{ZKMCompressShape, ZKMCompressWitnessValues, ZKMCompressWitnessVariable};

/// A program to verify a batch of recursive proofs and aggregate their public values.
#[derive(Debug, Clone, Copy)]
pub struct ZKMMerkleProofVerifier<C, SC> {
    _phantom: PhantomData<(C, SC)>,
}

/// The shape of the compress proof with vk validation proofs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZKMCompressWithVkeyShape {
    pub compress_shape: ZKMCompressShape,
    pub merkle_tree_height: usize,
}

/// Witness layout for the compress stage verifier.
pub struct ZKMMerkleProofWitnessVariable<
    C: CircuitConfig<F = KoalaBear>,
    SC: FieldHasherVariable<C> + KoalaBearFriParametersVariable<C>,
> {
    /// The shard proofs to verify.
    pub vk_merkle_proofs: Vec<MerkleProofVariable<C, SC>>,
    /// Hinted values to enable dummy digests.
    pub values: Vec<SC::DigestVariable>,
    /// The root of the merkle tree.
    pub root: SC::DigestVariable,
}

/// An input layout for the reduce verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "SC::Digest: Serialize"))]
#[serde(bound(deserialize = "SC::Digest: Deserialize<'de>"))]
pub struct ZKMMerkleProofWitnessValues<SC: FieldHasher<KoalaBear>> {
    pub vk_merkle_proofs: Vec<MerkleProof<KoalaBear, SC>>,
    pub values: Vec<SC::Digest>,
    pub root: SC::Digest,
}

impl<C, SC> ZKMMerkleProofVerifier<C, SC>
where
    SC: KoalaBearFriParametersVariable<C>,
    C: CircuitConfig<F = SC::Val, EF = SC::Challenge>,
{
    /// Verify (via Merkle tree) that the vkey digests of a proof belong to a specified set (encoded
    /// the Merkle tree proofs in input).
    pub fn verify(
        builder: &mut Builder<C>,
        digests: Vec<SC::DigestVariable>,
        input: ZKMMerkleProofWitnessVariable<C, SC>,
        value_assertions: bool,
    ) {
        let ZKMMerkleProofWitnessVariable { vk_merkle_proofs, values, root } = input;
        for ((proof, value), expected_value) in
            vk_merkle_proofs.into_iter().zip(values).zip(digests)
        {
            verify(builder, proof, value, root);
            if value_assertions {
                SC::assert_digest_eq(builder, expected_value, value);
            } else {
                SC::assert_digest_eq(builder, value, value);
            }
        }
    }
}

/// Witness layout for the verifier of the proof shape phase of the compress stage.
pub struct ZKMCompressWithVKeyWitnessVariable<
    C: CircuitConfig<F = KoalaBear>,
    SC: KoalaBearFriParametersVariable<C>,
> {
    pub compress_var: ZKMCompressWitnessVariable<C, SC>,
    pub merkle_var: ZKMMerkleProofWitnessVariable<C, SC>,
}

/// An input layout for the verifier of the proof shape phase of the compress stage.
pub struct ZKMCompressWithVKeyWitnessValues<SC: StarkGenericConfig + FieldHasher<KoalaBear>> {
    pub compress_val: ZKMCompressWitnessValues<SC>,
    pub merkle_val: ZKMMerkleProofWitnessValues<SC>,
}

impl<SC: KoalaBearFriParameters + FieldHasher<KoalaBear>> ZKMCompressWithVKeyWitnessValues<SC> {
    pub fn shape(&self) -> ZKMCompressWithVkeyShape {
        let merkle_tree_height = self.merkle_val.vk_merkle_proofs.first().unwrap().path.len();
        ZKMCompressWithVkeyShape { compress_shape: self.compress_val.shape(), merkle_tree_height }
    }
}

impl ZKMMerkleProofWitnessValues<KoalaBearPoseidon2> {
    pub fn dummy(num_proofs: usize, height: usize) -> Self {
        let dummy_digest = [KoalaBear::ZERO; DIGEST_SIZE];
        let vk_merkle_proofs =
            vec![MerkleProof { index: 0, path: vec![dummy_digest; height] }; num_proofs];
        let values = vec![dummy_digest; num_proofs];

        Self { vk_merkle_proofs, values, root: dummy_digest }
    }
}

impl ZKMCompressWithVKeyWitnessValues<KoalaBearPoseidon2> {
    /// Step 5 Phase 3b (May 19 2026) bound widening matches the
    /// `ZKMCompressWitnessValues::dummy` delegate below — propagates
    /// the `Air<VerifierConstraintFolder>` bound required by the
    /// basefold-shaped dummy under
    /// `ZIREN_FORCE_BASEFOLD_FOR_RECURSION=1`.
    pub fn dummy<A>(
        machine: &StarkMachine<KoalaBearPoseidon2, A>,
        shape: &ZKMCompressWithVkeyShape,
        log2_combined_leaves: Option<usize>,
    ) -> Self
    where
        A: MachineAir<KoalaBear>
            + for<'b> p3_air::Air<zkm_stark::folder::VerifierConstraintFolder<'b, KoalaBearPoseidon2>>,
    {
        let compress_val = ZKMCompressWitnessValues::<KoalaBearPoseidon2>::dummy(
            machine,
            &shape.compress_shape,
            log2_combined_leaves,
        );
        let num_proofs = compress_val.vks_and_proofs.len();
        let merkle_val = ZKMMerkleProofWitnessValues::<KoalaBearPoseidon2>::dummy(
            num_proofs,
            shape.merkle_tree_height,
        );
        Self { compress_val, merkle_val }
    }
}

impl<C: CircuitConfig<F = KoalaBear, EF = InnerChallenge>, SC: KoalaBearFriParametersVariable<C>>
    Witnessable<C> for ZKMCompressWithVKeyWitnessValues<SC>
where
    Com<SC>: Witnessable<C, WitnessVariable = <SC as FieldHasherVariable<C>>::DigestVariable>,
    // This trait bound is redundant, but Rust-Analyzer is not able to infer it.
    SC: FieldHasher<KoalaBear>,
    <SC as FieldHasher<KoalaBear>>::Digest: Witnessable<C, WitnessVariable = SC::DigestVariable>,
    OpeningProof<SC>: Witnessable<C, WitnessVariable = FriProofVariable<C, SC>>,
{
    type WitnessVariable = ZKMCompressWithVKeyWitnessVariable<C, SC>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        ZKMCompressWithVKeyWitnessVariable {
            compress_var: self.compress_val.read(builder),
            merkle_var: self.merkle_val.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.compress_val.write(witness);
        self.merkle_val.write(witness);
    }
}
