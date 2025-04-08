use std::marker::PhantomData;

use p3_air::Air;
use p3_commit::Mmcs;
use p3_field::FieldAlgebra;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use serde::{Deserialize, Serialize};
use zkm_recursion_compiler::ir::{Builder, Felt};
use zkm_recursion_core::DIGEST_SIZE;
use zkm_stark::{
    air::MachineAir, koala_bear_poseidon2::KoalaBearPoseidon2, Com, InnerChallenge, OpeningProof,
    StarkGenericConfig, StarkMachine,
};

use crate::{
    challenger::DuplexChallengerVariable,
    constraints::RecursiveVerifierConstraintFolder,
    hash::{FieldHasher, FieldHasherVariable},
    merkle_tree::{verify, MerkleProof},
    stark::MerkleProofVariable,
    witness::{WitnessWriter, Witnessable},
    CircuitConfig, FriProofVariable, KoalaBearFriConfig, KoalaBearFriConfigVariable,
};

use super::{
    PublicValuesOutputDigest, ZKMCompressShape, ZKMCompressVerifier, ZKMCompressWitnessValues,
    ZKMCompressWitnessVariable,
};

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
    SC: FieldHasherVariable<C> + KoalaBearFriConfigVariable<C>,
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
    SC: KoalaBearFriConfigVariable<C>,
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

#[derive(Debug, Clone, Copy)]
pub struct ZKMCompressWithVKeyVerifier<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

/// Witness layout for the verifier of the proof shape phase of the compress stage.
pub struct ZKMCompressWithVKeyWitnessVariable<
    C: CircuitConfig<F = KoalaBear>,
    SC: KoalaBearFriConfigVariable<C>,
> {
    pub compress_var: ZKMCompressWitnessVariable<C, SC>,
    pub merkle_var: ZKMMerkleProofWitnessVariable<C, SC>,
}

/// An input layout for the verifier of the proof shape phase of the compress stage.
pub struct ZKMCompressWithVKeyWitnessValues<SC: StarkGenericConfig + FieldHasher<KoalaBear>> {
    pub compress_val: ZKMCompressWitnessValues<SC>,
    pub merkle_val: ZKMMerkleProofWitnessValues<SC>,
}

impl<C, SC, A> ZKMCompressWithVKeyVerifier<C, SC, A>
where
    SC: KoalaBearFriConfigVariable<
        C,
        FriChallengerVariable = DuplexChallengerVariable<C>,
        DigestVariable = [Felt<KoalaBear>; DIGEST_SIZE],
    >,
    C: CircuitConfig<F = SC::Val, EF = SC::Challenge, Bit = Felt<KoalaBear>>,
    <SC::ValMmcs as Mmcs<KoalaBear>>::ProverData<RowMajorMatrix<KoalaBear>>: Clone,
    A: MachineAir<SC::Val> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
{
    /// Verify the proof shape phase of the compress stage.
    pub fn verify(
        builder: &mut Builder<C>,
        machine: &StarkMachine<SC, A>,
        input: ZKMCompressWithVKeyWitnessVariable<C, SC>,
        value_assertions: bool,
        kind: PublicValuesOutputDigest,
    ) {
        let values = input
            .compress_var
            .vks_and_proofs
            .iter()
            .map(|(vk, _)| vk.hash(builder))
            .collect::<Vec<_>>();
        let vk_root = input.merkle_var.root.map(|x| builder.eval(x));
        ZKMMerkleProofVerifier::verify(builder, values, input.merkle_var, value_assertions);
        ZKMCompressVerifier::verify(builder, machine, input.compress_var, vk_root, kind);
    }
}

impl<SC: KoalaBearFriConfig + FieldHasher<KoalaBear>> ZKMCompressWithVKeyWitnessValues<SC> {
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
    pub fn dummy<A: MachineAir<KoalaBear>>(
        machine: &StarkMachine<KoalaBearPoseidon2, A>,
        shape: &ZKMCompressWithVkeyShape,
    ) -> Self {
        let compress_val =
            ZKMCompressWitnessValues::<KoalaBearPoseidon2>::dummy(machine, &shape.compress_shape);
        let num_proofs = compress_val.vks_and_proofs.len();
        let merkle_val = ZKMMerkleProofWitnessValues::<KoalaBearPoseidon2>::dummy(
            num_proofs,
            shape.merkle_tree_height,
        );
        Self { compress_val, merkle_val }
    }
}

impl<C: CircuitConfig<F = KoalaBear, EF = InnerChallenge>, SC: KoalaBearFriConfigVariable<C>>
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
