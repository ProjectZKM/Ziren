use std::{borrow::Borrow, fs::File, path::Path};

use anyhow::Result;
use clap::ValueEnum;
use p3_bn254_fr::Bn254;
use p3_commit::Pcs;
use p3_field::{PrimeField, PrimeField32};
use p3_koala_bear::KoalaBear;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zkm_core_machine::{io::ZKMStdin, reduce::ZKMReduceProof};
use zkm_primitives::{io::ZKMPublicValues, poseidon2_hash};

use zkm_recursion_circuit::machine::compress_basefold::ZKMCompressBasefoldWitnessValues;
use zkm_recursion_circuit::machine::core_basefold::ZKMCoreBasefoldWitnessValues;
use zkm_recursion_circuit::machine::deferred_basefold::ZKMDeferredBasefoldWitnessValues;

use zkm_recursion_gnark_ffi::proof::{Groth16Bn254Proof, PlonkBn254Proof};

use thiserror::Error;
use zkm_pcs::{ShardProof, StarkGenericConfig, StarkProvingKey, StarkVerifyingKey, DIGEST_SIZE};

use crate::{
    utils::{koalabears_to_bn254, words_to_bytes_be},
    CompressedSC, CoreSC, InnerSC,
};

/// The information necessary to generate a proof for a given MIPS program.
#[derive(Clone, Serialize, Deserialize)]
pub struct ZKMProvingKey {
    pub pk: StarkProvingKey<CoreSC>,
    pub elf: Vec<u8>,
    /// Verifying key is also included as we need it for recursion
    pub vk: ZKMVerifyingKey,
}

/// The information necessary to verify a proof for a given MIPS program.
#[derive(Clone, Serialize, Deserialize)]
pub struct ZKMVerifyingKey {
    pub vk: StarkVerifyingKey<CoreSC>,
}

/// A trait for keys that can be hashed into a digest.
pub trait HashableKey {
    /// Hash the key into a digest of KoalaBear elements.
    fn hash_koalabear(&self) -> [KoalaBear; DIGEST_SIZE];

    /// Hash the key into a digest of  u32 elements.
    fn hash_u32(&self) -> [u32; DIGEST_SIZE];

    fn hash_bn254(&self) -> Bn254 {
        koalabears_to_bn254(&self.hash_koalabear())
    }

    fn bytes32(&self) -> String {
        let vkey_digest_bn254 = self.hash_bn254();
        format!("0x{:0>64}", vkey_digest_bn254.as_canonical_biguint().to_str_radix(16))
    }

    /// Hash the key into a digest of bytes elements.
    fn hash_bytes(&self) -> [u8; DIGEST_SIZE * 4] {
        words_to_bytes_be(&self.hash_u32())
    }
}

impl HashableKey for ZKMVerifyingKey {
    fn hash_koalabear(&self) -> [KoalaBear; DIGEST_SIZE] {
        <CoreSC as RingDigests>::vk_public_digest(&self.vk)
    }

    fn hash_u32(&self) -> [u32; DIGEST_SIZE] {
        self.hash_koalabear().map(|n| n.as_canonical_u32())
    }
}

impl<SC: StarkGenericConfig<Val = KoalaBear>> HashableKey for StarkVerifyingKey<SC>
where
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment:
        std::borrow::Borrow<[[KoalaBear; DIGEST_SIZE]]>,
{
    fn hash_koalabear(&self) -> [KoalaBear; DIGEST_SIZE] {
        let mut inputs: Vec<KoalaBear> = Vec::with_capacity(DIGEST_SIZE + 1 + 14);
        let cap: &[[KoalaBear; DIGEST_SIZE]] = self.commit.borrow();
        inputs.extend(&cap[0]);
        inputs.push(self.pc_start);
        inputs.extend(self.initial_global_cumulative_sum.0.x.0);
        inputs.extend(self.initial_global_cumulative_sum.0.y.0);

        poseidon2_hash(inputs)
    }

    fn hash_u32(&self) -> [u32; 8] {
        self.hash_koalabear()
            .into_iter()
            .map(|n| n.as_canonical_u32())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

/// A proof of a MIPS ELF execution with given inputs and outputs.
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound(serialize = "P: Serialize"))]
#[serde(bound(deserialize = "P: DeserializeOwned"))]
pub struct ZKMProofWithMetadata<P: Clone> {
    pub proof: P,
    pub stdin: ZKMStdin,
    pub public_values: ZKMPublicValues,
    pub cycles: u64,
}

impl<P: Serialize + DeserializeOwned + Clone> ZKMProofWithMetadata<P> {
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        bincode::serialize_into(File::create(path).expect("failed to open file"), self)
            .map_err(Into::into)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        bincode::deserialize_from(File::open(path).expect("failed to open file"))
            .map_err(Into::into)
    }
}

impl<P: std::fmt::Debug + Clone> std::fmt::Debug for ZKMProofWithMetadata<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZKMProofWithMetadata").field("proof", &self.proof).finish()
    }
}

/// A proof of a Ziren program without any wrapping.
pub type ZKMCoreProof = ZKMProofWithMetadata<ZKMCoreProofData>;

/// A Ziren proof that has been recursively reduced into a single proof. This proof can be verified
/// within Ziren programs.
pub type ZKMReducedProof = ZKMProofWithMetadata<ZKMReducedProofData>;

/// A Ziren proof that has been wrapped into a single PLONK proof and can be verified onchain.
pub type ZKMPlonkBn254Proof = ZKMProofWithMetadata<ZKMPlonkBn254ProofData>;

/// A Ziren proof that has been wrapped into a single Groth16 proof and can be verified onchain.
pub type ZKMGroth16Bn254Proof = ZKMProofWithMetadata<ZKMGroth16Bn254ProofData>;

/// A Ziren proof that has been wrapped into a single proof and can be verified onchain.
pub type ZKMProof = ZKMProofWithMetadata<ZKMBn254ProofData>;

#[derive(Serialize, Deserialize, Clone)]
pub struct ZKMCoreProofData(pub Vec<ShardProof<CoreSC>>);

#[derive(Serialize, Deserialize, Clone)]
pub struct ZKMReducedProofData(pub ShardProof<InnerSC>);

#[derive(Serialize, Deserialize, Clone)]
pub struct ZKMPlonkBn254ProofData(pub PlonkBn254Proof);

#[derive(Serialize, Deserialize, Clone)]
pub struct ZKMGroth16Bn254ProofData(pub Groth16Bn254Proof);

#[derive(Serialize, Deserialize, Clone)]
pub enum ZKMBn254ProofData {
    Plonk(PlonkBn254Proof),
    Groth16(Groth16Bn254Proof),
}

impl ZKMBn254ProofData {
    pub fn get_proof_system(&self) -> ProofSystem {
        match self {
            ZKMBn254ProofData::Plonk(_) => ProofSystem::Plonk,
            ZKMBn254ProofData::Groth16(_) => ProofSystem::Groth16,
        }
    }

    pub fn get_raw_proof(&self) -> &str {
        match self {
            ZKMBn254ProofData::Plonk(proof) => &proof.raw_proof,
            ZKMBn254ProofData::Groth16(proof) => &proof.raw_proof,
        }
    }
}

#[derive(Debug, Default, Clone, ValueEnum, PartialEq, Eq)]
pub enum ProverMode {
    #[default]
    Cpu,
    Cuda,
    Network,
    #[value(skip)]
    Mock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSystem {
    Plonk,
    Groth16,
}

impl ProofSystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProofSystem::Plonk => "Plonk",
            ProofSystem::Groth16 => "Groth16",
        }
    }
}

/// A proof that can be reduced along with other proofs into one proof.
#[derive(Serialize, Deserialize, Clone)]
pub enum ZKMReduceProofWrapper {
    Core(ZKMReduceProof<CoreSC>),
    Recursive(ZKMReduceProof<InnerSC>),
}

#[derive(Error, Debug)]
pub enum ZKMRecursionProverError {
    #[error("Runtime error: {0}")]
    RuntimeError(String),
    #[error("Generate traces error")]
    TracesGenerationError,
    #[error("Generate dependencies error")]
    DependenciesGenerationError,
    #[error("Binary stage error: {0}")]
    BinaryStage(String),
}

/// A proof of the binary stage: the shrink program it executes, the digest
/// it commits to, and the proof of the recursion machine over bits.
pub struct BinaryShrinkProof {
    /// The shrink program, which fixes the machine and its keys.
    pub program: std::sync::Arc<zkm_recursion_core::RecursionProgram<p3_koala_bear::KoalaBear>>,
    /// The digest the program commits to: the stage's public values.
    pub digest: [u32; zkm_recursion_core::DIGEST_SIZE],
    /// The public values the digest is of, as canonical elements.
    pub public_values: Vec<u32>,
    /// The proof.
    pub proof: zkm_binary_stark::config::MachineProof,
}

/// A recursion vk whose KoalaBear digest `digest` is not one of the
/// `map_size` keys of the vk allowlist.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("vk not allowed: {digest:?} (map_size={map_size})")]
pub struct VkNotAllowed {
    pub digest: Vec<u32>,
    pub map_size: usize,
}

impl From<VkNotAllowed> for ZKMRecursionProverError {
    fn from(e: VkNotAllowed) -> Self {
        Self::RuntimeError(e.to_string())
    }
}

#[allow(clippy::large_enum_variant)]
pub enum ZKMCircuitWitness {
    /// Basefold-shape normalize input — consumes `JaggedShardProof`s from
    /// the core prover (carried on `ShardProof.jagged_shard_proof`).
    /// Dispatches to `build_normalize_basefold_program` during compress.
    CoreBasefold(ZKMCoreBasefoldWitnessValues<CoreSC>),
    /// Basefold-shape compose input — tree-reduction layer.
    /// Dispatches to `build_compose_basefold_program`.
    ComposeBasefold(ZKMCompressBasefoldWitnessValues<InnerSC>),
    /// Basefold-shape deferred input — verifies already-recursed deferred
    /// branches. Dispatches to `build_deferred_basefold_program`.
    DeferredBasefold(ZKMDeferredBasefoldWitnessValues<CompressedSC>),
}

/// What a ring hashes on the host as its circuit hashes it in-ring: the
/// digests of verifying keys and of public values.
pub trait RingDigests:
    StarkGenericConfig<Val = KoalaBear> + zkm_recursion_circuit::hash::FieldHasher<KoalaBear>
{
    /// The key's digest, which keys the recursion key map and its tree.
    fn vk_map_digest(
        vk: &StarkVerifyingKey<Self>,
    ) -> <Self as zkm_recursion_circuit::hash::FieldHasher<KoalaBear>>::Digest;

    /// A digest as the eight elements the public values carry: the digest
    /// itself for an eight-element digest, its root felts for a Blake3 one.
    fn public_felts(
        digest: <Self as zkm_recursion_circuit::hash::FieldHasher<KoalaBear>>::Digest,
    ) -> [KoalaBear; DIGEST_SIZE];

    /// The key's digest as the eight elements the public values carry.
    fn vk_public_digest(vk: &StarkVerifyingKey<Self>) -> [KoalaBear; DIGEST_SIZE] {
        Self::public_felts(Self::vk_map_digest(vk))
    }

    /// The hash of `values` as the eight elements of a public values digest.
    fn hash_public_felts(&self, values: &[KoalaBear]) -> [KoalaBear; DIGEST_SIZE];
}

impl<const P: u8> RingDigests for zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2Ring<P> {
    fn vk_map_digest(vk: &StarkVerifyingKey<Self>) -> [KoalaBear; DIGEST_SIZE] {
        vk.hash_koalabear()
    }

    fn public_felts(digest: [KoalaBear; DIGEST_SIZE]) -> [KoalaBear; DIGEST_SIZE] {
        digest
    }

    fn hash_public_felts(&self, values: &[KoalaBear]) -> [KoalaBear; DIGEST_SIZE] {
        use p3_symmetric::CryptographicHasher;
        zkm_pcs::InnerHash::new(self.perm.clone()).hash_slice(values)
    }
}

impl RingDigests for zkm_pcs::KoalaBearBlake3 {
    fn vk_map_digest(
        vk: &StarkVerifyingKey<Self>,
    ) -> [KoalaBear; zkm_recursion_circuit::blake3_circuit::DIGEST_LIMBS] {
        zkm_recursion_circuit::blake3_circuit::vk_digest(vk)
    }

    fn public_felts(
        digest: [KoalaBear; zkm_recursion_circuit::blake3_circuit::DIGEST_LIMBS],
    ) -> [KoalaBear; DIGEST_SIZE] {
        zkm_pcs::kb31_blake3::root_felts(&zkm_recursion_circuit::blake3_circuit::limbs_digest(
            &digest,
        ))
    }

    fn hash_public_felts(&self, values: &[KoalaBear]) -> [KoalaBear; DIGEST_SIZE] {
        use p3_symmetric::CryptographicHasher;
        let bytes = values.iter().flat_map(|v| v.as_canonical_u32().to_le_bytes());
        let digest: [u8; 32] = p3_blake3::Blake3.hash_iter(bytes);
        zkm_pcs::kb31_blake3::root_felts(&digest)
    }
}

/// A verifying key's digest under its ring, as the recursion key map knows it.
pub trait RingVkDigest {
    /// The ring's digest of the key.
    type Digest;

    fn ring_digest(&self) -> Self::Digest;
}

impl<SC: RingDigests> RingVkDigest for StarkVerifyingKey<SC> {
    type Digest = <SC as zkm_recursion_circuit::hash::FieldHasher<KoalaBear>>::Digest;

    fn ring_digest(&self) -> Self::Digest {
        SC::vk_map_digest(self)
    }
}

impl RingVkDigest for ZKMVerifyingKey {
    type Digest = <CoreSC as zkm_recursion_circuit::hash::FieldHasher<KoalaBear>>::Digest;

    fn ring_digest(&self) -> Self::Digest {
        CoreSC::vk_map_digest(&self.vk)
    }
}
