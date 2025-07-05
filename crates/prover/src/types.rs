use std::{fs::File, path::Path};

use anyhow::Result;
use clap::ValueEnum;
use p3_bn254_fr::Bn254Fr;
use p3_commit::{Pcs, TwoAdicMultiplicativeCoset};
use p3_field::{FieldAlgebra, PrimeField, PrimeField32, TwoAdicField};
use p3_koala_bear::KoalaBear;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zkm_core_machine::{io::ZKMStdin, reduce::ZKMReduceProof};
use zkm_primitives::{io::ZKMPublicValues, poseidon2_hash};

use zkm_recursion_circuit::machine::{
    ZKMCompressWitnessValues, ZKMDeferredWitnessValues, ZKMRecursionWitnessValues,
};

use zkm_recursion_gnark_ffi::proof::{Groth16Bn254Proof, PlonkBn254Proof};

use thiserror::Error;
use zkm_stark::{ShardProof, StarkGenericConfig, StarkProvingKey, StarkVerifyingKey, DIGEST_SIZE};

use crate::{
    utils::{koalabears_to_bn254, words_to_bytes_be},
    CoreSC, InnerSC,
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

    fn hash_bn254(&self) -> Bn254Fr {
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
        self.vk.hash_koalabear()
    }

    fn hash_u32(&self) -> [u32; DIGEST_SIZE] {
        self.vk.hash_u32()
    }
}

impl<SC: StarkGenericConfig<Val = KoalaBear, Domain = TwoAdicMultiplicativeCoset<KoalaBear>>>
    HashableKey for StarkVerifyingKey<SC>
where
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: AsRef<[KoalaBear; DIGEST_SIZE]>,
{
    fn hash_koalabear(&self) -> [KoalaBear; DIGEST_SIZE] {
        let prep_domains = self.chip_information.iter().map(|(_, domain, _)| domain);
        let num_inputs = DIGEST_SIZE + 1 + 14 + (4 * prep_domains.len());
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(self.commit.as_ref());
        inputs.push(self.pc_start);
        inputs.extend(self.initial_global_cumulative_sum.0.x.0);
        inputs.extend(self.initial_global_cumulative_sum.0.y.0);
        for domain in prep_domains {
            inputs.push(KoalaBear::from_canonical_usize(domain.log_n));
            let size = 1 << domain.log_n;
            inputs.push(KoalaBear::from_canonical_usize(size));
            let g = KoalaBear::two_adic_generator(domain.log_n);
            inputs.push(domain.shift);
            inputs.push(g);
        }

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
}

#[allow(clippy::large_enum_variant)]
pub enum ZKMCircuitWitness {
    Core(ZKMRecursionWitnessValues<CoreSC>),
    Deferred(ZKMDeferredWitnessValues<InnerSC>),
    Compress(ZKMCompressWitnessValues<InnerSC>),
}
