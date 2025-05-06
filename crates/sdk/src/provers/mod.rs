mod cpu;
// #[cfg(feature = "cuda")]
// mod cuda;
mod mock;

pub use cpu::CpuProver;
// #[cfg(feature = "cuda")]
// pub use cuda::CudaProver;
pub use mock::MockProver;

use itertools::Itertools;
use p3_field::PrimeField32;
use std::borrow::Borrow;
use std::time::Duration;

use anyhow::Result;
use strum_macros::EnumString;
use thiserror::Error;
use zkm_core_executor::ExecutionReport;
use zkm_core_executor::ZKMContext;
use zkm_core_machine::{io::ZKMStdin, ZKM_CIRCUIT_VERSION};
use zkm_primitives::io::ZKMPublicValues;
use zkm_prover::{
    components::{DefaultProverComponents, ZKMProverComponents},
    CoreSC, InnerSC, ZKMCoreProofData, ZKMProver, ZKMProvingKey, ZKMVerifyingKey,
};
use zkm_stark::{air::PublicValues, MachineVerificationError, Word, ZKMProverOpts};

use crate::install::try_install_circuit_artifacts;
use crate::ProverClient;
use crate::{ZKMProof, ZKMProofKind, ZKMProofWithPublicValues};

/// The type of prover.
#[derive(Debug, PartialEq, EnumString)]
pub enum ProverType {
    Cpu,
    Cuda,
    Mock,
    Network,
}

/// Options to configure proof generation.
#[derive(Clone, Default)]
pub struct ProofOpts {
    /// Options to configure the zkMIPS prover.
    pub zkm_prover_opts: ZKMProverOpts,
    /// Optional timeout duration for proof generation.
    pub timeout: Option<Duration>,
}

#[derive(Error, Debug)]
pub enum ZKMVerificationError {
    #[error("Invalid public values")]
    InvalidPublicValues,
    #[error("Version mismatch")]
    VersionMismatch(String),
    #[error("Core machine verification error: {0}")]
    Core(MachineVerificationError<CoreSC>),
    #[error("Recursion verification error: {0}")]
    Recursion(MachineVerificationError<InnerSC>),
    #[error("Plonk verification error: {0}")]
    Plonk(anyhow::Error),
    #[error("Groth16 verification error: {0}")]
    Groth16(anyhow::Error),
}

/// An implementation of [crate::ProverClient].
pub trait Prover<C: ZKMProverComponents>: Send + Sync {
    fn id(&self) -> ProverType;

    fn zkm_prover(&self) -> &ZKMProver<C>;

    fn version(&self) -> &str {
        ZKM_CIRCUIT_VERSION
    }

    /// Executes the program on the given input.
    fn execute(&self, elf: &[u8], stdin: &ZKMStdin) -> Result<(ZKMPublicValues, ExecutionReport)> {
        Ok(self.zkm_prover().execute(elf, stdin, ZKMContext::default())?)
    }

    /// Generate the proving and verifying keys for the given program.
    fn setup(&self, elf: &[u8]) -> (ZKMProvingKey, ZKMVerifyingKey);

    /// Prove the execution of a MIPS ELF with the given inputs, according to the given proof mode.
    fn prove<'a>(
        &'a self,
        pk: &ZKMProvingKey,
        stdin: ZKMStdin,
        opts: ProofOpts,
        context: ZKMContext<'a>,
        kind: ZKMProofKind,
    ) -> Result<ZKMProofWithPublicValues>;

    /// Verify that an zkMIPS proof is valid given its vkey and metadata.
    /// For Plonk proofs, verifies that the public inputs of the PlonkBn254 proof match
    /// the hash of the VK and the committed public values of the ZKMProofWithPublicValues.
    fn verify(
        &self,
        bundle: &ZKMProofWithPublicValues,
        vkey: &ZKMVerifyingKey,
    ) -> Result<(), ZKMVerificationError> {
        if bundle.zkm_version != self.version() {
            return Err(ZKMVerificationError::VersionMismatch(bundle.zkm_version.clone()));
        }
        match &bundle.proof {
            ZKMProof::Core(proof) => {
                let public_values: &PublicValues<Word<_>, _> =
                    proof.last().unwrap().public_values.as_slice().borrow();

                // Get the committed value digest bytes.
                let committed_value_digest_bytes = public_values
                    .committed_value_digest
                    .iter()
                    .flat_map(|w| w.0.iter().map(|x| x.as_canonical_u32() as u8))
                    .collect_vec();

                // Make sure the committed value digest matches the public values hash.
                for (a, b) in
                    committed_value_digest_bytes.iter().zip_eq(bundle.public_values.hash())
                {
                    if *a != b {
                        return Err(ZKMVerificationError::InvalidPublicValues);
                    }
                }

                // Verify the core proof.
                self.zkm_prover()
                    .verify(&ZKMCoreProofData(proof.clone()), vkey)
                    .map_err(ZKMVerificationError::Core)
            }
            ZKMProof::Compressed(proof) => {
                let public_values: &PublicValues<Word<_>, _> =
                    proof.proof.public_values.as_slice().borrow();

                // Get the committed value digest bytes.
                let committed_value_digest_bytes = public_values
                    .committed_value_digest
                    .iter()
                    .flat_map(|w| w.0.iter().map(|x| x.as_canonical_u32() as u8))
                    .collect_vec();

                // Make sure the committed value digest matches the public values hash.
                for (a, b) in
                    committed_value_digest_bytes.iter().zip_eq(bundle.public_values.hash())
                {
                    if *a != b {
                        return Err(ZKMVerificationError::InvalidPublicValues);
                    }
                }

                self.zkm_prover()
                    .verify_compressed(proof, vkey)
                    .map_err(ZKMVerificationError::Recursion)
            }
            ZKMProof::Plonk(proof) => self
                .zkm_prover()
                .verify_plonk_bn254(
                    proof,
                    vkey,
                    &bundle.public_values,
                    &if zkm_prover::build::zkm_dev_mode() {
                        zkm_prover::build::plonk_bn254_artifacts_dev_dir()
                    } else {
                        try_install_circuit_artifacts("plonk")
                    },
                )
                .map_err(ZKMVerificationError::Plonk),
            ZKMProof::Groth16(proof) => self
                .zkm_prover()
                .verify_groth16_bn254(
                    proof,
                    vkey,
                    &bundle.public_values,
                    &if zkm_prover::build::zkm_dev_mode() {
                        zkm_prover::build::groth16_bn254_artifacts_dev_dir()
                    } else {
                        try_install_circuit_artifacts("groth16")
                    },
                )
                .map_err(ZKMVerificationError::Groth16),
        }
    }
}

impl Prover<DefaultProverComponents> for ProverClient {
    fn id(&self) -> ProverType {
        todo!()
    }

    fn zkm_prover(&self) -> &ZKMProver<DefaultProverComponents> {
        self.prover.zkm_prover()
    }

    fn setup(&self, elf: &[u8]) -> (ZKMProvingKey, ZKMVerifyingKey) {
        self.prover.setup(elf)
    }

    fn prove<'a>(
        &'a self,
        pk: &ZKMProvingKey,
        stdin: ZKMStdin,
        opts: ProofOpts,
        context: ZKMContext<'a>,
        kind: ZKMProofKind,
    ) -> Result<ZKMProofWithPublicValues> {
        self.prover.prove(pk, stdin, opts, context, kind)
    }

    fn verify(
        &self,
        bundle: &ZKMProofWithPublicValues,
        vkey: &ZKMVerifyingKey,
    ) -> Result<(), ZKMVerificationError> {
        self.prover.verify(bundle, vkey)
    }
}
