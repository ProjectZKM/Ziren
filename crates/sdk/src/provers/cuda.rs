use anyhow::Result;
use tonic::async_trait;
use zkm_core_executor::ZKMContext;
use zkm_core_machine::io::ZKMStdin;
use zkm_cuda::{ZKMCudaProver, ZKMGpuServer};
use zkm_prover::{components::DefaultProverComponents, ZKMProver};

use crate::{
    provers::ProofOpts, Prover, ZKMProof, ZKMProofKind, ZKMProofWithPublicValues, ZKMProvingKey,
    ZKMVerifyingKey,
};

use super::ProverType;

/// An implementation of [crate::ProverClient] that can generate end-to-end proofs locally.
pub struct CudaProver {
    pub(crate) cpu_prover: ZKMProver<DefaultProverComponents>,
    pub(crate) cuda_prover: ZKMCudaProver,
}

impl CudaProver {
    /// Creates a new [`CudaProver`].
    pub fn new(prover: ZKMProver, gpu_server: ZKMGpuServer) -> Self {
        let cuda_prover = ZKMCudaProver::new(gpu_server);
        Self {
            cpu_prover: prover,
            cuda_prover: cuda_prover.expect("Failed to initialize CUDA prover"),
        }
    }

    /// Proves the given program on the given input in the given proof mode,
    /// together with its cycle count.
    pub fn prove_with_cycles(
        &self,
        pk: &ZKMProvingKey,
        stdin: &ZKMStdin,
        kind: ZKMProofKind,
    ) -> Result<(ZKMProofWithPublicValues, u64)> {
        if !matches!(kind, ZKMProofKind::Core | ZKMProofKind::Compressed) {
            anyhow::bail!(super::wrap_unsupported(kind));
        }

        let proof = self.cuda_prover.prove_core_stateless_retaining(pk, stdin, false)?;
        let cycles = proof.cycles;
        if kind == ZKMProofKind::Core {
            let proof_with_pv = ZKMProofWithPublicValues {
                proof: ZKMProof::Core(proof.proof.0),
                public_values: proof.public_values,
                zkm_version: self.version().to_string(),
            };
            return Ok((proof_with_pv, cycles));
        }

        let compressed = if std::env::var_os("ZIREN_BINARY_ON_HOST").is_some() {
            self.cpu_prover.compress_binary(
                &pk.vk,
                &proof,
                &zkm_prover::binary_tree::BinaryKeyStore::from_env(),
            )?
        } else {
            self.cuda_prover.compress_binary(&pk.vk, proof.clone())?
        };
        Ok((
            ZKMProofWithPublicValues {
                proof: ZKMProof::Compressed(Box::new(compressed)),
                public_values: proof.public_values,
                zkm_version: self.version().to_string(),
            },
            cycles,
        ))
    }
}

#[async_trait]
impl Prover<DefaultProverComponents> for CudaProver {
    fn id(&self) -> ProverType {
        ProverType::Cuda
    }

    fn setup(&self, elf: &[u8]) -> (ZKMProvingKey, ZKMVerifyingKey) {
        let (pk, vk) = self.cuda_prover.setup(elf).unwrap();
        (pk, vk)
    }

    fn zkm_prover(&self) -> &ZKMProver<DefaultProverComponents> {
        &self.cpu_prover
    }

    fn take_prove_ms(&self) -> Option<u64> {
        self.cuda_prover.take_server_prove_ms()
    }

    fn prove_impl<'a>(
        &'a self,
        pk: &ZKMProvingKey,
        stdin: ZKMStdin,
        _opts: ProofOpts,
        _context: ZKMContext<'a>,
        kind: ZKMProofKind,
        _elf_id: Option<String>,
    ) -> Result<(ZKMProofWithPublicValues, u64)> {
        self.prove_with_cycles(pk, &stdin, kind)
    }
}

impl Default for CudaProver {
    fn default() -> Self {
        Self::new(ZKMProver::uninitialized(), ZKMGpuServer::default())
    }
}

#[cfg(test)]
mod test {
    use crate::{utils, ProverClient};
    use zkm_core_machine::io::ZKMStdin;

    #[ignore]
    #[test]
    fn test_proof_cuda_fib() {
        utils::setup_logger();

        let elf = test_artifacts::FIBONACCI_ELF;
        let client = ProverClient::cuda();
        let (pk, vk) = client.setup(elf);
        let mut stdin = ZKMStdin::new();
        stdin.write(&10u32);

        let proof = client.prove(&pk, stdin).run().unwrap();
        client.verify(&proof, &vk).unwrap();
    }
}
