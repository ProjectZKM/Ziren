use anyhow::Result;
use tonic::async_trait;
use zkm_core_executor::ZKMContext;
use zkm_core_machine::io::ZKMStdin;
use zkm_cuda::{ZKMCudaProver, ZKMGpuServer};
use zkm_prover::{components::DefaultProverComponents, ZKMProver};

use crate::install::try_install_circuit_artifacts;
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

    /// Proves the given program on the given input in the given proof mode.
    ///
    /// Returns the cycle count in addition to the proof.
    pub fn prove_with_cycles(
        &self,
        pk: &ZKMProvingKey,
        stdin: &ZKMStdin,
        kind: ZKMProofKind,
    ) -> Result<(ZKMProofWithPublicValues, u64)> {
        if kind == ZKMProofKind::CompressToGroth16 {
            return Ok((self.compress_to_groth16(stdin.clone())?, 0));
        }

        // Generate the core proof.
        let proof = self.cuda_prover.prove_core_stateless(pk, stdin)?;
        let cycles = proof.cycles;
        if kind == ZKMProofKind::Core {
            let proof_with_pv = ZKMProofWithPublicValues {
                proof: ZKMProof::Core(proof.proof.0),
                public_values: proof.public_values,
                zkm_version: self.version().to_string(),
            };
            return Ok((proof_with_pv, cycles));
        }

        // Generate the compressed proof.
        let deferred_proofs =
            stdin.proofs.iter().map(|(reduce_proof, _)| reduce_proof.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.cuda_prover.compress(&pk.vk, proof, deferred_proofs)?;
        if kind == ZKMProofKind::Compressed {
            let proof_with_pv = ZKMProofWithPublicValues {
                proof: ZKMProof::Compressed(Box::new(reduce_proof)),
                public_values,
                zkm_version: self.version().to_string(),
            };
            return Ok((proof_with_pv, cycles));
        }

        // Generate the shrink proof.
        let compress_proof = self.cuda_prover.shrink(reduce_proof)?;

        // Generate the wrap proof.
        let outer_proof = self.cuda_prover.wrap_bn254(compress_proof)?;

        if kind == ZKMProofKind::Plonk {
            let plonk_bn254_artifacts = if zkm_prover::build::zkm_dev_mode() {
                zkm_prover::build::try_build_plonk_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                try_install_circuit_artifacts("plonk")
            };
            let proof = self.cpu_prover.wrap_plonk_bn254(outer_proof, &plonk_bn254_artifacts);
            let proof_with_pv = ZKMProofWithPublicValues {
                proof: ZKMProof::Plonk(proof),
                public_values,
                zkm_version: self.version().to_string(),
            };
            return Ok((proof_with_pv, cycles));
        } else if kind == ZKMProofKind::Groth16 {
            let groth16_bn254_artifacts = if zkm_prover::build::zkm_dev_mode() {
                zkm_prover::build::try_build_groth16_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                try_install_circuit_artifacts("groth16")
            };

            let proof = self.cpu_prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
            let proof_with_pv = ZKMProofWithPublicValues {
                proof: ZKMProof::Groth16(proof),
                public_values,
                zkm_version: self.version().to_string(),
            };
            return Ok((proof_with_pv, cycles));
        }

        unreachable!()
    }

    fn compress_to_groth16(&self, mut stdin: ZKMStdin) -> Result<ZKMProofWithPublicValues> {
        assert_eq!(stdin.buffer.len(), 1);
        let public_values = bincode::deserialize(stdin.buffer.last().unwrap())?;

        assert_eq!(stdin.proofs.len(), 1);
        let (proof, _) = stdin.proofs.pop().unwrap();

        // Generate the shrink proof.
        let shrink_proof = self.cuda_prover.shrink(proof)?;

        // Generate the wrap proof.
        let outer_proof = self.cuda_prover.wrap_bn254(shrink_proof)?;

        let groth16_bn254_artifacts = if zkm_prover::build::zkm_dev_mode() {
            zkm_prover::build::try_build_groth16_bn254_artifacts_dev(
                &outer_proof.vk,
                &outer_proof.proof,
            )
        } else {
            try_install_circuit_artifacts("groth16")
        };

        let proof = self.cpu_prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
        Ok(ZKMProofWithPublicValues {
            proof: ZKMProof::Groth16(proof),
            public_values,
            zkm_version: self.version().to_string(),
        })
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
        Self::new(ZKMProver::new(), ZKMGpuServer::default())
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
        stdin.write(&10usize);

        let proof = client.prove(&pk, stdin).run().unwrap();
        client.verify(&proof, &vk).unwrap();
    }
}
