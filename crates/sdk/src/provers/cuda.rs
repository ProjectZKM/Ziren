use anyhow::Result;
use p3_field::PrimeField;
use std::fs;
use std::path::PathBuf;
use tonic::async_trait;
use zkm_core_executor::ZKMContext;
use zkm_core_machine::io::ZKMStdin;
use zkm_cuda::{ZKMCudaProver, ZKMGpuServer};
use zkm_prover::ZKM_CIRCUIT_VERSION;
use zkm_prover::{components::DefaultProverComponents, ZKMProver};

use crate::install::{try_install_circuit_artifacts, CircuitArtifacts};
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
        if kind == ZKMProofKind::CompressToGroth16 {
            return Ok((self.compress_to_groth16(stdin.clone())?, 0));
        }

        let proof = self.cuda_prover.prove_core_stateless_retaining(
            pk,
            stdin,
            kind != ZKMProofKind::Core,
        )?;
        let cycles = proof.cycles;
        if kind == ZKMProofKind::Core {
            let proof_with_pv = ZKMProofWithPublicValues {
                proof: ZKMProof::Core(proof.proof.0),
                public_values: proof.public_values,
                zkm_version: self.version().to_string(),
            };
            return Ok((proof_with_pv, cycles));
        }

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

        let compress_proof = self.cuda_prover.shrink(reduce_proof)?;

        let outer_proof = self.cuda_prover.wrap_bn254(compress_proof)?;

        let actual_digest = zkm_prover::utils::zkm_committed_values_digest_bn254(&outer_proof)
            .as_canonical_biguint();
        let expected_digest = public_values.hash_bn254();
        if actual_digest != expected_digest {
            anyhow::bail!(
                "guest committed-values digest doesn't match the hash algorithm this prover \
                 currently expects (ZKM_IMM_WRAP_VK={}); the guest ELF may have been built in a \
                 different mode",
                zkm_prover::build::zkm_imm_wrap_vk_mode()
            );
        }

        if kind == ZKMProofKind::Plonk {
            let plonk_bn254_artifacts = if zkm_prover::build::zkm_dev_mode() {
                zkm_prover::build::try_build_plonk_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                try_install_circuit_artifacts(CircuitArtifacts::Plonk, ZKM_CIRCUIT_VERSION)
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
                try_install_circuit_artifacts(CircuitArtifacts::Groth16, ZKM_CIRCUIT_VERSION)
            };

            let proof = self.cpu_prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
            let proof_with_pv = ZKMProofWithPublicValues {
                proof: ZKMProof::Groth16(proof),
                public_values,
                zkm_version: self.version().to_string(),
            };
            return Ok((proof_with_pv, cycles));
        } else if kind == ZKMProofKind::DvSnark {
            let store_dir: PathBuf = std::env::var("DVSNARK_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::new())
                .join(format!("dvsnark_artifacts_{}", env!("CARGO_PKG_VERSION")));
            fs::create_dir_all(&store_dir)
                .expect("failed to create dvsnark artifacts store directory");
            let dv_snark_artifacts = zkm_prover::build::try_build_dvsnark_bn254_artifacts_dev(
                &outer_proof.vk,
                &outer_proof.proof,
                &store_dir,
            );
            let proof =
                self.cpu_prover.wrap_dvsnark_bn254(outer_proof, &dv_snark_artifacts, &store_dir);
            return Ok((
                ZKMProofWithPublicValues {
                    proof: ZKMProof::DvSnark(proof),
                    public_values,
                    zkm_version: self.version().to_string(),
                },
                cycles,
            ));
        }

        unreachable!()
    }

    fn compress_to_groth16(&self, mut stdin: ZKMStdin) -> Result<ZKMProofWithPublicValues> {
        assert_eq!(stdin.buffer.len(), 1);
        let public_values: crate::ZKMPublicValues =
            bincode::deserialize(stdin.buffer.last().unwrap())?;

        assert_eq!(stdin.proofs.len(), 1);
        let (proof, _) = stdin.proofs.pop().unwrap();

        let shrink_proof = self.cuda_prover.shrink(proof)?;

        let outer_proof = self.cuda_prover.wrap_bn254(shrink_proof)?;

        let actual_digest = zkm_prover::utils::zkm_committed_values_digest_bn254(&outer_proof)
            .as_canonical_biguint();
        let expected_digest = public_values.hash_bn254();
        if actual_digest != expected_digest {
            anyhow::bail!(
                "guest committed-values digest doesn't match the hash algorithm this prover \
                 currently expects (ZKM_IMM_WRAP_VK={}); the guest ELF may have been built in a \
                 different mode",
                zkm_prover::build::zkm_imm_wrap_vk_mode()
            );
        }

        let groth16_bn254_artifacts = if zkm_prover::build::zkm_dev_mode() {
            zkm_prover::build::try_build_groth16_bn254_artifacts_dev(
                &outer_proof.vk,
                &outer_proof.proof,
            )
        } else {
            try_install_circuit_artifacts(CircuitArtifacts::Groth16, ZKM_CIRCUIT_VERSION)
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
        stdin.write(&10u32);

        let proof = client.prove(&pk, stdin).run().unwrap();
        client.verify(&proof, &vk).unwrap();
    }

    /// Deferred proofs through the GPU server: two compressed keccak proofs
    /// are absorbed by the verify program, whose reduce tree takes them as
    /// first-layer inputs after its core leaves.
    #[ignore]
    #[test]
    fn test_deferred_proofs_cuda() {
        use crate::{ZKMProof, ZKMProofWithPublicValues};
        use zkm_prover::types::HashableKey;
        utils::setup_logger();

        let client = ProverClient::cuda();
        let (keccak_pk, keccak_vk) = client.setup(test_artifacts::KECCAK_SPONGE_ELF);
        let (verify_pk, verify_vk) = client.setup(test_artifacts::VERIFY_PROOF_ELF);

        let mut stdin = ZKMStdin::new();
        stdin.write(&1usize);
        stdin.write(&vec![0u8, 0, 0]);
        let proof_1 = client.prove(&keccak_pk, stdin).compressed().run().unwrap();
        client.verify(&proof_1, &keccak_vk).unwrap();

        let mut stdin = ZKMStdin::new();
        stdin.write(&3usize);
        stdin.write(&vec![0u8, 1, 2]);
        stdin.write(&vec![2, 3, 4]);
        stdin.write(&vec![5, 6, 7]);
        let proof_2 = client.prove(&keccak_pk, stdin).compressed().run().unwrap();
        client.verify(&proof_2, &keccak_vk).unwrap();

        let reduced = |p: &ZKMProofWithPublicValues| match &p.proof {
            ZKMProof::Compressed(r) => (**r).clone(),
            _ => panic!("a compressed proof"),
        };
        let mut stdin = ZKMStdin::new();
        stdin.write(&keccak_vk.hash_u32());
        stdin.write(&vec![
            proof_1.public_values.as_slice().to_vec(),
            proof_2.public_values.as_slice().to_vec(),
            proof_2.public_values.as_slice().to_vec(),
        ]);
        stdin.write_proof(reduced(&proof_1), keccak_vk.vk.clone());
        stdin.write_proof(reduced(&proof_2), keccak_vk.vk.clone());
        stdin.write_proof(reduced(&proof_2), keccak_vk.vk.clone());

        let proof = client.prove(&verify_pk, stdin).compressed().run().unwrap();
        client.verify(&proof, &verify_vk).unwrap();
    }
}
