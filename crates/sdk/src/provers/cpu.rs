use anyhow::Result;
use zkm_core_executor::ZKMContext;
use zkm_core_machine::io::ZKMStdin;
use zkm_prover::{components::DefaultProverComponents, ZKMProver};

use crate::install::try_install_circuit_artifacts;
use crate::{
    provers::ProofOpts, Prover, ZKMProof, ZKMProofKind, ZKMProofWithPublicValues, ZKMProvingKey,
    ZKMVerifyingKey,
};

use super::ProverType;

/// An implementation of [crate::ProverClient] that can generate end-to-end proofs locally.
pub struct CpuProver {
    prover: ZKMProver<DefaultProverComponents>,
}

impl CpuProver {
    /// Creates a new [LocalProver].
    pub fn new() -> Self {
        let prover = ZKMProver::new();
        Self { prover }
    }

    /// Creates a new [LocalProver] from an existing [ZKMProver].
    pub fn from_prover(prover: ZKMProver<DefaultProverComponents>) -> Self {
        Self { prover }
    }

    fn compress_to_groth16(
        &self,
        mut stdin: ZKMStdin,
        opts: ProofOpts,
    ) -> Result<ZKMProofWithPublicValues> {
        assert_eq!(stdin.buffer.len(), 1);
        let public_values = bincode::deserialize(stdin.buffer.last().unwrap())?;

        assert_eq!(stdin.proofs.len(), 1);
        let (proof, _) = stdin.proofs.pop().unwrap();

        // Generate the shrink proof.
        let shrink_proof = self.prover.shrink(proof, opts.zkm_prover_opts)?;

        // Genenerate the wrap proof.
        let outer_proof = self.prover.wrap_bn254(shrink_proof, opts.zkm_prover_opts)?;

        let groth16_bn254_artifacts = if zkm_prover::build::zkm_dev_mode() {
            zkm_prover::build::try_build_groth16_bn254_artifacts_dev(
                &outer_proof.vk,
                &outer_proof.proof,
            )
        } else {
            try_install_circuit_artifacts("groth16")
        };

        let proof = self.prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
        Ok(ZKMProofWithPublicValues {
            proof: ZKMProof::Groth16(proof),
            stdin,
            public_values,
            zkm_version: self.version().to_string(),
        })
    }
}

impl Prover<DefaultProverComponents> for CpuProver {
    fn id(&self) -> ProverType {
        ProverType::Cpu
    }

    fn setup(&self, elf: &[u8]) -> (ZKMProvingKey, ZKMVerifyingKey) {
        self.prover.setup(elf)
    }

    fn zkm_prover(&self) -> &ZKMProver<DefaultProverComponents> {
        &self.prover
    }

    fn prove_impl<'a>(
        &'a self,
        pk: &ZKMProvingKey,
        stdin: ZKMStdin,
        opts: ProofOpts,
        context: ZKMContext<'a>,
        kind: ZKMProofKind,
        _elf_id: Option<String>,
    ) -> Result<(ZKMProofWithPublicValues, u64)> {
        if kind == ZKMProofKind::CompressToGroth16 {
            return Ok((self.compress_to_groth16(stdin, opts)?, 0));
        }

        // Generate the core proof.
        let proof: zkm_prover::ZKMProofWithMetadata<zkm_prover::ZKMCoreProofData> =
            self.prover.prove_core(pk, &stdin, opts.zkm_prover_opts, context)?;
        let cycles = proof.cycles;
        if kind == ZKMProofKind::Core {
            return Ok((
                ZKMProofWithPublicValues {
                    proof: ZKMProof::Core(proof.proof.0),
                    stdin: proof.stdin,
                    public_values: proof.public_values,
                    zkm_version: self.version().to_string(),
                },
                cycles,
            ));
        }

        let deferred_proofs =
            stdin.proofs.iter().map(|(reduce_proof, _)| reduce_proof.clone()).collect();
        let public_values = proof.public_values.clone();

        // Generate the compressed proof.
        let reduce_proof =
            self.prover.compress(&pk.vk, proof, deferred_proofs, opts.zkm_prover_opts)?;
        if kind == ZKMProofKind::Compressed {
            return Ok((
                ZKMProofWithPublicValues {
                    proof: ZKMProof::Compressed(Box::new(reduce_proof)),
                    stdin,
                    public_values,
                    zkm_version: self.version().to_string(),
                },
                cycles,
            ));
        }

        // Generate the shrink proof.
        let compress_proof = self.prover.shrink(reduce_proof, opts.zkm_prover_opts)?;

        // Genenerate the wrap proof.
        let outer_proof = self.prover.wrap_bn254(compress_proof, opts.zkm_prover_opts)?;

        if kind == ZKMProofKind::Plonk {
            let plonk_bn254_artifacts = if zkm_prover::build::zkm_dev_mode() {
                zkm_prover::build::try_build_plonk_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                try_install_circuit_artifacts("plonk")
            };
            let proof = self.prover.wrap_plonk_bn254(outer_proof, &plonk_bn254_artifacts);

            return Ok((
                ZKMProofWithPublicValues {
                    proof: ZKMProof::Plonk(proof),
                    stdin,
                    public_values,
                    zkm_version: self.version().to_string(),
                },
                cycles,
            ));
        } else if kind == ZKMProofKind::Groth16 {
            let groth16_bn254_artifacts = if zkm_prover::build::zkm_dev_mode() {
                zkm_prover::build::try_build_groth16_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                try_install_circuit_artifacts("groth16")
            };

            let proof = self.prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
            return Ok((
                ZKMProofWithPublicValues {
                    proof: ZKMProof::Groth16(proof),
                    stdin,
                    public_values,
                    zkm_version: self.version().to_string(),
                },
                cycles,
            ));
        }

        unreachable!()
    }
}

impl Default for CpuProver {
    fn default() -> Self {
        Self::new()
    }
}
