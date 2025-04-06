use anyhow::Result;
use zkm2_core_executor::ZKMContext;
use zkm2_core_machine::io::ZKMStdin;
use zkm2_prover::{components::DefaultProverComponents, ZKMProver};

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
}

impl Prover<DefaultProverComponents> for CpuProver {
    fn id(&self) -> ProverType {
        ProverType::Cpu
    }

    fn setup(&self, elf: &[u8]) -> (ZKMProvingKey, ZKMVerifyingKey) {
        self.prover.setup(elf)
    }

    fn zkm2_prover(&self) -> &ZKMProver<DefaultProverComponents> {
        &self.prover
    }

    fn prove<'a>(
        &'a self,
        pk: &ZKMProvingKey,
        stdin: ZKMStdin,
        opts: ProofOpts,
        context: ZKMContext<'a>,
        kind: ZKMProofKind,
    ) -> Result<ZKMProofWithPublicValues> {
        // Generate the core proof.
        let proof: zkm2_prover::ZKMProofWithMetadata<zkm2_prover::ZKMCoreProofData> =
            self.prover.prove_core(pk, &stdin, opts.zkm2_prover_opts, context)?;
        if kind == ZKMProofKind::Core {
            return Ok(ZKMProofWithPublicValues {
                proof: ZKMProof::Core(proof.proof.0),
                stdin: proof.stdin,
                public_values: proof.public_values,
                zkm2_version: self.version().to_string(),
            });
        }

        let deferred_proofs =
            stdin.proofs.iter().map(|(reduce_proof, _)| reduce_proof.clone()).collect();
        let public_values = proof.public_values.clone();

        // Generate the compressed proof.
        let reduce_proof =
            self.prover.compress(&pk.vk, proof, deferred_proofs, opts.zkm2_prover_opts)?;
        if kind == ZKMProofKind::Compressed {
            return Ok(ZKMProofWithPublicValues {
                proof: ZKMProof::Compressed(Box::new(reduce_proof)),
                stdin,
                public_values,
                zkm2_version: self.version().to_string(),
            });
        }
        
        log::info!("generate compress proof {:?}", reduce_proof);
        // Generate the shrink proof.
        let compress_proof = self.prover.shrink(reduce_proof, opts.zkm2_prover_opts)?;
        log::info!("generate shrink proof {:?}", compress_proof);

        // Genenerate the wrap proof.
        let outer_proof = self.prover.wrap_bn254(compress_proof, opts.zkm2_prover_opts)?;
        log::info!("generate outer proof {:?}", outer_proof);

        if kind == ZKMProofKind::Plonk {
            let plonk_bn254_artifacts = if zkm2_prover::build::zkm2_dev_mode() {
                zkm2_prover::build::try_build_plonk_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                panic!("only support dev mode for now");
                // try_install_circuit_artifacts("plonk")
            };
            let proof = self.prover.wrap_plonk_bn254(outer_proof, &plonk_bn254_artifacts);

            return Ok(ZKMProofWithPublicValues {
                proof: ZKMProof::Plonk(proof),
                stdin,
                public_values,
                zkm2_version: self.version().to_string(),
            });
        } else if kind == ZKMProofKind::Groth16 {
            let groth16_bn254_artifacts = if zkm2_prover::build::zkm2_dev_mode() {
                zkm2_prover::build::try_build_groth16_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                panic!("only support dev mode for now");
                // try_install_circuit_artifacts("groth16")
            };

            let proof = self.prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
            return Ok(ZKMProofWithPublicValues {
                proof: ZKMProof::Groth16(proof),
                stdin,
                public_values,
                zkm2_version: self.version().to_string(),
            });
        }

        unreachable!()
    }
}

impl Default for CpuProver {
    fn default() -> Self {
        Self::new()
    }
}
