use anyhow::Result;
use zkm_core_executor::ZKMContext;
use zkm_core_machine::io::ZKMStdin;
use zkm_prover::{components::DefaultProverComponents, ZKMProver};

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
    /// Creates a new [CpuProver].
    pub fn new() -> Self {
        let prover = ZKMProver::new();
        Self { prover }
    }

    /// Creates a new [CpuProver] from an existing [ZKMProver].
    pub fn from_prover(prover: ZKMProver<DefaultProverComponents>) -> Self {
        Self { prover }
    }
}

impl Prover<DefaultProverComponents> for CpuProver {
    fn id(&self) -> ProverType {
        ProverType::Cpu
    }

    fn setup(&self, elf: &[u8]) -> (ZKMProvingKey, ZKMVerifyingKey) {
        let (pk, _, _, vk) = self.prover.setup(elf);
        (pk, vk)
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
        if !matches!(kind, ZKMProofKind::Core | ZKMProofKind::Compressed) {
            anyhow::bail!(super::wrap_unsupported(kind));
        }

        let program = self.prover.get_program(&pk.elf).unwrap();

        let proof: zkm_prover::ZKMProofWithMetadata<zkm_prover::ZKMCoreProofData> =
            self.prover.prove_core(&pk.pk, program, &stdin, opts.zkm_prover_opts, context)?;
        let cycles = proof.cycles;
        if kind == ZKMProofKind::Core {
            return Ok((
                ZKMProofWithPublicValues {
                    proof: ZKMProof::Core(proof.proof.0),
                    public_values: proof.public_values,
                    zkm_version: self.version().to_string(),
                },
                cycles,
            ));
        }

        let compressed = self.prover.compress_binary(
            &pk.vk,
            &proof,
            &zkm_prover::binary_tree::BinaryKeyStore::from_env(),
        )?;
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

impl Default for CpuProver {
    fn default() -> Self {
        Self::new()
    }
}
