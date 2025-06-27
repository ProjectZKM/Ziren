#![allow(unused_variables)]
use hashbrown::HashMap;
use zkm_core_executor::{ZKMContext, ZKMReduceProof};
use zkm_core_machine::io::ZKMStdin;
use zkm_stark::{ShardCommitment, ShardOpenedValues, ShardProof, StarkVerifyingKey};

use crate::{
    Prover, ZKMProof, ZKMProofKind, ZKMProofWithPublicValues, ZKMProvingKey, ZKMVerificationError,
    ZKMVerifyingKey,
};
use anyhow::Result;
use p3_field::{FieldAlgebra, PrimeField};
use p3_fri::FriProof;
use p3_koala_bear::KoalaBear;
use zkm_prover::{
    components::DefaultProverComponents,
    verify::{verify_groth16_bn254_public_inputs, verify_plonk_bn254_public_inputs},
    Groth16Bn254Proof, HashableKey, PlonkBn254Proof, ZKMProver,
};
use zkm_stark::septic_digest::SepticDigest;

use super::{ProofOpts, ProverType};

/// An implementation of [crate::ProverClient] that can generate mock proofs.
pub struct MockProver {
    pub(crate) prover: ZKMProver,
}

impl MockProver {
    /// Creates a new [MockProver].
    pub fn new() -> Self {
        let prover = ZKMProver::new();
        Self { prover }
    }
}

impl Prover<DefaultProverComponents> for MockProver {
    fn id(&self) -> ProverType {
        ProverType::Mock
    }

    fn setup(&self, elf: &[u8]) -> (ZKMProvingKey, ZKMVerifyingKey) {
        self.prover.setup(elf)
    }

    fn zkm_prover(&self) -> &ZKMProver {
        &self.prover
    }

    fn prove_impl<'a>(
        &'a self,
        pk: &ZKMProvingKey,
        stdin: ZKMStdin,
        opts: ProofOpts,
        context: ZKMContext<'a>,
        kind: ZKMProofKind,
    ) -> Result<ZKMProofWithPublicValues> {
        match kind {
            ZKMProofKind::Core => {
                let (public_values, _) = self.prover.execute(&pk.elf, &stdin, context)?;
                Ok(ZKMProofWithPublicValues {
                    proof: ZKMProof::Core(vec![]),
                    stdin,
                    public_values,
                    zkm_version: self.version().to_string(),
                })
            }
            ZKMProofKind::Compressed => {
                let (public_values, _) = self.prover.execute(&pk.elf, &stdin, context)?;

                let shard_proof = ShardProof {
                    commitment: ShardCommitment {
                        main_commit: [KoalaBear::ZERO; 8].into(),
                        permutation_commit: [KoalaBear::ZERO; 8].into(),
                        quotient_commit: [KoalaBear::ZERO; 8].into(),
                    },
                    opened_values: ShardOpenedValues { chips: vec![] },
                    opening_proof: FriProof {
                        commit_phase_commits: vec![],
                        query_proofs: vec![],
                        final_poly: Default::default(),
                        pow_witness: KoalaBear::ZERO,
                    },
                    chip_ordering: HashMap::new(),
                    public_values: vec![],
                };

                let reduce_vk = StarkVerifyingKey {
                    commit: [KoalaBear::ZERO; 8].into(),
                    pc_start: KoalaBear::ZERO,
                    chip_information: vec![],
                    chip_ordering: HashMap::new(),
                    initial_global_cumulative_sum: SepticDigest::zero(),
                };

                let proof = ZKMProof::Compressed(Box::new(ZKMReduceProof {
                    vk: reduce_vk,
                    proof: shard_proof,
                }));

                Ok(ZKMProofWithPublicValues {
                    proof,
                    stdin,
                    public_values,
                    zkm_version: self.version().to_string(),
                })
            }
            ZKMProofKind::Plonk => {
                let (public_values, _) = self.prover.execute(&pk.elf, &stdin, context)?;
                Ok(ZKMProofWithPublicValues {
                    proof: ZKMProof::Plonk(PlonkBn254Proof {
                        public_inputs: [
                            pk.vk.hash_bn254().as_canonical_biguint().to_string(),
                            public_values.hash_bn254().to_string(),
                        ],
                        encoded_proof: "".to_string(),
                        raw_proof: "".to_string(),
                        plonk_vkey_hash: [0; 32],
                    }),
                    stdin,
                    public_values,
                    zkm_version: self.version().to_string(),
                })
            }
            ZKMProofKind::Groth16 => {
                let (public_values, _) = self.prover.execute(&pk.elf, &stdin, context)?;
                Ok(ZKMProofWithPublicValues {
                    proof: ZKMProof::Groth16(Groth16Bn254Proof {
                        public_inputs: [
                            pk.vk.hash_bn254().as_canonical_biguint().to_string(),
                            public_values.hash_bn254().to_string(),
                        ],
                        encoded_proof: "".to_string(),
                        raw_proof: "".to_string(),
                        groth16_vkey_hash: [0; 32],
                    }),
                    stdin,
                    public_values,
                    zkm_version: self.version().to_string(),
                })
            }
            ZKMProofKind::CompressToGroth16 => unreachable!(),
        }
    }

    fn verify(
        &self,
        bundle: &ZKMProofWithPublicValues,
        vkey: &ZKMVerifyingKey,
    ) -> Result<(), ZKMVerificationError> {
        match &bundle.proof {
            ZKMProof::Plonk(PlonkBn254Proof { public_inputs, .. }) => {
                verify_plonk_bn254_public_inputs(vkey, &bundle.public_values, public_inputs)
                    .map_err(ZKMVerificationError::Plonk)
            }
            ZKMProof::Groth16(Groth16Bn254Proof { public_inputs, .. }) => {
                verify_groth16_bn254_public_inputs(vkey, &bundle.public_values, public_inputs)
                    .map_err(ZKMVerificationError::Groth16)
            }
            _ => Ok(()),
        }
    }
}

impl Default for MockProver {
    fn default() -> Self {
        Self::new()
    }
}
