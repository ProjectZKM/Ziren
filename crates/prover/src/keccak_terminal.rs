//! Opt-in terminal over the existing, current-version shrink program.
use std::borrow::Borrow;

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use zkm_core_executor::ZKMReduceProof;
use zkm_pcs::{
    CpuProver, MachineProof, MachineProver, MachineVerificationError, StarkGenericConfig,
    ZKMProverOpts,
};
use zkm_primitives::io::ZKMPublicValues;
use zkm_recursion_circuit::machine::ZKMWrapBasefoldWitnessValues;
use zkm_recursion_circuit::witness::Witnessable;
use zkm_recursion_compiler::config::InnerConfig;
use zkm_recursion_core::{air::RecursionPublicValues, Runtime};

use crate::{
    components::ZKMProverComponents, utils::is_recursion_public_values_valid, CompressedSC,
    InnerSC, ShrinkAir, ShrinkKeccakSC, ZKMProver, ZKMRecursionProverError, ZKMVerifyingKey,
};

/// Construct only when this optional terminal is needed. Existing prover
/// construction and the Groth16/PLONK path allocate no extra terminal machine.
pub fn keccak_terminal_prover() -> CpuProver<ShrinkKeccakSC, ShrinkAir<KoalaBear>> {
    CpuProver::new(ShrinkAir::shrink_machine(ShrinkKeccakSC::default()))
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// Prove the unchanged shrink computation with host Keccak commitments.
    /// The compressed child's key must pass the existing admission check.
    pub fn shrink_keccak(
        &self,
        reduced_proof: ZKMReduceProof<CompressedSC>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<ShrinkKeccakSC>, ZKMRecursionProverError> {
        if !self.vk_verification {
            return Err(ZKMRecursionProverError::RuntimeError(
                "Keccak terminal requires recursion-key admission".into(),
            ));
        }
        let ZKMReduceProof { vk, proof } = reduced_proof;
        let vk_merkle_data = self.make_basefold_merkle_proofs(std::slice::from_ref(&vk))?;
        let input = ZKMWrapBasefoldWitnessValues {
            vks_and_proofs: vec![(vk, *proof.jagged_shard_proof)],
            vk_merkle_data,
        };
        let program = self.shrink_program_basefold(&input);
        let mut runtime = Runtime::<zkm_pcs::Val<InnerSC>, zkm_pcs::Challenge<InnerSC>, _>::new(
            program.clone(),
            self.shrink_prover.machine().config().perm.clone(),
        );
        let mut witness_stream = Vec::new();
        Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
        runtime.witness_stream = witness_stream.into();
        runtime.run().map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))?;
        let prover = keccak_terminal_prover();
        let (pk, vk) = prover.setup(&program);
        let mut challenger = prover.machine().config().challenger();
        let mut proof = prover
            .prove(&pk, vec![runtime.record], &mut challenger, opts.recursion_opts)
            .map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))?;
        Ok(ZKMReduceProof { vk, proof: proof.shard_proofs.pop().expect("one shrink shard") })
    }

    /// Authenticate the terminal key, application key, recursion root and full
    /// committed public-values digest. The expected terminal ID MUST come from
    /// independently approved setup, never from the submitted proof itself.
    pub fn verify_shrink_keccak(
        &self,
        proof: &ZKMReduceProof<ShrinkKeccakSC>,
        application_vk: &ZKMVerifyingKey,
        expected_terminal_key: &[u8; 32],
        public_values: &ZKMPublicValues,
    ) -> Result<(), MachineVerificationError<ShrinkKeccakSC>> {
        use crate::HashableKey;
        use zkm_pcs::shard_level::shard_proof::EvaluationProof;
        if !self.vk_verification
            || zkm_pcs::kb31_keccak::terminal_key_digest(&proof.vk) != *expected_terminal_key
        {
            return Err(MachineVerificationError::InvalidVerificationKey);
        }
        if proof.proof.public_values.len() != zkm_recursion_core::air::RECURSIVE_PROOF_NUM_PV_ELTS {
            return Err(MachineVerificationError::InvalidPublicValues(
                "terminal public-value length",
            ));
        }
        let bytes = match &proof.proof.jagged_shard_proof.evaluation_proof {
            EvaluationProof::Bytes(bytes) => bytes,
            _ => {
                return Err(MachineVerificationError::InvalidPublicValues("terminal WHIR opening"))
            }
        };
        let bundle = zkm_pcs::jagged_pcs::jagged::JaggedPcsProofGeneric::<
            zkm_pcs::kb31_keccak::KeccakMmcs,
        >::from_bytes_for_verification(bytes)
        .ok_or(MachineVerificationError::InvalidPublicValues("terminal WHIR encoding"))?;
        if bundle.commit.original_commitment.roots().len() != 1 || bundle.whir_proof.is_none() {
            return Err(MachineVerificationError::InvalidPublicValues(
                "terminal requires WHIR single-root cap",
            ));
        }
        let prover = keccak_terminal_prover();
        let mut challenger = prover.machine().config().challenger();
        prover.machine().verify(
            &proof.vk,
            &MachineProof { shard_proofs: vec![proof.proof.clone()] },
            &mut challenger,
        )?;
        let pv: &RecursionPublicValues<_> = proof.proof.public_values.as_slice().borrow();
        if !is_recursion_public_values_valid(self.compress_prover.machine().config(), pv)
            || pv.vk_root != self.recursion_vk_root
            || pv.zkm_vk_digest != application_vk.hash_koalabear()
            || pv.is_complete != KoalaBear::ONE
            || pv.contains_execution_shard != KoalaBear::ONE
            || pv.exit_code != KoalaBear::ZERO
        {
            return Err(MachineVerificationError::InvalidPublicValues(
                "terminal application binding",
            ));
        }
        if pv
            .committed_value_digest
            .iter()
            .flat_map(|w| w.0.iter())
            .zip(public_values.hash())
            .any(|(value, byte)| value.as_canonical_u32() != u32::from(byte))
        {
            return Err(MachineVerificationError::InvalidPublicValues(
                "public values digest mismatch",
            ));
        }
        Ok(())
    }
}
