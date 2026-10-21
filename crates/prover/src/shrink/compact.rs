//! Compact byte-hash strategies and their native verifier.
use super::{CompactShrinkStrategy, ShrinkStrategy};
use std::borrow::Borrow;
use zkm_pcs::shrink::{HashSuite, ShrinkVerifierData};

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
    components::ZKMProverComponents, CompactShrink, CompressedSC, InnerSC, ShrinkAir, ZKMProver,
    ZKMRecursionProverError, ZKMVerifyingKey,
};

/// Construct only when this optional shrink is needed. Existing prover
/// construction and the Groth16/PLONK path allocate no extra shrink machine.
pub fn compact_shrink_prover<S: HashSuite>() -> CpuProver<CompactShrink<S>, ShrinkAir<KoalaBear>> {
    CpuProver::new(ShrinkAir::shrink_machine(CompactShrink::<S>::default()))
}

impl<S: HashSuite> ShrinkStrategy for CompactShrink<S> {
    type Config = CompactShrink<S>;

    fn shrink<C: ZKMProverComponents>(
        prover: &ZKMProver<C>,
        reduced_proof: ZKMReduceProof<CompressedSC>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<Self::Config>, ZKMRecursionProverError> {
        if !prover.vk_verification {
            return Err(ZKMRecursionProverError::RuntimeError(
                "Compact shrink requires recursion-key admission".into(),
            ));
        }
        let ZKMReduceProof { vk, proof } = reduced_proof;
        let vk_merkle_data = prover.make_basefold_merkle_proofs(std::slice::from_ref(&vk))?;
        let input = ZKMWrapBasefoldWitnessValues {
            vks_and_proofs: vec![(vk, *proof.jagged_shard_proof)],
            vk_merkle_data,
        };
        let program = std::sync::Arc::new(
            zkm_recursion_circuit::machine::basefold_programs::build_wrap_basefold_program(
                prover.root_prover.machine(),
                &input,
                ZKMProver::<C>::pcs_max_log_row_count(),
                prover.vk_verification,
            ),
        );
        let mut runtime = Runtime::<zkm_pcs::Val<InnerSC>, zkm_pcs::Challenge<InnerSC>, _>::new(
            program.clone(),
            prover.shrink_prover.machine().config().perm.clone(),
        );
        let mut witness_stream = Vec::new();
        Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
        runtime.witness_stream = witness_stream.into();
        runtime.run().map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))?;
        let prover = compact_shrink_prover::<S>();
        let (pk, vk) = prover.setup(&program);
        let mut challenger = prover.machine().config().challenger();
        let mut proof = prover
            .prove(&pk, vec![runtime.record], &mut challenger, opts.recursion_opts)
            .map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))?;
        Ok(ZKMReduceProof { vk, proof: proof.shard_proofs.pop().expect("one shrink shard") })
    }
}

impl<S: HashSuite> CompactShrinkStrategy for CompactShrink<S> {
    type Suite = S;
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// Authenticate the shrink key, application key, recursion root and full
    /// committed public-values digest. The expected shrink ID MUST come from
    /// independently approved setup, never from the submitted proof itself.
    pub fn verify_shrink_with<T: CompactShrinkStrategy>(
        &self,
        proof: &ZKMReduceProof<CompactShrink<T::Suite>>,
        application_vk: &ZKMVerifyingKey,
        trusted: &ShrinkVerifierData<T::Suite>,
        public_values: &ZKMPublicValues,
    ) -> Result<(), MachineVerificationError<CompactShrink<T::Suite>>> {
        use crate::HashableKey;
        use zkm_pcs::shard_level::shard_proof::EvaluationProof;
        if !self.vk_verification || zkm_pcs::shrink::shrink_key_digest(&proof.vk) != *trusted.id() {
            return Err(MachineVerificationError::InvalidVerificationKey);
        }
        if proof.proof.public_values.len() != zkm_recursion_core::air::RECURSIVE_PROOF_NUM_PV_ELTS {
            return Err(MachineVerificationError::InvalidPublicValues(
                "shrink public-value length",
            ));
        }
        let bytes = match &proof.proof.jagged_shard_proof.evaluation_proof {
            EvaluationProof::Bytes(bytes) => bytes,
            _ => return Err(MachineVerificationError::InvalidPublicValues("shrink WHIR opening")),
        };
        let bundle = zkm_pcs::jagged_pcs::jagged::JaggedPcsProofGeneric::<
            zkm_pcs::shrink::CompactMmcs<T::Suite>,
        >::from_bytes_for_verification(bytes)
        .ok_or(MachineVerificationError::InvalidPublicValues("shrink WHIR encoding"))?;
        if bundle.commit.original_commitment.roots().len() != 1 || bundle.whir_proof.is_none() {
            return Err(MachineVerificationError::InvalidPublicValues(
                "shrink requires WHIR single-root cap",
            ));
        }
        let prover = compact_shrink_prover::<T::Suite>();
        let mut challenger = prover.machine().config().challenger();
        prover.machine().verify(
            trusted.vk(),
            &MachineProof { shard_proofs: vec![proof.proof.clone()] },
            &mut challenger,
        )?;
        // The statement is bound field by field: recursion root, application key,
        // completion flags, exit code and the full committed-value digest. The
        // wrap program (`PublicValuesOutputDigest::Reduce`) checks the child's
        // Poseidon2 digest and commits `pv.digest` itself, and nothing below
        // reads `pv.digest`, so it is not recomputed here. Byte-hash verifiers
        // (`HashSuite`) therefore need no Poseidon2 implementation.
        let pv: &RecursionPublicValues<_> = proof.proof.public_values.as_slice().borrow();
        if pv.vk_root != self.recursion_vk_root
            || pv.zkm_vk_digest != application_vk.hash_koalabear()
            || pv.is_complete != KoalaBear::ONE
            || pv.contains_execution_shard != KoalaBear::ONE
            || pv.exit_code != KoalaBear::ZERO
        {
            return Err(MachineVerificationError::InvalidPublicValues(
                "shrink application binding",
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
