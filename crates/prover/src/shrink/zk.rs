//! The zero-knowledge shrink strategy (feature `zk`) and its native verifier.
//!
//! [`ZkShrink`] proves the compress root's verification as a terminal proof
//! on the zk shrink ring ([`ZkShrinkSC`]): the program is the wrap program
//! committing the root digest (`ReduceToRoot`), so the proof binds exactly the
//! statement fields and nothing of the execution beyond them, and
//! [`ZKMProver::verify_zk_shrink`] checks it against a trusted key.
//!
//! The ring opens its commitments under the zero-knowledge stacked WHIR
//! (`zkm_pcs::whir::zk`): the opening reveals nothing of the committed
//! traces, and two proofs of one root differ in every opened value.  The
//! zerocheck and LogUp openings of the trace columns are not masked yet,
//! which the later phases add on this same ring.

use std::borrow::Borrow;
use std::sync::Arc;

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use zkm_core_executor::ZKMReduceProof;
use zkm_pcs::{
    CpuProver, MachineProof, MachineProver, MachineVerificationError, StarkGenericConfig,
    StarkVerifyingKey, ZKMProverOpts,
};
use zkm_primitives::io::ZKMPublicValues;
use zkm_recursion_circuit::machine::{
    PublicValuesOutputDigest, RootPublicValues, ZKMWrapWitnessValues,
};
use zkm_recursion_circuit::witness::Witnessable;
use zkm_recursion_compiler::config::InnerConfig;
use zkm_recursion_core::{air::RecursionPublicValues, RecursionProgram, Runtime};

use super::ShrinkStrategy;
use crate::{
    components::ZKMProverComponents, utils::is_root_public_values_valid, CompressedSC, HashableKey,
    InnerSC, ShrinkAir, ZKMProver, ZKMRecursionProverError, ZKMVerifyingKey,
};

/// The ring the zk shrink is proven and verified on.
pub type ZkShrinkSC = zkm_pcs::zk::KoalaBearPoseidon2ZkShrink;

/// The zk shrink strategy; see the module documentation.
#[derive(Clone, Copy, Debug, Default)]
pub struct ZkShrink;

/// The shard prover of the zk shrink machine.
pub fn zk_shrink_prover() -> CpuProver<ZkShrinkSC, ShrinkAir<KoalaBear>> {
    CpuProver::new(ShrinkAir::shrink_machine(ZkShrinkSC::compressed()))
}

impl ZkShrink {
    /// The zk shrink program over the compress root of `input`: the wrap
    /// program committing the root digest.  Its key depends only on the
    /// root's shape and the prover's key-admission mode.
    pub fn program<C: ZKMProverComponents>(
        prover: &ZKMProver<C>,
        input: &ZKMWrapWitnessValues<CompressedSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        Arc::new(zkm_recursion_circuit::machine::programs::build_wrap_program_with_digest(
            prover.root_prover.machine(),
            input,
            ZKMProver::<C>::pcs_max_log_row_count(),
            prover.vk_verification,
            PublicValuesOutputDigest::ReduceToRoot,
        ))
    }

    /// The zk shrink witness of a compress root proof.
    pub fn input<C: ZKMProverComponents>(
        prover: &ZKMProver<C>,
        reduced_proof: ZKMReduceProof<CompressedSC>,
    ) -> Result<ZKMWrapWitnessValues<CompressedSC>, ZKMRecursionProverError> {
        let ZKMReduceProof { vk, proof } = reduced_proof;
        let vk_merkle_data = prover.make_merkle_proofs(std::slice::from_ref(&vk))?;
        Ok(ZKMWrapWitnessValues {
            vks_and_proofs: vec![(vk, *proof.jagged_shard_proof)],
            vk_merkle_data,
        })
    }
}

impl ShrinkStrategy for ZkShrink {
    type Config = ZkShrinkSC;

    #[tracing::instrument(name = "zk_shrink", level = "info", skip_all)]
    fn shrink<C: ZKMProverComponents>(
        prover: &ZKMProver<C>,
        reduced_proof: ZKMReduceProof<CompressedSC>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<Self::Config>, ZKMRecursionProverError> {
        let input = Self::input(prover, reduced_proof)?;
        let program = Self::program(prover, &input);
        let mut runtime = Runtime::<zkm_pcs::Val<InnerSC>, zkm_pcs::Challenge<InnerSC>, _>::new(
            program.clone(),
            prover.shrink_prover.machine().config().perm.clone(),
        );
        let mut witness_stream = Vec::new();
        Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
        runtime.witness_stream = witness_stream.into();
        runtime.run().map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))?;
        runtime.print_stats();
        let zk_prover = zk_shrink_prover();
        let (pk, vk) =
            tracing::debug_span!("setup zk shrink").in_scope(|| zk_prover.setup(&program));
        let mut challenger = zk_prover.machine().config().challenger();
        let mut proof = tracing::debug_span!("prove zk shrink").in_scope(|| {
            zk_prover
                .prove(&pk, vec![runtime.record], &mut challenger, opts.recursion_opts)
                .map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))
        })?;
        Ok(ZKMReduceProof { vk, proof: proof.shard_proofs.pop().expect("one zk shrink shard") })
    }
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// Verify a zk shrink proof of `application_vk` with `public_values`
    /// against `trusted`, the zk shrink key of this prover's key-admission
    /// mode (the `vk` of any honest zk shrink proof; its distribution is the
    /// verifier's).
    pub fn verify_zk_shrink(
        &self,
        proof: &ZKMReduceProof<ZkShrinkSC>,
        application_vk: &ZKMVerifyingKey,
        trusted: &StarkVerifyingKey<ZkShrinkSC>,
        public_values: &ZKMPublicValues,
    ) -> Result<(), MachineVerificationError<ZkShrinkSC>> {
        if proof.vk.hash_koalabear() != trusted.hash_koalabear() {
            return Err(MachineVerificationError::InvalidVerificationKey);
        }
        if proof.proof.public_values.len() != zkm_recursion_core::air::RECURSIVE_PROOF_NUM_PV_ELTS {
            return Err(MachineVerificationError::InvalidPublicValues(
                "zk shrink public-value length",
            ));
        }
        let zk_prover = zk_shrink_prover();
        let mut challenger = zk_prover.machine().config().challenger();
        zk_prover.machine().verify(
            trusted,
            &MachineProof { shard_proofs: vec![proof.proof.clone()] },
            &mut challenger,
        )?;
        let root: &RootPublicValues<_> = proof.proof.public_values.as_slice().borrow();
        let pv: &RecursionPublicValues<_> = proof.proof.public_values.as_slice().borrow();
        if !is_root_public_values_valid(self.compress_prover.machine().config(), root)
            || pv.vk_root != self.recursion_vk_root
            || pv.zkm_vk_digest != application_vk.hash_koalabear()
            || pv.is_complete != KoalaBear::ONE
            || pv.contains_execution_shard != KoalaBear::ONE
            || pv.exit_code != KoalaBear::ZERO
        {
            return Err(MachineVerificationError::InvalidPublicValues(
                "zk shrink application binding",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::components::DefaultProverComponents;
    use anyhow::Result;
    use std::time::Instant;
    use zkm_core_executor::ZKMContext;
    use zkm_core_machine::io::ZKMStdin;
    use zkm_core_machine::utils::setup_logger;

    fn fib_stdin(n: u32) -> ZKMStdin {
        let mut stdin = ZKMStdin::new();
        stdin.write(&n);
        stdin
    }

    /// One zk shrink proof of the Fibonacci compress root beside the native
    /// shrink of the same root, timed and sized (`ZIREN_ZK_REPORT=<path>`
    /// writes the numbers as JSON); a second zk proof of the same root
    /// shares its key and public values and nothing else.
    #[test]
    #[ignore]
    fn test_e2e_zk_shrink_fibonacci() -> Result<()> {
        setup_logger();
        let elf = test_artifacts::FIBONACCI_ELF;
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let (_, pk_d, program, vk) = prover.setup(elf);
        let core_proof =
            prover.prove_core(&pk_d, program, &fib_stdin(10), opts, ZKMContext::default())?;
        let public_values = core_proof.public_values.clone();
        let compressed = prover.compress(&vk, core_proof, vec![], opts)?;
        prover.verify_compressed(&compressed, &vk)?;
        let compressed_bytes = bincode::serialize(&compressed)?.len();

        let start = Instant::now();
        let native = prover.shrink(compressed.clone(), opts)?;
        let native_secs = start.elapsed().as_secs_f64();
        let native_bytes = bincode::serialize(&native)?.len();
        let native_proof_bytes = bincode::serialize(&native.proof)?.len();
        prover.verify_shrink(&native, &vk)?;

        let start = Instant::now();
        let zk = prover.shrink_with::<ZkShrink>(compressed.clone(), opts)?;
        let zk_secs = start.elapsed().as_secs_f64();
        let zk_bytes = bincode::serialize(&zk)?.len();
        let zk_proof_bytes = bincode::serialize(&zk.proof)?.len();
        let start = Instant::now();
        prover.verify_zk_shrink(&zk, &vk, &zk.vk, &public_values)?;
        let zk_verify_secs = start.elapsed().as_secs_f64();

        let again = prover.shrink_with::<ZkShrink>(compressed, opts)?;
        assert_eq!(again.vk.hash_koalabear(), zk.vk.hash_koalabear());
        assert_ne!(zk.vk.hash_koalabear(), native.vk.hash_koalabear());
        assert_eq!(again.proof.public_values, zk.proof.public_values);
        assert_ne!(
            bincode::serialize(&again.proof)?,
            bincode::serialize(&zk.proof)?,
            "a zk shrink proof is randomised"
        );
        prover.verify_zk_shrink(&again, &vk, &zk.vk, &public_values)?;

        let mut wrong = public_values.clone();
        wrong.write(&1u8);
        assert!(prover.verify_zk_shrink(&zk, &vk, &zk.vk, &wrong).is_err());
        assert!(prover.verify_zk_shrink(&zk, &vk, &again.vk, &public_values).is_ok());

        let report = serde_json::json!({
            "compressed_bytes": compressed_bytes,
            "native_shrink": {"secs": native_secs, "bytes": native_bytes, "proof_bytes": native_proof_bytes},
            "zk_shrink": {"secs": zk_secs, "bytes": zk_bytes, "proof_bytes": zk_proof_bytes, "verify_secs": zk_verify_secs},
        });
        tracing::info!("zk shrink: {report}");
        if let Ok(path) = std::env::var("ZIREN_ZK_REPORT") {
            std::fs::write(path, serde_json::to_string_pretty(&report)?)?;
        }
        Ok(())
    }
}
