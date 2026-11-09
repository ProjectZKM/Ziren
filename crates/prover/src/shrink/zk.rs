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
    StarkVerifyingKey, VerificationError, ZKMProverOpts,
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

/// How many times the zk shrink proves a shard before giving up: each proof
/// is verified, and one whose transcript drew a degenerate challenge
/// ([`VerificationError::DegenerateChallenge`]) is proved again with fresh
/// random rows, masks and salts.  An honest proof is rejected with
/// probability below `2^-20`, so a second attempt is rare and a fourth
/// failure is a bug.
pub const ZK_SHRINK_ATTEMPTS: usize = 4;

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
        let record = runtime.record;
        for attempt in 1..=ZK_SHRINK_ATTEMPTS {
            let mut challenger = zk_prover.machine().config().challenger();
            let proof = tracing::debug_span!("prove zk shrink").in_scope(|| {
                zk_prover
                    .prove(&pk, vec![record.clone()], &mut challenger, opts.recursion_opts)
                    .map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))
            })?;
            let mut challenger = zk_prover.machine().config().challenger();
            match tracing::debug_span!("verify zk shrink")
                .in_scope(|| zk_prover.machine().verify(&vk, &proof, &mut challenger))
            {
                Ok(()) => {
                    let mut proof = proof;
                    return Ok(ZKMReduceProof {
                        vk,
                        proof: proof.shard_proofs.pop().expect("one zk shrink shard"),
                    });
                }
                Err(MachineVerificationError::InvalidShardProof(
                    VerificationError::DegenerateChallenge(why),
                )) => {
                    tracing::info!(
                        "zk shrink attempt {attempt} drew a degenerate challenge: {why}"
                    );
                }
                Err(e) => return Err(ZKMRecursionProverError::RuntimeError(e.to_string())),
            }
        }
        Err(ZKMRecursionProverError::RuntimeError(format!(
            "{ZK_SHRINK_ATTEMPTS} zk shrink proofs in a row drew a degenerate challenge"
        )))
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

    /// Every chip of the shrink machine admits cancelling random-row pairs
    /// and none of its main columns is pinned by its lookups in a pair's sum
    /// or difference, so the zk shard hides every opening.
    #[test]
    fn every_shrink_chip_admits_hidden_random_rows() {
        use p3_air::BaseAir;
        use zkm_pcs::shard_level::zk::RandomRowPlan;
        use zkm_pcs::MachineAir;
        let machine = ShrinkAir::<KoalaBear>::shrink_machine(ZkShrinkSC::compressed());
        for chip in machine.chips() {
            let width = <_ as BaseAir<KoalaBear>>::width(chip);
            let plan = RandomRowPlan::new(chip, width).unwrap_or_else(|e| panic!("{e}"));
            assert!(
                plan.exposed_columns().is_empty(),
                "chip {}: lookups pin columns {:?}",
                chip.name(),
                plan.exposed_columns()
            );
            assert!(
                plan.half_hidden_columns().is_empty(),
                "chip {}: lookups pin columns {:?} on one side",
                chip.name(),
                plan.half_hidden_columns()
            );
            assert_eq!(
                plan.exposed_dimension(),
                0,
                "chip {}: lookups pin a combination of columns",
                chip.name()
            );
        }
    }

    /// The shipped zk shrink keeps every zero-knowledge budget of
    /// `zkm_pcs::zk_budget` for the shrink machine's shard shape, and the
    /// error terms it adds stay far below the schedule's soundness.
    #[test]
    fn zk_shrink_keeps_the_zero_knowledge_budgets() {
        use zkm_pcs::shard_level::zk::num_interaction_variables;
        use zkm_pcs::zk_budget::{ZkBudget, ZkErrors, EF_DIM};
        use zkm_pcs::zk_mask::ZkCellLayout;
        let machine = ShrinkAir::<KoalaBear>::shrink_machine(ZkShrinkSC::compressed());
        let chips: Vec<_> = machine.chips().iter().collect();
        let interaction_variables = num_interaction_variables(&chips);
        let lsh = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
        let layout = ZkCellLayout::for_shard(
            EF_DIM,
            ZKMProver::<DefaultProverComponents>::pcs_max_log_row_count(),
            interaction_variables,
        );
        let budget = ZkBudget::for_schedule(
            &zkm_pcs::whir::jagged::zk_shrink_whir_config(lsh),
            lsh,
            &layout,
        );
        assert_eq!(budget.violations(), Vec::<String>::new(), "{budget}");
        let errors = ZkErrors::new(&budget, &layout, interaction_variables);
        assert!(errors.soundness_bits >= 110, "{errors}");
        assert!(errors.simulation_bits >= 150, "{errors}");
    }

    fn fib_stdin(n: u32) -> ZKMStdin {
        let mut stdin = ZKMStdin::new();
        stdin.write(&n);
        stdin
    }

    /// Every scalar of a proof, in serialisation order, as text, with the
    /// path that reaches it.
    fn scalars(value: &serde_json::Value, path: &str, out: &mut Vec<(String, String)>) {
        match value {
            serde_json::Value::Array(items) => {
                for (i, v) in items.iter().enumerate() {
                    scalars(v, &format!("{path}[{i}]"), out);
                }
            }
            serde_json::Value::Object(fields) => {
                for (k, v) in fields {
                    scalars(v, &format!("{path}.{k}"), out);
                }
            }
            other => out.push((path.to_string(), other.to_string())),
        }
    }

    /// Two witnesses of one statement: Fibonacci inputs 10 and 10 + 7918
    /// (the period of the pair `(a, b)` modulo 7919) commit the same values,
    /// so their compress roots prove the same zk-shrink statement from
    /// different traces.  A scalar of the proof that is equal across two
    /// proofs of one witness but differs across the witnesses would
    /// distinguish them; there is none.  Scalars below `2^20` (shape
    /// counts, indices, bytes) are left out of the comparison, which a
    /// uniform field element falls under with probability `2^-11`, and so
    /// are the authentication paths of the preprocessed tree: that tree is
    /// public and the same in every proof, and which of its sibling digests
    /// a proof carries at a query slot depends on the query index alone.
    #[test]
    #[ignore]
    fn test_e2e_zk_shrink_hides_the_witness() -> Result<()> {
        setup_logger();
        let elf = test_artifacts::FIBONACCI_ELF;
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let (_, pk_d, program, vk) = prover.setup(elf);
        let mut proofs = Vec::new();
        for n in [10u32, 10 + 7918, 10] {
            let core_proof = prover.prove_core(
                &pk_d,
                program.clone(),
                &fib_stdin(n),
                opts,
                ZKMContext::default(),
            )?;
            let public_values = core_proof.public_values.clone();
            let compressed = prover.compress(&vk, core_proof, vec![], opts)?;
            let zk = prover.shrink_with::<ZkShrink>(compressed, opts)?;
            proofs.push((zk, public_values));
        }
        let (first, public_values) = &proofs[0];
        for (zk, pv) in &proofs {
            assert_eq!(pv.hash(), public_values.hash(), "one statement");
            assert_eq!(zk.vk.hash_koalabear(), first.vk.hash_koalabear(), "one key");
            prover.verify_zk_shrink(zk, &vk, &first.vk, public_values)?;
        }
        let values: Vec<Vec<(String, String)>> = proofs
            .iter()
            .map(|(zk, _)| {
                let mut out = Vec::new();
                scalars(&serde_json::to_value(&zk.proof)?, "proof", &mut out);
                Ok(out)
            })
            .collect::<Result<_>>()?;
        assert_eq!(values[0].len(), values[1].len());
        assert_eq!(values[0].len(), values[2].len());
        let large = |s: &str| s.parse::<u64>().is_ok_and(|v| v >= 1 << 20);
        let preprocessed_path = |path: &str| -> bool {
            let Some(rest) = path.split("round_query_openings[0].leaves[").nth(1) else {
                return false;
            };
            let (index, tail) = rest.split_once(']').expect("a leaf index");
            index.parse::<usize>().expect("a leaf index") % 2 == 0 && tail.starts_with(".proof[")
        };
        let equal_at = |a: &[(String, String)], b: &[(String, String)]| -> Vec<usize> {
            (0..a.len())
                .filter(|&i| a[i].1 == b[i].1 && large(&a[i].1) && !preprocessed_path(&a[i].0))
                .collect()
        };
        let same_witness = equal_at(&values[0], &values[2]);
        let other_witness = equal_at(&values[0], &values[1]);
        let leaks: Vec<&(String, String)> = same_witness
            .iter()
            .filter(|i| !other_witness.contains(i))
            .map(|&i| &values[0][i])
            .collect();
        assert!(
            leaks.is_empty(),
            "{} scalars equal across proofs of one witness but not across witnesses: {:?}",
            leaks.len(),
            leaks.iter().take(12).collect::<Vec<_>>()
        );
        assert!(same_witness.len() * 4 < values[0].len(), "the proof is randomised");
        Ok(())
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
