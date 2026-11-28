//! Shrink, wrap and the SNARK wrappers around the wrap proof.

use crate::*;

/// What a SNARK wrap of a shrink proof proves: the outer witness and its
/// three public inputs.
struct SnarkWrapInput {
    witness: Witness<OuterConfig>,
    vkey_hash: p3_bn254_fr::Bn254,
    committed_values_digest: p3_bn254_fr::Bn254,
    vk_root: p3_bn254_fr::Bn254,
}

/// The outer witness of `proof` with its public inputs written.  With
/// `bind_part_vk` the vkey hash also commits to the proof's part vk, as the
/// immutable-wrap-vk Groth16 circuit expects.
fn snark_wrap_input(proof: &ZKMReduceProof<OuterSC>, bind_part_vk: bool) -> SnarkWrapInput {
    let input = ZKMWrapWitnessValues {
        vks_and_proofs: vec![(proof.vk.clone(), (*proof.proof.jagged_shard_proof).clone())],
        vk_merkle_data: ZKMMerkleProofWitnessValues::<OuterSC>::dummy(1, 1),
    };
    let mut vkey_hash = zkm_vkey_digest_bn254(proof);
    if bind_part_vk {
        vkey_hash = hash_vkey_with_part_vk(&proof.vk.part_vk(), vkey_hash);
    }
    let committed_values_digest = zkm_committed_values_digest_bn254(proof);
    let vk_root = zkm_vk_root_bn254(proof);
    let mut witness = Witness::default();
    input.write(&mut witness);
    witness.write_committed_values_digest(committed_values_digest);
    witness.write_vkey_hash(vkey_hash);
    witness.write_vk_root(vk_root);
    SnarkWrapInput { witness, vkey_hash, committed_values_digest, vk_root }
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// Build the shrink recursion program, which verifies the compressed proof.
    /// Band-snapped through [`Self::fix_recursion_shape`], like every other
    /// recursion stage whose verifying key the allowlist has to contain.
    pub fn shrink_program(
        &self,
        input: &ZKMWrapWitnessValues<CompressedSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        let max_log_row_count = self.root_prover.machine().max_log_row_count();
        let mut program = build_wrap_program(
            self.root_prover.machine(),
            input,
            max_log_row_count,
            self.vk_verification,
        );
        let shape = Self::shrink_shape();
        let caps = shape.clone_into_hash_map();
        for (name, height) in ShrinkAir::<KoalaBear>::heights(&program) {
            match caps.get(&name) {
                Some(cap) => assert!(
                    height <= *cap,
                    "shrink program needs {name} height {height}, frozen cap is {cap} rows — \
                     the frozen shrink shape no longer fits; changing it re-runs the ceremony",
                ),
                None => assert!(
                    height == 0,
                    "shrink program emits {height} {name} rows but the frozen shrink shape \
                     has no {name} entry — a shrink builder took a compress-only path",
                ),
            }
        }
        *program.shape_mut() = Some(shape);
        Arc::new(program)
    }

    /// The frozen shrink proof shape (per-chip row counts).  See
    /// [`Self::shrink_program`] — do not edit without re-running
    /// the gnark ceremony.
    pub(crate) fn shrink_shape() -> RecursionShape {
        [
            ("BaseAlu", 1 << 18),
            ("ExtAlu", 1 << 18),
            ("MemoryConst", 1 << 19),
            ("MemoryVar", 1 << 18),
            ("Poseidon2WideDeg3", 1 << 18),
            ("PublicValues", 1 << 4),
            ("Select", 1 << 19),
        ]
        .into_iter()
        .map(|(n, rows)| (n.to_string(), rows))
        .collect::<std::collections::BTreeMap<_, _>>()
        .into()
    }

    /// Build the wrap recursion program, the terminal stage, which verifies
    /// the shrink proof for the BN254 SNARK.
    ///
    /// Differs from [`Self::shrink_program`] in two ways:
    /// 1. Compiles with [`WrapConfig`] (instead of [`InnerConfig`]) so
    ///    the resulting [`RecursionProgram`] is provable on the OuterSC
    ///    (BN254-friendly) ring via [`Self::wrap_prover`], not the
    ///    KoalaBear-side [`Self::shrink_prover`].
    /// 2. Verifies the input proof against
    ///    [`Self::shrink_prover`]`.machine()` (the machine that produced
    ///    the shrink proof we are wrapping).
    ///
    /// The `verify_wrap_jagged` body is generic over `C: CircuitConfig`
    /// with `F=InnerVal` / `EF=InnerChallenge` / `Bit=Felt<KoalaBear>`,
    /// and `WrapConfig` satisfies these bounds (its `CircuitConfig` impl in
    /// `zkm_recursion_circuit`), so the same verifier function works
    /// unchanged here.
    ///
    /// Builds fresh on every call; [`Self::wrap_bn254`] goes through
    /// [`Self::wrap_programs_cache`].
    pub fn wrap_program(
        &self,
        input: &ZKMWrapWitnessValues<ShrinkSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        use zkm_pcs::air::MachineAir;
        use zkm_recursion_circuit::machine::wrap::verify_wrap_jagged;

        let max_log_row_count = self.shrink_prover.machine().max_log_row_count();

        let builder_span = tracing::debug_span!("build wrap program").entered();
        let mut builder = Builder::<WrapConfig>::new(RecursionProgramType::Wrap);
        let input_var = input.read(&mut builder);

        verify_wrap_jagged::<WrapConfig, ShrinkSC, _>(
            &mut builder,
            input_var,
            self.shrink_prover.machine(),
            self.vk_verification,
            max_log_row_count,
            PublicValuesOutputDigest::ReduceToRoot,
        );
        let operations = builder.into_operations();
        builder_span.exit();

        let compiler_span = tracing::debug_span!("compile wrap program").entered();
        let mut compiler = AsmCompiler::<WrapConfig>::default();
        let mut program = compiler.compile(operations);
        compiler_span.exit();

        // Preserve the wrap tables used by the published SNARK circuit. Other
        // unshaped recursion programs can use the tighter multiple-of-32 padding.
        let rows = WrapAir::<KoalaBear>::heights(&program)
            .into_iter()
            .filter(|(name, _)| {
                self.wrap_prover.machine().chips().iter().any(|c| c.name() == *name)
            })
            .map(|(name, rows)| {
                let rows = zkm_core_machine::utils::next_power_of_two(rows, None, &name);
                (name, rows)
            })
            .collect::<BTreeMap<_, _>>();
        *program.shape_mut() = Some(rows.into());
        Arc::new(program)
    }

    /// Wrap a reduce proof into a STARK proven over a SNARK-friendly field.
    #[instrument(name = "shrink", level = "info", skip_all)]
    pub fn shrink(
        &self,
        reduced_proof: ZKMReduceProof<CompressedSC>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<ShrinkSC>, ZKMRecursionProverError> {
        let ZKMReduceProof { vk: compressed_vk, proof: compressed_proof } = reduced_proof;
        let jagged_whir_proof = *compressed_proof.jagged_shard_proof;
        let vk_merkle_data = self.make_merkle_proofs(std::slice::from_ref(&compressed_vk))?;
        let input = ZKMWrapWitnessValues {
            vks_and_proofs: vec![(compressed_vk, jagged_whir_proof)],
            vk_merkle_data,
        };
        let program = self.shrink_program(&input);

        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            program.clone(),
            self.shrink_prover.machine().config().perm.clone(),
        );
        let mut witness_stream = Vec::new();
        Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
        runtime.witness_stream = witness_stream.into();
        runtime.run().map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))?;
        runtime.print_stats();
        tracing::debug!("shrink program executed successfully");

        let (shrink_pk, shrink_vk) =
            tracing::debug_span!("setup shrink").in_scope(|| self.shrink_prover.setup(&program));
        let mut challenger = self.shrink_prover.machine().config().challenger();

        let rec = runtime.record;
        let mut compress_proof = self
            .shrink_prover
            .prove(&shrink_pk, vec![rec.clone()], &mut challenger, opts.recursion_opts)
            .unwrap();
        let mut proof = compress_proof.shard_proofs.pop().unwrap();

        if let Some(jagged) =
            self.shrink_prover.reprove_shrink_shard(&shrink_pk, &rec, &opts.recursion_opts)
        {
            proof.jagged_shard_proof = jagged;
        }

        Ok(ZKMReduceProof { vk: shrink_vk, proof })
    }

    /// Wrap a reduce proof into a STARK proven over a SNARK-friendly field.
    #[instrument(name = "wrap_bn254", level = "info", skip_all)]
    pub fn wrap_bn254(
        &self,
        compressed_proof: ZKMReduceProof<ShrinkSC>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<OuterSC>, ZKMRecursionProverError> {
        let ZKMReduceProof { vk: compressed_vk, proof: compressed_proof } = compressed_proof;
        let jagged_whir_proof = *compressed_proof.jagged_shard_proof;
        let vk_merkle_data = self.make_merkle_proofs(std::slice::from_ref(&compressed_vk))?;
        let input = ZKMWrapWitnessValues {
            vks_and_proofs: vec![(compressed_vk, jagged_whir_proof)],
            vk_merkle_data,
        };
        let (program, digest) = self.wrap_program_cached(&input);

        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            program.clone(),
            self.shrink_prover.machine().config().perm.clone(),
        );
        let mut witness_stream = Vec::new();
        Witnessable::<WrapConfig>::write(&input, &mut witness_stream);
        runtime.witness_stream = witness_stream.into();
        runtime.run().map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))?;
        runtime.print_stats();
        tracing::debug!("wrap program executed successfully");

        let wrap_keys = tracing::debug_span!("setup wrap")
            .in_scope(|| self.wrap_keys_cached(&program, digest))?;
        let (wrap_pk, wrap_vk) = &*wrap_keys;
        if let Some(path) = std::env::var_os("ZIREN_DUMP_PART_STARK_VK") {
            match bincode::serialize(&wrap_vk.part_vk()) {
                Ok(bytes) => match std::fs::write(&path, &bytes) {
                    Ok(()) => {
                        tracing::info!(
                            ">>> PART_STARK_VK written {} bytes to {:?}",
                            bytes.len(),
                            path
                        )
                    }
                    Err(e) => tracing::warn!(">>> PART_STARK_VK write failed {:?}: {e}", path),
                },
                Err(e) => tracing::warn!(">>> PART_STARK_VK serialize failed: {e}"),
            }
        }

        let mut wrap_challenger = self.wrap_prover.machine().config().challenger();
        let time = std::time::Instant::now();
        let mut wrap_proof = self
            .wrap_prover
            .prove(wrap_pk, vec![runtime.record], &mut wrap_challenger, opts.recursion_opts)
            .unwrap();
        let elapsed = time.elapsed();
        tracing::debug!("wrap proving time: {:?}", elapsed);
        let mut wrap_challenger = self.wrap_prover.machine().config().challenger();
        self.wrap_prover.machine().verify(wrap_vk, &wrap_proof, &mut wrap_challenger).unwrap();
        tracing::info!("wrapping successful");

        Ok(ZKMReduceProof { vk: wrap_vk.clone(), proof: wrap_proof.shard_proofs.pop().unwrap() })
    }

    /// The wrap witness of a dummy shrink proof at the frozen shrink shape.
    pub(crate) fn dummy_wrap_input(&self) -> ZKMWrapWitnessValues<ShrinkSC> {
        let mut rows: Vec<(String, usize)> =
            Self::shrink_shape().clone_into_hash_map().into_iter().collect();
        rows.sort();
        ZKMWrapWitnessValues {
            vks_and_proofs: vec![zkm_recursion_circuit::stark::dummy_vk_and_shard_proof_rows(
                self.shrink_prover.machine(),
                &rows,
            )],
            vk_merkle_data: ZKMMerkleProofWitnessValues::dummy(1, VK_MERKLE_TREE_HEIGHT),
        }
    }

    /// The wrap program for `input` and its setup digest, through
    /// [`Self::wrap_programs_cache`], keyed like the other program caches
    /// (see [`Self::verification_keyed`]).
    pub(crate) fn wrap_program_cached(
        &self,
        input: &ZKMWrapWitnessValues<ShrinkSC>,
    ) -> (Arc<RecursionProgram<KoalaBear>>, [u8; 32]) {
        self.cached_program(
            &self.wrap_programs_cache,
            self.verification_keyed(input.shape_key()),
            "wrap",
            || self.wrap_program(input),
        )
    }

    /// The wrap keys of this prover, built by setup on the first call.
    ///
    /// `setup_digest` must be the digest returned with `program` by
    /// [`Self::cached_program`]. The lock is held through setup so concurrent
    /// calls reuse the resulting keys. The wrap program is fixed, so a call
    /// with another digest than the keys were built for is an error.
    pub fn wrap_keys_cached(
        &self,
        program: &RecursionProgram<KoalaBear>,
        setup_digest: [u8; 32],
    ) -> Result<Arc<WrapKeys<C>>, ZKMRecursionProverError> {
        let mut cache = self.wrap_keys_cache.lock().unwrap();
        if let Some((cached_digest, keys)) = cache.as_ref() {
            if *cached_digest != setup_digest {
                return Err(ZKMRecursionProverError::WrapProgramMismatch {
                    cached: hex::encode(cached_digest),
                    requested: hex::encode(setup_digest),
                });
            }
            tracing::debug!("wrap keys cache hit");
            return Ok(Arc::clone(keys));
        }
        let keys = Arc::new(self.wrap_prover.setup(program));
        *cache = Some((setup_digest, Arc::clone(&keys)));
        Ok(keys)
    }

    /// The wrap verifying key, from the wrap keys: `None` until a wrap or
    /// [`Self::prewarm_wrap_keys`] has built them.
    pub fn wrap_vk(&self) -> Option<StarkVerifyingKey<OuterSC>> {
        self.wrap_keys_cache.lock().unwrap().as_ref().map(|(_, keys)| keys.1.clone())
    }

    /// Wrap the STARK proven over a SNARK-friendly field into a PLONK proof.
    #[instrument(name = "wrap_plonk_bn254", level = "info", skip_all)]
    pub fn wrap_plonk_bn254(
        &self,
        proof: ZKMReduceProof<OuterSC>,
        build_dir: &Path,
    ) -> PlonkBn254Proof {
        let SnarkWrapInput { witness, vkey_hash, committed_values_digest, vk_root } =
            snark_wrap_input(&proof, false);

        let prover = PlonkBn254Prover::new();
        let proof = prover.prove(witness, build_dir.to_path_buf());

        prover
            .verify(
                &proof,
                &vkey_hash.as_canonical_biguint(),
                &committed_values_digest.as_canonical_biguint(),
                &vk_root.as_canonical_biguint(),
                build_dir,
            )
            .unwrap();

        proof
    }

    /// Wrap the STARK proven over a SNARK-friendly field into a Groth16 proof.
    #[instrument(name = "wrap_groth16_bn254", level = "info", skip_all)]
    pub fn wrap_groth16_bn254(
        &self,
        proof: ZKMReduceProof<OuterSC>,
        build_dir: &Path,
    ) -> Groth16Bn254Proof {
        let SnarkWrapInput { witness, vkey_hash, committed_values_digest, vk_root } =
            snark_wrap_input(&proof, crate::build::zkm_imm_wrap_vk_mode());

        let prover = Groth16Bn254Prover::new();
        let proof = prover.prove(witness, build_dir.to_path_buf());

        prover
            .verify(
                &proof,
                &vkey_hash.as_canonical_biguint(),
                &committed_values_digest.as_canonical_biguint(),
                &vk_root.as_canonical_biguint(),
                build_dir,
            )
            .unwrap();

        proof
    }

    /// Wrap the STARK proven over a SNARK-friendly field into a DV-SNARK proof.
    #[instrument(name = "wrap_dvsnark_bn254", level = "info", skip_all)]
    pub fn wrap_dvsnark_bn254(
        &self,
        proof: ZKMReduceProof<OuterSC>,
        build_dir: &Path,
        store_dir: &Path,
    ) -> DvSnarkBn254Proof {
        let witness = snark_wrap_input(&proof, false).witness;
        let prover = DvSnarkBn254Prover::new();
        prover.prove(witness, build_dir.to_path_buf(), store_dir.to_path_buf())
    }
}
