//! The compression pipeline: the first-layer inputs of a core proof and the
//! recursion tree that reduces them to one proof.

use crate::*;

/// A recursion node ready to prove, as the trace workers hand it to the
/// provers.
enum RecursionJob {
    /// A node below the root, with its traces under the compress machine.
    Node {
        range: crate::compress_tree::ShardRange,
        program: Arc<RecursionProgram<KoalaBear>>,
        record: ExecutionRecord<KoalaBear>,
        traces: zkm_pcs::Traces<KoalaBear>,
    },
    /// The root. The root prover generates the traces from the record.
    Root {
        range: crate::compress_tree::ShardRange,
        program: Arc<RecursionProgram<KoalaBear>>,
        record: ExecutionRecord<KoalaBear>,
    },
}

/// The global hash chain of a core proof, computed once for the first layer
/// ([`ZKMProver::global_chain_context`]).
pub struct GlobalChainContext {
    heads_before_and_after_shards: Vec<zkm_pcs::logup_gkr::GlobalChainHeads<KoalaBear>>,
    h_star: [KoalaBear; DIGEST_SIZE],
}

impl GlobalChainContext {
    /// The lane heads before the first shard, then after each shard.
    pub fn heads_before_and_after_shards(
        &self,
    ) -> &[zkm_pcs::logup_gkr::GlobalChainHeads<KoalaBear>] {
        &self.heads_before_and_after_shards
    }

    /// The chain's end, which every shard's global challenge is derived from.
    pub fn h_star(&self) -> [KoalaBear; DIGEST_SIZE] {
        self.h_star
    }
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// The global hash chain over `shard_proofs` under the core key `vk`: the
    /// lane heads of [`Self::global_chain_heads`] and the digest of the last.
    pub fn global_chain_context(
        &self,
        vk: &StarkVerifyingKey<CoreSC>,
        shard_proofs: &[ShardProof<CoreSC>],
    ) -> GlobalChainContext {
        let heads_before_and_after_shards = self.global_chain_heads(vk, shard_proofs);
        let end = heads_before_and_after_shards.last().expect("the chain holds at least its start");
        let h_star = self.core_prover.machine().global_chain_value(end);
        GlobalChainContext { heads_before_and_after_shards, h_star }
    }

    /// The lane heads of the global hash chain over `shard_proofs` under the
    /// core key `vk`: the heads before the first shard, then the heads after
    /// each shard, each shard's round on the lane the proof names.
    pub fn global_chain_heads(
        &self,
        vk: &StarkVerifyingKey<CoreSC>,
        shard_proofs: &[ShardProof<CoreSC>],
    ) -> Vec<zkm_pcs::logup_gkr::GlobalChainHeads<KoalaBear>> {
        let machine = self.core_prover.machine();
        let mut challenger = machine.config().challenger();
        vk.observe_into(&mut challenger);
        let rounds: Vec<_> =
            shard_proofs.iter().map(|sp| machine.global_round_binding(sp)).collect();
        machine.global_chain_heads(
            &challenger,
            rounds.iter().map(Option::as_ref),
            shard_proofs.iter().map(|sp| sp.global_chain_lane),
        )
    }

    /// The global hash chain over `shard_proofs` under the core key `vk`:
    /// its start, then its value after each shard, the last being the `h_star`
    /// every shard's global challenge is derived from. Each value is the
    /// digest of the lane heads there ([`Self::global_chain_heads`]).
    pub fn global_chain(
        &self,
        vk: &StarkVerifyingKey<CoreSC>,
        shard_proofs: &[ShardProof<CoreSC>],
    ) -> Vec<[KoalaBear; DIGEST_SIZE]> {
        let machine = self.core_prover.machine();
        self.global_chain_heads(vk, shard_proofs)
            .iter()
            .map(|lanes| machine.global_chain_value(lanes))
            .collect()
    }

    /// Wrap each batch of `ShardProof`s into a
    /// `ZKMCoreWitnessValues`, taking the `JaggedShardProof` each
    /// one carries, with the lane heads of the global hash chain before the
    /// shard, taken from `chain`, the context of these `shard_proofs`.
    pub fn get_recursion_core_inputs(
        &self,
        vk: &StarkVerifyingKey<CoreSC>,
        shard_proofs: &[ShardProof<CoreSC>],
        chain: &GlobalChainContext,
        batch_size: usize,
        is_complete: bool,
    ) -> Vec<ZKMCoreWitnessValues<CoreSC>> {
        let lanes = chain.heads_before_and_after_shards();
        assert_eq!(
            lanes.len(),
            shard_proofs.len() + 1,
            "the global chain context is of another proof"
        );
        let mut core_inputs = Vec::new();
        for (batch_idx, batch) in shard_proofs.chunks(batch_size).enumerate() {
            assert_eq!(
                batch.len(),
                1,
                "normalize is single-shard: get_recursion_core_inputs \
                 must be called with batch_size=1 (one core shard per normalize); \
                 got a batch of {} shards",
                batch.len()
            );
            core_inputs.push(self.get_recursion_core_input(
                vk,
                &batch[0],
                batch_idx == 0,
                is_complete,
                lanes[batch_idx],
            ));
        }

        core_inputs
    }

    /// The normalize input of one core shard proof: `global_chain_heads` holds the
    /// lane heads of the global hash chain before the shard,
    /// [`Self::global_chain_heads`]'s entry at the shard's index, and the shard's
    /// round extends the lane the proof names. The heads depend on the shards
    /// before this one only, so a shard can be normalized as soon as it is
    /// proven.
    pub fn get_recursion_core_input(
        &self,
        vk: &StarkVerifyingKey<CoreSC>,
        shard_proof: &ShardProof<CoreSC>,
        is_first_shard: bool,
        is_complete: bool,
        global_chain_heads: zkm_pcs::logup_gkr::GlobalChainHeads<KoalaBear>,
    ) -> ZKMCoreWitnessValues<CoreSC> {
        ZKMCoreWitnessValues {
            vk: vk.clone(),
            shard_proofs: vec![(*shard_proof.jagged_shard_proof).clone()],
            is_complete,
            is_first_shard,
            vk_root: self.recursion_vk_root,
            global_chain_heads,
            global_round_lanes: vec![shard_proof.global_chain_lane],
        }
    }

    /// The inputs of the global-round programs of a core proof, one for each
    /// global proof, in the order the compress tree takes them: before the
    /// shards, the lanes in descending order and each lane's proofs latest
    /// first, so that each one starts the global hash chain where the one
    /// before it ends. Every program finds the lane it steps back at the head
    /// its rounds end at: the lanes above it are back at their start and the
    /// lanes below it still at their end.
    ///
    /// A global proof is placed by the rounds it opens
    /// (`StarkMachine::global_proof_rounds`), whatever its position in
    /// `global_proofs`: they must be consecutive rounds of one lane, in the
    /// lane's order, and the proofs together must open every round the shards
    /// commit once.
    ///
    /// `chain` is the context of these `shard_proofs`. The inputs step every
    /// lane from its head at the chain's end back to its head at the chain's
    /// start.
    pub fn get_recursion_global_round_inputs(
        &self,
        vk: &StarkVerifyingKey<CoreSC>,
        shard_proofs: &[ShardProof<CoreSC>],
        global_proofs: &[ShardProof<CoreSC>],
        chain: &GlobalChainContext,
    ) -> Result<
        Vec<zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues<CoreSC>>,
        ZKMRecursionProverError,
    > {
        let invalid = |reason: String| {
            ZKMRecursionProverError::RuntimeError(format!("invalid global proofs: {reason}"))
        };
        let lanes = chain.heads_before_and_after_shards();
        assert_eq!(
            lanes.len(),
            shard_proofs.len() + 1,
            "the global chain context is of another proof"
        );
        let machine = self.core_prover.machine();
        let end = *lanes.last().expect("the chain holds at least its start");
        let global_h_star = chain.h_star();
        assert_eq!(
            global_h_star,
            machine.global_chain_value(&end),
            "the global chain context ends at another digest than its last heads"
        );
        let mut committed: [Vec<_>; zkm_pcs::logup_gkr::GLOBAL_CHAIN_LANE_COUNT] =
            core::array::from_fn(|_| Vec::new());
        for (shard, proof) in shard_proofs.iter().enumerate() {
            let Some(round) = machine.global_round_binding(proof) else {
                continue;
            };
            committed
                .get_mut(usize::from(proof.global_chain_lane))
                .ok_or_else(|| {
                    invalid(format!("shard {shard} is on the lane {}", proof.global_chain_lane))
                })?
                .push((shard, round, false));
        }
        let mut placed = Vec::with_capacity(global_proofs.len());
        for proof in global_proofs {
            let rounds = machine.global_proof_rounds(proof).map_err(invalid)?;
            let place = committed.iter().enumerate().find_map(|(lane, of_lane)| {
                of_lane
                    .windows(rounds.len())
                    .position(|window| {
                        window
                            .iter()
                            .zip(&rounds)
                            .all(|((_, round, opened), opens)| !*opened && round == opens)
                    })
                    .map(|first| (lane, first))
            });
            let Some((lane, first)) = place else {
                return Err(invalid(
                    "a global proof does not open consecutive rounds of one lane, in the lane's \
                     order, that no other global proof opens"
                        .into(),
                ));
            };
            for (_, _, opened) in &mut committed[lane][first..first + rounds.len()] {
                *opened = true;
            }
            placed.push((lane, first, proof));
        }
        let unopened = committed.iter().flatten().filter(|(_, _, opened)| !*opened).count();
        if unopened != 0 {
            return Err(invalid(format!(
                "{unopened} global rounds the shards commit are opened by no global proof"
            )));
        }
        placed.sort_by_key(|(lane, first, _)| std::cmp::Reverse((*lane, *first)));
        let mut heads = end;
        let inputs = placed
            .into_iter()
            .map(|(lane, first, proof)| {
                heads[lane] = lanes[committed[lane][first].0][lane];
                self.get_recursion_global_round_input(vk, proof, heads, lane as u8, global_h_star)
            })
            .collect();
        assert_eq!(
            heads, lanes[0],
            "the global round inputs do not step every lane back to the chain's start"
        );
        Ok(inputs)
    }

    /// The global-round input of one global proof, which opens consecutive
    /// rounds of lane `global_chain_lane` in the order of its table slots:
    /// `global_chain_heads` holds the lane heads of the global hash chain before
    /// the first of those rounds and `global_h_star` is the chain's end. The
    /// heads of the other lanes only pass through the program, so a prover
    /// with several devices builds the input of a proof from the state of
    /// its lane and the heads the compress tree reaches the proof with.
    pub fn get_recursion_global_round_input(
        &self,
        vk: &StarkVerifyingKey<CoreSC>,
        global_proof: &ShardProof<CoreSC>,
        global_chain_heads: zkm_pcs::logup_gkr::GlobalChainHeads<KoalaBear>,
        global_chain_lane: u8,
        global_h_star: [KoalaBear; DIGEST_SIZE],
    ) -> zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues<CoreSC> {
        zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues {
            vk: vk.clone(),
            proofs: vec![(*global_proof.jagged_shard_proof).clone()],
            vk_root: self.recursion_vk_root,
            global_chain_heads,
            global_chain_lane,
            global_h_star,
            global_pow_witness: global_proof
                .jagged_shard_proof
                .global_pow_witness
                .unwrap_or(KoalaBear::ZERO),
        }
    }

    /// Constructs `ZKMDeferredWitnessValues` from each batch, taking
    /// the `JaggedShardProof` each input proof carries. The deferred proofs
    /// follow the last shard, so they pass through `global_chain`, the global
    /// hash chain's end.
    pub fn get_recursion_deferred_inputs<'a>(
        &'a self,
        vk: &'a StarkVerifyingKey<CoreSC>,
        last_proof_pv: &PublicValues<Word<KoalaBear>, KoalaBear>,
        global_chain: [KoalaBear; DIGEST_SIZE],
        deferred_proofs: &[ZKMReduceProof<CompressedSC>],
        batch_size: usize,
    ) -> Result<Vec<ZKMDeferredWitnessValues<CompressedSC>>, VkNotAllowed> {
        let mut deferred_digest = [Val::<InnerSC>::ZERO; DIGEST_SIZE];
        let mut deferred_inputs = Vec::new();
        for batch in deferred_proofs.chunks(batch_size) {
            let vks_and_proofs: Vec<_> = batch
                .iter()
                .cloned()
                .map(|proof| (proof.vk, *proof.proof.jagged_shard_proof))
                .collect();

            let vks: Vec<StarkVerifyingKey<CompressedSC>> =
                vks_and_proofs.iter().map(|(vk, _)| vk.clone()).collect();
            let merkle = self.make_merkle_proofs(&vks)?;

            deferred_inputs.push(ZKMDeferredWitnessValues {
                vks_and_proofs,
                vk_merkle_data: merkle,
                start_reconstruct_deferred_digest: deferred_digest,
                is_complete: false,
                zkm_vk_digest: vk.hash_koalabear(),
                end_pc: Val::<InnerSC>::ZERO,
                end_shard: last_proof_pv.shard + KoalaBear::ONE,
                end_execution_shard: last_proof_pv.execution_shard,
                init_addr_bits: last_proof_pv.last_init_addr_bits,
                finalize_addr_bits: last_proof_pv.last_finalize_addr_bits,
                committed_value_digest: last_proof_pv.committed_value_digest,
                deferred_proofs_digest: last_proof_pv.deferred_proofs_digest,
                global_chain,
            });
            deferred_digest = Self::hash_deferred_proofs(deferred_digest, batch);
        }
        Ok(deferred_inputs)
    }

    /// Generate the inputs for the first layer of recursive proofs.
    ///
    /// Emits `ZKMCircuitWitness::CoreJagged` witnesses that dispatch to the
    /// Normalize program; deferred proofs follow
    /// the same dispatch.
    ///
    /// A leaf is never the root of the compress tree: an execution of one
    /// shard closes through a compose of arity one, whose key the allowlist
    /// enumerates with every other arity.  The leaf keys are therefore
    /// exactly the open normalize classes, one per `(chip set, preprocessed
    /// bucket, global class, main bucket)`, and the global-round shapes, and
    /// no leaf is snapped to the root geometry.
    #[allow(clippy::type_complexity)]
    pub fn get_first_layer_inputs<'a>(
        &'a self,
        vk: &'a ZKMVerifyingKey,
        shard_proofs: &[ShardProof<CoreSC>],
        global_proofs: &[ShardProof<CoreSC>],
        deferred_proofs: &[ZKMReduceProof<CompressedSC>],
        batch_size: usize,
    ) -> Result<Vec<ZKMCircuitWitness>, ZKMRecursionProverError> {
        let mut inputs = Vec::new();
        let chain = self.global_chain_context(&vk.vk, shard_proofs);

        let global_inputs =
            self.get_recursion_global_round_inputs(&vk.vk, shard_proofs, global_proofs, &chain)?;
        tracing::debug!(
            "emitting {} GlobalJagged witness(es) of {:?} round(s), {} program shape(s)",
            global_inputs.len(),
            global_inputs.iter().map(|input| input.rounds()).collect::<Vec<_>>(),
            global_inputs.iter().map(|input| input.shape_key()).collect::<BTreeSet<_>>().len(),
        );
        inputs.extend(global_inputs.into_iter().map(ZKMCircuitWitness::GlobalJagged));

        let jagged_inputs =
            self.get_recursion_core_inputs(&vk.vk, shard_proofs, &chain, batch_size, false);
        tracing::debug!("emitting {} CoreJagged witness(es)", jagged_inputs.len());
        inputs.extend(jagged_inputs.into_iter().map(ZKMCircuitWitness::CoreJagged));

        let last_proof_pv = shard_proofs.last().unwrap().public_values.as_slice().borrow();
        let jagged_deferred = self.get_recursion_deferred_inputs(
            &vk.vk,
            last_proof_pv,
            chain.h_star(),
            deferred_proofs,
            batch_size,
        )?;
        inputs.extend(jagged_deferred.into_iter().map(ZKMCircuitWitness::DeferredJagged));
        Ok(inputs)
    }

    /// Reduce shard proofs to a single shard proof using the recursion prover.
    #[instrument(name = "compress", level = "info", skip_all)]
    pub fn compress(
        &self,
        vk: &ZKMVerifyingKey,
        proof: ZKMCoreProof,
        deferred_proofs: Vec<ZKMReduceProof<CompressedSC>>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<CompressedSC>, ZKMRecursionProverError> {
        let batch_size = REDUCE_BATCH_SIZE;
        let first_layer_batch_size = 1;

        let shard_proofs = &proof.proof.0;

        let first_layer_inputs = self.get_first_layer_inputs(
            vk,
            shard_proofs,
            &proof.proof.1,
            &deferred_proofs,
            first_layer_batch_size,
        )?;

        let num_first_layer_inputs = first_layer_inputs.len();
        let global_rounds: usize = first_layer_inputs
            .iter()
            .map(|input| match input {
                ZKMCircuitWitness::GlobalJagged(input) => input.rounds(),
                _ => 0,
            })
            .sum();
        let mut chain = crate::compress_tree::ShardChain::with_global_rounds(global_rounds as u64);
        let first_layer_inputs: Vec<(crate::compress_tree::ShardRange, ZKMCircuitWitness)> =
            first_layer_inputs
                .into_iter()
                .map(|input| {
                    let range = match &input {
                        ZKMCircuitWitness::DeferredJagged(_) => chain.deferred(),
                        ZKMCircuitWitness::GlobalJagged(input) => {
                            chain.global_rounds(input.rounds() as u64)
                        }
                        _ => chain.core(),
                    };
                    (range, input)
                })
                .collect();
        let full_range = chain.full_range();

        let span = tracing::Span::current().clone();
        let (vk, proof) = thread::scope(|s| -> Result<_, VkNotAllowed> {
            let _span = span.enter();

            let (input_tx, input_rx) =
                sync_channel::<(crate::compress_tree::ShardRange, ZKMCircuitWitness)>(
                    opts.recursion_opts.checkpoints_channel_capacity,
                );
            let input_tx = Arc::new(Mutex::new(input_tx));
            {
                let input_tx = Arc::clone(&input_tx);
                s.spawn(move || {
                    for (range, input) in first_layer_inputs.into_iter() {
                        input_tx.lock().unwrap().send((range, input)).unwrap();
                    }
                });
            }

            let (record_and_trace_tx, record_and_trace_rx) = sync_channel::<RecursionJob>(
                opts.recursion_opts.records_and_traces_channel_capacity,
            );
            let record_and_trace_tx = Arc::new(Mutex::new(record_and_trace_tx));
            let record_and_trace_rx = Arc::new(Mutex::new(record_and_trace_rx));
            let input_rx = Arc::new(Mutex::new(input_rx));
            for _ in 0..opts.recursion_opts.trace_gen_workers {
                let record_and_trace_tx = Arc::clone(&record_and_trace_tx);
                let input_rx = Arc::clone(&input_rx);
                let span = tracing::debug_span!("generate records and traces");
                s.spawn(move || {
                    let _span = span.enter();
                    loop {
                        let received = { input_rx.lock().unwrap().recv() };
                        if let Ok((range, input)) = received {
                            let is_root = matches!(
                                &input,
                                ZKMCircuitWitness::ComposeJagged(w) if w.is_complete
                            );
                            let (program, witness_stream) = self.prepare_recursion_job(input);
                            let job = self.execute_and_generate_traces(
                                range,
                                is_root,
                                program,
                                witness_stream,
                                opts,
                            )?;
                            record_and_trace_tx.lock().unwrap().send(job).unwrap();
                        } else {
                            break Ok::<(), ZKMRecursionProverError>(());
                        }
                    }
                });
            }

            let (proofs_tx, proofs_rx) = sync_channel::<(
                crate::compress_tree::ShardRange,
                StarkVerifyingKey<InnerSC>,
                ShardProof<InnerSC>,
            )>(num_first_layer_inputs * 2);
            let proofs_tx = Arc::new(Mutex::new(proofs_tx));
            let proofs_rx = Arc::new(Mutex::new(proofs_rx));
            let mut prover_handles = Vec::new();
            for _ in 0..opts.recursion_opts.shard_batch_size {
                let record_and_trace_rx = Arc::clone(&record_and_trace_rx);
                let proofs_tx = Arc::clone(&proofs_tx);
                let span = tracing::debug_span!("prove");
                let handle = s.spawn(move || {
                    let _span = span.enter();
                    loop {
                        let received = { record_and_trace_rx.lock().unwrap().recv() };
                        if let Ok(job) = received {
                            let proved = self.prove_recursion_job(job, opts);
                            proofs_tx.lock().unwrap().send(proved).unwrap();
                        } else {
                            break;
                        }
                    }
                });
                prover_handles.push(handle);
            }

            let handle = {
                let input_tx = Arc::clone(&input_tx);
                let proofs_rx = Arc::clone(&proofs_rx);
                let span = tracing::debug_span!("reduce proofs");
                s.spawn(move || -> Result<(), VkNotAllowed> {
                    let _span = span.enter();
                    type Item = (StarkVerifyingKey<InnerSC>, ShardProof<InnerSC>);
                    let mut tree = crate::compress_tree::CompressTree::<Item>::new(batch_size);
                    let mut in_flight = num_first_layer_inputs;
                    loop {
                        let received = { proofs_rx.lock().unwrap().recv() };
                        let (range, vk, proof) = match received {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                        in_flight -= 1;
                        let reduction =
                            tree.insert(range, (vk, proof), in_flight, Some(full_range));
                        let (run, is_complete) = match reduction {
                            crate::compress_tree::Reduction::Emit { proofs, is_complete } => {
                                (proofs, is_complete)
                            }
                            crate::compress_tree::Reduction::Wait => continue,
                        };
                        let next_range = run.range();

                        let jagged_vks_and_proofs: Vec<_> = run
                            .into_proofs()
                            .map(|(vk, proof)| (vk, *proof.jagged_shard_proof))
                            .collect();
                        let vks_only: Vec<StarkVerifyingKey<InnerSC>> =
                            jagged_vks_and_proofs.iter().map(|(vk, _)| vk.clone()).collect();
                        let vk_merkle_data = match self.make_merkle_proofs(&vks_only) {
                            Ok(v) => v,
                            Err(e) => {
                                while in_flight > 0 && proofs_rx.lock().unwrap().recv().is_ok() {
                                    in_flight -= 1;
                                }
                                return Err(e);
                            }
                        };
                        let compose_values = ZKMCompressWitnessValues {
                            vks_and_proofs: jagged_vks_and_proofs,
                            vk_merkle_data,
                            is_complete,
                        };
                        let input = ZKMCircuitWitness::ComposeJagged(compose_values);

                        in_flight += 1;
                        input_tx.lock().unwrap().send((next_range, input)).unwrap();

                        if is_complete {
                            break;
                        }
                    }
                    Ok(())
                })
            };

            drop(input_tx);
            drop(record_and_trace_tx);
            drop(proofs_tx);
            for handle in prover_handles {
                handle.join().unwrap();
            }
            handle.join().unwrap()?;

            let (_, vk, proof) = proofs_rx.lock().unwrap().recv().unwrap();
            Ok((vk, proof))
        })?;

        Ok(ZKMReduceProof {
            vk: zkm_pcs::koala_bear_poseidon2::retype_vk(vk),
            proof: zkm_pcs::koala_bear_poseidon2::retype_shard_proof(proof),
        })
    }

    /// The program of a recursion node and the witness stream it reads.
    fn prepare_recursion_job(
        &self,
        input: ZKMCircuitWitness,
    ) -> (Arc<RecursionProgram<KoalaBear>>, Vec<zkm_recursion_core::air::Block<KoalaBear>>) {
        tracing::debug_span!("get program and witness stream").in_scope(|| {
            let mut witness_stream = Vec::new();
            let program = match input {
                ZKMCircuitWitness::CoreJagged(input) => {
                    Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                    self.recursion_program(&input).0
                }
                ZKMCircuitWitness::GlobalJagged(input) => {
                    Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                    self.global_round_program(&input).0
                }
                ZKMCircuitWitness::ComposeJagged(input) => {
                    Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                    self.compose_program(&input).0
                }
                ZKMCircuitWitness::DeferredJagged(input) => {
                    Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                    self.deferred_program(&input)
                }
            };
            (program, witness_stream)
        })
    }

    /// Runs `program` over `witness_stream` and builds its dependencies, then,
    /// for a node below the root, its traces under the compress machine.
    fn execute_and_generate_traces(
        &self,
        range: crate::compress_tree::ShardRange,
        is_root: bool,
        program: Arc<RecursionProgram<KoalaBear>>,
        witness_stream: Vec<zkm_recursion_core::air::Block<KoalaBear>>,
        opts: ZKMProverOpts,
    ) -> Result<RecursionJob, ZKMRecursionProverError> {
        let n_instructions = program.instruction_count();
        let run_start = std::time::Instant::now();
        let record = tracing::info_span!("execute_runtime", instructions = n_instructions)
            .in_scope(|| {
                let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
                    program.clone(),
                    self.compress_prover.machine().config().perm.clone(),
                );
                runtime.witness_stream = witness_stream.into();
                runtime
                    .run()
                    .map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))
                    .unwrap();
                runtime.record
            });
        tracing::info!(
            event = "execute_runtime_done",
            elapsed_ms = run_start.elapsed().as_millis() as u64,
            instructions = n_instructions,
            "compose-call runtime wall"
        );

        let mut records = vec![record];
        tracing::debug_span!("generate dependencies").in_scope(
            || -> Result<(), ZKMRecursionProverError> {
                match self.compress_prover.machine().generate_dependencies(
                    &mut records,
                    &opts.recursion_opts,
                    None,
                ) {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        tracing::error!(
                            "Failed to generate dependencies for recursion proof: {}",
                            e
                        );
                        Err(ZKMRecursionProverError::DependenciesGenerationError)
                    }
                }
            },
        )?;

        let record = records.into_iter().next().unwrap();
        if is_root {
            return Ok(RecursionJob::Root { range, program, record });
        }
        let traces = tracing::debug_span!("generate traces")
            .in_scope(|| self.compress_prover.generate_traces(&record));
        match traces {
            Ok(traces) => Ok(RecursionJob::Node { range, program, record, traces }),
            Err(e) => {
                tracing::error!("Failed to generate traces for recursion proof: {}", e);
                Err(ZKMRecursionProverError::TracesGenerationError)
            }
        }
    }

    /// Proves one recursion node: the root under the compress schedule, every
    /// other node with the cached compress key.
    fn prove_recursion_job(
        &self,
        job: RecursionJob,
        opts: ZKMProverOpts,
    ) -> (crate::compress_tree::ShardRange, StarkVerifyingKey<InnerSC>, ShardProof<InnerSC>) {
        let (range, program, record, traces) = match job {
            RecursionJob::Root { range, program, record } => {
                let (vk, proof) = self.prove_root_node(&program, record, opts);
                return (
                    range,
                    zkm_pcs::koala_bear_poseidon2::retype_vk(vk),
                    zkm_pcs::koala_bear_poseidon2::retype_shard_proof(proof),
                );
            }
            RecursionJob::Node { range, program, record, traces } => {
                (range, program, record, traces)
            }
        };
        tracing::debug_span!("batch").in_scope(|| {
            let keys = tracing::debug_span!("Setup compress program").in_scope(|| {
                self.recursion_pk_cached(&program, || {
                    let (pk, vk) = self.compress_prover.setup(&program);
                    (self.compress_prover.pk_to_host(&pk), vk)
                })
            });
            let pk = self.compress_prover.pk_to_device(&keys.0);
            let vk = keys.1.clone();

            let mut challenger = self.compress_prover.machine().config().challenger();
            tracing::debug_span!("observe proving key").in_scope(|| {
                pk.observe_into(&mut challenger);
            });

            #[cfg(feature = "debug")]
            self.compress_prover.machine().debug_constraints(
                &self.compress_prover.pk_to_host(&pk),
                vec![record.clone()],
                &mut challenger.clone(),
            );

            let data = tracing::debug_span!("commit")
                .in_scope(|| self.compress_prover.commit(&record, traces, None));

            let proof = tracing::debug_span!("open")
                .in_scope(|| self.compress_prover.open(&pk, data, &mut challenger).unwrap());

            #[cfg(feature = "debug")]
            self.compress_prover
                .machine()
                .verify(
                    &vk,
                    &zkm_pcs::MachineProof::from_shards(vec![proof.clone()]),
                    &mut self.compress_prover.machine().config().challenger(),
                )
                .unwrap();

            (range, vk, proof)
        })
    }

    /// Prove the root, the closing compose, under the compress schedule.
    ///
    /// Every other node of the tree is proved by the compress prover under the
    /// core schedule; the root's proof is the published one, so it alone pays
    /// for the size-tuned schedule.  Its traces are generated by the root
    /// prover, since the two provers' trace types need not agree.
    pub fn prove_root_node(
        &self,
        program: &Arc<RecursionProgram<KoalaBear>>,
        record: zkm_recursion_core::runtime::ExecutionRecord<KoalaBear>,
        _opts: ZKMProverOpts,
    ) -> (StarkVerifyingKey<CompressedSC>, ShardProof<CompressedSC>) {
        let _span = tracing::info_span!("prove root").entered();
        let (pk, vk) = self.root_prover.setup(program);
        let mut challenger = self.root_prover.machine().config().challenger();
        pk.observe_into(&mut challenger);
        let traces = self
            .root_prover
            .generate_traces(&record)
            .expect("root traces: the record was generated for the compress machine");
        let data = self.root_prover.commit(&record, traces, None);
        let proof = self.root_prover.open(&pk, data, &mut challenger).expect("root proof");
        (vk, proof)
    }

    /// Accumulate deferred proofs into a single digest.
    pub fn hash_deferred_proofs(
        prev_digest: [Val<CoreSC>; DIGEST_SIZE],
        deferred_proofs: &[ZKMReduceProof<CompressedSC>],
    ) -> [Val<CoreSC>; 8] {
        let mut digest = prev_digest;
        for proof in deferred_proofs.iter() {
            let pv: &RecursionPublicValues<Val<CoreSC>> =
                proof.proof.public_values.as_slice().borrow();
            let committed_values_digest = words_to_bytes(&pv.committed_value_digest);
            digest = hash_deferred_proof(
                &digest,
                &pv.zkm_vk_digest,
                &committed_values_digest.try_into().unwrap(),
            );
        }
        digest
    }
}
