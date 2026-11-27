use crate::mips::MipsAir;
use p3_maybe_rayon::prelude::*;
use std::{
    io,
    sync::{mpsc::sync_channel, Arc, Mutex},
};
use thiserror::Error;
use web_time::Instant;
use zkm_pcs::MachineProvingKey;

use p3_field::PrimeField32;

use crate::{
    cluster::ShardClusters,
    io::ZKMStdin,
    utils::{chunk_vec, concurrency::TurnBasedSync},
};
use zkm_core_executor::{
    events::{format_table_line, sorted_table_lines},
    subproof::NoOpSubproofVerifier,
    ExecutionError, ExecutionRecord, ExecutionReport, ExecutionState, Executor, Program,
    ZKMContext,
};

use zkm_pcs::{
    air::PublicValues, Com, MachineProof, MachineProver, MachineRecord, OpeningProof,
    PcsProverData, StarkGenericConfig, Val, ZKMCoreOpts,
};

#[derive(Error, Debug)]
pub enum ZKMCoreProverError {
    #[error("failed to execute program: {0}")]
    ExecutionError(ExecutionError),
    #[error("io error: {0}")]
    IoError(io::Error),
    #[error("serialization error: {0}")]
    SerializationError(bincode::Error),
    #[error("traces generation error")]
    TracesGenerationError,
    #[error("dependencies generation error")]
    DependenciesGenerationError,
    #[error("the execution has too many cross-shard lookups: {0}")]
    TooManyGlobalLookups(String),
}

pub fn prove<SC: StarkGenericConfig, P: MachineProver<SC, MipsAir<SC::Val>>>(
    program: Program,
    stdin: &ZKMStdin,
    config: SC,
    opts: ZKMCoreOpts,
) -> Result<(MachineProof<SC>, Vec<u8>, u64), ZKMCoreProverError>
where
    SC::Challenger: 'static + Clone + Send,
    <SC as StarkGenericConfig>::Val: PrimeField32,
    OpeningProof<SC>: Send,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    let machine = MipsAir::machine(config);
    let prover = P::new(machine);
    let (pk, _) = prover.setup(&program);
    prove_with_context::<SC, _>(&prover, &pk, program, stdin, opts, Default::default())
}

pub fn prove_with_context<SC: StarkGenericConfig, P: MachineProver<SC, MipsAir<SC::Val>>>(
    prover: &P,
    pk: &P::DeviceProvingKey,
    program: Program,
    stdin: &ZKMStdin,
    opts: ZKMCoreOpts,
    context: ZKMContext,
) -> Result<(MachineProof<SC>, Vec<u8>, u64), ZKMCoreProverError>
where
    SC::Val: PrimeField32,
    SC::Challenger: 'static + Clone + Send,
    OpeningProof<SC>: Send,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    let proving_start = Instant::now();

    let (checkpoint, public_values_stream) = execute_to_checkpoint(&program, stdin, opts, context)?;

    let mut challenger = prover.machine().config().challenger();
    pk.observe_into(&mut challenger);

    #[cfg(feature = "debug")]
    let (all_records_tx, all_records_rx) = std::sync::mpsc::channel::<Vec<ExecutionRecord>>();
    #[cfg(feature = "debug")]
    let all_records_tx = Some(all_records_tx);
    #[cfg(not(feature = "debug"))]
    let all_records_tx = None;

    let prepare_traces = |record: &ExecutionRecord| {
        prover.generate_traces(record).map_err(|e| {
            tracing::error!("Trace generation error: {:?}", e);
            ZKMCoreProverError::TracesGenerationError
        })
    };
    let prove_shard = |record, traces, cluster_widths| {
        Ok(prove_shard_and_keep_global_round::<SC, P>(
            prover,
            pk,
            &challenger,
            record,
            traces,
            cluster_widths,
        ))
    };
    let (proved, report_aggregate) = tracing::debug_span!("prove shards").in_scope(|| {
        run_shard_pipeline::<SC, P, _, _>(
            prover,
            &program,
            opts,
            checkpoint,
            &prepare_traces,
            &prove_shard,
            all_records_tx,
        )
    })?;

    tracing::info!(
        "execution report (totals): total_cycles={}, total_syscall_cycles={}, touched_memory_addresses={}",
        report_aggregate.total_instruction_count(),
        report_aggregate.total_syscall_count(),
        report_aggregate.touched_memory_addresses,
    );

    tracing::info!("execution report (opcode counts):");
    let (width, lines) = sorted_table_lines(report_aggregate.opcode_counts.as_ref());
    for (label, count) in lines {
        if *count > 0 {
            tracing::info!("  {}", format_table_line(&width, &label, count));
        } else {
            tracing::debug!("  {}", format_table_line(&width, &label, count));
        }
    }

    tracing::info!("execution report (syscall counts):");
    let (width, lines) = sorted_table_lines(report_aggregate.syscall_counts.as_ref());
    for (label, count) in lines {
        if *count > 0 {
            tracing::info!("  {}", format_table_line(&width, &label, count));
        } else {
            tracing::debug!("  {}", format_table_line(&width, &label, count));
        }
    }

    let (shard_proofs, tables): (Vec<_>, Vec<_>) = proved.into_iter().unzip();
    let rounds = shard_proofs
        .iter()
        .map(|proof| prover.machine().global_round_binding(proof))
        .collect::<Vec<_>>();
    prover
        .machine()
        .check_global_lookup_count(rounds.iter().flatten())
        .map_err(ZKMCoreProverError::TooManyGlobalLookups)?;
    let committed = rounds
        .iter()
        .zip(tables)
        .filter_map(|(round, tables)| Some((round.as_ref()?, tables?)))
        .collect::<Vec<_>>();
    let global_proofs = tracing::debug_span!("prove global rounds").in_scope(|| {
        let Some(global) = prover
            .machine()
            .global_challenge(&challenger, rounds.iter().map(Option::as_ref))
            .filter(|_| !committed.is_empty())
        else {
            return Vec::new();
        };
        prover
            .machine()
            .global_proof_groups(
                committed.iter().map(|(round, _)| *round),
                zkm_pcs::global_rounds_per_proof(),
            )
            .into_iter()
            .map(|group| {
                prover.prove_global_rounds(pk, &committed[group], &global, &challenger).unwrap()
            })
            .collect()
    });

    let proof = MachineProof::<SC> { shard_proofs, global_proofs };
    let cycles = report_aggregate.total_instruction_count();

    let proving_time = proving_start.elapsed().as_secs_f64();
    tracing::info!(
        "summary: cycles={}, e2e={}s, khz={:.2}, proofSize={}",
        cycles,
        proving_time,
        (cycles as f64 / (proving_time * 1000.0) as f64),
        bincode::serialize(&proof).unwrap().len(),
    );

    #[cfg(feature = "debug")]
    {
        let all_records = all_records_rx.iter().flatten().collect::<Vec<_>>();
        let mut challenger = prover.machine().config().challenger();
        let pk_host = prover.pk_to_host(pk);
        prover.machine().debug_constraints(&pk_host, all_records, &mut challenger);
    }

    Ok((proof, public_values_stream, cycles))
}

/// The state [`run_shard_pipeline`] starts tracing from: its index, the
/// executor state, and whether it runs to the end of the program, with the
/// program's cycle count.
type Checkpoint = (usize, ExecutionState, bool, u64);

/// Executes `program` on `stdin` once, returning the checkpoint
/// [`run_shard_pipeline`] traces from and the public values stream.
fn execute_to_checkpoint(
    program: &Program,
    stdin: &ZKMStdin,
    opts: ZKMCoreOpts,
    context: ZKMContext,
) -> Result<(Checkpoint, Vec<u8>), ZKMCoreProverError> {
    let mut runtime = Executor::with_context(program.clone(), opts, context);

    runtime.write_vecs(&stdin.buffer);
    for proof in stdin.proofs.iter() {
        let (proof, vk) = proof.clone();
        runtime.write_proof(proof, vk);
    }

    tracing::debug_span!("checkpoint generator").in_scope(|| {
        let initial_state = runtime.state.clone();
        let chunk = runtime
            .run_fast_capture_whole_program_chunk()
            .map_err(ZKMCoreProverError::ExecutionError)?;
        let global_clk = runtime.state.global_clk;
        tracing::debug!(
            target = "checkpoint_pin",
            "whole-program chunk clk=[{}..{}] mem_reads_oracle={} global_clk={}",
            chunk.clk_start,
            chunk.clk_end,
            chunk.mem_reads.len(),
            global_clk,
        );
        let public_values_stream = std::mem::take(&mut runtime.state.public_values_stream);
        Ok(((0, initial_state, true, global_clk), public_values_stream))
    })
}

/// The records of the shards [`prove_with_context`] proves for `program` on
/// `stdin`, in shard order, as its shard pipeline traces them: with their
/// dependencies generated, ready for a prover to commit.
pub fn shard_records<SC: StarkGenericConfig, P: MachineProver<SC, MipsAir<SC::Val>>>(
    prover: &P,
    program: &Program,
    stdin: &ZKMStdin,
    opts: ZKMCoreOpts,
) -> Result<Vec<ExecutionRecord>, ZKMCoreProverError>
where
    SC::Val: PrimeField32,
    SC::Challenger: 'static + Clone + Send,
    OpeningProof<SC>: Send,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    let (checkpoint, _) = execute_to_checkpoint(program, stdin, opts, ZKMContext::default())?;
    let (records_tx, records_rx) = std::sync::mpsc::channel();
    run_shard_pipeline::<SC, P, _, _>(
        prover,
        program,
        opts,
        checkpoint,
        &|_| Ok(()),
        &|_, (), _| Ok(()),
        Some(records_tx),
    )?;
    Ok(records_rx.into_iter().flatten().collect())
}

/// Proves one shard on its own, and keeps the tables of its global round for
/// the global proof made once every shard has committed.
fn prove_shard_and_keep_global_round<
    SC: StarkGenericConfig,
    P: MachineProver<SC, MipsAir<SC::Val>>,
>(
    prover: &P,
    pk: &P::DeviceProvingKey,
    challenger: &SC::Challenger,
    record: ExecutionRecord,
    main_traces: zkm_pcs::Traces<Val<SC>>,
    cluster_widths: Option<std::collections::BTreeMap<String, usize>>,
) -> (zkm_pcs::ShardProof<SC>, Option<zkm_pcs::Traces<Val<SC>>>)
where
    SC::Val: PrimeField32,
{
    let t_commit = std::time::Instant::now();
    let main_data = prover.commit(&record, main_traces, cluster_widths);
    let tables = prover.global_round_tables(&main_data);
    let commit_ms = t_commit.elapsed().as_millis();

    let opening_span = tracing::debug_span!("opening").entered();
    let t_open = std::time::Instant::now();
    let proof = prover.open(pk, main_data, &mut challenger.clone()).unwrap();
    let open_ms = t_open.elapsed().as_millis();
    opening_span.exit();

    tracing::info!(
        "PCS timing: commit={}ms open={}ms total={}ms",
        commit_ms,
        open_ms,
        commit_ms + open_ms
    );

    rayon::spawn(move || {
        drop(record);
    });

    (proof, tables)
}

/// Replays the program from `checkpoint` and cuts it into shard records.
/// `prepare_shard` runs on each record in the trace workers; `consume_shard`
/// runs in the prover worker on the record and the value `prepare_shard`
/// returned for it. The type parameter `T` guarantees only that: the
/// consuming stage receives the result prepared for its own shard. That
/// result is the shard's traces in [`prove_with_context`] and `()` in
/// [`shard_records`]. Results preserve shard order across both stages.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn run_shard_pipeline<
    SC: StarkGenericConfig,
    P: MachineProver<SC, MipsAir<SC::Val>>,
    T: Send,
    R: Send,
>(
    prover: &P,
    program: &Program,
    opts: ZKMCoreOpts,
    checkpoint: Checkpoint,
    prepare_shard: &(impl Fn(&ExecutionRecord) -> Result<T, ZKMCoreProverError> + Sync),
    consume_shard: &(impl Fn(
        ExecutionRecord,
        T,
        Option<std::collections::BTreeMap<String, usize>>,
    ) -> Result<R, ZKMCoreProverError>
          + Sync),
    all_records_tx: Option<std::sync::mpsc::Sender<Vec<ExecutionRecord>>>,
) -> Result<(Vec<R>, ExecutionReport), ZKMCoreProverError>
where
    SC::Val: PrimeField32,
    SC::Challenger: 'static + Clone + Send,
    OpeningProof<SC>: Send,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    let span = tracing::Span::current().clone();
    std::thread::scope(move |s| {
        let _span = span.enter();

        let record_gen_sync = Arc::new(TurnBasedSync::new());
        let trace_gen_sync = Arc::new(TurnBasedSync::new());
        let (prepared_records_tx, prepared_records_rx) =
            sync_channel::<Vec<(ExecutionRecord, T)>>(opts.records_and_traces_channel_capacity);
        let prepared_records_tx = Arc::new(Mutex::new(prepared_records_tx));

        let report_aggregate = Arc::new(Mutex::new(ExecutionReport::default()));
        let (checkpoints_tx, checkpoints_rx) =
            sync_channel::<(usize, ExecutionState, bool, u64)>(opts.checkpoints_channel_capacity);
        checkpoints_tx.send(checkpoint).unwrap();
        drop(checkpoints_tx);
        let checkpoints_rx = Arc::new(Mutex::new(checkpoints_rx));
        let state = Arc::new(Mutex::new(PublicValues::<u32, u32>::default().reset()));
        let deferred = Arc::new(Mutex::new(ExecutionRecord::new(program.clone().into())));
        let mut record_and_trace_gen_handles = Vec::new();
        for _ in 0..opts.trace_gen_workers {
            let record_gen_sync = Arc::clone(&record_gen_sync);
            let trace_gen_sync = Arc::clone(&trace_gen_sync);
            let prepared_records_tx = Arc::clone(&prepared_records_tx);
            let checkpoints_rx = Arc::clone(&checkpoints_rx);

            let report_aggregate = Arc::clone(&report_aggregate);
            let state = Arc::clone(&state);
            let deferred = Arc::clone(&deferred);
            let program = program.clone();

            let span = tracing::Span::current().clone();

            let all_records_tx = all_records_tx.clone();

            let handle = s.spawn(move || {
                let _span = span.enter();
                tracing::debug_span!("trace generation").in_scope(|| {
                    while let Ok((index, execution_state, done, num_cycles)) = {
                        let receiver = checkpoints_rx.lock().unwrap();
                        receiver.recv()
                    } {
                        tracing::trace!(
                            target = "checkpoint_pin",
                            event = "consume",
                            index = index,
                            done = done,
                            num_cycles = num_cycles,
                        );
                        let mut batch_index = index;
                        let mut process_batch =
                            |mut records: Vec<ExecutionRecord>,
                             report: ExecutionReport,
                             done: bool,
                             num_cycles: u64|
                             -> Result<(), ZKMCoreProverError> {
                                let index = batch_index;
                                batch_index += 1;
                                log::debug!("generated {} records", records.len());
                                *report_aggregate.lock().unwrap() += report;

                                record_gen_sync.wait_for_turn(index);

                                let mut state = state.lock().unwrap();
                                for record in records.iter_mut() {
                                    state.shard += 1;
                                    state.execution_shard = record.public_values.execution_shard;
                                    state.start_pc = record.public_values.start_pc;
                                    state.next_pc = record.public_values.next_pc;
                                    state.start_next_pc = record.public_values.start_next_pc;
                                    state.next_next_pc = record.public_values.next_next_pc;
                                    state.initial_timestamp =
                                        record.public_values.initial_timestamp;
                                    state.last_timestamp = record.public_values.last_timestamp;
                                    state.committed_value_digest =
                                        record.public_values.committed_value_digest;
                                    state.deferred_proofs_digest =
                                        record.public_values.deferred_proofs_digest;
                                    record.public_values = *state;
                                }

                                let mut deferred = deferred.lock().unwrap();
                                for record in records.iter_mut() {
                                    deferred.append(&mut record.defer());
                                }

                                let pack = done
                                    && num_cycles < 1 << 21
                                    && deferred.global_memory_initialize_events.len()
                                        < opts.split_opts.combine_memory_threshold
                                    && deferred.global_memory_finalize_events.len()
                                        < opts.split_opts.combine_memory_threshold;
                                let last_record = if pack { records.last_mut() } else { None };
                                let mut deferred =
                                    deferred.split(done, last_record, opts.split_opts);
                                tracing::debug!("deferred {} records", deferred.len());

                                if !done {
                                    state.execution_shard += 1;
                                }
                                for record in deferred.iter_mut() {
                                    state.shard += 1;
                                    state.previous_init_addr_bits =
                                        record.public_values.previous_init_addr_bits;
                                    state.last_init_addr_bits =
                                        record.public_values.last_init_addr_bits;
                                    state.previous_finalize_addr_bits =
                                        record.public_values.previous_finalize_addr_bits;
                                    state.last_finalize_addr_bits =
                                        record.public_values.last_finalize_addr_bits;
                                    state.start_pc = state.next_pc;
                                    state.start_next_pc = state.next_next_pc;
                                    state.last_timestamp = state.initial_timestamp;
                                    record.public_values = *state;
                                }
                                records.append(&mut deferred);

                                tracing::debug_span!("generate dependencies", index).in_scope(
                                    || {
                                        prover
                                            .machine()
                                            .generate_dependencies(&mut records, &opts, None)
                                            .map_err(|error| {
                                                tracing::error!(
                                                    "Error generating dependencies: {:?}",
                                                    error
                                                );
                                                ZKMCoreProverError::DependenciesGenerationError
                                            })
                                    },
                                )?;

                                record_gen_sync.advance_turn();

                                if let Some(tx) = &all_records_tx {
                                    tx.send(records.clone()).unwrap();
                                }

                                let prepared = tracing::debug_span!("prepare shards", index)
                                    .in_scope(|| {
                                        records
                                            .par_iter()
                                            .map(prepare_shard)
                                            .collect::<Result<Vec<_>, _>>()
                                    })?;

                                trace_gen_sync.wait_for_turn(index);

                                let prepared_records = records.into_iter().zip(prepared).collect();
                                for batch in chunk_vec(prepared_records, opts.shard_batch_size) {
                                    prepared_records_tx.lock().unwrap().send(batch).unwrap();
                                }

                                trace_gen_sync.advance_turn();
                                Ok(())
                            };

                        trace_checkpoint_to_completion(
                            program.clone(),
                            execution_state,
                            opts,
                            &mut process_batch,
                        )?;
                    }
                    Ok(())
                })
            });
            record_and_trace_gen_handles.push(handle);
        }
        drop(prepared_records_tx);
        drop(all_records_tx);

        let shard_clusters = ShardClusters::<SC::Val>::new();

        let prover_span = tracing::Span::current().clone();
        let prover_handle = s.spawn(move || {
            let _span = prover_span.enter();
            let mut outputs = Vec::new();
            tracing::debug_span!("shard prover").in_scope(|| {
                for batch in prepared_records_rx.into_iter() {
                    tracing::debug_span!("batch").in_scope(|| {
                        let span = tracing::Span::current().clone();
                        let results = batch
                            .into_par_iter()
                            .map(|(record, prepared)| {
                                let _span = span.enter();

                                let cluster_widths = shard_clusters.cluster_widths(&record);

                                consume_shard(record, prepared, cluster_widths)
                            })
                            .collect::<Vec<_>>();
                        outputs.extend(results);
                    });
                }
            });
            outputs.into_iter().collect::<Result<Vec<_>, ZKMCoreProverError>>()
        });

        for handle in record_and_trace_gen_handles {
            handle.join().unwrap()?;
        }

        let outputs = prover_handle.join().unwrap()?;
        let report = std::mem::take(&mut *report_aggregate.lock().unwrap());
        Ok((outputs, report))
    })
}

/// `trace_checkpoint`, driven to COMPLETION.
///
/// `trace_checkpoint` calls `Executor::execute_record` exactly ONCE, and
/// `Executor::execute` returns as soon as it has closed `shard_batch_size`
/// shards.  Over the multi-checkpoint producer that is correct — the producer
/// sends one checkpoint per batch — but the JIT producer sends a SINGLE
/// from-start, whole-program checkpoint, so one call covers only the first
/// batch and every later shard is silently dropped.  The truncated proof then
/// fails verification with
/// `Invalid public values: next_pc != 0: execution should have halted`
/// (invisible to any single-shard program, e.g. fibonacci).
///
/// This drives ONE carried executor with repeated `execute_record` calls until
/// it reports `done` — the Trace-mode mirror of the interpreter producer's
/// `execute_state` loop — and hands each batch to `on_batch` as it is
/// produced, so peak memory stays at a single `shard_batch_size` batch rather
/// than the whole program's records.
///
/// Per-batch semantics are IDENTICAL to the multi-checkpoint path: `execute`'s
/// finalization stamps `execution_shard = start_shard + i` and broadcasts the
/// batch's terminal public values over that batch's records either way, and
/// `execute_record` takes the executor's records each call.
pub fn trace_checkpoint_to_completion<F>(
    program: Program,
    state: ExecutionState,
    opts: ZKMCoreOpts,
    mut on_batch: F,
) -> Result<(), ZKMCoreProverError>
where
    F: FnMut(Vec<ExecutionRecord>, ExecutionReport, bool, u64) -> Result<(), ZKMCoreProverError>,
{
    let noop = NoOpSubproofVerifier;

    let mut runtime = Executor::recover(program, state, opts);
    runtime.subproof_verifier = Some(&noop);

    loop {
        let (records, done) =
            runtime.execute_record(true).map_err(ZKMCoreProverError::ExecutionError)?;
        let num_cycles = runtime.state.global_clk;
        let report =
            if done { std::mem::take(&mut runtime.report) } else { ExecutionReport::default() };
        on_batch(records, report, done, num_cycles)?;
        if done {
            break;
        }
    }

    Ok(())
}

pub fn trace_checkpoint(
    program: Program,
    state: ExecutionState,
    opts: ZKMCoreOpts,
) -> (Vec<ExecutionRecord>, ExecutionReport) {
    let noop = NoOpSubproofVerifier;

    let mut runtime = Executor::recover(program, state, opts);

    runtime.subproof_verifier = Some(&noop);

    let (records, _) = runtime.execute_record(true).unwrap();

    (records, runtime.report)
}
