use crate::mips::MipsAir;
use p3_maybe_rayon::prelude::*;
use std::thread::ScopedJoinHandle;
use std::{
    io,
    sync::{mpsc::sync_channel, Arc, Mutex},
};
use thiserror::Error;
use web_time::Instant;
use zkm_pcs::MachineProvingKey;

use p3_field::PrimeField32;

use crate::shape::CoreShapeConfig;
use crate::{
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
    air::{MachineAir, PublicValues},
    Com, MachineProof, MachineProver, MachineRecord, OpeningProof, PcsProverData,
    StarkGenericConfig, Val, ZKMCoreOpts,
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
}

pub fn prove<SC: StarkGenericConfig, P: MachineProver<SC, MipsAir<SC::Val>>>(
    program: Program,
    stdin: &ZKMStdin,
    config: SC,
    opts: ZKMCoreOpts,
    shape_config: Option<&CoreShapeConfig<SC::Val>>,
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
    prove_with_context::<SC, _>(
        &prover,
        &pk,
        program,
        stdin,
        opts,
        Default::default(),
        shape_config,
    )
}

pub fn prove_with_context<SC: StarkGenericConfig, P: MachineProver<SC, MipsAir<SC::Val>>>(
    prover: &P,
    pk: &P::DeviceProvingKey,
    program: Program,
    stdin: &ZKMStdin,
    opts: ZKMCoreOpts,
    context: ZKMContext,
    shape_config: Option<&CoreShapeConfig<SC::Val>>,
) -> Result<(MachineProof<SC>, Vec<u8>, u64), ZKMCoreProverError>
where
    SC::Val: PrimeField32,
    SC::Challenger: 'static + Clone + Send,
    OpeningProof<SC>: Send,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    let mut runtime = Executor::with_context(program.clone(), opts, context);
    runtime.maximal_shapes = shape_config.map(|config| {
        config.maximal_core_shapes(opts.shard_size.ilog2() as usize).into_iter().collect()
    });

    runtime.write_vecs(&stdin.buffer);
    for proof in stdin.proofs.iter() {
        let (proof, vk) = proof.clone();
        runtime.write_proof(proof, vk);
    }

    #[cfg(feature = "debug")]
    let (all_records_tx, all_records_rx) = std::sync::mpsc::channel::<Vec<ExecutionRecord>>();

    let proving_start = Instant::now();
    let span = tracing::Span::current().clone();
    std::thread::scope(move |s| {
        let _span = span.enter();

        let checkpoint_generator_span = tracing::Span::current().clone();
        let (checkpoints_tx, checkpoints_rx) =
            sync_channel::<(usize, ExecutionState, bool, u64)>(opts.checkpoints_channel_capacity);
        let checkpoint_generator_handle: ScopedJoinHandle<Result<_, ZKMCoreProverError>> =
            s.spawn(move || {
                let _span = checkpoint_generator_span.enter();
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
                    checkpoints_tx.send((0, initial_state, true, global_clk)).unwrap();
                    Ok(runtime.state.public_values_stream)
                })
            });

        let mut challenger = prover.machine().config().challenger();
        pk.observe_into(&mut challenger);

        let p2_record_gen_sync = Arc::new(TurnBasedSync::new());
        let p2_trace_gen_sync = Arc::new(TurnBasedSync::new());
        let checkpoints_rx = Arc::new(Mutex::new(checkpoints_rx));
        let (p2_records_and_traces_tx, p2_records_and_traces_rx) =
            sync_channel::<(Vec<ExecutionRecord>, Vec<zkm_pcs::Traces<Val<SC>>>)>(
                opts.records_and_traces_channel_capacity,
            );
        let p2_records_and_traces_tx = Arc::new(Mutex::new(p2_records_and_traces_tx));

        let report_aggregate = Arc::new(Mutex::new(ExecutionReport::default()));
        let state = Arc::new(Mutex::new(PublicValues::<u32, u32>::default().reset()));
        let deferred = Arc::new(Mutex::new(ExecutionRecord::new(program.clone().into())));
        let mut p2_record_and_trace_gen_handles = Vec::new();
        for _ in 0..opts.trace_gen_workers {
            let record_gen_sync = Arc::clone(&p2_record_gen_sync);
            let trace_gen_sync = Arc::clone(&p2_trace_gen_sync);
            let records_and_traces_tx = Arc::clone(&p2_records_and_traces_tx);
            let checkpoints_rx = Arc::clone(&checkpoints_rx);

            let report_aggregate = Arc::clone(&report_aggregate);
            let state = Arc::clone(&state);
            let deferred = Arc::clone(&deferred);
            let program = program.clone();

            let span = tracing::Span::current().clone();

            #[cfg(feature = "debug")]
            let all_records_tx = all_records_tx.clone();

            let handle = s.spawn(move || {
                let _span = span.enter();
                tracing::debug_span!("phase 2 trace generation").in_scope(|| {
                    let _: () =
                        loop {
                            let received = { checkpoints_rx.lock().unwrap().recv() };
                            if let Ok((index, execution_state, done, num_cycles)) = received {
                                tracing::trace!(
                                    target = "checkpoint_pin",
                                    event = "consume",
                                    index = index,
                                    done = done,
                                    num_cycles = num_cycles,
                                );
                                let mut batch_index = index;
                                let mut process_batch = |mut records: Vec<ExecutionRecord>,
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
                                state.initial_timestamp = record.public_values.initial_timestamp;
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

                            let mut shape_fixed_records = if done
                                && num_cycles < 1 << 21
                                && deferred.global_memory_initialize_events.len()
                                    < opts.split_opts.combine_memory_threshold
                                && deferred.global_memory_finalize_events.len()
                                    < opts.split_opts.combine_memory_threshold
                            {
                                let mut records_clone = records.clone();
                                let last_record = records_clone.last_mut();
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
                                records_clone.append(&mut deferred);

                                tracing::debug_span!("generate dependencies", index).in_scope(
                                    || -> Result<(), ZKMCoreProverError> {
                                        match prover.machine().generate_dependencies(
                                            &mut records_clone,
                                            &opts,
                                            None,
                                        ) {
                                            Ok(()) => Ok(()),
                                            Err(e) => {
                                                tracing::error!(
                                                    "Error generating dependencies: {:?}",
                                                    e
                                                );
                                                Err(ZKMCoreProverError::DependenciesGenerationError)
                                            }
                                        }
                                    },
                                )?;

                                record_gen_sync.advance_turn();

                                let mut fixed_shape = true;
                                if let Some(shape_config) = shape_config {
                                    for record in records_clone.iter_mut() {
                                        if shape_config.fix_shape(record).is_err() {
                                            fixed_shape = false;
                                        } else {
                                            crate::shape::canonicalize_shape_to_cluster(record);
                                        }
                                    }
                                }
                                fixed_shape.then_some(records_clone)
                            } else {
                                None
                            };

                            if shape_fixed_records.is_none() {
                                let mut deferred = deferred.split(done, None, opts.split_opts);
                                log::debug!("deferred {} records", deferred.len());

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
                                    || -> Result<(), ZKMCoreProverError> {
                                        match prover.machine().generate_dependencies(
                                            &mut records,
                                            &opts,
                                            None,
                                        ) {
                                            Ok(()) => Ok(()),
                                            Err(e) => {
                                                tracing::error!(
                                                    "Error generating dependencies: {:?}",
                                                    e
                                                );
                                                Err(ZKMCoreProverError::DependenciesGenerationError)
                                            }
                                        }
                                    },
                                )?;

                                record_gen_sync.advance_turn();

                                if let Some(shape_config) = shape_config {
                                    for record in records.iter_mut() {
                                        shape_config.fix_shape(record).unwrap();
                                        crate::shape::canonicalize_shape_to_cluster(record);
                                    }
                                }
                                shape_fixed_records = Some(records);
                            }

                            let records = shape_fixed_records.unwrap();

                            #[cfg(feature = "debug")]
                            all_records_tx.send(records.clone()).unwrap();

                            let main_traces_results: Vec<Result<_, _>> =
                                tracing::debug_span!("generate main traces", index).in_scope(
                                    || {
                                        records
                                            .par_iter()
                                            .map(|record| prover.generate_traces(record))
                                            .collect()
                                    },
                                );
                            let (successes, errors): (Vec<_>, Vec<_>) =
                                main_traces_results.into_iter().partition(Result::is_ok);
                            let main_traces = successes.into_iter().map(Result::unwrap).collect();
                            if !errors.is_empty() {
                                tracing::error!("Failed to generate {} traces", errors.len());
                                for error in errors {
                                    if let Err(e) = error {
                                        tracing::error!("Trace generation error: {:?}", e);
                                        return Err(ZKMCoreProverError::TracesGenerationError);
                                    }
                                }
                            }

                            trace_gen_sync.wait_for_turn(index);

                            let chunked_records = chunk_vec(records, opts.shard_batch_size);
                            let chunked_main_traces = chunk_vec(main_traces, opts.shard_batch_size);
                            chunked_records
                                .into_iter()
                                .zip(chunked_main_traces)
                                .for_each(|(records, main_traces)| {
                                    records_and_traces_tx
                                        .lock()
                                        .unwrap()
                                        .send((records, main_traces))
                                        .unwrap();
                                });

                            trace_gen_sync.advance_turn();
                            Ok(())
                            };

                                trace_checkpoint_to_completion::<SC, _>(
                                    program.clone(),
                                    execution_state,
                                    opts,
                                    shape_config,
                                    &mut process_batch,
                                )?;
                            } else {
                                break;
                            }
                        };
                    Ok(())
                })
            });
            p2_record_and_trace_gen_handles.push(handle);
        }
        drop(p2_records_and_traces_tx);
        #[cfg(feature = "debug")]
        drop(all_records_tx);

        let cluster_shape_config = CoreShapeConfig::<SC::Val>::default();

        let cluster_chip_widths: std::collections::BTreeMap<String, usize> = prover
            .machine()
            .chips()
            .iter()
            .map(|c| (MachineAir::<SC::Val>::name(c), p3_air::BaseAir::<SC::Val>::width(c).max(1)))
            .collect();

        let p2_prover_span = tracing::Span::current().clone();
        let p2_prover_handle = s.spawn(move || {
            let _span = p2_prover_span.enter();
            let mut shard_proofs = Vec::new();
            tracing::debug_span!("phase 2 prover").in_scope(|| {
                for (records, traces) in p2_records_and_traces_rx.into_iter() {
                    tracing::debug_span!("batch").in_scope(|| {
                        let span = tracing::Span::current().clone();
                        shard_proofs.par_extend(
                            records.into_par_iter().zip(traces.into_par_iter()).map(
                                |(record, main_traces)| {
                                    let _span = span.enter();

                                    let cluster_widths: Option<
                                        std::collections::BTreeMap<String, usize>,
                                    > = cluster_shape_config
                                        .find_canonical_cluster_shape(&record)
                                        .map(|shape| {
                                            shape
                                                .iter()
                                                .filter_map(|(air, _log_h)| {
                                                    let name = air.to_string();
                                                    let width =
                                                        cluster_chip_widths.get(&name).copied()?;
                                                    Some((name, width))
                                                })
                                                .collect()
                                        });

                                    let t_commit = std::time::Instant::now();
                                    let main_data =
                                        prover.commit(&record, main_traces, cluster_widths);
                                    let commit_ms = t_commit.elapsed().as_millis();

                                    let opening_span = tracing::debug_span!("opening").entered();
                                    let t_open = std::time::Instant::now();
                                    let proof = prover
                                        .open(pk, main_data, &mut challenger.clone())
                                        .unwrap();
                                    let open_ms = t_open.elapsed().as_millis();
                                    opening_span.exit();

                                    tracing::info!(
                                        "PCS timing: commit={}ms open={}ms total={}ms",
                                        commit_ms,
                                        open_ms,
                                        commit_ms + open_ms
                                    );

                                    #[cfg(debug_assertions)]
                                    {
                                        if let Some(ref shape) = record.shape {
                                            assert_eq!(
                                                proof.shape(),
                                                shape
                                                    .clone()
                                                    .into_iter()
                                                    .filter(|(k, _)| {
                                                        k != &zkm_core_executor::MipsAirId::Cpu
                                                    })
                                                    .map(|(k, v)| (k.to_string(), v as usize))
                                                    .collect(),
                                            );
                                        }
                                    }

                                    rayon::spawn(move || {
                                        drop(record);
                                    });

                                    proof
                                },
                            ),
                        );
                    });
                }
            });
            shard_proofs
        });

        let public_values_stream = checkpoint_generator_handle.join().unwrap()?;

        for handle in p2_record_and_trace_gen_handles {
            handle.join().unwrap()?;
        }

        let shard_proofs = p2_prover_handle.join().unwrap();

        let report_aggregate = report_aggregate.lock().unwrap();
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

        let proof = MachineProof::<SC> { shard_proofs };
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
pub fn trace_checkpoint_to_completion<SC: StarkGenericConfig, F>(
    program: Program,
    state: ExecutionState,
    opts: ZKMCoreOpts,
    shape_config: Option<&CoreShapeConfig<SC::Val>>,
    mut on_batch: F,
) -> Result<(), ZKMCoreProverError>
where
    <SC as StarkGenericConfig>::Val: PrimeField32,
    F: FnMut(Vec<ExecutionRecord>, ExecutionReport, bool, u64) -> Result<(), ZKMCoreProverError>,
{
    let noop = NoOpSubproofVerifier;

    let mut runtime = Executor::recover(program, state, opts);
    runtime.maximal_shapes = shape_config.map(|config| {
        config.maximal_core_shapes(opts.shard_size.ilog2() as usize).into_iter().collect()
    });
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

pub fn trace_checkpoint<SC: StarkGenericConfig>(
    program: Program,
    state: ExecutionState,
    opts: ZKMCoreOpts,
    shape_config: Option<&CoreShapeConfig<SC::Val>>,
) -> (Vec<ExecutionRecord>, ExecutionReport)
where
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    let noop = NoOpSubproofVerifier;

    let mut runtime = Executor::recover(program, state, opts);
    runtime.maximal_shapes = shape_config.map(|config| {
        config.maximal_core_shapes(opts.shard_size.ilog2() as usize).into_iter().collect()
    });

    runtime.subproof_verifier = Some(&noop);

    let (records, _) = runtime.execute_record(true).unwrap();

    (records, runtime.report)
}
