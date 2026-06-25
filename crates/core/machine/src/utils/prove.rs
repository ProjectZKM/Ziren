use crate::mips::MipsAir;
use p3_maybe_rayon::prelude::*;
use p3_uni_stark::SymbolicAirBuilder;
use serde::{de::DeserializeOwned, Serialize};
use size::Size;
use std::thread::ScopedJoinHandle;
use std::{
    io,
    sync::{mpsc::sync_channel, Arc, Mutex},
};
use thiserror::Error;
use web_time::Instant;
use zkm_pcs::{
    koala_bear_poseidon2::KoalaBearPoseidon2, MachineProvingKey, MachineVerificationError,
};

use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;

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
use zkm_primitives::io::ZKMPublicValues;

use zkm_pcs::{
    air::{MachineAir, PublicValues},
    Com, CpuProver, DebugConstraintBuilder, LookupBuilder, MachineProof, MachineProver,
    MachineRecord, OpeningProof, PcsProverData, ProverConstraintFolder, StarkGenericConfig,
    StarkMachine, StarkProvingKey, StarkVerifyingKey, UniConfig, Val, VerifierConstraintFolder,
    ZKMCoreOpts,
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
    // Setup the runtime.
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

    // Record the start of the process.
    let proving_start = Instant::now();
    let span = tracing::Span::current().clone();
    std::thread::scope(move |s| {
        let _span = span.enter();

        // Spawn the checkpoint generator thread.
        //
        // In-memory shard checkpoints: pin each per-shard
        // `ExecutionState` in RAM and send it directly through the channel.
        // The previous implementation wrote each checkpoint to a `tempfile`,
        // sent the `File` handle downstream, and the trace-gen worker
        // `bincode::deserialize_from`'d it back.  That roundtrip costs ~5 s
        // of wall time on the production reth wrap (per
        // `docs/perf_reth_gpu.md`) and burns inode + page-cache pressure
        // under `TMPDIR=/dev/shm`.  Mirrors the equivalent change already
        // landed in `ziren-gpu/prover/src/core_multi_gpu.rs:136-159` for
        // the multi-GPU code path; this brings the 1-GPU-fallback /
        // CPU-prover baseline into line.
        //
        // RAM cost: an `ExecutionState` is dominated by the memory image
        // diff since the last checkpoint (typically a few MB per shard),
        // bounded by `checkpoints_channel_capacity` in flight.  We log
        // every cache hit/miss-equivalent (here: every send/recv) at
        // `trace` level so behaviour can be verified at runtime.
        let checkpoint_generator_span = tracing::Span::current().clone();
        let (checkpoints_tx, checkpoints_rx) = sync_channel::<(
            usize,
            ExecutionState,
            bool,
            u64,
            // producer wiring: optional sidecar of
            // sealed TraceChunks accumulated since the last batch.
            // Consumer may use these via `trace_chunk` to avoid
            // re-executing memory state from scratch.
            Option<std::sync::Arc<[zkm_core_executor::minimal_trace::TraceChunk]>>,
        )>(opts.checkpoints_channel_capacity);
        // opt-in. When set, producer collects MinimalTrace
        // chunks during Checkpoint-mode execution and sends them alongside
        // each ExecutionState batch. Consumer may then prefer `trace_chunk`
        // (which uses the chunks' mem_reads oracle) over `trace_checkpoint`
        // (which re-executes from scratch). Default OFF — production path
        // unchanged.
        let use_minimal_trace = std::env::var("ZIREN_USE_MINIMAL_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false);
        if use_minimal_trace {
            runtime.minimal_trace_collector =
                Some(zkm_core_executor::minimal_trace::MinimalTrace::default());
        }
        let checkpoint_generator_handle: ScopedJoinHandle<Result<_, ZKMCoreProverError>> =
            s.spawn(move || {
                let _span = checkpoint_generator_span.enter();
                tracing::debug_span!("checkpoint generator").in_scope(|| {
                    let mut index = 0;
                    // track how many chunks we've already
                    // sent so each batch's sidecar only carries the NEW
                    // chunks added since the last `execute_state`.
                    let mut last_pulled_chunks = 0usize;
                    loop {
                        // Enter the span.
                        let span = tracing::debug_span!("batch");
                        let _span = span.enter();

                        // Execute the runtime until we reach a checkpoint.
                        let (checkpoint, done) = runtime
                            .execute_state(false)
                            .map_err(ZKMCoreProverError::ExecutionError)?;

                        // Send the checkpoint in-memory (no tempfile + bincode roundtrip).
                        let global_clk = runtime.state.global_clk;

                        // pull NEW chunks accumulated by
                        // the collector during this batch. Only sealed
                        // chunks (clk_end != u64::MAX) are eligible.
                        let chunks_sidecar = if use_minimal_trace {
                            if let Some(trace) = runtime.minimal_trace_collector.as_ref() {
                                let total = trace.chunks.len();
                                if total > last_pulled_chunks {
                                    let new_chunks: Vec<_> = trace.chunks
                                        [last_pulled_chunks..total]
                                        .iter()
                                        .filter(|c| c.clk_end != u64::MAX)
                                        .cloned()
                                        .collect();
                                    last_pulled_chunks = total;
                                    Some(std::sync::Arc::from(new_chunks))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        tracing::trace!(
                            target = "checkpoint_pin",
                            event = "produce",
                            index = index,
                            done = done,
                            global_clk = global_clk,
                            chunks = chunks_sidecar
                                .as_ref()
                                .map(|c: &std::sync::Arc<[zkm_core_executor::minimal_trace::TraceChunk]>| c.len())
                                .unwrap_or(0),
                        );
                        checkpoints_tx
                            .send((index, checkpoint, done, global_clk, chunks_sidecar))
                            .unwrap();

                        // If we've reached the final checkpoint, break out of the loop.
                        if done {
                            break Ok(runtime.state.public_values_stream);
                        }

                        // Update the index.
                        index += 1;
                    }
                })
            });

        // Create the challenger and observe the verifying key.
        let mut challenger = prover.config().challenger();
        pk.observe_into(&mut challenger);

        // Spawn the phase 2 record generator thread.
        let p2_record_gen_sync = Arc::new(TurnBasedSync::new());
        let p2_trace_gen_sync = Arc::new(TurnBasedSync::new());
        let checkpoints_rx = Arc::new(Mutex::new(checkpoints_rx));
        let (p2_records_and_traces_tx, p2_records_and_traces_rx) =
            sync_channel::<(Vec<ExecutionRecord>, Vec<Vec<(String, RowMajorMatrix<Val<SC>>)>>)>(
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
                    let _: () = loop {
                        // Receive the latest checkpoint.
                        let received = { checkpoints_rx.lock().unwrap().recv() };
                        if let Ok((index, execution_state, done, num_cycles, chunks_sidecar))
                            = received
                        {
                            // In-memory checkpoint — no
                            // tempfile read, no bincode::deserialize.
                            tracing::trace!(
                                target = "checkpoint_pin",
                                event = "consume",
                                index = index,
                                done = done,
                                num_cycles = num_cycles,
                            );
                            // if env-gated and the
                            // producer supplied chunks, use the oracle
                            // path (`trace_chunk`) instead of the
                            // re-execute-from-checkpoint path
                            // (`trace_checkpoint`). Falls back to
                            // checkpoint if no chunks were available
                            // (e.g. zero-cycle batches, or first batch
                            // before any shard boundary).
                            let _ = execution_state; // may be unused on chunk path
                            let (mut records, report) = tracing::debug_span!("trace checkpoint")
                                .in_scope(|| {
                                    match chunks_sidecar.as_ref() {
                                        Some(chunks) if !chunks.is_empty() => {
                                            let mut merged_records: Vec<ExecutionRecord> =
                                                Vec::new();
                                            for chunk in chunks.iter() {
                                                let (recs, _) = trace_chunk::<SC>(
                                                    program.clone(),
                                                    chunk,
                                                    opts,
                                                    shape_config,
                                                );
                                                merged_records.extend(recs);
                                            }
                                            (merged_records, ExecutionReport::default())
                                        }
                                        _ => trace_checkpoint::<SC>(
                                            program.clone(),
                                            execution_state,
                                            opts,
                                            shape_config,
                                        ),
                                    }
                                });
                            log::debug!("generated {} records", records.len());
                            *report_aggregate.lock().unwrap() += report;

                            // Wait for our turn to update the state.
                            record_gen_sync.wait_for_turn(index);

                            // Update the public values & prover state for the shards which contain
                            // "cpu events".
                            let mut state = state.lock().unwrap();
                            for record in records.iter_mut() {
                                state.shard += 1;
                                state.execution_shard = record.public_values.execution_shard;
                                state.start_pc = record.public_values.start_pc;
                                state.next_pc = record.public_values.next_pc;
                                // Option 2 State bus: the per-shard 2-pc endpoints and
                                // timestamps are populated by the executor's finalization,
                                // not the running `state`, so carry them here — otherwise the
                                // `record.public_values = *state` write below zeroes them and
                                // the `State`-bus multiset no longer balances.
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

                            // Defer events that are too expensive to include in every shard.
                            let mut deferred = deferred.lock().unwrap();
                            for record in records.iter_mut() {
                                deferred.append(&mut record.defer());
                            }

                            // We combine the memory init/finalize events if they are "small"
                            // and would affect performance.
                            let mut shape_fixed_records = if done
                                && num_cycles < 1 << 21
                                && deferred.global_memory_initialize_events.len()
                                    < opts.split_opts.combine_memory_threshold
                                && deferred.global_memory_finalize_events.len()
                                    < opts.split_opts.combine_memory_threshold
                            {
                                let mut records_clone = records.clone();
                                let last_record = records_clone.last_mut();
                                // See if any deferred shards are ready to be committed to.
                                let mut deferred =
                                    deferred.split(done, last_record, opts.split_opts);
                                tracing::debug!("deferred {} records", deferred.len());

                                // Update the public values & prover state for the shards which do
                                // not contain "cpu events" before
                                // committing to them.
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
                                    // Option 2 State bus: a no-CPU shard has no Cpu row chain,
                                    // so its PV-AIR send_state/receive_state must self-cancel —
                                    // force both endpoints equal (start==next 2-pc, equal ts).
                                    state.start_next_pc = state.next_next_pc;
                                    state.last_timestamp = state.initial_timestamp;
                                    record.public_values = *state;
                                }
                                records_clone.append(&mut deferred);

                                // Generate the dependencies.
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

                                // Let another worker update the state.
                                record_gen_sync.advance_turn();

                                // Fix the shape of the records.
                                let mut fixed_shape = true;
                                if let Some(shape_config) = shape_config {
                                    for record in records_clone.iter_mut() {
                                        if shape_config.fix_shape(record).is_err() {
                                            fixed_shape = false;
                                        } else {
                                            // VERIFY_VK multi-shard: canonical
                                            // cluster chip set (see the other site).
                                            crate::shape::canonicalize_shape_to_cluster(record);
                                        }
                                    }
                                }
                                if std::env::var("DUMP_SHARD_SHAPES").is_ok() && fixed_shape {
                                    use std::io::Write;
                                    let mut f = std::fs::OpenOptions::new()
                                        .create(true).append(true)
                                        .open("/tmp/shard_shapes.log")
                                        .expect("open shape dump");
                                    for record in records_clone.iter() {
                                        let mut shape_entries: Vec<(String, usize)> = record
                                            .shape
                                            .as_ref()
                                            .map(|s| s.iter().map(|(k, v)| (format!("{k:?}"), *v)).collect())
                                            .unwrap_or_default();
                                        shape_entries.sort();
                                        writeln!(f, "[A] shard {} shape: {:?}", record.public_values.shard, shape_entries).unwrap();
                                    }
                                    eprintln!("[DUMP_SHARD_SHAPES][A] wrote {} shapes", records_clone.len());
                                }
                                fixed_shape.then_some(records_clone)
                            } else {
                                None
                            };

                            if shape_fixed_records.is_none() {
                                // See if any deferred shards are ready to be committed to.
                                let mut deferred = deferred.split(done, None, opts.split_opts);
                                log::debug!("deferred {} records", deferred.len());

                                // Update the public values & prover state for the shards which do not
                                // contain "cpu events" before committing to them.
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
                                    // Option 2 State bus: a no-CPU shard has no Cpu row chain,
                                    // so its PV-AIR send_state/receive_state must self-cancel —
                                    // force both endpoints equal (start==next 2-pc, equal ts).
                                    state.start_next_pc = state.next_next_pc;
                                    state.last_timestamp = state.initial_timestamp;
                                    record.public_values = *state;
                                }
                                records.append(&mut deferred);

                                // Generate the dependencies.
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

                                // Let another worker update the state.
                                record_gen_sync.advance_turn();

                                // Fix the shape of the records.
                                if let Some(shape_config) = shape_config {
                                    for record in records.iter_mut() {
                                        shape_config.fix_shape(record).unwrap();
                                        // VERIFY_VK multi-shard: extend the
                                        // chosen shape up to the canonical stacked
                                        // cluster so per-guest event-driven chip
                                        // subsets don't explode the vk space.
                                        crate::shape::canonicalize_shape_to_cluster(record);
                                    }
                                }
                                // Diagnostic: dump per-shard shape to /tmp for diff'ing
                                // across runs to find non-determinism in shape selection.
                                if std::env::var("DUMP_SHARD_SHAPES").is_ok() {
                                    use std::io::Write;
                                    let path = "/tmp/shard_shapes.log";
                                    let mut f = std::fs::OpenOptions::new()
                                        .create(true).append(true)
                                        .open(path)
                                        .expect("open shape dump file");
                                    for record in records.iter() {
                                        let mut shape_entries: Vec<(String, usize)> = record
                                            .shape
                                            .as_ref()
                                            .map(|s| s.iter().map(|(k, v)| (format!("{k:?}"), *v)).collect())
                                            .unwrap_or_default();
                                        shape_entries.sort();
                                        writeln!(
                                            f,
                                            "shard {} shape: {:?}",
                                            record.public_values.shard,
                                            shape_entries
                                        ).expect("write shape line");
                                    }
                                    f.flush().expect("flush");
                                    eprintln!("[DUMP_SHARD_SHAPES] wrote {} shard shapes", records.len());
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

                            // Send the records to the phase 2 prover.
                            let chunked_records = chunk_vec(records, opts.shard_batch_size);
                            let chunked_main_traces = chunk_vec(main_traces, opts.shard_batch_size);
                            chunked_records
                                .into_iter()
                                .zip(chunked_main_traces.into_iter())
                                .for_each(|(records, main_traces)| {
                                    records_and_traces_tx
                                        .lock()
                                        .unwrap()
                                        .send((records, main_traces))
                                        .unwrap();
                                });

                            trace_gen_sync.advance_turn();
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

        // HEIGHT-AGNOSTIC RECURSION (step 5c): a CoreShapeConfig used ONLY to
        // compute the per-shard FULL canonical CLUSTER shape for the jagged
        // commit (`find_canonical_cluster_shape`), INDEPENDENT of
        // `FIX_CORE_SHAPES` (`shape_config`).  With `FIX_CORE_SHAPES=false` the
        // records stay at RAW heights and the core STARK proves at those
        // heights, but the jagged commit must still pad/extend to the SAME
        // canonical cluster shape `fix_shape` + `canonicalize_shape_to_cluster`
        // produce under FIX-on, so the recursion normalize VK = f(chip-SET) and
        // matches the production vk_map.  Built once per prove call (the same
        // default config the prover constructs at `ZKMProver::new`).
        let band_cap_shape_config = CoreShapeConfig::<SC::Val>::default();

        // HEIGHT-AGNOSTIC RECURSION (step 5c): chip NAME -> trace WIDTH, so the
        // band-cap can ADD a missing canonical-cluster chip's zero COMMIT trace
        // (width is required to size it).  Machine-static, built once.
        let band_cap_chip_widths: std::collections::BTreeMap<String, usize> = prover
            .machine()
            .chips()
            .iter()
            .map(|c| {
                (
                    MachineAir::<SC::Val>::name(c),
                    p3_air::BaseAir::<SC::Val>::width(c).max(1),
                )
            })
            .collect();

        // Spawn the phase 2 prover thread.
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

                                    // HEIGHT-AGNOSTIC RECURSION (step 5b):
                                    // compute this shard's per-chip CLUSTER
                                    // band-cap from its RAW core heights and
                                    // install it for the scope of commit+open
                                    // (which run on THIS rayon task).  The PCS
                                    // commit (`prove_shard_to_basefold_with_loader`)
                                    // reads it via `band_cap::current_band_cap`
                                    // and pads the jagged commit traces to it,
                                    // while the STARK stays at raw heights.
                                    // Keyed by chip NAME (the PCS layer cannot
                                    // depend on `MipsAirId`).  A shard whose
                                    // heights overflow every cluster yields
                                    // `None` (no pad/add, legacy own-height).
                                    let _band_cap_guard = {
                                        // Compute the FULL canonical CLUSTER shape
                                        // this raw record lifts to — the SAME shape
                                        // `fix_shape` + `canonicalize_shape_to_cluster`
                                        // produce under FIX_CORE_SHAPES=true (chip-SET
                                        // AND per-chip band-cap heights, incl. the
                                        // missing event-driven chips at log-height 1).
                                        // The map carries (width, log_height) so the
                                        // PCS commit can both PAD present chips and ADD
                                        // a trace for each MISSING canonical chip,
                                        // so the FIX-off normalize VK = the FIX-on
                                        // canonical cluster VK (production vk_map).
                                        band_cap_shape_config
                                            .find_canonical_cluster_shape(&record)
                                            .map(|shape| {
                                                // G1 Stage D1b (#88) gate probe:
                                                // dump the REAL canonical-cluster
                                                // shape the FIX-off jagged commit
                                                // pads to, so the membership gate
                                                // can compare it against the
                                                // ordered reconstruction.
                                                if std::env::var("ZIREN_VK_SHAPE_CAPTURE").is_ok() {
                                                    let mut sh: Vec<(String, usize)> = shape
                                                        .iter()
                                                        .map(|(a, h)| (a.to_string(), *h))
                                                        .collect();
                                                    sh.sort();
                                                    let mut ch: Vec<(String, usize)> =
                                                        crate::mips::MipsAir::<SC::Val>::core_heights(&record)
                                                            .into_iter()
                                                            .map(|(a, h)| (a.to_string(), h))
                                                            .collect();
                                                    ch.sort();
                                                    eprintln!(
                                                        "[REALCANON] shard={} canonical={:?}",
                                                        record.public_values.shard, sh
                                                    );
                                                    eprintln!(
                                                        "[REALCANON] shard={} core_heights_raw={:?}",
                                                        record.public_values.shard, ch
                                                    );
                                                }
                                                let map: std::collections::BTreeMap<
                                                    String,
                                                    (usize, usize),
                                                > = shape
                                                    .iter()
                                                    .map(|(air, log_h)| {
                                                        let name = air.to_string();
                                                        let width = band_cap_chip_widths
                                                            .get(&name)
                                                            .copied()
                                                            .unwrap_or(1);
                                                        (name, (width, *log_h))
                                                    })
                                                    .collect();

                                                // ROLLOUT 1b: generate the
                                                // CONSTRAINT-VALID traces of the
                                                // canonical-cluster chips this raw
                                                // shard is MISSING, the FIX-on way:
                                                // set the canonical shape on a CLONE
                                                // of the record and run the machine's
                                                // normal tracegen, so each chip's own
                                                // `MachineAir::generate_trace` lays
                                                // down its padding rows (dummy_row /
                                                // padded_row_template) that satisfy
                                                // that chip's AIR sanity constraints
                                                // (e.g. CloClz `a=32, is_bb_zero=1`).
                                                // The STARK keeps the PRESENT chips at
                                                // ACTUAL heights (`main_traces`); only
                                                // the MISSING chips (absent from
                                                // `main_traces`) are taken from this
                                                // canonical-shaped tracegen, then
                                                // injected by `commit_basefold_path`
                                                // for both `chip_ordering` and the
                                                // commit.  All-zero injection
                                                // (rollout 1) matched the VK but
                                                // tripped the injected chips'
                                                // constraints in `verify_shard`.
                                                let missing_traces: std::collections::BTreeMap<
                                                    String,
                                                    p3_matrix::dense::RowMajorMatrix<
                                                        zkm_pcs::InnerVal,
                                                    >,
                                                > = {
                                                    use core::any::TypeId;
                                                    // Only the KoalaBear inner ring
                                                    // takes the BaseFold band-cap path
                                                    // (the gate the injection itself
                                                    // assumes); on any other ring keep
                                                    // the rollout-1 fallback (empty =>
                                                    // zero injection) rather than an
                                                    // unsound transmute.
                                                    if TypeId::of::<SC::Val>()
                                                        == TypeId::of::<zkm_pcs::InnerVal>()
                                                    {
                                                        let present: std::collections::BTreeSet<
                                                            String,
                                                        > = main_traces
                                                            .iter()
                                                            .map(|(n, _)| n.clone())
                                                            .collect();
                                                        // Canonical-shaped clone (shares
                                                        // the program Arc); FIX-on path.
                                                        let mut gen_record = record.clone();
                                                        gen_record.shape = Some(shape.clone());
                                                        match prover.generate_traces(&gen_record) {
                                                            Ok(all_canonical) => {
                                                                // SC::Val == InnerVal here
                                                                // (TypeId-gated): reinterpret
                                                                // Vec<(String,
                                                                // RowMajorMatrix<SC::Val>)> as
                                                                // Vec<(String,
                                                                // RowMajorMatrix<InnerVal>)>,
                                                                // the same gate the commit
                                                                // injection relies on.
                                                                let inner: Vec<(
                                                                    String,
                                                                    p3_matrix::dense::RowMajorMatrix<
                                                                        zkm_pcs::InnerVal,
                                                                    >,
                                                                )> = unsafe {
                                                                    let mut v =
                                                                        core::mem::ManuallyDrop::new(
                                                                            all_canonical,
                                                                        );
                                                                    let ptr = v.as_mut_ptr();
                                                                    let len = v.len();
                                                                    let cap = v.capacity();
                                                                    Vec::from_raw_parts(
                                                                        ptr as *mut (
                                                                            String,
                                                                            p3_matrix::dense::RowMajorMatrix<
                                                                                zkm_pcs::InnerVal,
                                                                            >,
                                                                        ),
                                                                        len,
                                                                        cap,
                                                                    )
                                                                };
                                                                inner
                                                                    .into_iter()
                                                                    .filter(|(n, _)| {
                                                                        !present.contains(n)
                                                                    })
                                                                    .collect()
                                                            }
                                                            Err(_) => Default::default(),
                                                        }
                                                    } else {
                                                        Default::default()
                                                    }
                                                };

                                                // Low-placement raw log-heights: each PRESENT
                                                // chip's actual (raw) trace height.  Installed
                                                // for the whole guard scope so the jagged commit
                                                // (prover.commit) and the reduce (prover.open)
                                                // BOTH materialize with low-placement (raw data
                                                // in the low rows of each band slot).  Missing
                                                // (injected) chips are absent here => they pack at
                                                // their band height (raw==band, legacy no-op).
                                                let raw_log_heights: std::collections::BTreeMap<
                                                    String,
                                                    usize,
                                                > = {
                                                    let mut m = std::collections::BTreeMap::new();
                                                    for (n, t) in main_traces.iter() {
                                                        let w = t.width.max(1);
                                                        let h = t.values.len() / w;
                                                        if h.is_power_of_two() && h > 0 {
                                                            m.insert(
                                                                n.clone(),
                                                                h.trailing_zeros() as usize,
                                                            );
                                                        }
                                                    }
                                                    m
                                                };

                                                // STAGE 2.5 (#88) LOCKSTEP
                                                // ORIENTATION: compute the per-shard
                                                // rev(zeta) decision ONCE here (the
                                                // single source of truth) and install
                                                // it for the whole commit+open scope,
                                                // so the jagged COMMIT (materialize),
                                                // the `y_per_chip` recompute, and the
                                                // zerocheck residual all read ONE
                                                // boolean and can never drift.  On this
                                                // CPU core prove path there is no device
                                                // trace provider, so on the host every
                                                // chip carries `main_trace_evaluations_
                                                // full` and this equals the zerocheck's
                                                // full predicate (`_device_traces.is_
                                                // none()` + all-full-openings); the
                                                // zerocheck re-applies the device-none /
                                                // full-openings guard locally where that
                                                // info is known, so a GPU run (out of
                                                // scope; flag default-OFF) stays bitrev.
                                                // Flag OFF => `false` => the legacy
                                                // bitrev branch, byte-identical to today.
                                                let stage2_use_rev = std::env::var(
                                                    "ZIREN_STAGE2_REVZETA",
                                                )
                                                .map(|v| {
                                                    v != "0"
                                                        && !v.eq_ignore_ascii_case("false")
                                                })
                                                .unwrap_or(false);

                                                zkm_pcs::shard_level::band_cap::BandCapGuard::new(
                                                    map,
                                                    missing_traces,
                                                    raw_log_heights,
                                                    stage2_use_rev,
                                                )
                                            })
                                    };

                                    let t_commit = std::time::Instant::now();
                                    let main_data = prover.commit(&record, main_traces);
                                    let commit_ms = t_commit.elapsed().as_millis();

                                    let opening_span = tracing::debug_span!("opening").entered();
                                    let t_open = std::time::Instant::now();
                                    let proof = prover
                                        .open(pk, main_data, &mut challenger.clone())
                                        .unwrap();
                                    let open_ms = t_open.elapsed().as_millis();
                                    opening_span.exit();
                                    drop(_band_cap_guard);

                                    tracing::info!(
                                        "PCS timing: commit={}ms open={}ms total={}ms",
                                        commit_ms, open_ms, commit_ms + open_ms
                                    );

                                    #[cfg(debug_assertions)]
                                    {
                                        if let Some(ref shape) = record.shape {
                                            assert_eq!(
                                                proof.shape(),
                                                shape
                                                    .clone()
                                                    .into_iter()
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

        // Wait until the checkpoint generator handle has fully finished.
        let public_values_stream = checkpoint_generator_handle.join().unwrap()?;

        // Wait until the records and traces have been fully generated for phase 2.
        for handle in p2_record_and_trace_gen_handles {
            handle.join().unwrap()?;
        }

        // Wait until the phase 2 prover has finished.
        let shard_proofs = p2_prover_handle.join().unwrap();

        // Log some of the `ExecutionReport` information.
        let report_aggregate = report_aggregate.lock().unwrap();
        tracing::info!(
            "execution report (totals): total_cycles={}, total_syscall_cycles={}, touched_memory_addresses={}",
            report_aggregate.total_instruction_count(),
            report_aggregate.total_syscall_count(),
            report_aggregate.touched_memory_addresses,
        );

        // Print the opcode and syscall count tables like `du`: sorted by count (descending) and
        // with the count in the first column.
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

        // Print the summary.
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

/// Runs a program and returns the public values stream.
pub fn run_test_io<P: MachineProver<KoalaBearPoseidon2, MipsAir<KoalaBear>>>(
    mut program: Program,
    inputs: ZKMStdin,
) -> Result<ZKMPublicValues, MachineVerificationError<KoalaBearPoseidon2>> {
    let shape_config = CoreShapeConfig::<KoalaBear>::default();
    shape_config.fix_preprocessed_shape(&mut program).unwrap();
    let runtime = tracing::debug_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.write_vecs(&inputs.buffer);
        runtime.run().unwrap();
        runtime
    });
    let public_values = ZKMPublicValues::from(&runtime.state.public_values_stream);

    let _ = run_test_core::<P>(runtime, inputs, Some(&shape_config))?;
    Ok(public_values)
}

pub fn run_test<P: MachineProver<KoalaBearPoseidon2, MipsAir<KoalaBear>>>(
    mut program: Program,
) -> Result<MachineProof<KoalaBearPoseidon2>, MachineVerificationError<KoalaBearPoseidon2>> {
    let shape_config = CoreShapeConfig::default();
    shape_config.fix_preprocessed_shape(&mut program).unwrap();
    let runtime = tracing::debug_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        runtime
    });
    run_test_core::<P>(runtime, ZKMStdin::new(), Some(&shape_config))
}

#[allow(unused_variables)]
pub fn run_test_core<P: MachineProver<KoalaBearPoseidon2, MipsAir<KoalaBear>>>(
    runtime: Executor,
    inputs: ZKMStdin,
    shape_config: Option<&CoreShapeConfig<KoalaBear>>,
) -> Result<MachineProof<KoalaBearPoseidon2>, MachineVerificationError<KoalaBearPoseidon2>> {
    let config = KoalaBearPoseidon2::new();
    let machine = MipsAir::machine(config);
    let prover = P::new(machine);

    let (pk, _) = prover.setup(runtime.program.as_ref());
    let (proof, output, _) = prove_with_context(
        &prover,
        &pk,
        Program::clone(&runtime.program),
        &inputs,
        ZKMCoreOpts::default(),
        ZKMContext::default(),
        shape_config,
    )
    .unwrap();

    let config = KoalaBearPoseidon2::new();
    let machine = MipsAir::machine(config);
    let (pk, vk) = machine.setup(runtime.program.as_ref());
    let mut challenger = machine.config().challenger();
    machine.verify(&vk, &proof, &mut challenger).unwrap();

    Ok(proof)
}

#[allow(unused_variables)]
pub fn run_test_machine_with_prover<SC, A, P: MachineProver<SC, A>>(
    prover: &P,
    records: Vec<A::Record>,
    pk: P::DeviceProvingKey,
    vk: StarkVerifyingKey<SC>,
) -> Result<MachineProof<SC>, MachineVerificationError<SC>>
where
    A: MachineAir<SC::Val>
        + Air<LookupBuilder<Val<SC>>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>
        + for<'b> Air<zkm_pcs::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
            'b,
            Val<SC>,
            <SC as StarkGenericConfig>::Challenge,
        >>
        + Air<SymbolicAirBuilder<SC::Val>>,
    A::Record: MachineRecord<Config = ZKMCoreOpts>,
    SC: StarkGenericConfig + zkm_pcs::BasefoldRing,
    SC::Val: p3_field::PrimeField32,
    SC::Challenger: Clone + Sync,
    SC: Sync,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
    OpeningProof<SC>: Send + Sync,
    zkm_pcs::ShardProof<SC>: Sync,
{
    let mut challenger = prover.config().challenger();
    let prove_span = tracing::debug_span!("prove").entered();

    #[cfg(feature = "debug")]
    prover.machine().debug_constraints(
        &prover.pk_to_host(&pk),
        records.clone(),
        &mut challenger.clone(),
    );

    let proof = prover.prove(&pk, records, &mut challenger, ZKMCoreOpts::default()).unwrap();
    prove_span.exit();
    let nb_bytes = bincode::serialize(&proof).unwrap().len();

    let mut challenger = prover.config().challenger();
    prover.machine().verify(&vk, &proof, &mut challenger)?;

    Ok(proof)
}

#[allow(unused_variables)]
pub fn run_test_machine<SC, A>(
    records: Vec<A::Record>,
    machine: StarkMachine<SC, A>,
    pk: StarkProvingKey<SC>,
    vk: StarkVerifyingKey<SC>,
) -> Result<MachineProof<SC>, MachineVerificationError<SC>>
where
    A: MachineAir<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + Air<LookupBuilder<Val<SC>>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>
        + for<'b> Air<zkm_pcs::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
            'b,
            Val<SC>,
            <SC as StarkGenericConfig>::Challenge,
        >>
        + Air<SymbolicAirBuilder<SC::Val>>,
    A::Record: MachineRecord<Config = ZKMCoreOpts>,
    SC: StarkGenericConfig + zkm_pcs::BasefoldRing,
    SC::Val: p3_field::PrimeField32,
    SC::Challenger: Clone,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync + Clone + Serialize + DeserializeOwned,
    OpeningProof<SC>: Send + Sync,
{
    let prover = CpuProver::new(machine);
    run_test_machine_with_prover::<SC, A, CpuProver<_, _>>(&prover, records, pk, vk)
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

    // We already passed the deferred proof verifier when creating checkpoints, so the proofs were
    // already verified. So here we use a noop verifier to not print any warnings.
    runtime.subproof_verifier = Some(&noop);

    // Execute from the checkpoint.
    let (records, _) = runtime.execute_record(true).unwrap();

    (records, runtime.report)
}

/// drop-in replacement for `trace_checkpoint` that
/// consumes a [`zkm_core_executor::minimal_trace::TraceChunk`] instead
/// of a full [`ExecutionState`]. The chunk's `mem_reads` oracle
/// pre-populates the worker's memory; `start_registers` seeds the
/// register file; `clk_end` bounds the worker.
///
/// Signature mirrors `trace_checkpoint` so call sites can swap in via
/// a single conditional once the producer side of the pipeline emits
/// chunks instead of `ExecutionState` snapshots.
///
/// Byte-equivalence with `trace_checkpoint` is validated by
/// `crates/core/executor/examples/byte_equiv_probe.rs` — single-shard
/// PASS on fibonacci/u256/biguint/ed25519; multi-shard PASS on ed25519
/// with `SHARD_SIZE=1M` (4 shards, ~188K oracle entries/shard).
pub fn trace_chunk<SC: StarkGenericConfig>(
    program: Program,
    chunk: &zkm_core_executor::minimal_trace::TraceChunk,
    opts: ZKMCoreOpts,
    shape_config: Option<&CoreShapeConfig<SC::Val>>,
) -> (Vec<ExecutionRecord>, ExecutionReport)
where
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    use std::sync::Arc;
    use zkm_core_executor::tracing_vm::drive_tracing_vm_parallel;

    // Single-chunk MinimalTrace; the driver returns 1 record.
    let trace = zkm_core_executor::minimal_trace::MinimalTrace {
        chunks: vec![chunk.clone()],
        public_values: Vec::new(),
        total_cycles: chunk.clk_end,
    };
    let records = drive_tracing_vm_parallel(Arc::new(program), opts, &trace)
        .expect("drive_tracing_vm_parallel");
    // `drive_tracing_vm_parallel` doesn't aggregate a Report; for D.4
    // wiring the caller (consumer thread in prove.rs) reads from the
    // record stream directly. Until the consumer migrates, this
    // returns ExecutionReport::default() — callers that rely on the
    // report should keep using trace_checkpoint until D.4 producer
    // migration.
    let _ = shape_config;
    (records, ExecutionReport::default())
}

#[cfg(debug_assertions)]
#[cfg(not(doctest))]
pub fn uni_stark_prove<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    trace: RowMajorMatrix<SC::Val>,
) -> Proof<UniConfig<SC>>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::ProverConstraintFolder<'a, UniConfig<SC>>>
        + for<'a> Air<p3_air::DebugConstraintBuilder<'a, SC::Val>>,
{
    p3_uni_stark::prove(&UniConfig(config.clone()), air, trace, &vec![])
}

#[cfg(not(debug_assertions))]
pub fn uni_stark_prove<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    trace: RowMajorMatrix<SC::Val>,
) -> Proof<UniConfig<SC>>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::ProverConstraintFolder<'a, UniConfig<SC>>>,
{
    p3_uni_stark::prove(&UniConfig(config.clone()), air, trace, &vec![])
}

#[cfg(debug_assertions)]
#[cfg(not(doctest))]
pub fn uni_stark_verify<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    proof: &Proof<UniConfig<SC>>,
) -> Result<(), p3_uni_stark::VerificationError<p3_uni_stark::PcsError<UniConfig<SC>>>>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::VerifierConstraintFolder<'a, UniConfig<SC>>>
        + for<'a> Air<p3_air::DebugConstraintBuilder<'a, SC::Val>>,
{
    p3_uni_stark::verify(&UniConfig(config.clone()), air, proof, &vec![])
}

#[cfg(not(debug_assertions))]
pub fn uni_stark_verify<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    proof: &Proof<UniConfig<SC>>,
) -> Result<(), p3_uni_stark::VerificationError<p3_uni_stark::PcsError<UniConfig<SC>>>>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::VerifierConstraintFolder<'a, UniConfig<SC>>>,
{
    p3_uni_stark::verify(&UniConfig(config.clone()), air, proof, &vec![])
}

use p3_air::Air;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;
