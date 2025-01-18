# Prover Architecture

1. Create a program with instruction list;
2. Create a runtime with the executor, and generate the runtime state and event for each instruction;

```
let runtime = tracing::debug_span!("runtime.run(...)").in_scope(|| {
    let mut runtime = Executor::new(program, ZKMCoreOpts::default());
    runtime.maximal_shapes = Some(
        shape_config
            .maximal_core_shapes()
            .into_iter()
            .map(|s| s.inner)
            .collect(),
    );
    runtime.run().unwrap();
}
```

Where the runtime performs each transaction by `execute_cycle` to generate the event for each transaction, and create a `LookupId` for each event.

Unconstained Mode: In this mode, any events, clock, register, or memory changes are reset after leaving the unconstrained block. The only thing preserved is written to the input stream.

3. Create a Machine prover with [Stark config](./stark.md);
4. Run the setup for [PAIR](./arithmetization.md) to generate the preprocessed traces(constant vairables, which is shared by all prover instance for a program), and generate PCS for the traces. A proving key (the traces and prover data(Merkle Tree)) and a verification key (the commit of the traces) are generated.
5. Prove the program:

> Phase 0: Generate checkpoint for each shard;

```rust

let (checkpoint, done) = runtime
    .execute_state(false)
    .map_err(ZKMCoreProverError::ExecutionError)?;


```

> Phase 1: Read the checkpoint, and generate `ExectionRecord` and its trace for each instraction
```rust
trace_checkpoint::<SC>(
    program.clone(),
    &checkpoint,
    opts,
    shape_config,
    ) {

    ...
    let (records, _) = runtime.execute_record(true).unwrap();
    ...
}


/// Execute up to `self.shard_batch_size` cycles, returning the events emitted and whether the
/// program ended.
///
/// # Errors
///
/// This function will return an error if the program execution fails.
pub fn execute_record(
    &mut self,
    emit_global_memory_events: bool,
) -> Result<(Vec<ExecutionRecord>, bool), ExecutionError> {
    self.executor_mode = ExecutorMode::Trace;
    self.emit_global_memory_events = emit_global_memory_events;
    self.print_report = true;
    let done = self.execute()?;
    Ok((std::mem::take(&mut self.records), done))
}

```

Now we can generate_traces for each chip.

> Phase 2: Collect the public values and commit to each shard.

## Machine Prover/VM Prover


## Aggregation Prover


## Compression Prover
