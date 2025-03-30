# STARK Aggregation

ZKM2's STARK aggregation system decomposes program proofs into parallelizable segment proofs and recursively compresses them into a single STARK proof. 

## Segment Proof Generation

Parallel generation of execution trace proofs for program segments follows these procedures:

- Splits program execution (ELF binaries) into segments (fixed-size batches).
- Transform program executions in each segment into constrained execution traces.
- Commit and prove the trace polynomials and constraint polynomials with STARK. 

The prove_core `prove_core` function generates segment proofs from input ELF files and data.

In this function, the program executable (in ELF format) is first converted into a program format. The core prover then generates segment proofs corresponding to different execution segments.  

```rust
pub fn prove_core<'a>(
        &'a self,
        pk: &ZKMProvingKey,
        stdin: &ZKMStdin,
        opts: ZKMProverOpts,
        mut context: ZKMContext<'a>,
    ) -> Result<ZKMCoreProof, ZKMCoreProverError> {
        context.subproof_verifier = Some(self);
        let program = self.get_program(&pk.elf).unwrap();
        let pk = self.core_prover.pk_to_device(&pk.pk);
        let (proof, public_values_stream, cycles) =
            zkm2_core_machine::utils::prove_with_context::<_, C::CoreProver>(
                &self.core_prover,
                &pk,
                program,
                stdin,
                opts.core_opts,
                context,
                self.core_shape_config.as_ref(),
            )?;
        Self::check_for_high_cycles(cycles);
        let public_values = ZKMPublicValues::from(&public_values_stream);
        Ok(ZKMCoreProof {
            proof: ZKMCoreProofData(proof.shard_proofs),
            stdin: stdin.clone(),
            public_values,
            cycles,
        })
```

## Recursive Aggregation

Recursive aggregations are used to recursively compress multiple segment proofs into one.

### Preparing Recursive Aggregation Inputs

The helper function `get_first_layer_inputs` converts segment proofs into a recursive format.

The function processes core segment proofs and any deferred proofs (if present), converting them into a recursive-aggregator-compatible format. These inputs are first categorized into ​core/deferred types, then merged into a unified vector that initiates the aggregation process.

```rust
pub fn get_first_layer_inputs<'a>(
        &'a self,
        vk: &'a ZKMVerifyingKey,
        shard_proofs: &[ShardProof<InnerSC>],
        deferred_proofs: &[ZKMReduceProof<InnerSC>],
        batch_size: usize,
    ) -> Vec<ZKMCircuitWitness> {
        let is_complete = shard_proofs.len() == 1 && deferred_proofs.is_empty();
        let core_inputs =
            self.get_recursion_core_inputs(&vk.vk, shard_proofs, batch_size, is_complete);
        let last_proof_pv = shard_proofs.last().unwrap().public_values.as_slice().borrow();
        let deferred_inputs =
            self.get_recursion_deferred_inputs(&vk.vk, last_proof_pv, deferred_proofs, batch_size);

        let mut inputs = Vec::new();
        inputs.extend(core_inputs.into_iter().map(ZKMCircuitWitness::Core));
        inputs.extend(deferred_inputs.into_iter().map(ZKMCircuitWitness::Deferred));
        inputs
    }
```

### Aggregation Proof Generation

The `compress` function recursively aggregates proofs using multi-threading.

The aggregation engine employs recursive composition to merge fragmented proofs through multi-threaded processing with synchronized channels. This hierarchical approach maintains proof validity and execution order integrity, ultimately producing a unified STARK proof that encapsulates the complete program execution. 

```rust
pub fn compress(
    &self,
    vk: &ZKMVerifyingKey,             
    proof: ZKMCoreProof,              
    deferred_proofs: Vec<ZKMReduceProof<InnerSC>>, 
    opts: ZKMProverOpts,              
) -> Result<ZKMReduceProof<InnerSC>, ZKMRecursionProverError> {
    // Sets up multi-threaded channels and synchronization logic
    let first_layer_inputs = self.get_first_layer_inputs(
        vk,
        &leaf_challenger,
        segment_proofs, // Renamed: shard→segment
        &deferred_proofs,
        first_layer_batch_size,
    );
    
    ... // Processes batches recursively
    Ok(ZKMReduceProof { vk, proof })
}
```

The system generates multiple ​segment proofs and aggregates them into a single STARK proof.