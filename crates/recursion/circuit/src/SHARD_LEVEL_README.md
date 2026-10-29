# Shard-Level (SP1-style) Recursion Circuit Modules

Parallel-codebase modules under the `shard-level-proof` feature
flag.  Bridge the host-side `JaggedShardProof` (from
`zkm_pcs::shard_level`) into the in-circuit
`JaggedShardProofVariable` and dispatch to
`JaggedShardVerifier::verify_shard`.

## Module map

| Module | Purpose |
|---|---|
| `shard_level_witness` | Witnessable impls for the SP1-style stark-side proof types |
| `shard_proof_variable_lift` | Type-lift adapters: stark-side → recursion-circuit-side |
| `jagged_pcs_lift` | Bytes → JaggedPcsProofVariable adapter |
| `machine::compress_jagged` | Compress-stage SP1-style verifier (full body wired) |
| `machine::deferred_jagged` | Deferred-stage SP1-style verifier (full body wired) |
| `machine::wrap` | Wrap-stage SP1-style verifier (full body wired) |
| `machine::core_jagged` | Core-stage SP1-style verifier (full body wired) |

## Enabling the feature

```toml
zkm-recursion-circuit = { ..., features = ["shard-level-proof"] }
```

## Status

All four recursion machine bodies invoke
`JaggedShardVerifier::verify_shard` end-to-end.  Closures
(`noop_eval_public_values_fn`, `placeholder_jagged_evaluator_fn`)
are placeholders for compilation; production wiring requires
machine-specific constraint folder closures.

See `docs/sp1_shard_proof_port_status.md` for full port history.
