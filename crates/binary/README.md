# Binary proof engine on current Ziren

This optional workspace package proves recursion-VM executions over GF(2^128), using Boolean WHIR and BLAKE3. `zkm-binary-recursion` records that verifier and can prove its recording as a narrower binary execution. Neither package is a dependency of the default Ziren prover.

The port starts from Ziren's current recursion implementation (`a26a53d59718b192ae29919864fd7be7055030fe`, including the global-sum and leaf-binding fixes), plus the shared compact-shrinker API. It restores the engine from research revision `f6137ecc9b0a1b8ba5d89224d51419dca98649d0`; it does not restore that revision's recursion circuits or replace current main with the research branch.

## Dependency boundary

| Component | Plonky3 revision | Types |
| --- | --- | --- |
| Existing Ziren prover, PCS and recursion VM | `4dd0d47a8176503fbaa7293c9f0e3b20004e16b2` | Current KoalaBear and E4 |
| Experimental binary AIRs, PCS and recorded verifier | `fb5d0d8976dcc6b94d11f08de98be0f285450020` | GF(2^128), binary tables and WHIR |

`p3-field-current` imports the VM's canonical-word traits at the boundary. There is no field-element transmute between revisions. The engine reads current `RecursionProgram<KoalaBear>` and `ExecutionRecord<KoalaBear>` values and constrains their arithmetic as bits. The standalone Plonky3 example harness is not a dependency.

## Proving and verification

1. Construct the verifier program from independently approved setup.
2. Construct `RecursionMachine::new(&program, &schedule)`. Its preprocessed tables commit the program's addresses, operations, constants and read multiplicities.
3. Execute that same program with the current recursion runtime.
4. Prove the execution with `machine.prove(&record)`.
5. Verify against the independently retained machine and expected digest with `machine.verify(&proof, &digest)`.

A submitted proof must not choose its verifier program. The eight public digest words must be canonical KoalaBear values; verification rejects noncanonical words before binary packing. Canonical byte codecs and consumer deployment/export remain separate from this engine.

Supported constrained operations include base/E4 arithmetic, selection, memory, BLAKE3 compression, canonical limb decomposition, Poseidon2 and digest commitment. Poseidon2 tables are included only when the program uses that operation. They allow a future compact adapter to retain current Ziren's public-value digest check; carrying an unchecked child digest is not an acceptable substitute. Unsupported constrained VM instructions are explicitly refused.

The new BLAKE3 and limb instructions are appended to the instruction enum, preserving existing instruction discriminants. Runtime event records and event counts gain fields; persisted records/programs are internal versioned data, and consumers must regenerate binary programs rather than load historical research records as current ones.

## Compact-shrinker integration status

The shared API is `CompactShrink<Suite>`, with a typed `BinaryAdapterBackend<Suite>` boundary in `zkm-prover`. **This engine port does not yet implement that trait or prove a new compact proof end to end.** In particular, the old `KoalaBearBlake3` verifier circuit cannot be reused unchanged:

- the compact BLAKE3 suite has versioned transcript and root domains;
- its absorb cap is 100 bytes;
- field challenges use exact 31-bit rejection sampling;
- root projection hashes the full root under its domain before field reduction;
- input-key metadata and the complete application/public-value statement must be bound;
- current public-value digest recomputation must remain constrained.

The rejection-sampling frontend must constrain every rejected candidate and the first accepted candidate under an independently approved program/key. A host-recorded rejection pattern must not let the submitted proof select its verifier program.

The input suite and binary output suite are independent. Keccak/SHA-256 input gadgets are separate work; the output engine currently uses BLAKE3. The historical carried-digest circuit, 64-bit modular sampler and truncated-root projection are deliberately absent.

GC-specific tape export and compilation belong in `bitcoin-stark-verifier`. No current-main level-4 workload, one-hour GC verification result, production PQ-security claim, Ethereum cost or Metis integration is established by these small engine tests. The binary schedule's security reporting is the upstream research implementation's model and still needs review for the final composed construction. The machine enforces the grinding ceiling; query and transport-byte budget checks are not yet a deployment gate.

## Validation

Keep all build/proof/benchmark output outside the repository:

```sh
export CARGO_TARGET_DIR=/path/outside/Ziren/binary-target
cargo test --locked --release -p zkm-binary-stark -p zkm-binary-recursion
cargo test --locked --release -p zkm-recursion-core existing_instruction_discriminants_are_unchanged
cargo clippy --locked -p zkm-binary-stark -p zkm-binary-recursion --tests -- -D warnings
```

Size/schedule sweeps remain ignored tests. The normal suite includes genuine WHIR proofs, corrupted arithmetic/hash/limb/public-value rejection, native-versus-recorded verifier checks and a small narrow-recursion round trip. Generated artifacts are not tracked.
