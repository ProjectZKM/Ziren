# Proof Composition

A guest program can verify other Ziren proofs. The guest states which proofs it relies on, and the recursion tree checks them as *deferred* proofs, so the guest does not run a STARK verifier inside the MIPS machine.

## Use cases

- **Aggregation.** Combine many independent proofs, for example of blocks or transactions, into one proof.
- **Modular programs.** Split an application into programs that are proved separately and composed, so that one part can change without re-proving the rest.
- **Pipelining.** Prove the parts of a long computation in parallel and join them in a final program.

## Interface

In the guest, with the `verify` feature of `zkm-zkvm`:

```rust
zkm_zkvm::lib::verify::verify_zkm_proof(&vk_digest, &public_values_digest);
```

`vk_digest: &[u32; 8]` is the digest of the inner program's verifying key, and `public_values_digest: &[u8; 32]` is the digest of its public values. The call does not verify anything by itself. It issues the `VERIFY_ZKM_PROOF` syscall (`0x1B`) and folds the pair into the guest's running deferred-proof digest:

\\[ D \leftarrow \mathrm{Poseidon2}(D, \mathit{vk\\_digest}, \mathit{pv\\_digest}), \qquad D_0 = 0. \\]

When the guest halts, it commits \\( D \\) word by word with the `COMMIT_DEFERRED_PROOFS` syscall. The `SyscallInstrs` chip checks each word against the shard's public `deferred_proofs_digest`.

On the host, the inner proofs must be compressed proofs (`ZKMReduceProof`). They are passed in with the input, in the order the guest verifies them:

```rust
stdin.write_proof(inner_proof, inner_vk);
```

During execution, each `VERIFY_ZKM_PROOF` call takes the next proof from this list, and unless deferred-proof verification is disabled in the executor options, the executor checks it against the call's `(vk_digest, pv_digest)`. This check only reports errors early; soundness comes from the recursion.

## How the recursion checks it

`compress` passes the inner proofs to the *deferred* program in batches (`get_recursion_deferred_inputs_basefold`). For each batch, the deferred program:

1. verifies each inner compressed proof, including the Merkle proof that its verifying key is in the recursion key set;
2. requires each proof to be complete;
3. folds each proof's verifying-key digest and committed-value digest into the reconstructed digest with the same Poseidon2 hash, starting from the previous batch's value.

Deferred batches are placed in the shard range after the last execution shard, so the compose programs join them to the execution like any other range and chain `start_reconstruct_deferred_digest` to `end_reconstruct_deferred_digest`. At the root, `assert_complete` requires the reconstruction to start at zero and to end at the `deferred_proofs_digest` the guest committed. A guest that claims a proof the prover did not supply, or a different one, therefore produces a digest that the reconstruction cannot match.

## Verification

The outer proof is verified like any other Ziren proof, against the outer program's verifying key. Its public values are only the outer guest's. The inner proofs and their public values are bound through the deferred digest and are not needed by the verifier.
