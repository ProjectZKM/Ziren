# Poseidon2 round change: what has to be regenerated

The permutation changed from 8 full + 13 partial rounds to 8 full + 20 partial
(Ziren `b54a0347`, ziren-gpu `6ff4278`). Plonky3's `poseidon2_round_numbers_128` gives (8, 20)
for a 31-bit prime at width 16 with S-box degree 3 and (8, 13) at degree 7; KoalaBear is degree
3, so 13 was the BabyBear number on a KoalaBear permutation.

**This changes every hash the system computes.** The transcript, the Merkle commitments, the
public-values digests and the in-circuit recursion hash all move, so every verifying key moves
with them. Nothing below is optional before the change can be deployed.

## What is stale

| Artifact | Why |
|---|---|
| `crates/prover/vk_map.bin` | every recursion verifying key changed |
| `crates/verifier/bn254-vk/vk_root.bin` | the allowlist root is a function of that map, and is now a public input of the wrap circuit |
| `crates/prover/scripts/artifacts/*.bin` | collected keys from earlier runs |
| `crates/prover/proof-with-pis.bin` | fixture proof under the old hash |
| `crates/prover/scripts/write_basefold_vk_map.rs` | hardcoded key hashes, including one for the fibonacci test ELF, which itself changed |
| `crates/verifier/bn254-vk/*.bin` | the wrap circuit's constraint system changed: the recursion Poseidon2 chip is 14 columns wider |
| the gnark Groth16 and PLONK circuit artifacts | same reason; they are built over the frozen shrink shape |
| the GPU build | kernels carry the round count and the baked constants |

Key verification defaults to on and the map is compiled in with `include_bytes!`, so until the
map is regenerated every recursion proof is rejected and a miss is a hard panic. Run any
validation with `VERIFY_VK=false`; the collected digests are identical either way, only the
leaf-index lookup differs.

## Order of operations

1. **Rebuild the GPU prover.** Move ziren-gpu's pinned Ziren revision to a commit that includes
   the round change and rebuild the CUDA. The generated recursion header takes the round count
   from cbindgen, so it follows automatically; the hash kernel's constants and the tracegen
   macro do not, and were changed by hand in `6ff4278`.
2. **Validate the permutation end to end** before spending anything on keys. The cheap gate is
   `cargo test --release -p zkm-recursion-core poseidon2`, which proves the recursion machine
   and compares the chip against the host permutation. Then a
   `VERIFY_VK=false` core-to-wrap run.
3. **Collect the keys rather than enumerating them.** A full regeneration is about fifteen
   hours and still misses shapes real workloads reach. Set `ZIREN_VK_COLLECT=<path>` and prove
   the workloads that matter; every recursion key the prover actually touches is written in the
   map's wire format. Merge with the `merge_vk_maps` binary.
4. **Regenerate the pinned allowlist root** once the map is final:
   `cargo run -p zkm-prover --bin write_vk_root --release`. It is a public input of the wrap
   circuit and is baked into the generated Solidity verifier, so it has to be right *before*
   the artifacts are built, not after.
5. **Rebuild the gnark artifacts** over the new shrink shape, and publish them under a new
   circuit version so no client mixes old and new. The wrap circuit now has three public
   inputs rather than two, so the verifier contract's ABI changes and existing deployments
   cannot verify new proofs.
6. **Only then** consider the block-proving service. Do not deploy a prover whose key map, GPU
   build and circuit artifacts are not all from the same revision.

## Keeping the seven sites in step

The round count appears in four places in Ziren and three in ziren-gpu, and they must agree or
the circuits prove a different permutation than the transcript and the trees use.

- Ziren: `zkm_primitives::poseidon2_init`, `zkm_pcs::koala_bear_poseidon2::my_perm`, the core
  machine's `operations::poseidon2::NUM_INTERNAL_ROUNDS`, and the recursion
  `chips::poseidon2_wide::NUM_INTERNAL_ROUNDS`.
- ziren-gpu: `core/src/poseidon2/koala_bear.rs` `ROUNDS_P`, the `P2_INT_ROUNDS` macro in
  `cuda/tracegen/core.cuh`, and the baked Montgomery arrays in
  `cuda/hashes/poseidon2/poseidon2_kb31_16.cuh`.

The constant table `RC_16_30` has 30 rows, so 28 rounds still fit. The layout is: external
first half from rows 0 to 4, internal from rows 4 to 4+P taking element 0 of each, external
second half from rows 4+P to 8+P. The kernel's arrays hold those values in Montgomery form,
that is the value times 2^32 reduced modulo p.
