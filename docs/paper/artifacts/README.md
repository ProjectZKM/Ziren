# Paper evidence

These artifacts describe Ziren `cf0b3742` and transcript profile
`71a49cf2564480354be2cd1b7e0c0bb379720c7c1a07cc6912f676ec54967f69`.
They replace the older soundness report in the ignored working-notes directory.

## Interactive soundness

`soundness-census.toml` is the output of:

```sh
cargo run --release -p zkm-prover --bin soundcalc_census
cargo test --release -p zkm-core-machine committed_stripe_bound_over_both_rounds
```

The census also emits the verifier's fixed 22-variable row cube for both stages.
The stripe test checks bounds admitted by the verifier: 32 preprocessed plus
512 main stripes for core, and 32 plus 32 for the largest recursion class.
`soundness.toml` uses these bounds, the census dimensions and the emitted
schedules. It bounds proofs below the root with the core-machine census and
core schedule; only the final root uses the compress schedule.

Reproduce the report with Python 3.11 or later and the `toml` package:

```sh
git clone https://github.com/ethereum/soundcalc.git /tmp/ziren-soundcalc
git -C /tmp/ziren-soundcalc fetch origin refs/pull/91/head
git -C /tmp/ziren-soundcalc checkout --detach d683f29183d8e831fb0bd8fdb8c39ce8598e43ab
PYTHONPATH=/tmp/ziren-soundcalc python3 docs/paper/artifacts/reproduce_soundness.py
```

The driver explicitly selects Johnson multiplicity 6 for the root's dense
WHIR argument; the pinned loader otherwise selects unique decoding for
JaggedCircuit. The jagged reduction, zerocheck and lookup terms are algebraic
field-size bounds, independent of the decoding regime. The calculator already
includes the final-query error as `fin`; the driver counts it once. It sums
the errors after soundcalc floors each component to integer bits. The example
150-proof tree is an explicit composition example, not a measured tree census.
These results exclude the Fiat–Shamir query factor, function-binding loss,
cross-shard digest and hash-collision terms specified separately in the paper.

## Compressed-proof benchmark

`compressed-proof-benchmark.json` records the exact serialized sizes and five
warm native-verifier timings on the evaluation host. The Fibonacci guest uses
input 500. `VERIFY_VK=true` is set in both the GPU server and client, and the
benchmark asserts that the client's verifier has key checks enabled.

To rebuild the benchmark, copy `compressed_proof_bench.rs` to
`examples/fibonacci/host/bin/paper_bench.rs`, add `bincode = "1.3.3"` to that
host's dependencies, and add this bin entry to its Cargo manifest:

```toml
[[bin]]
name = "paper_bench"
path = "bin/paper_bench.rs"
```

Build from the host directory, then run against the matching GPU server:

```sh
cargo build --release --bin paper_bench
VERIFY_VK=true ZKM_PROVER=cuda CUDA_RUN_DOCKER=false \
CUDA_ENDPOINT=http://127.0.0.1:30560/twirp/ RAYON_NUM_THREADS=24 \
cargo run --release --bin paper_bench
```

The server must also use the regenerated map and `VERIFY_VK=true`. The JSON
records its map hash and root. Proof size measures `ZKMReduceProof`, including
the recursion key; the STARK wire format adds a four-byte enum tag, and the
SDK container additionally carries the public outputs and version. Timings
exclude setup, proving, deserialization and one verifier warmup. The CUDA
backend is private, as disclosed in the paper.

## Lean determinism evidence

The current [Lean archive](https://zkm-toolchain.s3.amazonaws.com/fv/ziren-fv-lean-20261014.tar.gz)
contains 104 theorems across 57 chips and 9,854 split modules. The archive manifest records the runtime revision, generated-source hashes,
checked-source hashes, theorem inventories, module counts and tool inputs.
`validate_lean_archive.py` checks all receipts and diagnostics and compares
every non-proof declaration and public determinism statement with a fresh
extraction of the current AIR. This permits checked derivation scripts to
differ from regenerated proof hints while requiring the same constraints,
gadget relations, inputs, outputs and theorem assumptions.

The archive also includes the external snippet generators and recipes, the
checked split Lean sources, library and toolchain pins, and instructions for
rebuilding all proofs from source.
