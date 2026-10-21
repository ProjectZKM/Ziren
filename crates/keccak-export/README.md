# KoalaBear / Keccak terminal

This optional package owns the compact proof codec, trusted verifier-data export,
Solidity verifier and Python/Yul compiler. PCS and prover code do not depend on it.
Application settlement contracts, chain adapters and approved deployment profiles
belong in the consuming application (for example, zkOP).

Enable `zkm-pcs/keccak-terminal` for the terminal ring and
`zkm-prover/keccak-terminal` for `shrink_keccak`, `verify_shrink_keccak` and
`keccak_terminal_prover`. The existing shrink computation verifies the compressed
Poseidon2 proof. Its final host commitments and transcript use Keccak-256;
Keccak is not computed inside a KoalaBear AIR. Existing Groth16/PLONK paths are
unchanged. This terminal is not an input to an existing recursion circuit.

## Trust and parameter boundaries

The terminal ring fixes folds `[1,3,4,4,4]`, queried inverse-rate logs
`[4,6,8,10,12]`, Johnson multiplicity 3, component query target 106 and grinding
27. At stacking log 21 this resolves to queries `[45,29,21,17,14]` and a final
polynomial of 32 coefficients. No terminal environment variable or submitted
proof selects a schedule. `KeccakWhirParameters::resolve` validates geometry and
solves query counts; it is not a complete soundness or quantum-security proof.
In particular, folding, stripe batching, OOD, union bounds and Fiat–Shamir
security need independent review against the deployment's security target.
Inherited child/GKR parameters retain current Ziren behavior and are bound in
the terminal key ID. Custom parameter resolution does not change the ring's
fixed version-one schedule.

The caller supplies an independently approved terminal key ID, application key
and public values. Terminal verification requires recursion-key admission to be
enabled, authenticates the recursion root and complete successful execution,
and checks the entire public-values digest. Key IDs use the version-two domain,
canonical integers, resolved parameters and the complete child transcript
profile; historical staging key IDs must be regenerated. The port preserves
current main's leaf global-sum binding and key admission. No fixture helper
extends the production recursion-key map.

`wire::Profile::from_trusted_proof` is a low-level setup API: it requires an
already authenticated reference and trusted key. Its result is deployment
configuration, never submission data. The `machine` feature enables
`machine::export`, which verifies the reference against the caller's trusted
key ID, application and public values before exporting symbolic AIR, key data
and a fixed wire schema. Unsupported AIR operations fail export. Symbolic AIR
is compared against the native folder on the reference and independent rows.
Proof-dependent field/hash values remain wire inputs; they cannot authorize
the verifier program, key, geometry or contract modules.

## Verification and deployment

See [Solidity tooling](solidity/README.md). An independently approved symbolic
program compiles into immutable Yul kernels and a Solidity entry point, WHIR
tail and math helpers. Deployment can use several creation transactions to
respect per-contract code and initcode limits. The entry pins module code and
order; one submitted proof is verified in one transaction using `STATICCALL`.
No optimistic execution or persisted partial verification is introduced.

The compact transport removes repeated full hashes and zero field runs without
truncating hashes or skipping proof equations. Rust `wire::Mode::{Raw,Shared,Dag}`
are native codec modes 0/1/2. The generated EVM's outer transports 2 (dictionary)
and 3 (zero runs plus dictionary) restore an approved **raw** packet. EVM mode 2
is not Rust DAG mode 2. Use `solidity/native/transport.py` for the outer codec;
do not interchange those namespaces.

## Validation and release gate

Unit tests fix canonical field bytes, transcript answers, root projection,
terminal key identity, schedule geometry and codec arithmetic. Full proving is
an explicit ignored integration test using the normal admitted key map. Tests
and benchmarks write artifacts outside the checkout.

```sh
CARGO_TARGET_DIR="$EXTERNAL_TARGET" cargo test -p zkm-pcs \
  --features keccak-terminal --lib kb31_keccak
CARGO_TARGET_DIR="$EXTERNAL_TARGET" cargo test -p zkm-keccak-export --lib
# Point ZIREN_KECCAK_TEST_ELF at an independently approved Fibonacci guest ELF.
CARGO_TARGET_DIR="$EXTERNAL_TARGET" cargo test --release -p zkm-keccak-export \
  --features machine --test terminal -- --ignored
```

The imported native-verifier regressions use an independently approved
historical Fibonacci(10) fixture from revision
`f6137ecc9b0a1b8ba5d89224d51419dca98649d0`. That fixture previously verified at
16,666,725 gas with 224,478 submitted proof bytes and 597,513 total runtime
bytes across 52 contracts. These are historical measurements, not current-main
gas guarantees, Metis execution results or mainnet deployment evidence.

Before production use: regenerate admitted current-version reference proofs
and verifier data, compile and compare every Rust/Python/EVM checkpoint,
retest actual capped transactions and deployment sizes, and review security
parameters and the cryptographic/compiler trust boundary. Do not reuse a
historical fixture's key-map additions or deployed profile as current setup.
