# Compact shrinker

`CompactShrink<Suite>` proves the compressed-proof verification computation over
KoalaBear and its quartic extension. The suite chooses byte-hash commitments,
the transcript, digest projection and their versioned domains. It does not name
a consumer or require the proof to be the last step of a recursion chain.

```rust,ignore
let proof = prover.shrink_with::<CompactShrink<Keccak256Suite>>(compressed, opts)?;
let proof = prover.shrink_with::<CompactShrink<Sha256Suite>>(compressed, opts)?;
let proof = prover.shrink_with::<CompactShrink<Blake3Suite>>(compressed, opts)?;
```

All three suites share the canonical LE32 field encoding and uniform 31-bit
rejection sampling used by this compact configuration. A suite includes the
transcript initialization/domain and absorb boundary; a hash function name
alone does not specify a compatible proof protocol. Existing Keccak transcript
and root-projection domain bytes are preserved by the API refactor. New SHA-256
and BLAKE3 suites have independent versioned domains. The new BLAKE3 suite is
not wire/transcript-compatible with the historical research `KoalaBearBlake3`
ring, which used a different sampler, initial state and digest projection.

The common compact WHIR profile resolves to folds `[1,3,4,4,4]`, queried inverse
rate logs `[4,6,8,10,12]` and query counts `[45,29,21,17,14]` at stacking log 21.
`CompactWhirParameters::resolve` is a geometry/query-count solver, not a complete
security proof. Production parameter approval must cover all components and
their union, including batching cardinality and the Fiat–Shamir compilation.
Consumer-specific tuning needs a separately approved immutable profile; it
cannot be selected by a submitted proof.

The default `shrink` and its frozen wrap-compatible shape remain unchanged.
`shrink_with` builds the same verifier computation without inheriting that
Groth16-wrap shape policy. Its actual key geometry is part of independently
approved setup. No key-map additions or membership bypasses are installed.

## Trusted verification and adapters

`ShrinkVerifierData<Suite>::from_trusted_key` snapshots an independently approved
setup key. Never construct the expected verifier data from a submitted proof.
`verify_shrink_with` authenticates the key, application, recursion root, complete
successful execution and full public-values digest. The version-three key ID
binds the suite ID, all suite domains, absorb boundary, resolved configuration,
child transcript profile and canonical key geometry. Exported profiles and key
IDs from the earlier PR version must be regenerated; this descriptor change
does not alter the Keccak transcript known-answer vectors.

`zkm_prover::shrink::adapter` defines a typed `BinaryAdapterBackend<Suite>` input
boundary. `adapt_shrink_binary` first verifies the compact proof, passes an
immutable `VerifiedShrink` containing trusted verifier data and statement to a
supported backend, then verifies the backend output against independently
approved binary verifier data and the same statement.

The backend MUST prove the complete compact-verifier relation, including key,
profile, application and public-value binding. Native verification is an input
check, not a substitute for that relation. The binary proof uses its own field,
PCS and hash suite; the input and output hash suites need not match. Only
backends implementing the exact input suite can implement that specialization.

The historical binary WHIR engine is not present on current main and relies
on another Plonky3 revision. This interface does not restore that engine or
claim that old verifier tapes accept the new compact BLAKE3 proof. Its concrete
backend port and new native/circuit/binary/GC conformance proofs are separate
integration gates. GC tape generation belongs to the GC consumer repository.

## Ownership and validation

Ziren owns the shrinker, suites, typed proof/key APIs, adapter boundary and
reusable Solidity primitives in `crates/verifier/solidity/shrink`. The compact
calldata codec, exporter and Python/Yul compiler live in ProjectZKM/zkOP's
`crates/shrink-export` and `contracts/keccak-wire`. PCS/prover depend on neither
exporter nor consumer package.

Suite tests prove and verify small multi-round WHIR components for all three
hashes, reject relabeled cross-suite proofs, changed claims/leaves/final
polynomials and surplus messages, and check trusted descriptor identity. They
do not replace full current-version core/compress/shrink production proving,
security review, actual transaction-cap measurements or binary/GC integration.
