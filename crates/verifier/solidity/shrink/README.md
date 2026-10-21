# Shrink verification libraries

Reusable field arithmetic, Keccak transcript, WHIR verification, compact packet
decoding and immutable module-binding Solidity sources live here. Ziren owns
these libraries alongside its proof verification integrations.

ProjectZKM/zkOP owns the consumer calldata codec/exporter, Python/Yul compiler,
profile-specific generated entry/modules, deployment configuration and local
measurements. The generator must use sources compatible with its pinned Ziren
revision and independently approved verifier data. Proofs, generated contracts,
bytecode and benchmark artifacts stay outside tracked source files.

The current Solidity backend implements the Keccak-256 compact proof protocol.
SHA-256 and BLAKE3 support in the Rust shrinker does not imply support in these
libraries or the consumer generator. The interpreted reference verifier is for
conformance and can exceed Ethereum limits; deployment requires separately
measured generated modules and application-approved code/profile identities.
