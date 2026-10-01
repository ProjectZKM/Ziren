# Patched Crates

Patching a crate means replacing the implementation of a specific interface within the crate with a call to the corresponding zkVM precompile, which reduces the number of cycles, and therefore the proving cost, substantially.

## Supported Crates

The patches are maintained in the [ziren-patches](https://github.com/ziren-patches) organization. The following are used by the examples in the Ziren repository ([`examples/Cargo.toml`](https://github.com/ProjectZKM/Ziren/blob/main/examples/Cargo.toml)):

| **Crate Name**    | **Repository**                                               | **Versions** |
| ----------------- | ------------------------------------------------------------ | ------------ |
| sha2              | `sha2-v0-10-8 = { git = "https://github.com/ziren-patches/RustCrypto-hashes", package = "sha2", branch = "patch-sha2-0.10.8" }` | 0.10.8       |
| curve25519-dalek  | `curve25519-dalek = { git = "https://github.com/ziren-patches/curve25519-dalek", branch = "patch-4.1.3" }` | 4.1.3        |
| secp256k1         | `secp256k1 = { git = "https://github.com/ziren-patches/rust-secp256k1", branch = "patch-0.29.1" }` | 0.29.1 |
| substrate-bn      | `substrate-bn = { git = "https://github.com/ziren-patches/bn", branch = "patch-0.6.0" }` | 0.6.0 |
| rsa               | `rsa = { git = "https://github.com/ziren-patches/RustCrypto-RSA.git", branch = "patch-rsa-0.9.6" }` | 0.9.6        |
| ecdsa             | `ecdsa-core = { git = "https://github.com/ziren-patches/signatures", package = "ecdsa", branch = "patch-ecdsa-0.16.9" }` | 0.16.9       |
| k256              | `k256 = { git = "https://github.com/ziren-patches/elliptic-curves", branch = "patch-k256-0.13.4" }` | 0.13.4       |
| p256              | `p256 = { git = "https://github.com/ziren-patches/elliptic-curves", branch = "patch-p256-0.13.2" }` | 0.13.2       |

The following are used by the Ethereum block prover [reth-processor](https://github.com/ProjectZKM/reth-processor) (patched in [`bin/guest/Cargo.toml`](https://github.com/ProjectZKM/reth-processor/blob/main/bin/guest/Cargo.toml); `kzg-rs` is a workspace dependency in the root `Cargo.toml`), in addition to `substrate-bn`, `k256` and `p256` above:

| **Crate Name**    | **Repository**                                               | **Versions** |
| ----------------- | ------------------------------------------------------------ | ------------ |
| sha2              | `sha2 = { git = "https://github.com/ziren-patches/RustCrypto-hashes", branch = "patch-sha2-0.10.9", package = "sha2" }` | 0.10.9 |
| alloy-primitives  | `alloy-primitives-v1-4-1 = { git = "https://github.com/ziren-patches/core.git", package = "alloy-primitives", branch = "patch-alloy-primitives-1.4.1" }` | 1.4.1 |
| kzg-rs            | `kzg-rs = { git = "https://github.com/ziren-patches/kzg-rs", branch = "patch-0.2.7", default-features = false }` | 0.2.7 |

## Using Patched Crates

There are two approaches to using patched crates.

Option 1: add the patched crate directly as a dependency in the guest program's `Cargo.toml`. For example:

```toml
[dependencies]
sha2 = { git = "https://github.com/ziren-patches/RustCrypto-hashes.git", package = "sha2", branch = "patch-sha2-0.10.8" }
```

Option 2: keep the crates.io dependency and add a patch entry to the guest's `Cargo.toml`. This also replaces the crate when it is a transitive dependency. For example:

```toml
[dependencies]
sha2 = "0.10.8"

[patch.crates-io]
sha2 = { git = "https://github.com/ziren-patches/RustCrypto-hashes.git", package = "sha2", branch = "patch-sha2-0.10.8" }
```

When the crate comes from a git repository rather than crates.io, the patch section must name that source repository. For example:

```toml
[dependencies]
ed25519-dalek = { git = "https://github.com/dalek-cryptography/curve25519-dalek" }

[patch."https://github.com/dalek-cryptography/curve25519-dalek"]
ed25519-dalek = { git = "https://github.com/ziren-patches/curve25519-dalek", branch = "patch-4.1.3" }
```

A patch only takes effect if its version matches the version Cargo resolves. Check that the patched crate appears in `Cargo.lock` with the `ziren-patches` source; Cargo prints a warning for patches it did not use.

## How to Patch a Crate

First, the operation must exist as a zkVM precompile (for example `syscall_keccak_sponge`), with its chip and constraints in Ziren. The available precompiles are listed on the [Precompiles](./precompiles.md) page; since a new precompile needs circuit work, open an issue to request one.

Then replace the crate's implementation with a call to the precompile, under `#[cfg(target_os = "zkvm")]`. For example, Ziren implements [keccak256](https://github.com/ProjectZKM/Ziren/blob/main/crates/zkvm/lib/src/keccak256.rs) with `syscall_keccak_sponge`, and the patched [alloy-primitives](https://github.com/ziren-patches/core/tree/patch-alloy-primitives-1.4.1) uses it for `keccak256`:

```rust
if #[cfg(target_os = "zkvm")] {
    let output = zkm_zkvm::lib::keccak256::keccak256(bytes);
    B256::from(output)
}
```

Finally, patch the crate in the guest as shown above, as [reth-processor](https://github.com/ProjectZKM/reth-processor/blob/main/bin/guest/Cargo.toml) does.
