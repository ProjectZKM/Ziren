# Patched Crates

Patching a crate refers to replacing the implementation of a specific interface within the crate with a corresponding zkVM precompile, which can achieve significant performance improvements.

## Supported Crates

| **Crate Name**        | **Repository**                                               | **Versions** |
| ----------------- | ------------------------------------------------------------ | ------------ |
| revm | `revm = { git = "https://github.com/zkMIPS/revm", branch = "zkm" }` | 6.0.0        |
| sha2              | `sha2-v0-10-8 = { git = "https://github.com/zkMIPS-patches/RustCrypto-hashes", package = "sha2", branch = "patch-sha2-0.10.8" }` | 0.10.8       |
| curve25519-dalek  | `curve25519-dalek = { git = "https://github.com/zkMIPS-patches/curve25519-dalek", branch = "patch-4.1.3" }` | 4.1.3        |
| curve25519-dalek-ng | `curve25519-dalek-ng = { git = "https://github.com/zkMIPS-patches/curve25519-dalek-ng", branch = "patch-4.1.1" } ` | 4.1.1 |
| secp256k1 | `secp256k1 = { git = "https://github.com/zkMIPS-patches/rust-secp256k1", branch = "patch-0.29.1" }` | 0.29.1 |
| substrate-bn | `substrate-bn = { git = "https://github.com/zkMIPS-patches/bn", branch = "patch-0.6.0" }` | 0.6.0 |
| rsa               | `rsa = { git = "https://github.com/zkMIPS-patches/RustCrypto-RSA.git", branch = "patch-rsa-0.9.6" }` | 0.9.6        |

## Using Patched Crates

There are two approaches to using patched crates:

Option 1: Directly add the patched crates as dependencies in the guest program's `Cargo.toml`. For example:

```
[dependencies]
sha2 = { git = "https://github.com/zkMIPS-patches/RustCrypto-hashes.git", package = "sha2", branch = "patch-sha2-0.10.8" }
```

Option 2: Add the appropriate patch entries to your guest's `Cargo.toml`. For example:

```
[dependencies]
sha2 = "0.10.8"

[patch.crates-io]
sha2 = { git = "https://github.com/zkMIPS-patches/RustCrypto-hashes.git", package = "sha2", branch = "patch-sha2-0.10.8" }
```

When patching a crate from a GitHub repository rather than crates.io, you need to explicitly declare the source repository in the patch section. For example:

```
[dependencies]
ed25519-dalek = { git = "https://github.com/dalek-cryptography/curve25519-dalek" }

[patch."https://github.com/dalek-cryptography/curve25519-dalek"]
ed25519-dalek = { git = "https://github.com/zkMIPS-patches/curve25519-dalek", branch = "patch-4.1.3" }
```

## How to Patch a Crate

First, implement the target precompile in zkVM (e.g., `syscall_keccak_sponge`) with full circuit logic. Given the implementation complexity, we recommend submitting an issue for requested precompiles.

Then replace the target crate's existing implementation with the zkVM precompile (e.g., `syscall_keccak_sponge`). For example, we have reimplemented [keccak256](https://github.com/zkMIPS/zkMIPS/blob/main/crates/zkvm/lib/src/keccak256.rs) by `syscall_keccak_sponge`, and use this implementation to replace `keccak256` in the [core](https://github.com/alloy-rs/core/compare/main...zkMIPS-patches:core:patch-alloy-primitives-1.0.0) crate.

```rust
if #[cfg(target_os = "zkvm")] {
    let output = zkm_zkvm::lib::keccak256::keccak256(bytes);
    B256::from(output)
}
```

Finally, we can use the patched crate [core](https://github.com/zkMIPS-patches/core/tree/patch-alloy-primitives-1.0.0) in the [reth-processor](https://github.com/zkMIPS/reth-processor/blob/main/bin/guest/Cargo.toml#L27).
