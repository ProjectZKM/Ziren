# Patched Crates

Patching a crate refers to replacing the implementation of a specific interface within the crate with a corresponding zkVM precompile, which can achieve significant performance improvements.

## Supported Crates

| **Crate Name**        | **Repository**                                               | **Notes**      | **Versions** |
| ----------------- | ------------------------------------------------------------ | -------------- | ------------ |
| revm-primitives/k | [zkMIPS/revm](https://github.com/zkMIPS/revm)                | keccak256      | 6.0.0        |
| sha2              | [zkMIPS-patches/RustCrypto-hashes](https://github.com/zkMIPS-patches/RustCrypto-hashes) | sha256         | 0.10.8       |
| curve25519-dalek  | [zkMIPS-patches/curve25519-dalek](https://github.com/zkMIPS-patches/curve25519-dalek) | ed25519 verify | 4.1.3        |
| rsa               | [zkMIPS-patches/RustCrypto-RSA](https://github.com/zkMIPS-patches/RustCrypto-RSA) | RSA            | 0.9.6        |

## Using Patched Crates

There are two approaches to using patched crates:

Option 1: Directly add the patched crates as dependencies in the guest program's `Cargo.toml`. For example:

```
[dependencies]
sha2 = { git = "https://github.com/zkMIPS-patches/RustCrypto-hashes.git", package = "sha2", branch = "patch-sha2-v0.10.8" }
```

Here is a example: a

Option 2: Add the appropriate patch entries to your guest's `Cargo.toml`. For example:

```
[dependencies]
sha2 = "0.10.8"

[patch.crates-io]
sha2 = { git = "https://github.com/zkMIPS-patches/RustCrypto-hashes.git", package = "sha2", branch = "patch-sha2-v0.10.8" }
```

When patching a crate from a GitHub repository rather than crates.io, you need to explicitly declare the source repository in the patch section. For example:

```
[dependencies]
ed25519-dalek = { git = "https://github.com/dalek-cryptography/curve25519-dalek" }

[patch."https://github.com/dalek-cryptography/curve25519-dalek"]
ed25519-dalek = { git = "https://github.com/zkMIPS-patches/curve25519-dalek", branch = "patch-curve25519-v4.1.3" }
```

## How to Patch a Crate

First, implement the target precompile in zkVM (e.g., `syscall_keccak_sponge`) with full circuit logic. Given the implementation complexity, we recommend submitting an issue for requested precompiles.

Then replace the target crate's existing implementation with the zkVM precompile (e.g., `syscall_keccak_sponge`). For example, we have reimplemented [keccak256](https://github.com/zkMIPS/zkm2/blob/dev/init/crates/zkvm/lib/src/keccak256.rs) by `syscall_keccak_sponge`, and use this implementation to replace `keccak256` in the revm crate.

```rust
use zkm2_zkvm::lib::keccak256::keccak256 as keccak256_zkvm;

// Define the keccak256 function
#[inline]
pub fn keccak256<T: AsRef<[u8]>>(bytes: T) -> B256 {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "zkvm")] {
            let output = keccak256_zkvm(bytes.as_ref());
            B256::from(output)
        } else {
            keccak256_alloy(bytes)
        }
    }
}
```

Finally, we can use the new `keccak256` in the [revme guest lib](https://github.com/zkMIPS/revme/blob/cbor-zkm2/guest/src/lib.rs), which the [revme guest](https://github.com/zkMIPS/zkm2/tree/dev/init/examples/revme/guest) depends on.
