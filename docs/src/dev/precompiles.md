# Precompiles

Precompiles are operations, mostly cryptographic, that Ziren proves with a dedicated chip instead of executing them as MIPS instructions. A precompile call costs one `syscall` instruction plus rows in the precompile's own table, far fewer cycles than the same operation compiled to MIPS code. Hashing, signature verification and pairing-based cryptography in a guest should therefore go through the precompiles, usually via a [patched crate](./patched-crates.md).

Within the zkVM, precompiles are invoked with the MIPS `syscall` instruction. Register `$v0` holds the system call code, and `$a0` and `$a1` hold the arguments, usually pointers to the operands in memory. The result is written back in place, to the memory the first argument points to.

## Specification

A system call code is a 32-bit integer with the following little-endian layout:

| Byte 0 | Byte 1 | Byte 2 | Byte 3 |
| ------ | ------ | ------ | ------ |
|   ID0  |  ID1   | Table  | Cycles |

- Bytes 0 and 1 are the system call identifier.
- Byte 2 is 1 if the system call is proved in its own chip table, and 0 otherwise.
- Byte 3 is the number of additional cycles the system call takes, which bounds its memory accesses.

The system calls and precompiles, from [`crates/core/executor/src/syscalls/code.rs`](https://github.com/ProjectZKM/Ziren/blob/main/crates/core/executor/src/syscalls/code.rs):

| Syscall | Code | Operation |
|---|---|---|
| `HALT` | `0x00_00_00_00` | Halts the program with an exit code. |
| `WRITE` | `0x00_00_00_02` | Writes to a file descriptor (stdout, stderr, hooks). |
| `ENTER_UNCONSTRAINED` | `0x00_00_00_03` | Enters unconstrained execution. |
| `EXIT_UNCONSTRAINED` | `0x00_00_00_04` | Exits unconstrained execution. |
| `COMMIT` | `0x00_00_00_10` | Commits a word of the public values digest. |
| `COMMIT_DEFERRED_PROOFS` | `0x00_00_00_1A` | Commits a word of the deferred proofs digest. |
| `VERIFY_ZKM_PROOF` | `0x00_00_00_1B` | Verifies a Ziren proof (deferred to recursion). |
| `SYSHINTLEN` | `0x00_00_00_F0` | Returns the length of the next input. |
| `SYSHINTREAD` | `0x00_00_00_F1` | Reads the next input into memory. |
| `SYSVERIFY` | `0x00_00_00_F2` | Verifies a Ziren proof (Go runtime). |
| `SHA_EXTEND` | `0x30_01_00_05` | SHA-256 message schedule extension. |
| `SHA_COMPRESS` | `0x01_01_00_06` | SHA-256 compression. |
| `KECCAK_SPONGE` | `0x01_01_00_09` | Keccak-256 sponge over a padded input. |
| `POSEIDON2_PERMUTE` | `0x00_01_00_30` | Poseidon2 permutation over KoalaBear. |
| `ED_ADD` | `0x01_01_00_07` | Ed25519 point addition. |
| `ED_DECOMPRESS` | `0x00_01_00_08` | Ed25519 point decompression. |
| `SECP256K1_ADD` | `0x01_01_00_0A` | secp256k1 point addition. |
| `SECP256K1_DOUBLE` | `0x00_01_00_0B` | secp256k1 point doubling. |
| `SECP256K1_DECOMPRESS` | `0x00_01_00_0C` | secp256k1 point decompression. |
| `SECP256R1_ADD` | `0x01_01_00_2C` | secp256r1 point addition. |
| `SECP256R1_DOUBLE` | `0x00_01_00_2D` | secp256r1 point doubling. |
| `SECP256R1_DECOMPRESS` | `0x00_01_00_2E` | secp256r1 point decompression. |
| `BN254_ADD` | `0x01_01_00_0E` | BN254 G1 point addition. |
| `BN254_DOUBLE` | `0x00_01_00_0F` | BN254 G1 point doubling. |
| `BN254_FP_ADD / SUB / MUL` | `0x01_01_00_26 to 0x01_01_00_28` | BN254 base field operations. |
| `BN254_FP2_ADD / SUB / MUL` | `0x01_01_00_29 to 0x01_01_00_2B` | BN254 quadratic extension field operations. |
| `BLS12381_ADD` | `0x01_01_00_1E` | BLS12-381 G1 point addition. |
| `BLS12381_DOUBLE` | `0x00_01_00_1F` | BLS12-381 G1 point doubling. |
| `BLS12381_DECOMPRESS` | `0x00_01_00_1C` | BLS12-381 G1 point decompression. |
| `BLS12381_FP_ADD / SUB / MUL` | `0x01_01_00_20 to 0x01_01_00_22` | BLS12-381 base field operations. |
| `BLS12381_FP2_ADD / SUB / MUL` | `0x01_01_00_23 to 0x01_01_00_25` | BLS12-381 quadratic extension field operations. |
| `UINT256_MUL` | `0x01_01_00_1D` | 256-bit modular multiplication. |
| `U256XU2048_MUL` | `0x01_01_00_2F` | 256-bit by 2048-bit multiplication. |

The executor also emulates the subset of Linux MIPS system calls (codes 4000 and above, for example `SYS_BRK`, `SYS_MMAP` and `SYS_READ`) that the Go runtime needs.

## Guest Interface

The `zkm_zkvm::syscalls` module implements each system call as a `#[no_mangle] extern "C"` function that issues the `syscall` instruction; a guest calls them directly, for example `zkm_zkvm::syscalls::syscall_sha256_extend`. The `zkm-lib` crate, re-exported as `zkm_zkvm::lib`, declares the same functions for crates that do not depend on `zkm-zkvm` (the patched crates use it), and provides higher-level wrappers such as `zkm_zkvm::lib::keccak256::keccak256`. Its declarations, from [`crates/zkvm/lib/src/lib.rs`](https://github.com/ProjectZKM/Ziren/blob/main/crates/zkvm/lib/src/lib.rs):

```rust
//! Syscalls for the Ziren zkVM.
//!
//! Documentation for these syscalls can be found in the zkVM entrypoint
//! `zkm_zkvm::syscalls` module.
pub mod bls12381;
pub mod bn254;
#[cfg(feature = "ecdsa")]
pub mod ecdsa;

pub mod ed25519;
pub mod io;
pub mod keccak256;
pub mod poseidon2;
pub mod secp256k1;
pub mod secp256r1;
pub mod sha3;
pub mod unconstrained;
pub mod utils;
#[cfg(feature = "verify")]
pub mod verify;

extern "C" {
    /// Halts the program with the given exit code.
    pub fn syscall_halt(exit_code: u8) -> !;

    /// Writes the bytes in the given buffer to the given file descriptor.
    pub fn syscall_write(fd: u32, write_buf: *const u8, nbytes: usize);

    /// Reads the bytes from the given file descriptor into the given buffer.
    pub fn syscall_read(fd: u32, read_buf: *mut u8, nbytes: usize);

    /// Executes the SHA-256 extend operation on the given word array.
    pub fn syscall_sha256_extend(w: *mut [u32; 64]);

    /// Executes the SHA-256 compress operation on the given word array and a given state.
    pub fn syscall_sha256_compress(w: *mut [u32; 64], state: *mut [u32; 8]);

    /// Executes an Ed25519 curve addition on the given points.
    pub fn syscall_ed_add(p: *mut [u32; 16], q: *const [u32; 16]);

    /// Executes an Ed25519 curve decompression on the given point.
    pub fn syscall_ed_decompress(point: &mut [u8; 64]);

    /// Executes an Sepc256k1 curve addition on the given points.
    pub fn syscall_secp256k1_add(p: *mut [u32; 16], q: *const [u32; 16]);

    /// Executes an Secp256k1 curve doubling on the given point.
    pub fn syscall_secp256k1_double(p: *mut [u32; 16]);

    /// Executes an Secp256k1 curve decompression on the given point.
    pub fn syscall_secp256k1_decompress(point: &mut [u8; 64], is_odd: bool);

    /// Executes an Secp256r1 curve addition on the given points.
    pub fn syscall_secp256r1_add(p: *mut [u32; 16], q: *const [u32; 16]);

    /// Executes an Secp256r1 curve doubling on the given point.
    pub fn syscall_secp256r1_double(p: *mut [u32; 16]);

    /// Executes an Secp256r1 curve decompression on the given point.
    pub fn syscall_secp256r1_decompress(point: &mut [u8; 64], is_odd: bool);

    /// Executes a Bn254 curve addition on the given points.
    pub fn syscall_bn254_add(p: *mut [u32; 16], q: *const [u32; 16]);

    /// Executes a Bn254 curve doubling on the given point.
    pub fn syscall_bn254_double(p: *mut [u32; 16]);

    /// Executes a BLS12-381 curve addition on the given points.
    pub fn syscall_bls12381_add(p: *mut [u32; 24], q: *const [u32; 24]);

    /// Executes a BLS12-381 curve doubling on the given point.
    pub fn syscall_bls12381_double(p: *mut [u32; 24]);

    /// Executes the Keccak Sponge
    pub fn syscall_keccak_sponge(input: *const u32, result: *mut [u32; 17]);

    /// Executes the Poseidon2 permutation
    pub fn syscall_poseidon2_permute(state: *mut [u32; 16]);

    /// Executes an uint256 multiplication on the given inputs.
    pub fn syscall_uint256_mulmod(x: *mut [u32; 8], y: *const [u32; 8]);

    /// Executes a 256-bit by 2048-bit multiplication on the given inputs.
    pub fn syscall_u256x2048_mul(
        x: *const [u32; 8],
        y: *const [u32; 64],
        lo: *mut [u32; 64],
        hi: *mut [u32; 8],
    );
    /// Enters unconstrained mode.
    pub fn syscall_enter_unconstrained() -> bool;

    /// Exits unconstrained mode.
    pub fn syscall_exit_unconstrained();

    /// Defers the verification of a valid Ziren zkVM proof.
    pub fn syscall_verify_zkm_proof(vk_digest: &[u32; 8], pv_digest: &[u8; 32]);

    /// Returns the length of the next element in the hint stream.
    pub fn syscall_hint_len() -> usize;

    /// Reads the next element in the hint stream into the given buffer.
    pub fn syscall_hint_read(ptr: *mut u8, len: usize);

    /// Allocates a buffer aligned to the given alignment.
    pub fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8;

    /// Decompresses a BLS12-381 point.
    pub fn syscall_bls12381_decompress(point: &mut [u8; 96], is_odd: bool);

    /// Computes a big integer operation with a modulus.
    pub fn sys_bigint(
        result: *mut [u32; 8],
        op: u32,
        x: *const [u32; 8],
        y: *const [u32; 8],
        modulus: *const [u32; 8],
    );

    /// Executes a BLS12-381 field addition on the given inputs.
    pub fn syscall_bls12381_fp_addmod(p: *mut u32, q: *const u32);

    /// Executes a BLS12-381 field subtraction on the given inputs.
    pub fn syscall_bls12381_fp_submod(p: *mut u32, q: *const u32);

    /// Executes a BLS12-381 field multiplication on the given inputs.
    pub fn syscall_bls12381_fp_mulmod(p: *mut u32, q: *const u32);

    /// Executes a BLS12-381 Fp2 addition on the given inputs.
    pub fn syscall_bls12381_fp2_addmod(p: *mut u32, q: *const u32);

    /// Executes a BLS12-381 Fp2 subtraction on the given inputs.
    pub fn syscall_bls12381_fp2_submod(p: *mut u32, q: *const u32);

    /// Executes a BLS12-381 Fp2 multiplication on the given inputs.
    pub fn syscall_bls12381_fp2_mulmod(p: *mut u32, q: *const u32);

    /// Executes a BN254 field addition on the given inputs.
    pub fn syscall_bn254_fp_addmod(p: *mut u32, q: *const u32);

    /// Executes a BN254 field subtraction on the given inputs.
    pub fn syscall_bn254_fp_submod(p: *mut u32, q: *const u32);

    /// Executes a BN254 field multiplication on the given inputs.
    pub fn syscall_bn254_fp_mulmod(p: *mut u32, q: *const u32);

    /// Executes a BN254 Fp2 addition on the given inputs.
    pub fn syscall_bn254_fp2_addmod(p: *mut u32, q: *const u32);

    /// Executes a BN254 Fp2 subtraction on the given inputs.
    pub fn syscall_bn254_fp2_submod(p: *mut u32, q: *const u32);

    /// Executes a BN254 Fp2 multiplication on the given inputs.
    pub fn syscall_bn254_fp2_mulmod(p: *mut u32, q: *const u32);

    /// Reads a buffer from the input stream.
    pub fn read_vec_raw() -> ReadVecResult;
}

#[repr(C)]
pub struct ReadVecResult {
    pub ptr: *mut u8,
    pub len: usize,
    pub capacity: usize,
}
```

## Guest Example: [syscall_sha256_extend](https://github.com/ProjectZKM/Ziren/tree/main/crates/test-artifacts/guests/sha-extend)

This guest calls the SHA-256 message schedule precompile three times:

```rust
#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

use zkm_zkvm::syscalls::syscall_sha256_extend;

pub fn main() {
    let mut w = [1u32; 64];
    syscall_sha256_extend(&mut w);
    syscall_sha256_extend(&mut w);
    syscall_sha256_extend(&mut w);
}
```
