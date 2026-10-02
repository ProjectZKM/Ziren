# Example Walkthrough - Best Practices

This page walks through the [Fibonacci example](https://github.com/ProjectZKM/Ziren/tree/main/examples/fibonacci) in the Ziren repository. It has the standard layout of a Ziren application:

```shell
examples/fibonacci
├── guest
│   ├── Cargo.toml
│   └── src/main.rs        # the program that is proved
└── host
    ├── Cargo.toml
    ├── build.rs           # compiles the guest to a MIPS ELF
    ├── bin/               # one binary per proof mode
    └── src/main.rs        # executes, proves and verifies the guest
```

## Guest

`guest/src/main.rs`:

```rust
//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

pub fn main() {
    // Read an input to the program. Behind the scenes, this is a system call that reads from
    // the input stream the host provided.
    let n = zkm_zkvm::io::read::<u32>();

    // Commit n to the public values.
    zkm_zkvm::io::commit(&n);

    // Compute the n'th fibonacci number, using normal Rust code.
    let mut a = 0;
    let mut b = 1;
    for _ in 0..n {
        let mut c = a + b;
        c %= 7919; // Modulus to prevent overflow.
        a = b;
        b = c;
    }

    // Commit the outputs of the program.
    zkm_zkvm::io::commit(&a);
    zkm_zkvm::io::commit(&b);
}
```

`guest/Cargo.toml`:

```toml
[package]
name = "fibonacci"
version = "1.1.0"
edition = "2021"
publish = false

[dependencies]
zkm-zkvm = { path = "../../../crates/zkvm/entrypoint", features= ["embedded"] }
```

The package name (`fibonacci`) is the name the host passes to `include_elf!`. The `embedded` feature selects an allocator that can free memory, in place of the default bump allocator. Outside the Ziren repository, replace the `path` dependency by a git dependency, as shown in [Guest Program](./guest-program.md#compiling-guest-program).

## Host

`host/build.rs` compiles the guest whenever the host is built:

```rust
fn main() {
    zkm_build::build_program("../guest");
}
```

`host/Cargo.toml` (abbreviated; the example also declares the other binaries in `bin/`):

```toml
[package]
name = "fibonacci-host"
version = { workspace = true }
edition = { workspace = true }
default-run = "fibonacci-host"
publish = false

[dependencies]
hex = "0.4.3"
zkm-sdk = { workspace = true }

[build-dependencies]
zkm-build = { workspace = true }

[[bin]]
name = "groth16_bn254"
path = "bin/groth16_bn254.rs"

[[bin]]
name = "fibonacci-host"
path = "src/main.rs"
```

`host/src/main.rs` executes the guest, generates a core proof, reads the public values, and verifies the proof; it is listed on the [Host Program](./host-program.md) page. The `bin/` directory holds one host per mode:

| Binary          | What it does                                            |
|-----------------|---------------------------------------------------------|
| `execute`       | executes the guest and prints the execution report      |
| `compressed`    | generates and verifies a compressed proof               |
| `groth16_bn254` | generates and verifies a Groth16 proof for on-chain use |
| `plonk_bn254`   | generates and verifies a PLONK proof for on-chain use   |

`host/bin/groth16_bn254.rs`:

```rust
use zkm_sdk::{include_elf, utils, HashableKey, ProverClient, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci");

fn main() {
    utils::setup_logger();

    let n = 500u32;

    let mut stdin = ZKMStdin::new();
    stdin.write(&n);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    println!("vk: {:?}", vk.bytes32());

    let proof = client.prove(&pk, stdin).groth16().run().unwrap();
    println!("generated proof");

    let public_values = proof.public_values.as_slice();
    println!("public values: 0x{}", hex::encode(public_values));

    let solidity_proof = proof.bytes().expect("the proof has a byte encoding");
    println!("proof: 0x{}", hex::encode(solidity_proof));

    client.verify(&proof, &vk).expect("verification failed");

    proof.save("fibonacci-groth16.bin").expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
```

`vk.bytes32()` is the program verifying key hash that an on-chain verifier checks the proof against, `proof.public_values.as_slice()` are the committed public values, and `proof.bytes()` is the proof in the encoding the Solidity verifier expects (see [Verifier](./verifier.md)).

## Running the Example

From `examples/fibonacci/host`:

```shell
# execute, prove (core mode) and verify
RUST_LOG=info cargo run --release

# execute only
RUST_LOG=info cargo run --release --bin execute

# Groth16 proof for on-chain verification
RUST_LOG=info cargo run --release --bin groth16_bn254
```

## Best Practices

### Guest

- Start every Rust guest with `#![no_std]`, `#![no_main]` and `zkm_zkvm::entrypoint!(main);`.
- Read inputs in the order the host wrote them, with the same types. `read::<T>()` deserializes with bincode; for raw bytes, `read_vec()` and `commit_slice()` skip serialization and cost fewer cycles.
- Commit only what the verifier needs to see. Everything committed with `commit` or `commit_slice` becomes public.
- If a Solidity contract consumes the public values, commit them in an ABI encoding (for example with `alloy_sol_types::SolType::abi_encode`) and decode them on-chain with `abi.decode`.
- Use the precompiles for cryptographic operations; they are much cheaper than the same code compiled to MIPS instructions. For example, the [keccak-precompile example](https://github.com/ProjectZKM/Ziren/blob/main/examples/keccak-precompile/guest/src/main.rs) hashes with:

  ```rust
  use zkm_zkvm::lib::keccak256::keccak256;

  let output = keccak256(&input.as_slice());
  ```

  Many common crates (`sha2`, `k256`, `p256`, `substrate-bn`, and others) have [patched versions](./patched-crates.md) that call the precompiles.
- Keep the guest's dependencies pinned. Any change to the guest ELF changes the program's verifying key.

### Host

- Run `execute` before `prove`. It is much faster, catches guest panics, and its report gives the cycle count (see [Optimizations](./optimizations.md)).
- Read the public values in the order the guest committed them. In the Fibonacci example the first value is `n`.
- Choose the proof mode by the consumer: core or compressed proofs for off-chain verification, Groth16 or PLONK for on-chain verification.
- Publish `vk.bytes32()` with the application. A verifier contract must be configured with this value, and it only changes when the guest ELF changes.
- Save proofs with `proof.save(...)` and load them with `ZKMProofWithPublicValues::load(...)` to verify them elsewhere.
