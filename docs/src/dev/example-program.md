# Example Walkthrough - Best Practices 

From Ziren’s [project template](https://github.com/ProjectZKM/Ziren), you can directly make adjustments to the guest and host Rust programs: 

- guest/main.rs
- host/main.rs

The implementations with the guest and host programs for proving the Fibonacci sequence (the default example in the project template are below): 

`./guest/main.rs`

```rust
//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.

// directives to make the Rust program compatible with the zkVM 
#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main); // marks main() as the program entrypoint when compiled for the zkVM

use alloy_sol_types::SolType; // abi encoding and decoding compatible with Solidity for verification
use fibonacci_lib::{PublicValuesStruct, fibonacci}; // crate with struct to represent public output values and function to compute Fibonacci numbers

pub fn main() { // main function for guest. Execution begins here 
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a system call which handles reading inputs
    // from the prover.
    let n = zkm_zkvm::io::read::<u32>(); // reads an input n from the host. System call allows host to pass in serialized input

    // Compute the n'th fibonacci number using a function from the workspace lib crate.
    let (a, b) = fibonacci(n); // computes (n-1)th = a and nth = b Fibonacci numbers

    // Encode the public values of the program.
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { n, a, b }); // wraps result into struct and ABI encodes it into a byte array using SolType

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    zkm_zkvm::io::commit_slice(&bytes); // commits output bytes to zkVM's public output allowing verifier to validate that output matches input and computation
}

```

`./host/main.rs`

```rust
//! An end-to-end example of using the zkMIPS SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --core
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --compressed
//! ```

use alloy_sol_types::SolType; // abi encoding and decoding compatible with Solidity for verification
use clap::Parser;
use fibonacci_lib::PublicValuesStruct;
use zkm_sdk::{ProverClient, ZKMStdin, include_elf};

/// The ELF (executable and linkable format) file for the zkMIPS zkVM.
pub const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci"); // includes compiled fibonacci guest ELF binary at compile

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args { // defines CLI arguments 
    #[arg(long)]
    execute: bool, // runs guest directly inside zkVM 

    #[arg(long)]
    core: bool, // generates core proof 

    #[arg(long)]
    compressed: bool, // generates compressed proof 

    #[arg(long, default_value = "20")]
    n: u32, // input value to send to guest program 
}

fn main() {
    // Setup the logger. 
    zkm_sdk::utils::setup_logger(); // logging setup
    dotenv::dotenv().ok(); // loading any .env variables 

    // Parse the CLI arguments and enforces exactly one mode is chosen 
    let args = Args::parse();

    if args.execute == args.core && args.compressed == args.execute {
        eprintln!("Error: You must specify either --execute, --core, or --compress");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the inputs.
    let mut stdin = ZKMStdin::new();
    stdin.write(&args.n); // writes n into stdin for guest to read 

    println!("n: {}", args.n);

		// execution mode: 
    if args.execute {
        // Execute the program
        let (output, report) = client.execute(FIBONACCI_ELF, stdin).run().unwrap();
        println!("Program executed successfully.");
        // runs guest program inside zkVM without generating proof and captures output and report 

        // Read the output.
        // output decoding from guest using ABI rules 
        let decoded = PublicValuesStruct::abi_decode(output.as_slice()).unwrap();
        let PublicValuesStruct { n, a, b } = decoded;
        
        // validates output correctness by re-computing it locally and comparing
        println!("n: {}", n);
        println!("a: {}", a);
        println!("b: {}", b);

        let (expected_a, expected_b) = fibonacci_lib::fibonacci(n);
        assert_eq!(a, expected_a);
        assert_eq!(b, expected_b);
        println!("Values are correct!");

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
        
    // proving mode: 
    } else {
        // Setup the program for proving.
        // sets up proving and verification keys from the ELF
        let (pk, vk) = client.setup(FIBONACCI_ELF);

        // Generate the Core proof
        let proof = if args.core {
            client.prove(&pk, stdin).run().expect("failed to generate Core proof")
        // generats compressed proof 
        } else {
            client
                .prove(&pk, stdin)
                .compressed()
                .run()
                .expect("failed to generate Compressed Proof")
        };
        println!("Successfully generated proof!");

        // Verify the proof using verification key. ends process if successful 
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}

```

### Guest Program Best Practices

From the example above, the guest program includes the code that will be executed inside Ziren. It must be compiled to a MIPS-compatible ELF binary. Key components to include in the guest program are: 

- `#![no_std]`, `#![no_main]` using the zkm_zkvm crate: this is required for the compilation to MIPS ELF
    
    ```rust
    #![no_std]
    #![no_main]
    zkm_zkvm::entrypoint!(main);
    ```
    
- `zkm_zkvm::entrypoint!(main)`: Defines the entrypoint for zkVM
- `zkm_zkvm::io::read::<T>()`: System call to receive input from the host
- Computation logic: Call or define functions e.g., the fibonacci function in the example (recommended to separate logic in a shared crate)
- To minimize memory, avoid dynamic memory allocation and test on smaller inputs first to avoid exceeding cycle limits.
- ABI encoding: Use `SolType` from `alloy_sol_types` for Solidity-compatible public output
- `zkm_zkvm::io::commit_slice`: Commits data to zkVM’s public output
- For programs utilizing cryptographic operations e.g., SHA256, Keccak, BN254, Ziren provides precompiles which you can call via a syscall. For example, when utilizing the keccak precompile:

```rust
use zkm_zkvm::syscalls::syscall_keccak;

let input: [u8; 64] = [0u8; 64];
let mut output: [u8; 32] = [0u8; 32];
syscall_keccak(&input, &mut output);

```

### Host Program Best Practices

The **host** handles setup, runs the guest, and optionally generates/verifies a proof.

The host program manages the VM execution, proof generation, and verification, handling:

- Input preparation
- zkVM execution or proof generation (core, compressed, evm-compatible)
- Output decoding
- Output validation

Structure your host around the following:

1. Parse CLI args
2. Load or compile guest program
3. Set up for execution or proving 
4. Printing the verifier key 

- You can define CLI args to configure the program:

```rust
#[derive(Parser)]
struct Args {
    #[arg(long)]
    pub a: u32,
    #[arg(long)]
    pub b: u32,
}
```

In the above fibonacci example, execute, core, compressed and n are defined as CLI arguments: 

```rust

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args { // defines CLI arguments 
    #[arg(long)]
    execute: bool, // runs guest directly inside zkVM 

    #[arg(long)]
    core: bool, // generates core proof 

    #[arg(long)]
    compressed: bool, // generates compressed proof 

    #[arg(long, default_value = "20")]
    n: u32, // input value to send to guest program 
```

- Printing the `vkey_hash` after proof generation will bind the guest code to the verifier contract:

```rust
let vkey_hash = prover.vkey_hash();
println!("vkey_hash: {:?}", vkey_hash);

```

Some additional best practices for output handling and validation: 

- Define a `SolType`compatible struct for outputs (e.g., `PublicValuesStruct`)
- Use `.abi_encode()` in guest and `.abi_decode()` in host to ensure Solidity/verifier compatibility
- Recompute expected outputs in host using `execute` and assert they match guest output, ensuring correctness (expected outputs) before proving and selecting form the proving modes:  `-core` , `-compressed` , `-evm`.