# Host Program

In a Ziren application, the host is the machine that is running the zkVM. The host is an untrusted agent that sets up the zkVM environment and handles inputs/outputs during execution for guest.

## Example: [Fibonacci](https://github.com/ProjectZKM/Ziren/blob/main/examples/fibonacci/host/src/main.rs)

This host program sends the input `n = 1000` to the guest program for proving knowledge of the Nth Fibonacci number without revealing the computational path.

```rust
use zkm_sdk::{include_elf, utils, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci");

fn main() {
    // Create an input stream and write '1000' to it.
    let n = 1000u32;

    // The input stream that the guest will read from using `zkm_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the program.
    let mut stdin = ZKMStdin::new();
    stdin.write(&n);

    // Create a `ProverClient` method.
    let client = ProverClient::new();

    // Execute the guest using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, stdin.clone()).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    // Generate the proof for the given program and input.
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).run().unwrap();

    // Read and verify the output.
    //
    // Note that this output is read from values committed to in the program using
    // `zkm_zkvm::io::commit`.
    let n = proof.public_values.read::<u32>();
    let a = proof.public_values.read::<u32>();
    let b = proof.public_values.read::<u32>();

    println!("n: {}", n);
    println!("a: {}", a);
    println!("b: {}", b);

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");
}
```

For more details, please refer to document [prover](./prover.md).
