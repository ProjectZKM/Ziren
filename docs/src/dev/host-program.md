# Host Program

In a Ziren application, the host is the machine that runs the zkVM. The host is an untrusted agent that sets up the zkVM environment, supplies inputs to the guest, and collects its outputs and proofs.

## Example: [Fibonacci](https://github.com/ProjectZKM/Ziren/blob/main/examples/fibonacci/host/src/main.rs)

This host program sends the input `n = 1000` to the guest program, executes it, proves it, and verifies the proof.

```rust
use zkm_sdk::{include_elf, utils, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci");

fn main() {
    utils::setup_logger();

    // The input stream that the guest reads with `zkm_zkvm::io::read`. The types written here
    // must match the types the guest reads, in the same order.
    let n = 1000u32;
    let mut stdin = ZKMStdin::new();
    stdin.write(&n);

    // The prover is selected by the `ZKM_PROVER` environment variable (CPU by default).
    let client = ProverClient::new();

    // Execute the guest without generating a proof.
    let (_, report) = client.execute(ELF, &stdin).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    // Generate the proving and verifying keys, then a proof (core mode by default).
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).run().unwrap();

    println!("generated proof");

    // Read the values the guest committed with `zkm_zkvm::io::commit`, in the same order.
    let _ = proof.public_values.read::<u32>();
    let a = proof.public_values.read::<u32>();
    let b = proof.public_values.read::<u32>();

    println!("a: {}", a);
    println!("b: {}", b);

    // Verify the proof and its public values.
    client.verify(&proof, &vk).expect("verification failed");

    // Proofs can be saved and loaded.
    proof.save("proof-with-pis.bin").expect("saving proof failed");
    let deserialized_proof =
        ZKMProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
```

Note that `execute` takes the input stream by reference (`&stdin`), while `prove` takes it by value.

For more details, see the [Prover](./prover.md) page.
