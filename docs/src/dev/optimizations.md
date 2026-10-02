# Optimizations

There are several ways to reduce the cost of proving a program:

- measure where the cycles go with cycle tracking, and optimize those parts;
- route cryptographic operations through precompiles, directly or via patched crates;
- prove on a GPU, or enable AVX on the CPU prover;
- avoid unnecessary work in the guest, such as copying data or serializing and deserializing it more often than needed.

### Testing Your Program

Test your program and check its outputs before generating proofs; execution is much faster than proving.

To execute your program without generating a proof, call `ProverClient::execute` from the host:

```rust
let client = ProverClient::new();
let (_, report) = client.execute(ELF, &stdin).run().unwrap();
println!("executed program with {} cycles", report.total_instruction_count());
```

`execute` returns the public values the program committed with `zkm_zkvm::io::commit` and an `ExecutionReport`, which holds the instruction count per opcode (`opcode_counts`), the system call count per system call (`syscall_counts`) and the cycle tracker results (`cycle_tracker`). The report implements `Display`, so `println!("{}", report)` prints all of them.

### Acceleration Options

**Acceleration via Precompiles**

Precompiles are dedicated chips for common cryptographic operations, such as SHA-256, Keccak-256, elliptic curve arithmetic over secp256k1, secp256r1, Ed25519, BN254 and BLS12-381, and 256-bit modular multiplication. A precompile call costs far fewer cycles than the same operation compiled to MIPS instructions.

A guest can call the precompiles directly with system calls. The [Precompiles](./precompiles.md) page lists them and has an example guest program.

Alternatively, use the [patched crates](./patched-crates.md), which replace the implementation of common crates (`sha2`, `k256`, `p256`, `substrate-bn`, and others) with precompile calls, so that existing code uses the precompiles without changes.

The Ethereum block prover [reth-processor](https://github.com/ProjectZKM/reth-processor) is an example; note the patch entries for `sha2`, `bn`, `k256`, `p256` and `alloy-primitives` in its guest's `Cargo.toml`.

**Acceleration via Hardware**

Ziren supports hardware acceleration for proof generation on both GPU and CPU:

- a CUDA-based GPU prover, selected with the `ZKM_PROVER=cuda` environment variable or the `ProverClient::cuda()` constructor;
- AVX2/AVX512 optimizations on x86 CPUs via Plonky3, enabled through `RUSTFLAGS`.

For setup and examples, see the [Prover](./prover.md) page.

### Cycle Tracking

Cycle counts show where a program spends its execution and which parts to optimize. More cycles mean longer proving. Proving cost more precisely follows the number of rows the execution fills across all chip tables, and precompile calls and memory accesses add rows of their own; the cycle count is a good first proxy.

The guest marks a region with `cycle-tracker-start` and `cycle-tracker-end` lines printed to stdout, or a whole function with the `#[zkm_derive::cycle_tracker]` attribute (from the `zkm-derive` crate). The executor then logs the cycles each region takes. With `cycle-tracker-report-start` and `cycle-tracker-report-end`, it also stores the count in the execution report under the region's name.

The [cycle-tracking example](https://github.com/ProjectZKM/Ziren/tree/main/examples/cycle-tracking) has two guest programs. [`normal.rs`](https://github.com/ProjectZKM/Ziren/blob/main/examples/cycle-tracking/guest/bin/normal.rs) logs the cycles of its regions:

```rust
#![no_main]
zkm_zkvm::entrypoint!(main);

#[zkm_derive::cycle_tracker]
pub fn expensive_function(x: usize) -> usize {
    let mut y = 1;
    for _ in 0..100 {
        y *= x;
        y %= 7919;
    }
    y
}

pub fn main() {
    let mut nums = vec![1, 1];

    println!("cycle-tracker-start: setup");
    for _ in 0..100 {
        let mut c = nums[nums.len() - 1] + nums[nums.len() - 2];
        c %= 7919;
        nums.push(c);
    }
    println!("cycle-tracker-end: setup");

    println!("cycle-tracker-start: main-body");
    for i in 0..2 {
        let result = expensive_function(nums[nums.len() - i - 1]);
        println!("result: {}", result);
    }
    println!("cycle-tracker-end: main-body");
}
```

[`report.rs`](https://github.com/ProjectZKM/Ziren/blob/main/examples/cycle-tracking/guest/bin/report.rs) uses `cycle-tracker-report-start: setup` and `cycle-tracker-report-end: setup` instead, and the host reads the result from the report:

```rust
let (_, report) = client.execute(REPORT_ELF, &ZKMStdin::new()).run().expect("proving failed");

let setup_cycles = report.cycle_tracker.get("setup").unwrap();
```

Run the example with `RUST_LOG=info` from `examples/cycle-tracking/host` to see the logged cycle counts:

```shell
RUST_LOG=info cargo run --release
```
