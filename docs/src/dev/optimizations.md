# Optimizations

There are various ways to optimize your program, including: 

- identifying places for improvement performance via cycle tracking and profiling
- acceleration for cryptographic primitives via precompiles
- hardware prover acceleration with AVX support
- other general practices e.g., avoiding copying or serializing and deserializing data when it is not necessary

### Testing Your Program

It is best practice to test your program and check its outputs prior to generating proofs and save on proof generation costs and time. To execute your program without generating a proof, use the following command: 

```rust
cargo run --release -- --execute
```

You can also determine the public inputs with `<zkm_zkvm::io::commit>` to commit to the public values of the program. 

### Acceleration Options

**Acceleration via Precompiles** 

Precompiles are specialized circuits in Ziren’s implementation used to accelerate programs utilizing certain cryptographic operations, allowing for faster program execution and less computationally expensive workload during proving. 

To use a precompile, you can directly interact with them using external system calls. Ziren has a list of all available precompiles [here.](https://docs.zkm.io/mips-vm/mips-isa.html#supported-syscalls) The [precompiles section](https://docs.zkm.io/dev/precompiles.html) also has an example on calling a precompile and an accompanying guest program. 

Alternatively, you can interact with the precompiles through patched crates. The patched crates can be added to your dependencies for performance improvements in your programs without directly using a system call. View all of Ziren’s supported crates and examples on adding patch entries [here](https://docs.zkm.io/dev/patched-crates.html). 

An example on using these crates for proving the execution of EVM blocks using Reth can be found in [reth-processor](https://github.com/ProjectZKM/reth-processor). Note the patch entries of `sha2`, `bn`, `k256`, `p256`, and `alloy-primitives` in the guest’s `Cargo.toml` file. 

**Acceleration via Hardware** 

Ziren provides hardware acceleration support through AVX on Intel x86 CPUs via Plonky3. To activate AVX256/AVX512, view the guide [here](https://docs.zkm.io/dev/prover.html). 

### Cycle Tracking

Tracking the number of cycles for your program’s execution can be a helpful way to identify performance bottlenecks and identify specific parts of your program for improvement. A higher number of cycles in an execution will lead to longer proving times. 

To print to your console the number of execution cycles occurring while executing your program, 

- cycle-tracking example:

The cycle-tracking example can help measure the execution cost of guest programs in terms of MIPS instruction cycles consisting of a host and two guest program [normal.rs](http://normal.rs) and [report.rs](http://report.rs)  that reads and prints the cycle count. For example:
```rust
stdout: result: 5561
stdout: result: 2940
Using cycle-tracker-report saves the number of cycles to the cycle-tracker mapping in the report.
Here's the number of cycles used by the setup: 3191
```