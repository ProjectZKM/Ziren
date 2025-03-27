# Guest Program

In zkMIPS<sup>+</sup>, the guest program is the code that will be executed and proven by the zkVM.

Any program written in C, Go, Rust, etc. can be compiled into a MIPS R3000 be ELF executable file using a universal MIPS compiler, meeting the requirements.

zkMIPS<sup>+</sup> provides Rust runtime libraries for guest programs to handle input/output operations:
- `zkm2_zkvm::io::read::<T>` (for reading structured data)
- `zkm2_zkvm::io::commit::<T>` (for committing structured data)

Note that type `T` must implement both `serde::Serialize` and `serde::Deserialize`. For direct byte-level operations, use the following methods to bypass serialization and reduce cycle counts:
- `zkm2_zkvm::io::read_vec` (raw byte reading)
- `zkm2_zkvm::io::commit_slice` (raw byte writing)

## Example: [Fibonacci](https://github.com/zkMIPS/zkm2/blob/dev/init/examples/fibonacci/guest/src/main.rs)

```rust
//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_std]
#![no_main]
zkm2_zkvm::entrypoint!(main);

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a system call which handles reading inputs
    // from the prover.
    let n = zkm2_zkvm::io::read::<u32>();

    // Write n to public input
    zkm2_zkvm::io::commit(&n);

    // Compute the n'th fibonacci number, using normal Rust code.
    let mut a = 0;
    let mut b = 1;
    for _ in 0..n {
        let mut c = a + b;
        c %= 7919; // Modulus to prevent overflow.
        a = b;
        b = c;
    }

    // Write the output of the program.
    //
    // Behind the scenes, this also compiles down to a system call which handles writing
    // outputs to the prover.
    zkm2_zkvm::io::commit(&a);
    zkm2_zkvm::io::commit(&b);
}
```
