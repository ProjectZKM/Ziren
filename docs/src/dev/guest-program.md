# Guest Program

In Ziren, the guest program is the code that will be executed and proven by the zkVM.

Any program written in C, Go, Rust, etc. can be compiled into a MIPS32 little-endian ELF executable file using a universal MIPS compiler, that satisfies the required specification.

Ziren provides Rust runtime libraries for guest programs to handle input/output operations:
- `zkm_zkvm::io::read::<T>` (for reading structured data)
- `zkm_zkvm::io::commit::<T>` (for committing structured data)

Note that type `T` must implement both `serde::Serialize` and `serde::Deserialize`. For direct byte-level operations, use the following methods to bypass serialization and reduce cycle counts:
- `zkm_zkvm::io::read_vec` (raw byte reading)
- `zkm_zkvm::io::commit_slice` (raw byte writing)

Ziren also provides Go runtime libraries for guest programs to handle input/output operations and exit operation:
- `zkm_runtime.Read[T any]` (for reading structured data)
- `zkm_runtime.Commit[T any]` (for committing structured data)
- `zkm_runtime.RuntimeExit` (for exiting program)

## Guest Program Example

Ziren supports multiple programming languages. Below are examples of guest programs written in Rust and C/C++.

### Rust Example: [Fibonacci](https://github.com/ProjectZKM/Ziren/blob/main/examples/fibonacci/guest/src/main.rs)

```rust
//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th Fibonacci
//! number as output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a system call which handles reading inputs
    // from the prover.
    let n = zkm_zkvm::io::read::<u32>();

    // Write n to public input
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

    // Write the output of the program.
    //
    // Behind the scenes, this also compiles down to a system call which handles writing
    // outputs to the prover.
    zkm_zkvm::io::commit(&a);
    zkm_zkvm::io::commit(&b);
}
```

### Go Example: [Simple-Go](https://github.com/ProjectZKM/Ziren/blob/main/examples/simple-go/guest/main.go)

```go
//! A simple program that takes a number `n` as input, and writes the `n`
//! number as output.

package main

import (
	"log"

	"github.com/ProjectZKM/Ziren/crates/go-runtime/zkm_runtime"
)

func main() {
	a := zkm_runtime.Read[uint32]()

	if a != 10 {
		log.Fatal("%x != 10", a)
	}

	zkm_runtime.Commit[uint32](a)
}
```

### C/C++ Example: [Fibonacci_C](https://github.com/ProjectZKM/Ziren/blob/main/examples/fibonacci_c_lib/guest/src/main.rs)

For non-Rust languages, you can compile them to static libraries and link them in Rust by FFI. For [example](https://github.com/ProjectZKM/Ziren/blob/main/examples/fibonacci_c_lib/guest/src/c_lib/add.cpp):

```C
extern "C" {
    unsigned int add(unsigned int a, unsigned int b) {
        return a + b;
    }
}

unsigned int modulus(unsigned int a, unsigned int b) {
    return a % b;
}
```

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

// Use add function from Libexample.a
extern "C" {
    fn add(a: u32, b: u32) -> u32;
    fn modulus(a: u32, b: u32) -> u32;
}

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a system call which handles reading inputs
    // from the prover.
    let n = zkm_zkvm::io::read::<u32>();

    // Write n to public input
    zkm_zkvm::io::commit(&n);

    // Compute the n'th fibonacci number, using normal Rust code.
    let mut a = 0;
    let mut b = 1;
    unsafe {
        for _ in 0..n {
            let mut c = add(a, b);
            c = modulus(c, 7919); // Modulus to prevent overflow.
            a = b;
            b = c;
        }
    }

    // Write the output of the program.
    //
    // Behind the scenes, this also compiles down to a system call which handles writing
    // outputs to the prover.
    zkm_zkvm::io::commit(&a);
    zkm_zkvm::io::commit(&b);
}
```

## Compiling Guest Program

Now you need compile your guest program to an ELF file that can be executed in the zkVM.

To enable automatic building of your guest crate when compiling/running the host crate, create a `build.rs` file in your `host/` directory (adjacent to the host crate's `Cargo.toml`) that utilizes the `zkm-build` crate.

```shell
.
├── guest
└── host
    ├── build.rs # Add this file
    ├── Cargo.toml
    └── src
```

`build.rs`:
```rust
fn main() {
    zkm_build::build_program("../guest");
}
```

And add `zkm-build` as a build dependency in `host/Cargo.toml`:

```toml
[build-dependencies]
zkm-build = "1.0.0"
```

### Advanced Build Options

The build process using `zkm-build` can be configured by passing a `BuildArg`s struct to the `build_program_with_args()` function.

For example, you can use the default `BuildArgs` to batch compile guest programs in a specified directory.

```rust
use std::io::{Error, Result};
use std::io::path::PathBuf;

use zkm_build::{build_program_with_args, BuildArgs};

fn main() -> Result<()> {
    let tests_path = [env!("CARGO_MANIFEST_DIR"), "guests"]
        .iter()
        .collect::<PathBuf>()
        .canonicalize()?;

    build_program_with_args(
        tests_path
            .to_str()
            .ok_or_else(|| Error::other(format!("expected {guests_path:?} to be valid UTF-8")))?,
            BuildArgs::default(),
    );

    Ok(())
}
```
