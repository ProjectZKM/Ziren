# Guest Program

In Ziren, the guest program is the code that is executed and proven by the zkVM.

Programs written in Rust, Go, C/C++ and other languages can be compiled into a MIPS32r2 little-endian ELF executable with the Ziren toolchain, as long as the result satisfies the zkVM's specification.

Ziren provides Rust runtime libraries for guest programs to handle input and output:
- `zkm_zkvm::io::read::<T>()` reads a value of type `T` from the input stream.
- `zkm_zkvm::io::commit::<T>(&value)` commits a value of type `T` to the public values.

`T` must implement `serde::Deserialize` (for `read`) or `serde::Serialize` (for `commit`). For raw bytes, the following functions bypass serialization and use fewer cycles:
- `zkm_zkvm::io::read_vec()` reads the next input as a `Vec<u8>`.
- `zkm_zkvm::io::commit_slice(&[u8])` commits raw bytes to the public values.

Ziren also provides a Go runtime library, `github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime`, with:
- `zkvm_runtime.Read[T any]()` for reading structured data;
- `zkvm_runtime.Commit[T any](value)` for committing structured data;
- `zkvm_runtime.RuntimeExit(code)` for exiting the program.

## Guest Program Example

Below are guest programs written in Rust, Go and C/C++.

### Rust Example: [Fibonacci](https://github.com/ProjectZKM/Ziren/blob/main/examples/fibonacci/guest/src/main.rs)

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

### Go Example: [Simple-Go](https://github.com/ProjectZKM/Ziren/blob/main/examples/simple-go/guest/main.go)

```go
package main

import (
	"log"

	"github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime"
)

func main() {
	a := zkvm_runtime.Read[uint32]()

	if a != 10 {
		log.Fatal("%x != 10", a)
	}

	zkvm_runtime.Commit[uint32](a)
}
```

A Go guest is compiled with the standard Go toolchain for `GOOS=linux GOARCH=mipsle GOMIPS=softfloat`, with the `ziren` build tag and the overlay that `zkm_build::generate_go_overlay` produces. The example's [`host/build.rs`](https://github.com/ProjectZKM/Ziren/blob/main/examples/simple-go/host/build.rs) shows the full command; the host then embeds the resulting binary with `include_bytes!`.

### C/C++ Example: [Fibonacci_C](https://github.com/ProjectZKM/Ziren/blob/main/examples/fibonacci_c_lib/guest/src/main.rs)

For other languages, compile the code to a static library and link it into a Rust guest through FFI. The example compiles [`add.cpp`](https://github.com/ProjectZKM/Ziren/blob/main/examples/fibonacci_c_lib/guest/src/c_lib/add.cpp) and [`modulus.c`](https://github.com/ProjectZKM/Ziren/blob/main/examples/fibonacci_c_lib/guest/src/c_lib/modulus.c) with the `cc` crate in the guest's `build.rs`:

```rust
fn main() {
    cc::Build::new().file("src/c_lib/add.cpp").compile("libadd.a");

    cc::Build::new().file("src/c_lib/modulus.c").compile("libmodulus.a");
}
```

`add.cpp`:

```C
extern "C" {
    unsigned int add(unsigned int a, unsigned int b) {
        return a + b;
    }
}
```

The Rust guest declares and calls the C functions:

```rust
#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

// Use the add and modulus functions from the static libraries.
extern "C" {
    fn add(a: u32, b: u32) -> u32;
    fn modulus(a: u32, b: u32) -> u32;
}

pub fn main() {
    let n = zkm_zkvm::io::read::<u32>();

    zkm_zkvm::io::commit(&n);

    let mut a = 0;
    let mut b = 1;
    unsafe {
        for _ in 0..n {
            let mut c = add(a, b);
            c = modulus(c, 7919);
            a = b;
            b = c;
        }
    }

    zkm_zkvm::io::commit(&a);
    zkm_zkvm::io::commit(&b);
}
```

## Compiling Guest Program

The guest program has to be compiled to an ELF file that the zkVM executes. The Ziren toolchain must be installed (see [Installation](../introduction/installation.md)).

To build the guest automatically when compiling or running the host crate, add a `build.rs` file to your `host/` directory (next to the host crate's `Cargo.toml`) that uses the `zkm-build` crate:

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

The host then embeds the compiled ELF with `zkm_sdk::include_elf!("<guest package name>")`.

The Ziren crates are not published on crates.io; depend on them from the Ziren repository. In `host/Cargo.toml`:

```toml
[dependencies]
zkm-sdk = { git = "https://github.com/ProjectZKM/Ziren" }

[build-dependencies]
zkm-build = { git = "https://github.com/ProjectZKM/Ziren" }
```

and in `guest/Cargo.toml`:

```toml
[dependencies]
zkm-zkvm = { git = "https://github.com/ProjectZKM/Ziren" }
```

Pin a tag or a revision (`tag = "..."` or `rev = "..."`) so that the guest ELF, and therefore the program's verifying key, does not change when the repository moves.

### Advanced Build Options

The build can be configured by passing a `BuildArgs` struct to `build_program_with_args()`. `BuildArgs` selects features, extra `rustc` flags, packages, binaries, the output ELF name and directory, and static C/C++ libraries to link.

For example, the following `build.rs` builds every guest program in a `guests` workspace with the default arguments:

```rust
use std::{
    io::{Error, Result},
    path::PathBuf,
};

use zkm_build::build_program_with_args;

fn main() -> Result<()> {
    let workspace_path =
        [env!("CARGO_MANIFEST_DIR"), "guests"].iter().collect::<PathBuf>().canonicalize()?;

    build_program_with_args(
        workspace_path.to_str().ok_or_else(|| {
            Error::other(format!("expected {workspace_path:?} to be valid UTF-8"))
        })?,
        Default::default(),
    );

    Ok(())
}
```
