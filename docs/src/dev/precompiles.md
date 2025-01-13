# Precompiles

Precompiles are built into the zkMIPS to optimize the performance of zero-knowledge proofs (ZKPs) and related cryptographic operations. The goal is to enable more efficient handling of complex cryptographic tasks that would otherwise be computationally expensive if implemented in smart contracts.

Within the zkVM, precompiles are made available as system calls executed through the `syscall` MIPS instruction. Each precompile is identified by a distinct system call number and provides a specific computational interface.

zkMIPS is also specifically designed to simplify the process for external contributors to create and extend the zkVM by adding their own precompiles. Further details are as follows.

## Specification

For advanced users, it's possible to directly interact with the precompiles through external system calls.

Here is a list of all available [system calls & precompiles](https://github.com/zkMIPS/zkm/blob/main/runtime/precompiles/src/lib.rs).

```rust
pub mod io;
pub mod utils;

pub const BIGINT_WIDTH_WORDS: usize = 8;

extern "C" {
    pub fn syscall_halt(exit_code: u8) -> !;
    pub fn syscall_write(fd: u32, write_buf: *const u8, nbytes: usize);
    pub fn syscall_hint_len() -> usize;
    pub fn syscall_hint_read(ptr: *mut u8, len: usize);
    pub fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8;
    pub fn syscall_verify(claim_digest: &[u8; 32]);
    /// Executes the Keccak-256 permutation on the given state.
    pub fn syscall_keccak(state: *const u32, len: usize, result: *mut u8);
}
```

## Example: [Keccak256](https://github.com/zkMIPS/zkm/tree/main/prover/examples/keccak)

### Guest Program

In the guest program, you can call `keccak` in the following way:

```rust
zkm_runtime::io::keccak(&info.code)
```

The complete code is as follows:

```rust
#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;

zkm_runtime::entrypoint!(main);

pub fn main() {
    let public_input: Vec<u8> = zkm_runtime::io::read();
    let input: Vec<u8> = zkm_runtime::io::read();

    let output = zkm_runtime::io::keccak(&input.as_slice());
    assert_eq!(output.to_vec(), public_input);
    zkm_runtime::io::commit::<[u8; 32]>(&output);
}
```

### Host Program

The host program is as follows:

```rust
use std::env;

use zkm_emulator::utils::{load_elf_with_patch, split_prog_into_segs};
use zkm_utils::utils::prove_segments;

const ELF_PATH: &str = "../guest/elf/mips-zkm-zkvm-elf";

fn prove_keccak_rust() {
    // split ELF into segs
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or("65536".to_string());
    let seg_size = seg_size.parse::<_>().unwrap_or(0);

    let mut state = load_elf_with_patch(ELF_PATH, vec![]);
    // load input
    let args = env::var("ARGS").unwrap_or("data-to-hash".to_string());
    // assume the first arg is the hash output(which is a public input), and the second is the input.
    let args: Vec<&str> = args.split_whitespace().collect();
    assert!(args.len() >= 1);

    let public_input: Vec<u8> = hex::decode(args[0]).unwrap();
    state.add_input_stream(&public_input);
    log::info!("expected public value in hex: {:X?}", args[0]);
    log::info!("expected public value: {:X?}", public_input);

    let private_input: Vec<u8> = if args.len() > 1 {
        hex::decode(args[1]).unwrap()
    } else {
        vec![]
    };
    log::info!("private input value: {:X?}", private_input);
    state.add_input_stream(&private_input);

    let (_total_steps, seg_num, mut state) = split_prog_into_segs(state, &seg_path, "", seg_size);

    let value = state.read_public_values::<[u8; 32]>();
    log::info!("public value: {:X?}", value);
    log::info!("public value: {} in hex", hex::encode(value));

    let _ = prove_segments(&seg_path, "", "", "", seg_num, 0, vec![]).unwrap();
}

fn main() {
    env_logger::try_init().unwrap_or_default();
    prove_keccak_rust();
}
```

## Add your own precompiles

### sha2-precompile: [guest program](https://github.com/zkMIPS/zkm-project-template/tree/main/guest-program/sha2-precompile)

Compared to [sha2-rust](https://github.com/zkMIPS/zkm-project-template/tree/main/guest-program/sha2-rust), [sha2-precompile](https://github.com/zkMIPS/zkm-project-template/tree/main/guest-program/sha2-precompile) first reads the [receipt](http://3.15.141.150:8080/dev/proof-composition.html) produced by [sha2-rust](https://github.com/zkMIPS/zkm-project-template/tree/main/guest-program/sha2-rust) and verifies it, and then produces its own receipt.

```rust
let elf_id: Vec<u8> = zkm_runtime::io::read();
zkm_runtime::io::verify(elf_id, &input);
```

The complete code is as follows:

```rust
#![no_std]
#![no_main]

use sha2::{Digest, Sha256};
extern crate alloc;
use alloc::vec::Vec;

zkm_runtime::entrypoint!(main);

pub fn main() {
    let public_input: Vec<u8> = zkm_runtime::io::read();
    let input: [u8; 32] = zkm_runtime::io::read();
    let elf_id: Vec<u8> = zkm_runtime::io::read();

    zkm_runtime::io::verify(elf_id, &input);
    let mut hasher = Sha256::new();
    hasher.update(input.to_vec());
    let result = hasher.finalize();

    let output: [u8; 32] = result.into();
    assert_eq!(output.to_vec(), public_input);

    zkm_runtime::io::commit::<[u8; 32]>(&output);
}
```

### sha2-precompile: [host program](https://github.com/zkMIPS/zkm-project-template/tree/main/host-program/sha2-precompile)

Compared to [sha2-rust](https://github.com/zkMIPS/zkm-project-template/tree/main/host-program/sha2-rust), [sha2-precompile](https://github.com/zkMIPS/zkm-project-template/tree/main/host-program/sha2-precompile) first generates the [receipt](receipt) of [sha2-rust](https://github.com/zkMIPS/zkm-project-template/tree/main/host-program/sha2-rust), and then generates its own.

The complete code is here: [code](https://github.com/zkMIPS/zkm-project-template/blob/main/host-program/sha2-precompile/src/main.rs).
