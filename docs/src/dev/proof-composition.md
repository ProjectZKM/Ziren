# Proof Composition

## What is a receipt?

A receipt gives the results of your program along with proof that they were produced honestly.

## What is Proof Composition

You can verify other receipts in the guest use ```zkm_runtime::io::verify```

## Example

```rust
#![no_std]
#![no_main]

use sha2::{Digest, Sha256};
extern crate alloc;
use alloc::vec::Vec;

zkm_runtime::entrypoint!(main);

pub fn main() {
    let public_input: Vec<u8> = zkm_runtime::io::read();
    let input: Vec<u8> = zkm_runtime::io::read();
    let elf_id: Vec<u8> = zkm_runtime::io::read();

    zkm_runtime::io::verify(elf_id, &input);
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();

    let output: [u8; 32] = result.into();
    assert_eq!(output.to_vec(), public_input);

    zkm_runtime::io::commit::<[u8; 32]>(&output);
}
```
