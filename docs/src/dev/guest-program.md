# Guest Program

In zkMIPS, the guest program is the code that will be executed and proven by the zkMIPS.

Any program written in C, Go, Rust, etc. can be compiled into a MIPS R3000 be ELF executable file using a universal MIPS compiler, meeting the requirements.

ZkMIPS provides Golang and Rust runtime libraries for guests to obtain input and commit output.

## Example: [RUST](https://github.com/zkMIPS/zkm-project-template/blob/main/guest-program/sha2-rust/src/main.rs)

```zkm_runtime::io::read```
```zkm_runtime::io::commit```

example:
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

    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();

    let output: [u8; 32] = result.into();
    assert_eq!(output.to_vec(), public_input);

    zkm_runtime::io::commit::<[u8; 32]>(&output);
}
```

## Example: [GOLANG](https://github.com/zkMIPS/zkm-project-template/blob/main/guest-program/sha2-go/main.go)

```zkm_runtime.Read[T]()```
```zkm_runtime.Commit```

example:
```go
package main

import (
	"bytes"
	"crypto/sha256"
	"log"

	"github.com/zkMIPS/zkm/go-runtime/zkm_runtime"
)

type DataId uint32

// use iota to create enum
const (
	TYPE1 DataId = iota
	TYPE2
	TYPE3
)

type Data struct {
	Input1  [10]byte
	Input2  uint8
	Input3  int8
	Input4  uint16
	Input5  int16
	Input6  uint32
	Input7  int32
	Input8  uint64
	Input9  int64
	Input10 []byte
	Input11 DataId
	Input12 string
}

func main() {
	a := zkm_runtime.Read[Data]()

	data := []byte(a.Input12)
	hash := sha256.Sum256(data)

	assertEqual(hash[:], a.Input10)

	zkm_runtime.Commit[Data](a)
}

func assertEqual(a []byte, b []byte) {
	if !bytes.Equal(a, b) {
		log.Fatal("%x != %x", a, b)
	}
}

```