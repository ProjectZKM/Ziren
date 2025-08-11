package main

import (
	"bytes"
	"log"
	"github.com/ProjectZKM/Ziren/crates/go-runtime/zkm_runtime"
)

func main() {
	a := zkm_runtime.Read[uint32]()

	if a != 10 {
		log.Fatal("%x != 10", a)
	}
	// assertEqual(a[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a})

	zkm_runtime.Commit[uint32](a)
}

func assertEqual(a []byte, b []byte) {
	if !bytes.Equal(a, b) {
		log.Fatal("%x != %x", a, b)
	}
}
