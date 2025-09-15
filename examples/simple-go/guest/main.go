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
