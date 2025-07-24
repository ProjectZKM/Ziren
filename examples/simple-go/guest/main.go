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
