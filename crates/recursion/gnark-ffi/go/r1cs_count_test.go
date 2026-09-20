package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	zkm "github.com/ProjectZKM/zkm-recursion-gnark/zkm"
)

// DR23 measure-only: compile the gnark outer circuit to a groth16 R1CS and print
// GetNbConstraints — the same metric as DR19's 25,151,698 and DR22's SP1
// 15,972,262. Skips DummySetup/Prove. Drive with:
//   GROTH16=1 WITNESS_JSON=.../groth16_witness.json CONSTRAINTS_JSON=.../constraints.json \
//     go test -run TestR1CSCount -v
func TestR1CSCount(t *testing.T) {
	os.Setenv("GROTH16", "1")

	fileName := os.Getenv("WITNESS_JSON")
	if fileName == "" {
		fileName = "groth16_witness.json"
	}
	data, err := os.ReadFile(fileName)
	if err != nil {
		t.Fatal(err)
	}
	var inputs zkm.WitnessInput
	if err := json.Unmarshal(data, &inputs); err != nil {
		t.Fatal(err)
	}

	circuit := zkm.NewCircuit(inputs)
	builder := r1cs.NewBuilder
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("[zkm] gnark verifier R1CS constraints:", cs.GetNbConstraints())
}
