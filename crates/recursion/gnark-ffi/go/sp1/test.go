package sp1

import (
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/koalabear"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/poseidon2"
)

type TestPoseidon2KoalaBearCircuit struct {
	Input          [poseidon2.KOALABEAR_WIDTH]koalabear.Variable `gnark:",public"`
	ExpectedOutput [poseidon2.KOALABEAR_WIDTH]koalabear.Variable `gnark:",public"`
}

func (circuit *TestPoseidon2KoalaBearCircuit) Define(api frontend.API) error {
	poseidon2KoalaBearChip := poseidon2.NewKoalaBearChip(api)
	fieldApi := koalabear.NewChip(api)

	zero := koalabear.NewF("0")
	input := [poseidon2.KOALABEAR_WIDTH]koalabear.Variable{}
	for i := 0; i < poseidon2.KOALABEAR_WIDTH; i++ {
		input[i] = fieldApi.AddF(circuit.Input[i], zero)
	}

	poseidon2KoalaBearChip.PermuteMut(&input)

	for i := 0; i < poseidon2.KOALABEAR_WIDTH; i++ {
		fieldApi.AssertIsEqualF(circuit.ExpectedOutput[i], input[i])
	}

	return nil
}
