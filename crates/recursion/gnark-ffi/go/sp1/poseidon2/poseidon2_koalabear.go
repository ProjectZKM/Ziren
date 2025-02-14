package poseidon2

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/koalabear"
)

const KOALABEAR_WIDTH = 16
const koalabearNumExternalRounds = 8
const koalabearNumInternalRounds = 13

type Poseidon2KoalaBearChip struct {
	api      frontend.API
	fieldApi *koalabear.Chip
}

func NewKoalaBearChip(api frontend.API) *Poseidon2KoalaBearChip {
	return &Poseidon2KoalaBearChip{
		api:      api,
		fieldApi: koalabear.NewChip(api),
	}
}

func (p *Poseidon2KoalaBearChip) PermuteMut(state *[KOALABEAR_WIDTH]koalabear.Variable) {
	// The initial linear layer.
	p.externalLinearLayer(state)

	// The first half of the external rounds.
	rounds := koalabearNumExternalRounds + koalabearNumInternalRounds
	roundsFBeginning := koalabearNumExternalRounds / 2
	for r := 0; r < roundsFBeginning; r++ {
		p.addRc(state, rc16[r])
		p.sbox(state)
		p.externalLinearLayer(state)
	}

	// The internal rounds.
	p_end := roundsFBeginning + koalabearNumInternalRounds
	for r := roundsFBeginning; r < p_end; r++ {
		state[0] = p.fieldApi.AddF(state[0], rc16[r][0])
		state[0] = p.sboxP(state[0])
		p.diffusionPermuteMut(state)
	}

	// The second half of the external rounds.
	for r := p_end; r < rounds; r++ {
		p.addRc(state, rc16[r])
		p.sbox(state)
		p.externalLinearLayer(state)
	}
}

func (p *Poseidon2KoalaBearChip) addRc(state *[KOALABEAR_WIDTH]koalabear.Variable, rc [KOALABEAR_WIDTH]koalabear.Variable) {
	for i := 0; i < KOALABEAR_WIDTH; i++ {
		state[i] = p.fieldApi.AddF(state[i], rc[i])
	}
}

func (p *Poseidon2KoalaBearChip) sboxP(input koalabear.Variable) koalabear.Variable {
	zero := koalabear.NewFConst("0")
	inputCpy := p.fieldApi.AddF(input, zero)
	inputCpy = p.fieldApi.ReduceSlow(inputCpy)
	inputValue := inputCpy.Value
	i2 := p.api.Mul(inputValue, inputValue)
	i4 := p.api.Mul(i2, i2)
	i6 := p.api.Mul(i4, i2)
	i7 := p.api.Mul(i6, inputValue)
	i7bb := p.fieldApi.ReduceSlow(koalabear.Variable{
		Value:      i7,
		UpperBound: new(big.Int).Exp(new(big.Int).SetUint64(2013265921), new(big.Int).SetUint64(7), new(big.Int).SetUint64(0)),
	})
	return i7bb
}

func (p *Poseidon2KoalaBearChip) sbox(state *[KOALABEAR_WIDTH]koalabear.Variable) {
	for i := 0; i < KOALABEAR_WIDTH; i++ {
		state[i] = p.sboxP(state[i])
	}
}

func (p *Poseidon2KoalaBearChip) mdsLightPermutation4x4(state []koalabear.Variable) {
	t01 := p.fieldApi.AddF(state[0], state[1])
	t23 := p.fieldApi.AddF(state[2], state[3])
	t0123 := p.fieldApi.AddF(t01, t23)
	t01123 := p.fieldApi.AddF(t0123, state[1])
	t01233 := p.fieldApi.AddF(t0123, state[3])
	state[3] = p.fieldApi.AddF(t01233, p.fieldApi.MulFConst(state[0], 2))
	state[1] = p.fieldApi.AddF(t01123, p.fieldApi.MulFConst(state[2], 2))
	state[0] = p.fieldApi.AddF(t01123, t01)
	state[2] = p.fieldApi.AddF(t01233, t23)
}

func (p *Poseidon2KoalaBearChip) externalLinearLayer(state *[KOALABEAR_WIDTH]koalabear.Variable) {
	for i := 0; i < KOALABEAR_WIDTH; i += 4 {
		p.mdsLightPermutation4x4(state[i : i+4])
	}

	sums := [4]koalabear.Variable{
		state[0],
		state[1],
		state[2],
		state[3],
	}
	for i := 4; i < KOALABEAR_WIDTH; i += 4 {
		sums[0] = p.fieldApi.AddF(sums[0], state[i])
		sums[1] = p.fieldApi.AddF(sums[1], state[i+1])
		sums[2] = p.fieldApi.AddF(sums[2], state[i+2])
		sums[3] = p.fieldApi.AddF(sums[3], state[i+3])
	}

	for i := 0; i < KOALABEAR_WIDTH; i++ {
		state[i] = p.fieldApi.AddF(state[i], sums[i%4])
	}
}

// todo: update
func (p *Poseidon2KoalaBearChip) diffusionPermuteMut(state *[KOALABEAR_WIDTH]koalabear.Variable) {
	// Reference: https://github.com/zkMIPS/Plonky3/blob/main/koala-bear/src/poseidon2.rs#L10
	// V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/4, 1/8, 1/2^27, -1/2^8, -1/16, -1/2^27]
	// V = [2013265919, 1, 2, 1006632961, 3, 4, 1006632960, 2013265918, 2013265917, 2005401601, 1509949441, 1761607681, 2013265906, 7864320, 125829120, 15]
	matInternalDiagM1 := [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("2013265919"),
		koalabear.NewFConst("1"),
		koalabear.NewFConst("2"),
		koalabear.NewFConst("1006632961"),
		koalabear.NewFConst("3"),
		koalabear.NewFConst("4"),
		koalabear.NewFConst("1006632960"),
		koalabear.NewFConst("2013265918"),
		koalabear.NewFConst("2013265917"),
		koalabear.NewFConst("2005401601"),
		koalabear.NewFConst("1509949441"),
		koalabear.NewFConst("1761607681"),
		koalabear.NewFConst("2013265906"),
		koalabear.NewFConst("7864320"),
		koalabear.NewFConst("125829120"),
		koalabear.NewFConst("15"),
	}
	p.matmulInternal(state, &matInternalDiagM1)
}

func (p *Poseidon2KoalaBearChip) matmulInternal(
	state *[KOALABEAR_WIDTH]koalabear.Variable,
	matInternalDiagM1 *[KOALABEAR_WIDTH]koalabear.Variable,
) {
	sum := koalabear.NewFConst("0")
	for i := 0; i < KOALABEAR_WIDTH; i++ {
		sum = p.fieldApi.AddF(sum, state[i])
	}

	for i := 0; i < KOALABEAR_WIDTH; i++ {
		state[i] = p.fieldApi.MulF(state[i], matInternalDiagM1[i])
		state[i] = p.fieldApi.AddF(state[i], sum)
	}
}
