package poseidon2

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/babybear"
)

const BABYBEAR_WIDTH = 16
const babybearNumExternalRounds = 8
const babybearNumInternalRounds = 13

type Poseidon2BabyBearChip struct {
	api      frontend.API
	fieldApi *babybear.Chip
}

func NewBabyBearChip(api frontend.API) *Poseidon2BabyBearChip {
	return &Poseidon2BabyBearChip{
		api:      api,
		fieldApi: babybear.NewChip(api),
	}
}

func (p *Poseidon2BabyBearChip) PermuteMut(state *[BABYBEAR_WIDTH]babybear.Variable) {
	// The initial linear layer.
	p.externalLinearLayer(state)

	// The first half of the external rounds.
	rounds := babybearNumExternalRounds + babybearNumInternalRounds
	roundsFBeginning := babybearNumExternalRounds / 2
	for r := 0; r < roundsFBeginning; r++ {
		p.addRc(state, rc16[r])
		p.sbox(state)
		p.externalLinearLayer(state)
	}

	// The internal rounds.
	p_end := roundsFBeginning + babybearNumInternalRounds
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

func (p *Poseidon2BabyBearChip) addRc(state *[BABYBEAR_WIDTH]babybear.Variable, rc [BABYBEAR_WIDTH]babybear.Variable) {
	for i := 0; i < BABYBEAR_WIDTH; i++ {
		state[i] = p.fieldApi.AddF(state[i], rc[i])
	}
}

func (p *Poseidon2BabyBearChip) sboxP(input babybear.Variable) babybear.Variable {
	zero := babybear.NewFConst("0")
	inputCpy := p.fieldApi.AddF(input, zero)
	inputCpy = p.fieldApi.ReduceSlow(inputCpy)
	inputValue := inputCpy.Value
	i2 := p.api.Mul(inputValue, inputValue)
	i4 := p.api.Mul(i2, i2)
	i6 := p.api.Mul(i4, i2)
	i7 := p.api.Mul(i6, inputValue)
	i7bb := p.fieldApi.ReduceSlow(babybear.Variable{
		Value:      i7,
		UpperBound: new(big.Int).Exp(new(big.Int).SetUint64(2013265921), new(big.Int).SetUint64(7), new(big.Int).SetUint64(0)),
	})
	return i7bb
}

func (p *Poseidon2BabyBearChip) sbox(state *[BABYBEAR_WIDTH]babybear.Variable) {
	for i := 0; i < BABYBEAR_WIDTH; i++ {
		state[i] = p.sboxP(state[i])
	}
}

func (p *Poseidon2BabyBearChip) mdsLightPermutation4x4(state []babybear.Variable) {
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

func (p *Poseidon2BabyBearChip) externalLinearLayer(state *[BABYBEAR_WIDTH]babybear.Variable) {
	for i := 0; i < BABYBEAR_WIDTH; i += 4 {
		p.mdsLightPermutation4x4(state[i : i+4])
	}

	sums := [4]babybear.Variable{
		state[0],
		state[1],
		state[2],
		state[3],
	}
	for i := 4; i < BABYBEAR_WIDTH; i += 4 {
		sums[0] = p.fieldApi.AddF(sums[0], state[i])
		sums[1] = p.fieldApi.AddF(sums[1], state[i+1])
		sums[2] = p.fieldApi.AddF(sums[2], state[i+2])
		sums[3] = p.fieldApi.AddF(sums[3], state[i+3])
	}

	for i := 0; i < BABYBEAR_WIDTH; i++ {
		state[i] = p.fieldApi.AddF(state[i], sums[i%4])
	}
}

func (p *Poseidon2BabyBearChip) diffusionPermuteMut(state *[BABYBEAR_WIDTH]babybear.Variable) {
// V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/4, 1/8, 1/2^27, -1/2^8, -1/16, -1/2^27]
// V = [2013265919, 1, 2, 1006632961, 3, 4, 1006632960, 2013265918, 2013265917, 2005401601, 1509949441, 1761607681, 2013265906, 7864320, 125829120, 15]
	matInternalDiagM1 := [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("2013265919"),
		babybear.NewFConst("1"),
		babybear.NewFConst("2"),
		babybear.NewFConst("1006632961"),
		babybear.NewFConst("3"),
		babybear.NewFConst("4"),
		babybear.NewFConst("1006632960"),
		babybear.NewFConst("2013265918"),
		babybear.NewFConst("2013265917"),
		babybear.NewFConst("2005401601"),
		babybear.NewFConst("1509949441"),
		babybear.NewFConst("1761607681"),
		babybear.NewFConst("2013265906"),
		babybear.NewFConst("7864320"),
		babybear.NewFConst("125829120"),
		babybear.NewFConst("15"),
	}
	p.matmulInternal(state, &matInternalDiagM1)
}

func (p *Poseidon2BabyBearChip) matmulInternal(
	state *[BABYBEAR_WIDTH]babybear.Variable,
	matInternalDiagM1 *[BABYBEAR_WIDTH]babybear.Variable,
) {
	sum := babybear.NewFConst("0")
	for i := 0; i < BABYBEAR_WIDTH; i++ {
		sum = p.fieldApi.AddF(sum, state[i])
	}

	for i := 0; i < BABYBEAR_WIDTH; i++ {
		state[i] = p.fieldApi.MulF(state[i], matInternalDiagM1[i])
		state[i] = p.fieldApi.AddF(state[i], sum)
	}
}
