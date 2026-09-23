package poseidon2

import (
	"math/big"

	"github.com/ProjectZKM/zkm-recursion-gnark/zkm/koalabear"
	"github.com/consensys/gnark/frontend"
)

const KOALABEAR_WIDTH = 16
const koalabearNumExternalRounds = 8
// Must equal `zkm_primitives::poseidon2_init`'s ROUNDS_P.  Plonky3's
// poseidon2_round_numbers_128 gives (8, 20) for a 31-bit prime at width 16 with
// S-box degree 3; 13 is the degree-7 (BabyBear) number.  The rc16 table has 30
// rows, and this loop indexes it as 0..4, 4..4+P, 4+P..8+P, the same layout the
// Rust and CUDA implementations use, so 8 + 20 = 28 still fits.
const koalabearNumInternalRounds = 20

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
	i3 := p.api.Mul(i2, inputValue)
	i7bb := p.fieldApi.ReduceSlow(koalabear.Variable{
		Value:      i3,
		UpperBound: new(big.Int).Exp(new(big.Int).SetUint64(2130706433), new(big.Int).SetUint64(3), new(big.Int).SetUint64(0)),
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

// koalaBearInternalDiagM1 is the diagonal V of the internal (partial-round)
// linear layer s -> (1 + Diag(V)) s, as KoalaBear residues:
//
//	V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24, -1/2^8, -1/8, -1/16, -1/2^24]
//
// Source: INTERNAL_DIAG_MONTY_16 in koala-bear/src/poseidon2.rs of p3-koala-bear
// (ProjectZKM/Plonky3, branch zkm/whir-pcs, the revision pinned by Cargo.lock).
// TestKoalaBearInternalDiagonal checks these values against the closed form,
// and the Rust test go_internal_diagonal_matches_the_rust_permutation in
// crates/recursion/core carries the same values and checks them against the
// constant the host permutation uses.
var koalaBearInternalDiagM1 = [KOALABEAR_WIDTH]string{
	"2130706431",
	"1",
	"2",
	"1065353217",
	"3",
	"4",
	"1065353216",
	"2130706430",
	"2130706429",
	"2122383361",
	"1864368129",
	"2130706306",
	"8323072",
	"266338304",
	"133169152",
	"127",
}

func (p *Poseidon2KoalaBearChip) diffusionPermuteMut(state *[KOALABEAR_WIDTH]koalabear.Variable) {
	matInternalDiagM1 := [KOALABEAR_WIDTH]koalabear.Variable{}
	for i, v := range koalaBearInternalDiagM1 {
		matInternalDiagM1[i] = koalabear.NewFConst(v)
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
