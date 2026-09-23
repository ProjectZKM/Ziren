package diagonal

import (
	"math/big"
	"testing"
)

// The closed form of the internal diagonal, evaluated in the KoalaBear field
// p = 2^31 - 2^24 + 1, must reproduce the residues the circuit carries.
func TestKoalaBearInternalDiagonal(t *testing.T) {
	p := big.NewInt(2130706433)
	inv := func(x int64) *big.Int { return new(big.Int).ModInverse(big.NewInt(x), p) }
	neg := func(x *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Neg(x), p) }
	closedForm := []*big.Int{
		neg(big.NewInt(2)),
		big.NewInt(1),
		big.NewInt(2),
		inv(2),
		big.NewInt(3),
		big.NewInt(4),
		neg(inv(2)),
		neg(big.NewInt(3)),
		neg(big.NewInt(4)),
		inv(1 << 8),
		inv(8),
		inv(1 << 24),
		neg(inv(1 << 8)),
		neg(inv(8)),
		neg(inv(16)),
		neg(inv(1 << 24)),
	}
	if len(closedForm) != Width {
		t.Fatalf("closed form has %d entries, width is %d", len(closedForm), Width)
	}
	for i, want := range closedForm {
		if got := KoalaBearInternalDiagM1[i]; got != want.String() {
			t.Fatalf("diagonal[%d] = %s, closed form gives %s", i, got, want.String())
		}
	}
}
