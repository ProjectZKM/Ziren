package koalabear

// Quintic extension field arithmetic for F_p[X]/(X^5 + X^2 - 1).
// Reduction identity: X^5 = 1 - X^2
//
// This file adds D=5 extension support alongside the existing D=4
// BinomialExtensionField operations in koalabear.go.

/*
#include "../../koalabear.h"
*/
import "C"

import (
	"math/big"
	"os"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func init() {
	solver.RegisterHint(InvE5Hint)
}

// newVariable creates a Variable from a decimal string.
func newVariable(s string) Variable {
	v, _ := new(big.Int).SetString(s, 10)
	return Variable{
		Value:      frontend.Variable(s),
		UpperBound: v,
	}
}

// Ext5Variable represents an element of the quintic extension field.
type Ext5Variable struct {
	Value [5]Variable
}

// NewE5 creates a quintic extension element from 5 base field variables.
func NewE5(a, b, c, d, e Variable) Ext5Variable {
	return Ext5Variable{Value: [5]Variable{a, b, c, d, e}}
}

// Felts2Ext5 converts 5 base field variables to a quintic extension element.
func Felts2Ext5(a, b, c, d, e Variable) Ext5Variable {
	return NewE5(a, b, c, d, e)
}

// NewE5Const creates a quintic extension constant from string values.
func NewE5Const(v []string) Ext5Variable {
	return Ext5Variable{Value: [5]Variable{
		newVariable(v[0]),
		newVariable(v[1]),
		newVariable(v[2]),
		newVariable(v[3]),
		newVariable(v[4]),
	}}
}

// E5FromFelt creates a quintic extension element from a base field element.
func E5FromFelt(a Variable) Ext5Variable {
	return Ext5Variable{Value: [5]Variable{a, Zero(), Zero(), Zero(), Zero()}}
}

// AddE5 adds two quintic extension elements.
func (chip *Chip) AddE5(a, b Ext5Variable) Ext5Variable {
	v := [5]Variable{}
	for i := 0; i < 5; i++ {
		v[i] = chip.AddF(a.Value[i], b.Value[i], false)
	}
	return Ext5Variable{Value: v}
}

// SubE5 subtracts two quintic extension elements.
func (chip *Chip) SubE5(a, b Ext5Variable) Ext5Variable {
	v := [5]Variable{}
	for i := 0; i < 5; i++ {
		v[i] = chip.SubF(a.Value[i], b.Value[i])
	}
	return Ext5Variable{Value: v}
}

// NegE5 negates a quintic extension element.
func (chip *Chip) NegE5(a Ext5Variable) Ext5Variable {
	v := [5]Variable{}
	for i := 0; i < 5; i++ {
		v[i] = chip.negF(a.Value[i])
	}
	return Ext5Variable{Value: v}
}

// MulEF5 multiplies a quintic extension element by a base field element.
func (chip *Chip) MulEF5(a Ext5Variable, b Variable) Ext5Variable {
	v := [5]Variable{}
	for i := 0; i < 5; i++ {
		v[i] = chip.MulF(a.Value[i], b, false)
	}
	return Ext5Variable{Value: v}
}

// AddEF5 adds a base field element to a quintic extension element.
func (chip *Chip) AddEF5(a Ext5Variable, b Variable) Ext5Variable {
	v := a.Value
	v[0] = chip.AddF(a.Value[0], b, false)
	return Ext5Variable{Value: v}
}

// SubEF5 subtracts a base field element from a quintic extension element.
func (chip *Chip) SubEF5(a Ext5Variable, b Variable) Ext5Variable {
	v := a.Value
	v[0] = chip.SubF(a.Value[0], b)
	return Ext5Variable{Value: v}
}

// MulE5 multiplies two quintic extension elements.
//
// The extension is F_p[X]/(X^5 + X^2 - 1).
// Reduction: X^5 = 1 - X^2, X^6 = X - X^3, X^7 = X^2 - X^4, X^8 = X^3 + X^2 - 1
//
// Given a = a0 + a1*X + a2*X^2 + a3*X^3 + a4*X^4
// and   b = b0 + b1*X + b2*X^2 + b3*X^3 + b4*X^4
//
// Product before reduction has terms up to X^8.
// We reduce using:
//   X^5 = 1 - X^2
//   X^6 = X - X^3
//   X^7 = X^2 - X^4
//   X^8 = X^3 + X^2 - 1
func (chip *Chip) MulE5(a, b Ext5Variable) Ext5Variable {
	// Schoolbook multiplication: compute all 9 coefficients of the product
	var c [9]Variable
	for i := 0; i < 9; i++ {
		c[i] = Zero()
	}

	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			c[i+j] = chip.AddF(c[i+j], chip.MulF(a.Value[i], b.Value[j], false), false)
		}
	}

	// Reduce c[5..8] using X^5 = 1 - X^2:
	//   c5 * X^5 = c5 * (1 - X^2)       → c[0] += c5,  c[2] -= c5
	//   c6 * X^6 = c6 * (X - X^3)       → c[1] += c6,  c[3] -= c6
	//   c7 * X^7 = c7 * (X^2 - X^4)     → c[2] += c7,  c[4] -= c7
	//   c8 * X^8 = c8 * (X^3 + X^2 - 1) → c[3] += c8,  c[2] += c8,  c[0] -= c8
	var r [5]Variable

	// r[0] = c[0] + c[5] - c[8]
	r[0] = chip.AddF(c[0], c[5], false)
	r[0] = chip.SubF(r[0], c[8])

	// r[1] = c[1] + c[6]
	r[1] = chip.AddF(c[1], c[6], false)

	// r[2] = c[2] - c[5] + c[7] + c[8]
	r[2] = chip.SubF(c[2], c[5])
	r[2] = chip.AddF(r[2], c[7], false)
	r[2] = chip.AddF(r[2], c[8], false)

	// r[3] = c[3] - c[6] + c[8]
	r[3] = chip.SubF(c[3], c[6])
	r[3] = chip.AddF(r[3], c[8], false)

	// r[4] = c[4] - c[7]
	r[4] = chip.SubF(c[4], c[7])

	// Reduce to ensure bounds stay manageable
	for i := 0; i < 5; i++ {
		r[i] = chip.reduceFast(r[i])
	}

	return Ext5Variable{Value: r}
}

// AssertIsEqualE5 asserts that two quintic extension elements are equal.
func (chip *Chip) AssertIsEqualE5(a, b Ext5Variable) {
	for i := 0; i < 5; i++ {
		chip.AssertIsEqualF(a.Value[i], b.Value[i])
	}
}

// SelectE5 selects between two quintic extension elements based on a condition.
func (chip *Chip) SelectE5(cond frontend.Variable, a, b Ext5Variable) Ext5Variable {
	v := [5]Variable{}
	for i := 0; i < 5; i++ {
		v[i] = chip.SelectF(cond, a.Value[i], b.Value[i])
	}
	return Ext5Variable{Value: v}
}

// InvE5 computes the multiplicative inverse of a quintic extension element.
// Uses a hint for the computation and verifies via MulE5(a, a_inv) == 1.
func (chip *Chip) InvE5(in Ext5Variable) Ext5Variable {
	result, err := chip.api.Compiler().NewHint(InvE5Hint, 5,
		in.Value[0].Value, in.Value[1].Value, in.Value[2].Value,
		in.Value[3].Value, in.Value[4].Value)
	if err != nil {
		panic(err)
	}

	var out Ext5Variable
	for i := 0; i < 5; i++ {
		out.Value[i] = Variable{Value: result[i], UpperBound: new(big.Int).SetUint64(2147483648)}
		if os.Getenv("GROTH16") != "1" {
			chip.RangeChecker.Check(result[i], 31)
		} else {
			chip.api.ToBinary(result[i], 31)
		}
	}

	// Verify: in * out == 1
	product := chip.MulE5(in, out)
	chip.AssertIsEqualE5(product, NewE5Const([]string{"1", "0", "0", "0", "0"}))

	return out
}

// DivE5 divides two quintic extension elements.
func (chip *Chip) DivE5(a, b Ext5Variable) Ext5Variable {
	bInv := chip.InvE5(b)
	return chip.MulE5(a, bInv)
}

// DivEF5 divides a quintic extension element by a base field element.
func (chip *Chip) DivEF5(a Ext5Variable, b Variable) Ext5Variable {
	bInv := chip.invF(b)
	return chip.MulEF5(a, bInv)
}

// Ext5ToFelt decomposes a quintic extension element into 5 base field elements.
func (chip *Chip) Ext5ToFelt(in Ext5Variable) [5]Variable {
	return in.Value
}

// ReduceE5 reduces all components of a quintic extension element.
func (chip *Chip) ReduceE5(x Ext5Variable) Ext5Variable {
	for i := 0; i < 5; i++ {
		x.Value[i] = chip.ReduceSlow(x.Value[i])
	}
	return x
}

// InvE5Hint computes the inverse of a quintic extension element via C FFI.
func InvE5Hint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	a := C.uint(new(big.Int).Mod(inputs[0], modulus).Uint64())
	b := C.uint(new(big.Int).Mod(inputs[1], modulus).Uint64())
	c := C.uint(new(big.Int).Mod(inputs[2], modulus).Uint64())
	d := C.uint(new(big.Int).Mod(inputs[3], modulus).Uint64())
	e := C.uint(new(big.Int).Mod(inputs[4], modulus).Uint64())

	for i := 0; i < 5; i++ {
		inv := C.koalabearext5inv(a, b, c, d, e, C.uint(i))
		results[i].SetUint64(uint64(inv))
	}
	return nil
}
