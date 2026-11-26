package koalabear

/*
#include "../../koalabear.h"
*/
import "C"

import (
	"fmt"
	"math"
	"math/big"
	"os"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

var modulus = new(big.Int).SetUint64(2130706433)
var modulus_sub_1 = new(big.Int).SetUint64(2130706432)

func init() {
	// These functions must be public so Gnark's hint system can access them.
	solver.RegisterHint(InvFHint)
	solver.RegisterHint(InvEHint)
	solver.RegisterHint(ReduceHint)
	solver.RegisterHint(SplitLimbsHint)
	solver.RegisterHint(FieldOrderLimbsHint)
}

type Variable struct {
	Value      frontend.Variable
	UpperBound *big.Int
}

// D is the degree of the extension field over KoalaBear.
const D = 5

// ExtensionVariable is an element of F_p[X]/(X^5 + X^2 - 1), low coefficient first.
type ExtensionVariable struct {
	Value [D]Variable
}

type Chip struct {
	api          frontend.API
	RangeChecker frontend.Rangechecker
}

func NewChip(api frontend.API) *Chip {
	return &Chip{
		api:          api,
		RangeChecker: rangecheck.New(api),
	}
}

func Zero() Variable {
	return Variable{
		Value:      frontend.Variable("0"),
		UpperBound: new(big.Int).SetUint64(0),
	}
}

func One() Variable {
	return Variable{
		Value:      frontend.Variable("1"),
		UpperBound: new(big.Int).SetUint64(1),
	}
}

func NewFConst(value string) Variable {
	int_value, success := new(big.Int).SetString(value, 10)
	if !success {
		panic("string to int conversion failed")
	}
	return Variable{
		Value:      frontend.Variable(value),
		UpperBound: int_value,
	}
}

func NewF(value string) Variable {
	return Variable{
		Value:      frontend.Variable(value),
		UpperBound: new(big.Int).SetUint64(uint64(math.Pow(2, 32))),
	}
}

func NewE(value []string) ExtensionVariable {
	var out ExtensionVariable
	for i := 0; i < D; i++ {
		out.Value[i] = NewF(value[i])
	}
	return out
}

func NewEConst(value []string) ExtensionVariable {
	var out ExtensionVariable
	for i := 0; i < D; i++ {
		out.Value[i] = NewFConst(value[i])
	}
	return out
}

func Felts2Ext(felts [D]Variable) ExtensionVariable {
	return ExtensionVariable{Value: felts}
}

func (c *Chip) AddF(a, b Variable, forceReduce ...bool) Variable {
	result := Variable{
		Value:      c.api.Add(a.Value, b.Value),
		UpperBound: new(big.Int).Add(a.UpperBound, b.UpperBound),
	}
	if len(forceReduce) > 0 && !forceReduce[0] {
		return result
	}
	return c.reduceFast(result)
}

func (c *Chip) SubF(a, b Variable) Variable {
	negB := c.negF(b)
	return c.AddF(a, negB)
}

func (c *Chip) MulF(a, b Variable, forceReduce ...bool) Variable {
	result := Variable{
		Value:      c.api.Mul(a.Value, b.Value),
		UpperBound: new(big.Int).Mul(a.UpperBound, b.UpperBound),
	}
	if len(forceReduce) > 0 && !forceReduce[0] {
		return result
	}
	return c.reduceFast(result)
}

func (c *Chip) MulFConst(a Variable, b int, forceReduce ...bool) Variable {
	result := Variable{
		Value:      c.api.Mul(a.Value, b),
		UpperBound: new(big.Int).Mul(a.UpperBound, new(big.Int).SetUint64(uint64(b))),
	}
	if len(forceReduce) > 0 && !forceReduce[0] {
		return result
	}
	return c.reduceFast(result)
}

func (c *Chip) negF(a Variable) Variable {
	divisor := new(big.Int).Div(a.UpperBound, modulus)
	divisorPlusOne := new(big.Int).Add(divisor, big.NewInt(1))
	liftedModulus := new(big.Int).Mul(divisorPlusOne, modulus)

	return c.reduceFast(Variable{
		Value:      c.api.Sub(liftedModulus, a.Value),
		UpperBound: liftedModulus,
	})
}

func (c *Chip) invF(in Variable) Variable {
	result, err := c.api.Compiler().NewHint(InvFHint, 1, in.Value)
	if err != nil {
		panic(err)
	}

	xinv := Variable{
		Value:      result[0],
		UpperBound: new(big.Int).SetUint64(2147483648),
	}
	if os.Getenv("GROTH16") != "1" {
		c.RangeChecker.Check(result[0], 31)
	} else {
		c.api.ToBinary(result[0], 31)
	}
	product := c.MulF(in, xinv)
	c.AssertIsEqualF(product, NewFConst("1"))

	return xinv
}

func (c *Chip) DivF(a, b Variable) Variable {
	bInv := c.invF(b)
	return c.MulF(a, bInv)
}

func (c *Chip) AssertIsEqualF(a, b Variable) {
	a2 := c.ReduceSlow(a)
	b2 := c.ReduceSlow(b)
	c.api.AssertIsEqual(a2.Value, b2.Value)
}

func (c *Chip) AssertNotEqualF(a, b Variable) {
	a2 := c.ReduceSlow(a)
	b2 := c.ReduceSlow(b)
	c.api.AssertIsDifferent(a2.Value, b2.Value)
}

func (c *Chip) AssertIsEqualE(a, b ExtensionVariable) {
	for i := 0; i < D; i++ {
		c.AssertIsEqualF(a.Value[i], b.Value[i])
	}
}

// AssertNotEqualE holds when a - b has an inverse, which InvE constrains.
func (c *Chip) AssertNotEqualE(a, b ExtensionVariable) {
	c.InvE(c.SubE(a, b))
}

func (c *Chip) SelectF(cond frontend.Variable, a, b Variable) Variable {
	var UpperBound *big.Int
	if a.UpperBound.Cmp(b.UpperBound) == -1 {
		UpperBound = b.UpperBound
	} else {
		UpperBound = a.UpperBound
	}
	return Variable{
		Value:      c.api.Select(cond, a.Value, b.Value),
		UpperBound: UpperBound,
	}
}

func (c *Chip) SelectE(cond frontend.Variable, a, b ExtensionVariable) ExtensionVariable {
	var out ExtensionVariable
	for i := 0; i < D; i++ {
		out.Value[i] = c.SelectF(cond, a.Value[i], b.Value[i])
	}
	return out
}

func (c *Chip) AddEF(a ExtensionVariable, b Variable) ExtensionVariable {
	out := a
	out.Value[0] = c.AddF(a.Value[0], b)
	return out
}

func (c *Chip) AddE(a, b ExtensionVariable) ExtensionVariable {
	var out ExtensionVariable
	for i := 0; i < D; i++ {
		out.Value[i] = c.AddF(a.Value[i], b.Value[i])
	}
	return out
}

func (c *Chip) SubE(a, b ExtensionVariable) ExtensionVariable {
	var out ExtensionVariable
	for i := 0; i < D; i++ {
		out.Value[i] = c.SubF(a.Value[i], b.Value[i])
	}
	return out
}

func (c *Chip) SubEF(a ExtensionVariable, b Variable) ExtensionVariable {
	out := a
	out.Value[0] = c.SubF(a.Value[0], b)
	return out
}

// MulE multiplies two extension elements modulo X^5 + X^2 - 1.
//
// With c the product of the two polynomials, the identities X^5 = 1 - X^2,
// X^6 = X - X^3, X^7 = X^2 - X^4 and X^8 = X^3 + X^2 - 1 fold c[5..8] into
// the low coefficients.
func (c *Chip) MulE(a, b ExtensionVariable) ExtensionVariable {
	var p [2*D - 1]Variable
	for i := range p {
		p[i] = Zero()
	}
	for i := 0; i < D; i++ {
		for j := 0; j < D; j++ {
			p[i+j] = c.AddF(p[i+j], c.MulF(a.Value[i], b.Value[j], false), false)
		}
	}

	var r [D]Variable
	r[0] = c.SubF(c.AddF(p[0], p[5], false), p[8])
	r[1] = c.AddF(p[1], p[6], false)
	r[2] = c.AddF(c.AddF(c.SubF(p[2], p[5]), p[7], false), p[8], false)
	r[3] = c.AddF(c.SubF(p[3], p[6]), p[8], false)
	r[4] = c.SubF(p[4], p[7])
	for i := 0; i < D; i++ {
		r[i] = c.reduceFast(r[i])
	}
	return ExtensionVariable{Value: r}
}

func (c *Chip) MulEF(a ExtensionVariable, b Variable) ExtensionVariable {
	var out ExtensionVariable
	for i := 0; i < D; i++ {
		out.Value[i] = c.MulF(a.Value[i], b)
	}
	return out
}

func (c *Chip) InvE(in ExtensionVariable) ExtensionVariable {
	inputs := make([]frontend.Variable, D)
	for i := 0; i < D; i++ {
		inputs[i] = in.Value[i].Value
	}
	result, err := c.api.Compiler().NewHint(InvEHint, D, inputs...)
	if err != nil {
		panic(err)
	}

	var out ExtensionVariable
	for i := 0; i < D; i++ {
		out.Value[i] = Variable{Value: result[i], UpperBound: new(big.Int).SetUint64(2147483648)}
		if os.Getenv("GROTH16") != "1" {
			c.RangeChecker.Check(result[i], 31)
		} else {
			c.api.ToBinary(result[i], 31)
		}
	}

	product := c.MulE(in, out)
	c.AssertIsEqualE(product, NewEConst([]string{"1", "0", "0", "0", "0"}))

	return out
}

func (c *Chip) Ext2Felt(in ExtensionVariable) [D]Variable {
	return in.Value
}

func (c *Chip) DivE(a, b ExtensionVariable) ExtensionVariable {
	bInv := c.InvE(b)
	return c.MulE(a, bInv)
}

func (c *Chip) DivEF(a ExtensionVariable, b Variable) ExtensionVariable {
	bInv := c.invF(b)
	return c.MulEF(a, bInv)
}

func (c *Chip) NegE(a ExtensionVariable) ExtensionVariable {
	var out ExtensionVariable
	for i := 0; i < D; i++ {
		out.Value[i] = c.negF(a.Value[i])
	}
	return out
}

func (c *Chip) ToBinary(in Variable) []frontend.Variable {
	return c.api.ToBinary(c.ReduceSlow(in).Value, 31)
}

func (p *Chip) reduceFast(x Variable) Variable {
	if x.UpperBound.BitLen() >= 120 {
		return Variable{
			Value:      p.reduceWithMaxBits(x.Value, uint64(x.UpperBound.BitLen())),
			UpperBound: modulus_sub_1,
		}
	}
	return x
}

func (p *Chip) ReduceSlow(x Variable) Variable {
	if x.UpperBound.Cmp(modulus) == -1 {
		return x
	}
	return Variable{
		Value:      p.reduceWithMaxBits(x.Value, uint64(x.UpperBound.BitLen())),
		UpperBound: modulus_sub_1,
	}
}

func (p *Chip) reduceWithMaxBits(x frontend.Variable, maxNbBits uint64) frontend.Variable {
	if maxNbBits <= 30 {
		return x
	}
	result, err := p.api.Compiler().NewHint(ReduceHint, 2, x)
	if err != nil {
		panic(err)
	}

	quotient := result[0]
	remainder := result[1]

	p.rangeCheck(quotient, int(maxNbBits-30))
	p.assertLessThanModulus(remainder)

	p.api.AssertIsEqual(x, p.api.Add(p.api.Mul(quotient, modulus), remainder))

	return remainder
}

func (p *Chip) rangeCheck(x frontend.Variable, nbBits int) {
	if os.Getenv("GROTH16") != "1" {
		p.RangeChecker.Check(x, nbBits)
	} else {
		p.api.ToBinary(x, nbBits)
	}
}

func (p *Chip) assertLessThanModulus(remainder frontend.Variable) {
	// Check that the remainder has size less than the KoalaBear modulus, by decomposing it into a 24
	// bit limb and a 7 bit limb.
	new_result, new_err := p.api.Compiler().NewHint(SplitLimbsHint, 2, remainder)
	if new_err != nil {
		panic(new_err)
	}

	lowLimb := new_result[0]
	highLimb := new_result[1]

	// Check that the hint is correct.
	p.api.AssertIsEqual(
		p.api.Add(
			p.api.Mul(highLimb, frontend.Variable(uint64(math.Pow(2, 24)))),
			lowLimb,
		),
		remainder,
	)
	p.rangeCheck(highLimb, 7)
	p.rangeCheck(lowLimb, 24)

	// If the most significant bits are all 1, then we need to check that the least significant bits
	// are all zero in order for element to be less than the KoalaBear modulus. Otherwise, we don't
	// need to do any checks, since we already know that the element is less than the KoalaBear modulus.
	shouldCheck := p.api.IsZero(p.api.Sub(highLimb, uint64(math.Pow(2, 7))-1))
	p.api.AssertIsEqual(
		p.api.Mul(
			shouldCheck,
			lowLimb,
		),
		frontend.Variable(0),
	)
}

// Var2FieldOrderLimbs returns the numLimbs least significant digits of the base-modulus expansion
// of x, and constrains that expansion to be the canonical one of x as an integer below the native
// field order.
func (p *Chip) Var2FieldOrderLimbs(x frontend.Variable, numLimbs int) []Variable {
	result, err := p.api.Compiler().NewHint(FieldOrderLimbsHint, numLimbs+1, x)
	if err != nil {
		panic(err)
	}

	nativeMax := new(big.Int).Sub(p.api.Compiler().Field(), big.NewInt(1))
	limbsOrder := new(big.Int).Exp(modulus, big.NewInt(int64(numLimbs)), nil)
	highMax := new(big.Int).Div(nativeMax, limbsOrder)
	lowMaxAtHighMax := new(big.Int).Mod(nativeMax, limbsOrder)

	limbs := make([]Variable, numLimbs)
	low := frontend.Variable(0)
	weight := big.NewInt(1)
	for i := 0; i < numLimbs; i++ {
		p.assertLessThanModulus(result[i])
		limbs[i] = Variable{Value: result[i], UpperBound: modulus_sub_1}
		low = p.api.Add(low, p.api.Mul(result[i], new(big.Int).Set(weight)))
		weight.Mul(weight, modulus)
	}

	// 0 <= high <= highMax, and low <= lowMaxAtHighMax whenever high == highMax, so that
	// low + high * limbsOrder is below the native field order and the equality below holds over
	// the integers.
	high := result[numLimbs]
	p.rangeCheck(high, highMax.BitLen())
	p.rangeCheck(p.api.Sub(highMax, high), highMax.BitLen())
	atHighMax := p.api.IsZero(p.api.Sub(highMax, high))
	p.rangeCheck(p.api.Select(atHighMax, p.api.Sub(lowMaxAtHighMax, low), 0), limbsOrder.BitLen())

	p.api.AssertIsEqual(x, p.api.Add(low, p.api.Mul(high, limbsOrder)))

	return limbs
}

// The hint used to compute Var2FieldOrderLimbs: the base-modulus digits of the input followed by
// the remaining high part.
func FieldOrderLimbsHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		panic("FieldOrderLimbsHint expects 1 input operand")
	}
	rem := new(big.Int).Set(inputs[0])
	for i := 0; i < len(results)-1; i++ {
		results[i].Mod(rem, modulus)
		rem.Div(rem, modulus)
	}
	results[len(results)-1].Set(rem)
	return nil
}

// The hint used to compute Reduce.
func ReduceHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		panic("reduceHint expects 1 input operand")
	}
	input := inputs[0]
	quotient := new(big.Int).Div(input, modulus)
	remainder := new(big.Int).Rem(input, modulus)
	results[0] = quotient
	results[1] = remainder
	return nil
}

func (p *Chip) ReduceE(x ExtensionVariable) ExtensionVariable {
	for i := 0; i < D; i++ {
		x.Value[i] = p.ReduceSlow(x.Value[i])
	}
	return x
}

func InvFHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	a := C.uint(new(big.Int).Mod(inputs[0], modulus).Uint64())
	ainv := C.koalabearinv(a)
	results[0].SetUint64(uint64(ainv))
	return nil
}

// The hint used to split a KoalaBear Variable into a 7 bit limb (the most significant bits) and a
// 24 bit limb.
func SplitLimbsHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		panic("SplitLimbsHint expects 1 input operand")
	}

	// The KoalaBear field element
	input := inputs[0]

	if input.Cmp(modulus) == 0 || input.Cmp(modulus) == 1 {
		return fmt.Errorf("input is not in the field")
	}

	two_24 := big.NewInt(int64(math.Pow(2, 24)))

	// The least significant bits
	results[0] = new(big.Int).Rem(input, two_24)
	// The most significant bits
	results[1] = new(big.Int).Quo(input, two_24)

	return nil
}

func InvEHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	var in [D]C.uint
	for i := 0; i < D; i++ {
		in[i] = C.uint(new(big.Int).Mod(inputs[i], modulus).Uint64())
	}
	for i := 0; i < D; i++ {
		inv := C.koalabearextinv(in[0], in[1], in[2], in[3], in[4], C.uint(i))
		results[i].SetUint64(uint64(inv))
	}
	return nil
}
