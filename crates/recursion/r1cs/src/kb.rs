//! KoalaBear arithmetic on words.
//!
//! An element is its canonical value `v < p` in the low bits of a word,
//! `p = 2^31 - 2^24 + 1`.  Every value a gadget returns is canonical, and
//! every gadget may assume its inputs are.  The identities below are over
//! the integers: each carry chain is bounded so that it cannot wrap, or is
//! made not to by its carry-out relation.
//!
//! - `out < p` is the absence of a carry out of `out + (2^64 - p)`.
//! - For a bit `k`, `k p` is the XOR of `k` moved to bits 0 and 24..=30,
//!   since those bits of `p` are disjoint.
//! - For `q < 2^31`, `q p = (q << 31) ^ q - (q << 24)`, so `x = q p + r`
//!   is `x + (q << 24) = ((q << 31) ^ q) + r`.
//! - An extension product reduces each coefficient once: its four
//!   products `a_i b'_j < p^2`, with `b'_j = 3 b_j` reduced where the
//!   product wraps past `X^4 = 3`, sum below `2^64`, and the quotient is
//!   below `2^33`.

use p3_field::{
    extension::BinomialExtensionField, BasedVectorSpace, Field, PrimeCharacteristicRing,
    PrimeField32,
};
use p3_koala_bear::KoalaBear;
use p3_word::{ShiftKind, ShiftedValue};

use crate::builder::{Builder, Term, Val};

/// The KoalaBear modulus.
pub const P: u64 = 0x7f00_0001;

/// The bits of `P`.
const P_BITS: [usize; 8] = [0, 24, 25, 26, 27, 28, 29, 30];

/// The degree-4 extension, `X^4 = 3`.
pub type Ext = [Val; 4];

/// The native extension field.
pub type Ef = BinomialExtensionField<KoalaBear, 4>;

fn felt(value: u64) -> KoalaBear {
    KoalaBear::from_u64(value)
}

fn canonical(value: KoalaBear) -> u64 {
    u64::from(value.as_canonical_u32())
}

/// The runtime's quotient: `a / b`, with `0 / 0 = 1` and `a / 0 = 0`.
pub fn quotient(a: u64, b: u64) -> u64 {
    match (a, b) {
        (0, 0) => 1,
        (_, 0) => 0,
        _ => canonical(felt(a) * felt(b).inverse()),
    }
}

/// The native element of `value`.
pub fn ext_value(value: &Ext) -> Ef {
    Ef::from_basis_coefficients_fn(|i| felt(value[i].value))
}

impl Builder {
    fn plain_term(&mut self, value: Val) -> Term {
        self.materialize(value).plain().expect("a materialized value is plain")
    }

    fn moved(term: Term, amount: usize) -> Term {
        ShiftedValue::single(
            term.index(),
            p3_word::Shift::new(ShiftKind::LogicalLeft, amount).expect("a shift within the word"),
        )
    }

    fn times_p(bit: Term) -> Vec<Term> {
        P_BITS.iter().map(|&shift| Self::moved(bit, shift)).collect()
    }

    fn below(&mut self, term: Term, bits: usize) {
        self.below_bits(term, bits);
    }

    /// `value < p`.  Checks are emitted two at a time, one per lane of a
    /// carry chain adding `2^32 - p` to each: a lane below `p` does not
    /// carry out of its bit 31.
    pub fn range(&mut self, value: Val) {
        if value.constant {
            return;
        }
        match self.pending_range.take() {
            None => self.pending_range = Some(value),
            Some(first) => self.range_lanes(first, Some(value)),
        }
    }

    /// Emits a range check still waiting for a partner.
    pub fn flush_ranges(&mut self) {
        if let Some(value) = self.pending_range.take() {
            self.range_lanes(value, None);
        }
    }

    fn range_lanes(&mut self, low: Val, high: Option<Val>) {
        let low = self.materialize(low);
        self.below(low.plain().expect("a materialized value is plain"), 32);
        let high = high.map(|value| {
            let value = self.materialize(value);
            self.below(value.plain().expect("a materialized value is plain"), 32);
            value
        });
        let packed = self.lanes(low, high);
        let bound = (1u64 << 32) - P;
        let bound = self.constant(bound | if high.is_some() { bound << 32 } else { 0 });
        let packed_terms: Vec<Term> = packed.terms().collect();
        let bound_terms: Vec<Term> = bound.terms().collect();
        let chain = self.chain(&packed_terms, packed.value, &bound_terms, bound.value, true, false);
        self.assert_zero([ShiftedValue::single(
            chain.carry.index(),
            p3_word::Shift::new(ShiftKind::Lane32LogicalRight, 31).expect("a lane shift"),
        )]);
    }

    /// A hinted element, checked canonical.
    pub fn hint(&mut self, value: u64) -> Val {
        let word = self.word(value);
        self.range(word);
        word
    }

    /// A hinted bit.
    pub fn hint_bit(&mut self, value: u64) -> Val {
        let word = self.word(value);
        let term = word.plain().expect("a fresh word is plain");
        self.below(term, 1);
        word.narrowed()
    }

    /// `value`, checked to be a bit.
    pub fn bit(&mut self, value: Val) -> Val {
        if value.constant {
            assert!(value.value <= 1, "a constant bit is 0 or 1");
            return value;
        }
        let value = self.materialize(value);
        let term = value.plain().expect("a materialized value is plain");
        self.below(term, 1);
        value.narrowed()
    }

    /// `a + b`.
    pub fn add(&mut self, a: Val, b: Val) -> Val {
        if a.is_zero() {
            return b;
        }
        if b.is_zero() {
            return a;
        }
        let sum = a.value + b.value;
        let wraps = u64::from(sum >= P);
        if a.constant && b.constant {
            return self.constant(sum - wraps * P);
        }
        let out = self.word(sum - wraps * P);
        self.equal_sums(a, b, out, wraps);
        self.range(out);
        out
    }

    /// `a - b`.
    pub fn sub(&mut self, a: Val, b: Val) -> Val {
        if b.is_zero() {
            return a;
        }
        let borrows = u64::from(a.value < b.value);
        let diff = a.value + borrows * P - b.value;
        if a.constant && b.constant {
            return self.constant(diff);
        }
        let out = self.word(diff);
        self.equal_sums(out, b, a, borrows);
        self.range(out);
        out
    }

    /// `x + y = out + k p` for a hinted bit `k`.
    fn equal_sums(&mut self, x: Val, y: Val, out: Val, wraps: u64) {
        let k = self.word(wraps).plain().expect("a fresh word is plain");
        self.below(k, 1);
        let x_terms: Vec<Term> = x.terms().collect();
        let y_terms: Vec<Term> = y.terms().collect();
        let left = self.chain(&x_terms, x.value, &y_terms, y.value, false, false);
        let out_terms: Vec<Term> = out.terms().collect();
        let right = self.chain(&out_terms, out.value, &Self::times_p(k), wraps * P, false, false);
        self.assert_zero(left.sum.into_iter().chain(right.sum));
    }

    /// `x = q p + r` for a hinted `q < 2^31` and a committed word `x`;
    /// the first chain may not wrap, since `x` is bounded only by `2^64`
    /// when one factor of it is not range-checked.
    fn reduce_small(&mut self, x: Term, x_value: u64, r: Val) {
        let q_value = x_value / P;
        let q = self.word(q_value).plain().expect("a fresh word is plain");
        self.below(q, 31);
        let left = self.chain(&[x], x_value, &[Self::moved(q, 24)], q_value << 24, false, true);
        let r_terms: Vec<Term> = r.terms().collect();
        let right = self.chain(
            &[Self::moved(q, 31), q],
            (q_value << 31) | q_value,
            &r_terms,
            r.value,
            false,
            false,
        );
        self.assert_zero(left.sum.into_iter().chain(right.sum));
    }

    /// `a * b`.
    pub fn mul(&mut self, a: Val, b: Val) -> Val {
        if a.is_zero() || b.is_zero() {
            return Val::ZERO;
        }
        let product = a.value * b.value;
        if a.constant && b.constant {
            return self.constant(product % P);
        }
        if a.constant && a.value == 1 {
            return b;
        }
        if b.constant && b.value == 1 {
            return a;
        }
        let r = self.word(product % P);
        self.range(r);
        self.mul_into(a, b, r);
        r
    }

    /// `a * b = r` for a canonical `r`.
    pub fn mul_into(&mut self, a: Val, b: Val, r: Val) {
        if a.is_zero() || b.is_zero() {
            self.assert_zero(r.terms());
            return;
        }
        let product = a.value * b.value;
        let x = self.word(product).plain().expect("a fresh word is plain");
        self.imul(a.terms(), b.terms(), [x], []);
        self.reduce_small(x, product, r);
    }

    /// `a / b`, the runtime's quotient; `canonical_out` range-checks the
    /// result, which an assertion whose result nobody reads does not need.
    pub fn div(&mut self, a: Val, b: Val, canonical_out: bool) -> Val {
        let value = quotient(a.value, b.value);
        if a.constant && b.constant {
            return self.constant(value);
        }
        let out = self.word(value);
        if canonical_out {
            self.range(out);
        }
        self.mul_into(b, out, a);
        out
    }

    /// `3 b`.
    pub fn triple(&mut self, b: Val) -> Val {
        if b.is_zero() {
            return b;
        }
        let tripled = 3 * b.value;
        if b.constant {
            return self.constant(tripled % P);
        }
        let b_term = self.plain_term(b);
        let k_value = tripled / P;
        let out_value = tripled % P;
        let k = self.word(k_value).plain().expect("a fresh word is plain");
        self.below(k, 2);
        let out = self.word(out_value);
        let out_term = out.plain().expect("a fresh word is plain");
        let sum =
            self.chain(&[b_term], b.value, &[Self::moved(b_term, 1)], 2 * b.value, false, false);
        let left =
            self.chain(&sum.sum, tripled, &[Self::moved(k, 24)], k_value << 24, false, false);
        let right = self.chain(
            &[Self::moved(k, 31), out_term],
            (k_value << 31) | out_value,
            &[k],
            k_value,
            false,
            false,
        );
        self.assert_zero(left.sum.into_iter().chain(right.sum));
        self.range(out);
        out
    }

    /// `[v, 0, 0, 0]`.
    pub fn embed(value: Val) -> Ext {
        [value, Val::ZERO, Val::ZERO, Val::ZERO]
    }

    fn constant_ext(&mut self, value: Ef) -> Ext {
        let coefficients = value.as_basis_coefficients_slice();
        std::array::from_fn(|i| self.constant(canonical(coefficients[i])))
    }

    /// `a + b`.
    pub fn ext_add(&mut self, a: Ext, b: Ext) -> Ext {
        std::array::from_fn(|i| self.add(a[i], b[i]))
    }

    /// `a - b`.
    pub fn ext_sub(&mut self, a: Ext, b: Ext) -> Ext {
        std::array::from_fn(|i| self.sub(a[i], b[i]))
    }

    fn is_base(value: &Ext) -> bool {
        value[1..].iter().all(Val::is_zero)
    }

    fn is_constant(value: &Ext) -> bool {
        value.iter().all(|v| v.constant)
    }

    /// `a * b`.
    pub fn ext_mul(&mut self, a: Ext, b: Ext) -> Ext {
        if Self::is_constant(&a) && Self::is_constant(&b) {
            return self.constant_ext(ext_value(&a) * ext_value(&b));
        }
        if Self::is_base(&b) {
            return std::array::from_fn(|i| self.mul(a[i], b[0]));
        }
        if Self::is_base(&a) {
            return std::array::from_fn(|i| self.mul(a[0], b[i]));
        }
        let product = ext_value(&a) * ext_value(&b);
        let coefficients = product.as_basis_coefficients_slice();
        let out: Ext = std::array::from_fn(|i| self.word(canonical(coefficients[i])));
        for value in out {
            self.range(value);
        }
        self.ext_mul_into(a, b, out);
        out
    }

    /// `a * b = out` for a canonical `out`.
    pub fn ext_mul_into(&mut self, a: Ext, b: Ext, out: Ext) {
        if Self::is_base(&b) {
            for i in 0..4 {
                self.mul_into(a[i], b[0], out[i]);
            }
            return;
        }
        if Self::is_base(&a) {
            for i in 0..4 {
                self.mul_into(a[0], b[i], out[i]);
            }
            return;
        }
        let tripled: [Val; 4] =
            std::array::from_fn(|j| if j == 0 { Val::ZERO } else { self.triple(b[j]) });
        for (k, coefficient) in out.into_iter().enumerate() {
            let mut sum: Vec<Term> = Vec::new();
            let mut total = 0u64;
            for (i, left) in a.into_iter().enumerate() {
                let j = (k + 4 - i) % 4;
                let factor = if i <= k { b[j] } else { tripled[j] };
                if left.is_zero() || factor.is_zero() {
                    continue;
                }
                let product = left.value * factor.value;
                let x = self.word(product).plain().expect("a fresh word is plain");
                self.imul(left.terms(), factor.terms(), [x], []);
                if sum.is_empty() {
                    sum = vec![x];
                } else {
                    sum = self.chain(&sum, total, &[x], product, false, false).sum;
                }
                total += product;
            }
            self.reduce_wide(&sum, total, coefficient);
        }
    }

    /// `x = q p + r` for a hinted `q < 2^33`, where `x` is below `2^64`.
    fn reduce_wide(&mut self, x: &[Term], x_value: u64, r: Val) {
        if x.is_empty() {
            self.assert_zero(r.terms());
            return;
        }
        let q_value = x_value / P;
        let q = self.word(q_value).plain().expect("a fresh word is plain");
        self.below(q, 33);
        let left = self.chain(x, x_value, &[Self::moved(q, 24)], q_value << 24, false, true);
        let high = self.chain(&[Self::moved(q, 31)], q_value << 31, &[q], q_value, false, true);
        let r_terms: Vec<Term> = r.terms().collect();
        let right = self.chain(&high.sum, high.value, &r_terms, r.value, false, true);
        self.assert_zero(left.sum.into_iter().chain(right.sum));
    }

    /// `a / b`, with the runtime's conventions at zero.  The quotient is
    /// always range-checked: the product check assumes canonical factors.
    pub fn ext_div(&mut self, a: Ext, b: Ext) -> Ext {
        let b_value = ext_value(&b);
        let value = if b_value.is_zero() {
            if ext_value(&a).is_zero() {
                Ef::ONE
            } else {
                Ef::ZERO
            }
        } else {
            ext_value(&a) * b_value.inverse()
        };
        if Self::is_constant(&a) && Self::is_constant(&b) {
            return self.constant_ext(value);
        }
        let coefficients = value.as_basis_coefficients_slice();
        let out: Ext = std::array::from_fn(|i| self.word(canonical(coefficients[i])));
        for value in out {
            self.range(value);
        }
        self.ext_mul_into(b, out, a);
        out
    }

    /// The two outputs of a conditional swap: `bit ? (b, a) : (a, b)`.
    pub fn select(&mut self, bit: Val, a: Val, b: Val) -> (Val, Val) {
        if bit.constant {
            return if bit.value == 1 { (b, a) } else { (a, b) };
        }
        let bit_term = self.plain_term(bit);
        self.below(bit_term, 1);
        let mask = ShiftedValue::pair(
            bit_term.index(),
            p3_word::Shift::new(ShiftKind::LogicalLeft, 63).expect("a shift within the word"),
            p3_word::Shift::new(ShiftKind::ArithmeticRight, 63).expect("a shift within the word"),
        )
        .expect("a sign-extended bit is an irreducible pair");
        let a = self.materialize(a);
        let b = self.materialize(b);
        let diff_value = if bit.value == 1 { a.value ^ b.value } else { 0 };
        let diff = self.word(diff_value);
        self.and([mask], a.terms().chain(b.terms()), diff.terms());
        let first = self.xor(a, diff);
        let second = self.xor(b, diff);
        (first, second)
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;

    fn random(rng: &mut StdRng) -> u64 {
        rng.gen_range(0..P)
    }

    #[test]
    fn base_arithmetic_satisfies_its_relations() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut builder = Builder::new(0);
        for _ in 0..200 {
            let (x, y) = (random(&mut rng), random(&mut rng));
            let a = builder.hint(x);
            let b = builder.hint(y);
            let (fx, fy) = (felt(x), felt(y));
            assert_eq!(builder.add(a, b).value, canonical(fx + fy));
            assert_eq!(builder.sub(a, b).value, canonical(fx - fy));
            assert_eq!(builder.mul(a, b).value, canonical(fx * fy));
            assert_eq!(builder.triple(b).value, canonical(fy * KoalaBear::from_u8(3)));
            assert_eq!(builder.div(a, b, true).value, canonical(fx / fy));
            let c = builder.constant(y);
            assert_eq!(builder.mul(a, c).value, canonical(fx * fy));
        }
        for (x, y) in [(0, 0), (P - 1, P - 1), (P - 1, 1), (0, P - 1)] {
            let a = builder.hint(x);
            let b = builder.hint(y);
            builder.add(a, b);
            builder.sub(a, b);
            builder.mul(a, b);
            builder.triple(a);
        }
        let built = builder.build().unwrap();
        built.system.verify(&built.public, &built.witness).unwrap();
    }

    #[test]
    fn extension_arithmetic_satisfies_its_relations() {
        let mut rng = StdRng::seed_from_u64(2);
        let mut builder = Builder::new(0);
        for _ in 0..50 {
            let a: Ext = std::array::from_fn(|_| builder.hint(random(&mut rng)));
            let b: Ext = std::array::from_fn(|_| builder.hint(random(&mut rng)));
            let (x, y) = (ext_value(&a), ext_value(&b));
            assert_eq!(ext_value(&builder.ext_mul(a, b)), x * y);
            assert_eq!(ext_value(&builder.ext_div(a, b)), x / y);
            assert_eq!(ext_value(&builder.ext_add(a, b)), x + y);
            assert_eq!(ext_value(&builder.ext_sub(a, b)), x - y);
            let base = Builder::embed(b[0]);
            assert_eq!(ext_value(&builder.ext_mul(a, base)), x * Ef::from(felt(b[0].value)));
        }
        let worst: Ext = std::array::from_fn(|_| builder.hint(P - 1));
        builder.ext_mul(worst, worst);
        let built = builder.build().unwrap();
        built.system.verify(&built.public, &built.witness).unwrap();
    }

    #[test]
    fn a_wrong_product_is_rejected() {
        let mut builder = Builder::new(0);
        let a = builder.hint(123_456_789);
        let b = builder.hint(987_654_321 % P);
        let product = builder.mul(a, b);
        let built = builder.build().unwrap();
        let mut witness = built.witness.clone();
        let index = product.plain().unwrap().index().position() as usize;
        witness[index] = p3_word::Word64::new((product.value + 1) % P);
        assert!(built.system.verify(&built.public, &witness).is_err());
        witness[index] = p3_word::Word64::new(product.value + P);
        assert!(built.system.verify(&built.public, &witness).is_err());
    }

    #[test]
    fn select_swaps_on_one() {
        let mut builder = Builder::new(0);
        let a = builder.hint(5);
        let b = builder.hint(9);
        for bit in [0, 1] {
            let bit = builder.hint_bit(bit);
            let (first, second) = builder.select(bit, a, b);
            let expected = if bit.value == 1 { (9, 5) } else { (5, 9) };
            assert_eq!((first.value, second.value), expected);
        }
        let built = builder.build().unwrap();
        built.system.verify(&built.public, &built.witness).unwrap();
    }
}
