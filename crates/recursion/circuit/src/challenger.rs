use p3_field::{
    absorb_radix_bits, max_absorb_injective_limbs, squeeze_field_order_num_limbs, BasedVectorSpace,
    PrimeCharacteristicRing,
};
use p3_koala_bear::KoalaBear;
use zkm_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{DslIr, Var},
    prelude::{Builder, Config, Ext, Felt},
};
use zkm_recursion_core::{
    air::ChallengerPublicValues,
    runtime::{HASH_RATE, PERMUTATION_WIDTH},
    stark::{
        OUTER_MULTI_FIELD_CHALLENGER_DIGEST_SIZE, OUTER_MULTI_FIELD_CHALLENGER_RATE,
        OUTER_MULTI_FIELD_CHALLENGER_WIDTH,
    },
    NUM_BITS,
};

// use crate::{DigestVariable, VerifyingKeyVariable};

pub trait CanCopyChallenger<C: Config> {
    fn copy(&self, builder: &mut Builder<C>) -> Self;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpongeChallengerShape {
    pub input_buffer_len: usize,
    pub output_buffer_len: usize,
}

/// Reference: [p3_challenger::CanObserve].
pub trait CanObserveVariable<C: Config, V> {
    fn observe(&mut self, builder: &mut Builder<C>, value: V);

    fn observe_slice(&mut self, builder: &mut Builder<C>, values: impl IntoIterator<Item = V>) {
        for value in values {
            self.observe(builder, value);
        }
    }
}

pub trait CanSampleVariable<C: Config, V> {
    fn sample(&mut self, builder: &mut Builder<C>) -> V;
}

/// Reference: [p3_challenger::FieldChallenger].
pub trait FieldChallengerVariable<C: Config, Bit>:
    CanObserveVariable<C, Felt<C::F>> + CanSampleVariable<C, Felt<C::F>> + CanSampleBitsVariable<C, Bit>
{
    fn sample_ext(&mut self, builder: &mut Builder<C>) -> Ext<C::F, C::EF>;

    fn check_witness(&mut self, builder: &mut Builder<C>, nb_bits: usize, witness: Felt<C::F>);

    /// LogUp-GKR grinding check, mirroring the host `gkr_check_witness`
    /// (crates/pcs/src/logup_gkr.rs).
    ///
    /// EVERY production ring performs it. The default delegates to
    /// [`Self::check_witness`] — observe the witness, sample `nb_bits`, assert
    /// they are zero — and no ring overrides it.
    ///
    /// An override that returned without touching the challenger would not be a
    /// cheaper equivalent. It would leave the transcript un-advanced while the
    /// prover's grind advanced its own, desynchronising every subsequent
    /// alpha/beta; and `docs/soundness/ziren.soundcalc.toml` credits
    /// `grinding_bits_lookup = 16` on every circuit, so the accounting would
    /// describe a transcript the protocol did not execute. Such an override
    /// existed here on the wrap ring, on the premise that the outer challenger
    /// could not grind — a premise the wrap WHIR open disproves by grinding
    /// its query, folding and batching challenges through the same trait.
    fn gkr_check_witness(&mut self, builder: &mut Builder<C>, nb_bits: usize, witness: Felt<C::F>) {
        self.check_witness(builder, nb_bits, witness);
    }

    fn duplexing(&mut self, builder: &mut Builder<C>);
}

pub trait CanSampleBitsVariable<C: Config, V> {
    fn sample_bits(&mut self, builder: &mut Builder<C>, nb_bits: usize) -> Vec<V>;
}

/// Reference: [p3_challenger::DuplexChallenger]
#[derive(Clone, Debug)]
pub struct DuplexChallengerVariable<C: Config> {
    pub sponge_state: [Felt<C::F>; PERMUTATION_WIDTH],
    pub input_buffer: Vec<Felt<C::F>>,
    pub output_buffer: Vec<Felt<C::F>>,
}

impl<C: Config<F = KoalaBear>> DuplexChallengerVariable<C> {
    /// Creates a new duplex challenger with the default state.
    pub fn new(builder: &mut Builder<C>) -> Self {
        DuplexChallengerVariable::<C> {
            sponge_state: core::array::from_fn(|_| builder.eval(C::F::ZERO)),
            input_buffer: vec![],
            output_buffer: vec![],
        }
    }

    /// Creates a new challenger with the same state as an existing challenger.
    pub fn copy(&self, builder: &mut Builder<C>) -> Self {
        let DuplexChallengerVariable { sponge_state, input_buffer, output_buffer } = self;
        let sponge_state = sponge_state.map(|x| builder.eval(x));
        let mut copy_vec = |v: &Vec<Felt<C::F>>| v.iter().map(|x| builder.eval(*x)).collect();
        DuplexChallengerVariable::<C> {
            sponge_state,
            input_buffer: copy_vec(input_buffer),
            output_buffer: copy_vec(output_buffer),
        }
    }

    fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        self.output_buffer.clear();

        self.input_buffer.push(value);

        if self.input_buffer.len() == HASH_RATE {
            self.duplexing(builder);
        }
    }

    fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
            self.duplexing(builder);
        }

        self.output_buffer.pop().expect("output buffer should be non-empty")
    }

    fn sample_bits(&mut self, builder: &mut Builder<C>, nb_bits: usize) -> Vec<Felt<C::F>> {
        assert!(nb_bits <= NUM_BITS);
        let rand_f = self.sample(builder);
        let mut rand_f_bits = builder.num2bits_v2_f(rand_f, NUM_BITS);
        rand_f_bits.truncate(nb_bits);
        rand_f_bits
    }

    pub fn public_values(&self, builder: &mut Builder<C>) -> ChallengerPublicValues<Felt<C::F>> {
        assert!(self.input_buffer.len() <= PERMUTATION_WIDTH);
        assert!(self.output_buffer.len() <= PERMUTATION_WIDTH);

        let sponge_state = self.sponge_state;
        let num_inputs = builder.eval(C::F::from_usize(self.input_buffer.len()));
        let num_outputs = builder.eval(C::F::from_usize(self.output_buffer.len()));

        let input_buffer: [_; PERMUTATION_WIDTH] = self
            .input_buffer
            .iter()
            .copied()
            .chain((self.input_buffer.len()..PERMUTATION_WIDTH).map(|_| builder.eval(C::F::ZERO)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let output_buffer: [_; PERMUTATION_WIDTH] = self
            .output_buffer
            .iter()
            .copied()
            .chain((self.output_buffer.len()..PERMUTATION_WIDTH).map(|_| builder.eval(C::F::ZERO)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        ChallengerPublicValues {
            sponge_state,
            num_inputs,
            input_buffer,
            num_outputs,
            output_buffer,
        }
    }
}

impl<C: Config<F = KoalaBear>> CanCopyChallenger<C> for DuplexChallengerVariable<C> {
    fn copy(&self, builder: &mut Builder<C>) -> Self {
        DuplexChallengerVariable::copy(self, builder)
    }
}

impl<C: Config<F = KoalaBear>> CanObserveVariable<C, Felt<C::F>> for DuplexChallengerVariable<C> {
    fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        DuplexChallengerVariable::observe(self, builder, value);
    }

    fn observe_slice(
        &mut self,
        builder: &mut Builder<C>,
        values: impl IntoIterator<Item = Felt<C::F>>,
    ) {
        for value in values {
            self.observe(builder, value);
        }
    }
}

impl<C: Config<F = KoalaBear>, const N: usize> CanObserveVariable<C, [Felt<C::F>; N]>
    for DuplexChallengerVariable<C>
{
    fn observe(&mut self, builder: &mut Builder<C>, values: [Felt<C::F>; N]) {
        for value in values {
            self.observe(builder, value);
        }
    }
}

impl<C: Config<F = KoalaBear>> CanSampleVariable<C, Felt<C::F>> for DuplexChallengerVariable<C> {
    fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        DuplexChallengerVariable::sample(self, builder)
    }
}

impl<C: Config<F = KoalaBear>> CanSampleBitsVariable<C, Felt<C::F>>
    for DuplexChallengerVariable<C>
{
    fn sample_bits(&mut self, builder: &mut Builder<C>, nb_bits: usize) -> Vec<Felt<C::F>> {
        DuplexChallengerVariable::sample_bits(self, builder, nb_bits)
    }
}

impl<C: Config<F = KoalaBear>> FieldChallengerVariable<C, Felt<C::F>>
    for DuplexChallengerVariable<C>
{
    fn sample_ext(&mut self, builder: &mut Builder<C>) -> Ext<C::F, C::EF> {
        let a = self.sample(builder);
        let b = self.sample(builder);
        let c = self.sample(builder);
        let d = self.sample(builder);
        builder.ext_from_base_slice(&[a, b, c, d])
    }

    fn check_witness(
        &mut self,
        builder: &mut Builder<C>,
        nb_bits: usize,
        witness: Felt<<C as Config>::F>,
    ) {
        if nb_bits == 0 {
            return;
        }
        self.observe(builder, witness);
        let element_bits = self.sample_bits(builder, nb_bits);
        for bit in element_bits {
            builder.assert_felt_eq(bit, C::F::ZERO);
        }
    }

    fn duplexing(&mut self, builder: &mut Builder<C>) {
        let num_absorbed = self.input_buffer.len();
        assert!(num_absorbed <= HASH_RATE);

        self.sponge_state[0..num_absorbed].copy_from_slice(self.input_buffer.as_slice());
        self.input_buffer.clear();

        // An absorb zeroes the rate slots it did not fill and binds its length into the first
        // capacity element; a squeeze permutes the state as it is.
        if num_absorbed > 0 {
            for slot in &mut self.sponge_state[num_absorbed..HASH_RATE] {
                *slot = builder.eval(C::F::ZERO);
            }
            self.sponge_state[HASH_RATE] =
                builder.eval(self.sponge_state[HASH_RATE] + C::F::from_usize(num_absorbed));
        }

        self.sponge_state = builder.poseidon2_permute_v2(self.sponge_state);

        self.output_buffer.clear();
        self.output_buffer.extend_from_slice(&self.sponge_state[..HASH_RATE]);
    }
}

/// In-circuit twin of [`p3_challenger::MultiField32Challenger`].
#[derive(Clone)]
pub struct MultiField32ChallengerVariable<C: Config> {
    sponge_state: [Var<C::N>; OUTER_MULTI_FIELD_CHALLENGER_WIDTH],
    input_buffer: Vec<Felt<C::F>>,
    output_buffer: Vec<Felt<C::F>>,
    /// Whether the rate of `sponge_state` has been permuted but not yet squeezed.
    rate_unsqueezed: bool,
}

impl<C: Config> MultiField32ChallengerVariable<C> {
    pub fn new(builder: &mut Builder<C>) -> Self {
        MultiField32ChallengerVariable::<C> {
            sponge_state: core::array::from_fn(|_| builder.eval(C::N::ZERO)),
            input_buffer: vec![],
            output_buffer: vec![],
            rate_unsqueezed: false,
        }
    }

    fn absorb_num_f_elms() -> usize {
        max_absorb_injective_limbs::<C::F, C::N>()
    }

    fn squeeze_num_f_elms() -> usize {
        squeeze_field_order_num_limbs::<C::N, C::F>()
    }

    /// Reference: [p3_challenger::DuplexChallenger::absorb_rate_padded_with_tag].
    fn absorb_rate_padded_with_tag(
        &mut self,
        builder: &mut Builder<C>,
        values: &[Var<C::N>],
        length_tag: u8,
    ) {
        assert!(values.len() <= OUTER_MULTI_FIELD_CHALLENGER_RATE);
        for (i, slot) in
            self.sponge_state[..OUTER_MULTI_FIELD_CHALLENGER_RATE].iter_mut().enumerate()
        {
            *slot = match values.get(i) {
                Some(&value) => value,
                None => builder.eval(C::N::ZERO),
            };
        }
        let capacity = self.sponge_state[OUTER_MULTI_FIELD_CHALLENGER_RATE];
        self.sponge_state[OUTER_MULTI_FIELD_CHALLENGER_RATE] =
            builder.eval(capacity + C::N::from_u8(length_tag));
        builder.push_op(DslIr::CircuitPoseidon2Permute(self.sponge_state));
        self.output_buffer.clear();
        self.rate_unsqueezed = true;
    }

    fn flush_input_buffer(&mut self, builder: &mut Builder<C>) {
        if self.input_buffer.is_empty() {
            return;
        }
        let num_absorbed = self.input_buffer.len();
        assert!(num_absorbed <= Self::absorb_num_f_elms() * OUTER_MULTI_FIELD_CHALLENGER_RATE);
        let radix_bits = absorb_radix_bits::<C::F>();
        let packed = self
            .input_buffer
            .chunks(Self::absorb_num_f_elms())
            .map(|chunk| reduce_packed(builder, chunk, radix_bits, 0))
            .collect::<Vec<_>>();
        self.input_buffer.clear();
        self.absorb_rate_padded_with_tag(builder, &packed, num_absorbed as u8);
    }

    pub fn duplexing(&mut self, builder: &mut Builder<C>) {
        if !self.input_buffer.is_empty() {
            self.flush_input_buffer(builder);
            return;
        }
        builder.push_op(DslIr::CircuitPoseidon2Permute(self.sponge_state));
        self.output_buffer.clear();
        self.rate_unsqueezed = true;
    }

    pub fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        self.output_buffer.clear();
        self.rate_unsqueezed = false;

        self.input_buffer.push(value);
        if self.input_buffer.len() == Self::absorb_num_f_elms() * OUTER_MULTI_FIELD_CHALLENGER_RATE
        {
            self.flush_input_buffer(builder);
        }
    }

    pub fn observe_commitment(
        &mut self,
        builder: &mut Builder<C>,
        value: [Var<C::N>; OUTER_MULTI_FIELD_CHALLENGER_DIGEST_SIZE],
    ) {
        self.output_buffer.clear();
        self.rate_unsqueezed = false;
        self.flush_input_buffer(builder);
        for chunk in value.chunks(OUTER_MULTI_FIELD_CHALLENGER_RATE) {
            self.absorb_rate_padded_with_tag(builder, chunk, chunk.len() as u8);
        }
    }

    pub fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        self.flush_input_buffer(builder);
        if self.output_buffer.is_empty() {
            if !self.rate_unsqueezed {
                self.duplexing(builder);
            }
            for &pf_val in self.sponge_state[..OUTER_MULTI_FIELD_CHALLENGER_RATE].iter() {
                let limbs =
                    builder.var2field_order_limbs_circuit(pf_val, Self::squeeze_num_f_elms());
                self.output_buffer.extend(limbs);
            }
            self.rate_unsqueezed = false;
        }

        self.output_buffer.pop().expect("output buffer should be non-empty")
    }

    pub fn sample_ext(&mut self, builder: &mut Builder<C>) -> Ext<C::F, C::EF> {
        let dim = <C::EF as BasedVectorSpace<C::F>>::DIMENSION;
        let samples: Vec<Felt<C::F>> = (0..dim).map(|_| self.sample(builder)).collect();
        builder.felts2ext(&samples)
    }

    pub fn sample_bits(&mut self, builder: &mut Builder<C>, bits: usize) -> Vec<Var<C::N>> {
        let rand_f = self.sample(builder);
        builder.num2bits_f_circuit(rand_f)[0..bits].to_vec()
    }

    pub fn check_witness(&mut self, builder: &mut Builder<C>, bits: usize, witness: Felt<C::F>) {
        if bits == 0 {
            return;
        }
        self.observe(builder, witness);
        let sampled = self.sample_bits(builder, bits);
        for bit in sampled {
            builder.assert_var_eq(bit, C::N::ZERO);
        }
    }
}

impl<C: Config> CanCopyChallenger<C> for MultiField32ChallengerVariable<C> {
    /// Creates a new challenger with the same state as an existing challenger.
    fn copy(&self, builder: &mut Builder<C>) -> Self {
        let MultiField32ChallengerVariable {
            sponge_state,
            input_buffer,
            output_buffer,
            rate_unsqueezed,
        } = self;
        let sponge_state = sponge_state.map(|x| builder.eval(x));
        let mut copy_vec = |v: &Vec<Felt<C::F>>| v.iter().map(|x| builder.eval(*x)).collect();
        MultiField32ChallengerVariable::<C> {
            sponge_state,
            input_buffer: copy_vec(input_buffer),
            output_buffer: copy_vec(output_buffer),
            rate_unsqueezed: *rate_unsqueezed,
        }
    }
}

impl<C: Config> CanObserveVariable<C, Felt<C::F>> for MultiField32ChallengerVariable<C> {
    fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        MultiField32ChallengerVariable::observe(self, builder, value);
    }
}

impl<C: Config> CanObserveVariable<C, [Var<C::N>; OUTER_MULTI_FIELD_CHALLENGER_DIGEST_SIZE]>
    for MultiField32ChallengerVariable<C>
{
    fn observe(
        &mut self,
        builder: &mut Builder<C>,
        value: [Var<C::N>; OUTER_MULTI_FIELD_CHALLENGER_DIGEST_SIZE],
    ) {
        self.observe_commitment(builder, value)
    }
}

impl<C: Config> CanObserveVariable<C, Var<C::N>> for MultiField32ChallengerVariable<C> {
    fn observe(&mut self, builder: &mut Builder<C>, value: Var<C::N>) {
        self.observe_commitment(builder, [value])
    }
}

impl<C: Config> CanSampleVariable<C, Felt<C::F>> for MultiField32ChallengerVariable<C> {
    fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        MultiField32ChallengerVariable::sample(self, builder)
    }
}

impl<C: Config> CanSampleBitsVariable<C, Var<C::N>> for MultiField32ChallengerVariable<C> {
    fn sample_bits(&mut self, builder: &mut Builder<C>, bits: usize) -> Vec<Var<C::N>> {
        MultiField32ChallengerVariable::sample_bits(self, builder, bits)
    }
}

impl<C: Config> FieldChallengerVariable<C, Var<C::N>> for MultiField32ChallengerVariable<C> {
    fn sample_ext(&mut self, builder: &mut Builder<C>) -> Ext<C::F, C::EF> {
        MultiField32ChallengerVariable::sample_ext(self, builder)
    }

    fn check_witness(&mut self, builder: &mut Builder<C>, bits: usize, witness: Felt<C::F>) {
        MultiField32ChallengerVariable::check_witness(self, builder, bits, witness);
    }

    // No `gkr_check_witness` override: this ring takes the trait default, which
    // delegates to `check_witness` above — observe the witness, sample
    // `nb_bits`, assert they are zero.  The prover grinds on every ring
    // (`prove_shard_logup_gkr_rows`), so a no-op here would leave the
    // transcript un-advanced and desync every subsequent alpha/beta.

    fn duplexing(&mut self, builder: &mut Builder<C>) {
        MultiField32ChallengerVariable::duplexing(self, builder);
    }
}

/// Packs `vals` little-endian in radix `2^radix_bits`, adding `shift` to every digit.
///
/// Reference: [p3_field::reduce_packed] (`shift == 0`) and [p3_field::reduce_packed_shifted]
/// (`shift == 1`).
pub fn reduce_packed<C: Config>(
    builder: &mut Builder<C>,
    vals: &[Felt<C::F>],
    radix_bits: u32,
    shift: u64,
) -> Var<C::N> {
    let base = C::N::from_u64(1u64 << radix_bits);
    let mut power = C::N::ONE;
    let result: Var<C::N> = builder.eval(C::N::ZERO);
    for val in vals.iter() {
        let val = builder.felt2var_circuit(*val);
        builder.assign(result, result + (val + C::N::from_u64(shift)) * power);
        power *= base;
    }
    result
}

pub fn split_32<C: Config>(builder: &mut Builder<C>, val: Var<C::N>, n: usize) -> Vec<Felt<C::F>> {
    let bits = builder.num2bits_v_circuit(val, 256);
    let mut results = Vec::new();
    for i in 0..n {
        let result: Felt<C::F> = builder.eval(C::F::ZERO);
        for j in 0..64 {
            let bit = bits[i * 64 + j];
            let t = builder.eval(result + C::F::from_u64(1 << j));
            let z = builder.select_f(bit, t, result);
            builder.assign(result, z);
        }
        results.push(result);
    }
    results
}

#[cfg(test)]
pub(crate) mod tests {
    use std::iter::zip;

    use crate::{
        challenger::{CanCopyChallenger, CanObserveVariable, MultiField32ChallengerVariable},
        hash::{FieldHasherVariable, BN254_DIGEST_SIZE},
        utils::tests::run_test_recursion,
    };
    use num_bigint::BigUint;
    use p3_bn254_fr::Bn254;
    use p3_challenger::{
        CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger,
    };
    use p3_field::{
        split_pf_to_field_order_limbs, squeeze_field_order_num_limbs, Field,
        PrimeCharacteristicRing, PrimeField32,
    };
    use p3_koala_bear::KoalaBear;
    use p3_symmetric::{CryptographicHasher, Hash, PseudoCompressionFunction};
    use zkm_pcs::{koala_bear_poseidon2::KoalaBearPoseidon2, StarkGenericConfig};
    use zkm_recursion_compiler::{
        circuit::{AsmBuilder, AsmConfig},
        config::OuterConfig,
        constraints::ConstraintCompiler,
        ir::{Builder, Config, Ext, ExtConst, Felt, Var},
    };
    use zkm_recursion_core::stark::{
        outer_perm, KoalaBearPoseidon2Outer, OuterCompress, OuterHash,
    };
    use zkm_recursion_gnark_ffi::PlonkBn254Prover;

    use crate::{
        challenger::{DuplexChallengerVariable, FieldChallengerVariable},
        witness::OuterWitness,
    };

    type SC = KoalaBearPoseidon2;
    type C = OuterConfig;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    #[test]
    fn test_compiler_challenger() {
        let config = SC::default();
        let mut challenger = config.challenger();
        challenger.observe(F::ONE);
        challenger.observe(F::TWO);
        challenger.observe(F::TWO);
        challenger.observe(F::TWO);
        let result: F = challenger.sample();
        println!("expected result: {result}");
        let result_ef: EF = challenger.sample_algebra_element();
        println!("expected result_ef: {result_ef}");

        let mut builder = AsmBuilder::<F, EF>::default();

        let mut challenger = DuplexChallengerVariable::<AsmConfig<F, EF>> {
            sponge_state: core::array::from_fn(|_| builder.eval(F::ZERO)),
            input_buffer: vec![],
            output_buffer: vec![],
        };
        let one: Felt<_> = builder.eval(F::ONE);
        let two: Felt<_> = builder.eval(F::TWO);

        challenger.observe(&mut builder, one);
        challenger.observe(&mut builder, two);
        challenger.observe(&mut builder, two);
        challenger.observe(&mut builder, two);
        let element = challenger.sample(&mut builder);
        let element_ef = challenger.sample_ext(&mut builder);

        let expected_result: Felt<_> = builder.eval(result);
        let expected_result_ef: Ext<_, _> = builder.eval(result_ef.cons());
        builder.print_f(element);
        builder.assert_felt_eq(expected_result, element);
        builder.print_e(element_ef);
        builder.assert_ext_eq(expected_result_ef, element_ef);

        run_test_recursion(builder.into_operations(), None);
    }

    #[test]
    fn test_compiler_challenger_buffer_boundaries() {
        let lengths = [0usize, 1, 7, 8, 9, 15, 16, 17];
        let value = |k: usize, j: usize| F::from_usize(k * 31 + j + 1);
        let bits = 8;

        let config = SC::default();
        let mut challenger = config.challenger();
        let mut expected = Vec::new();
        for k in lengths {
            for j in 0..k {
                challenger.observe(value(k, j));
            }
            expected.push(CanSample::<F>::sample(&mut challenger));
        }
        let expected_ef: EF = challenger.sample_algebra_element();
        challenger.observe(F::from_u32(5));
        let witness = challenger.grind(bits);
        let expected_after_grind: F = challenger.sample();

        let mut builder = AsmBuilder::<F, EF>::default();
        let mut challenger = DuplexChallengerVariable::<AsmConfig<F, EF>>::new(&mut builder);
        for (k, expected) in lengths.into_iter().zip(expected) {
            for j in 0..k {
                let v: Felt<_> = builder.eval(value(k, j));
                challenger.observe(&mut builder, v);
            }
            let element = challenger.sample(&mut builder);
            builder.assert_felt_eq(element, expected);
        }
        let element_ef = challenger.sample_ext(&mut builder);
        let expected_ef: Ext<_, _> = builder.eval(expected_ef.cons());
        builder.assert_ext_eq(expected_ef, element_ef);
        let five: Felt<_> = builder.eval(F::from_u32(5));
        challenger.observe(&mut builder, five);
        let witness: Felt<_> = builder.eval(witness);
        challenger.check_witness(&mut builder, bits, witness);
        let element = challenger.sample(&mut builder);
        builder.assert_felt_eq(element, expected_after_grind);

        run_test_recursion(builder.into_operations(), None);
    }

    #[test]
    fn test_challenger_outer() {
        type SC = KoalaBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type N = <C as Config>::N;

        let config = SC::default();
        let mut challenger = config.challenger();
        challenger.observe(F::ONE);
        challenger.observe(F::TWO);
        challenger.observe(F::TWO);
        challenger.observe(F::TWO);
        let commit = Hash::from([N::TWO]);
        challenger.observe(commit);
        let result: F = challenger.sample();
        println!("expected result: {result}");
        let result_ef: EF = challenger.sample_algebra_element();
        println!("expected result_ef: {result_ef}");
        let mut bits = challenger.sample_bits(30);
        let mut bits_vec = vec![];
        for _ in 0..30 {
            bits_vec.push(bits % 2);
            bits >>= 1;
        }
        println!("expected bits: {bits_vec:?}");

        let mut builder = Builder::<C>::default();

        let mut challenger = MultiField32ChallengerVariable::<C>::new(&mut builder);
        let one: Felt<_> = builder.eval(F::ONE);
        let two: Felt<_> = builder.eval(F::TWO);
        let two_var: Var<_> = builder.eval(N::TWO);
        challenger.observe(&mut builder, one);
        challenger.observe(&mut builder, two);
        challenger.observe(&mut builder, two);
        challenger.observe(&mut builder, two);
        challenger.observe_commitment(&mut builder, [two_var]);

        challenger = challenger.copy(&mut builder);
        let element = challenger.sample(&mut builder);
        let element_ef = challenger.sample_ext(&mut builder);
        let bits = challenger.sample_bits(&mut builder, 31);

        let expected_result: Felt<_> = builder.eval(result);
        let expected_result_ef: Ext<_, _> = builder.eval(result_ef.cons());
        builder.print_f(element);
        builder.assert_felt_eq(expected_result, element);
        builder.print_e(element_ef);
        builder.assert_ext_eq(expected_result_ef, element_ef);
        for (expected_bit, bit) in zip(bits_vec.iter(), bits.iter()) {
            let expected_bit: Var<_> = builder.eval(N::from_usize(*expected_bit));
            builder.print_v(*bit);
            builder.assert_var_eq(expected_bit, *bit);
        }

        let mut backend = ConstraintCompiler::<C>::default();
        let constraints = backend.emit(builder.into_operations());
        let witness = OuterWitness::default();
        PlonkBn254Prover::test::<C>(constraints, witness);
    }

    #[test]
    fn test_challenger_outer_buffer_boundaries() {
        type SC = KoalaBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type N = <C as Config>::N;

        let inputs: Vec<F> = (0..37u32).map(|i| F::from_u32(i * 0x0101_0101 + 7)).collect();
        let commits = [N::from_u64(3), -N::ONE];

        let config = SC::default();
        let mut challenger = config.challenger();
        let mut expected: Vec<F> = vec![];
        challenger.observe_slice(&inputs[..16]);
        challenger.observe(Hash::from([commits[0]]));
        expected.extend((0..15).map(|_| CanSample::<F>::sample(&mut challenger)));
        challenger.observe_slice(&inputs[16..]);
        expected.push(challenger.sample());
        challenger.observe(Hash::from([commits[1]]));
        challenger.observe(inputs[0]);
        expected.extend((0..30).map(|_| CanSample::<F>::sample(&mut challenger)));

        let mut builder = Builder::<C>::default();
        let inputs: Vec<Felt<_>> = inputs.iter().map(|x| builder.eval(*x)).collect();
        let commits: Vec<Var<_>> = commits.iter().map(|x| builder.eval(*x)).collect();
        let mut challenger = MultiField32ChallengerVariable::<C>::new(&mut builder);
        let mut actual: Vec<Felt<_>> = vec![];
        challenger.observe_slice(&mut builder, inputs[..16].iter().copied());
        challenger.observe_commitment(&mut builder, [commits[0]]);
        actual.extend((0..15).map(|_| challenger.sample(&mut builder)));
        challenger.observe_slice(&mut builder, inputs[16..].iter().copied());
        actual.push(challenger.sample(&mut builder));
        challenger.observe_commitment(&mut builder, [commits[1]]);
        challenger.observe(&mut builder, inputs[0]);
        actual.extend((0..30).map(|_| challenger.sample(&mut builder)));

        for (expected, actual) in zip(expected, actual) {
            let expected: Felt<_> = builder.eval(expected);
            builder.assert_felt_eq(expected, actual);
        }

        let mut backend = ConstraintCompiler::<C>::default();
        let constraints = backend.emit(builder.into_operations());
        PlonkBn254Prover::test::<C>(constraints, OuterWitness::default());
    }

    #[test]
    fn test_var2field_order_limbs() {
        type N = <C as Config>::N;

        let p = BigUint::from(KoalaBear::ORDER_U32);
        let num_limbs = squeeze_field_order_num_limbs::<N, KoalaBear>();
        let limbs_order = p.pow(num_limbs as u32);
        let native_max = N::order() - 1u32;
        let high_max = &native_max / &limbs_order;
        let values = [
            BigUint::ZERO,
            BigUint::from(1u32),
            &p - 1u32,
            &limbs_order - 1u32,
            limbs_order.clone(),
            &high_max * &limbs_order - 1u32,
            &high_max * &limbs_order,
            native_max.clone(),
        ];

        let mut builder = Builder::<C>::default();
        for value in values {
            let value = value
                .to_u32_digits()
                .iter()
                .rev()
                .fold(N::ZERO, |acc, &digit| acc * N::from_u64(1 << 32) + N::from_u32(digit));
            let expected = split_pf_to_field_order_limbs::<N, KoalaBear>(value, num_limbs);
            let var: Var<_> = builder.eval(value);
            let limbs = builder.var2field_order_limbs_circuit(var, num_limbs);
            for (expected, limb) in zip(expected, limbs) {
                let expected: Felt<_> = builder.eval(expected);
                builder.assert_felt_eq(expected, limb);
            }
        }

        let mut backend = ConstraintCompiler::<C>::default();
        let constraints = backend.emit(builder.into_operations());
        PlonkBn254Prover::test::<C>(constraints, OuterWitness::default());
    }

    #[test]
    fn test_select_chain_digest() {
        type N = <C as Config>::N;

        let mut builder = Builder::<C>::default();

        let one: Var<_> = builder.eval(N::ONE);
        let two: Var<_> = builder.eval(N::TWO);

        let to_swap = [[one], [two]];
        let result = KoalaBearPoseidon2Outer::select_chain_digest(&mut builder, one, to_swap);

        builder.assert_var_eq(result[0][0], two);
        builder.assert_var_eq(result[1][0], one);

        let mut backend = ConstraintCompiler::<C>::default();
        let constraints = backend.emit(builder.into_operations());
        let witness = OuterWitness::default();
        PlonkBn254Prover::test::<C>(constraints, witness);
    }

    #[test]
    fn test_p2_hash() {
        let perm = outer_perm();
        let hasher = OuterHash::new(perm.clone()).unwrap();

        let input: [KoalaBear; 7] = [
            KoalaBear::from_u32(0),
            KoalaBear::from_u32(1),
            KoalaBear::from_u32(2),
            KoalaBear::from_u32(2),
            KoalaBear::from_u32(2),
            KoalaBear::from_u32(2),
            KoalaBear::from_u32(2),
        ];
        let output = hasher.hash_iter(input);

        let mut builder = Builder::<C>::default();
        let a: Felt<_> = builder.eval(input[0]);
        let b: Felt<_> = builder.eval(input[1]);
        let c: Felt<_> = builder.eval(input[2]);
        let d: Felt<_> = builder.eval(input[3]);
        let e: Felt<_> = builder.eval(input[4]);
        let f: Felt<_> = builder.eval(input[5]);
        let g: Felt<_> = builder.eval(input[6]);
        let result = KoalaBearPoseidon2Outer::hash(&mut builder, &[a, b, c, d, e, f, g]);

        builder.assert_var_eq(result[0], output[0]);

        let mut backend = ConstraintCompiler::<C>::default();
        let constraints = backend.emit(builder.into_operations());
        PlonkBn254Prover::test::<C>(constraints.clone(), OuterWitness::default());
    }

    #[test]
    fn test_p2_hash_multi_block() {
        let hasher = OuterHash::new(outer_perm()).unwrap();

        let mut builder = Builder::<C>::default();
        for len in [8, 16, 17, 37] {
            let input: Vec<KoalaBear> = (0..len as u32)
                .map(|i| if i % 3 == 0 { -KoalaBear::ONE } else { KoalaBear::from_u32(i) })
                .collect();
            let output = hasher.hash_iter(input.clone());
            let input: Vec<Felt<_>> = input.iter().map(|x| builder.eval(*x)).collect();
            let result = KoalaBearPoseidon2Outer::hash(&mut builder, &input);
            builder.assert_var_eq(result[0], output[0]);
        }

        let mut backend = ConstraintCompiler::<C>::default();
        let constraints = backend.emit(builder.into_operations());
        PlonkBn254Prover::test::<C>(constraints, OuterWitness::default());
    }

    #[test]
    fn test_p2_hash_separates_radix_2_32_aliases() {
        // Two leaves whose radix-2^32 packings agree modulo the BN254 order.
        let a = [
            1674139105, 783634716, 83980271, 435370277, 2128230004, 1631819590, 1715136804,
            319034021,
        ]
        .map(KoalaBear::from_u32);
        let b = [
            1405703650, 1922516656, 2126176384, 1109860717, 6000337, 429120765, 1198295374,
            1130914072,
        ]
        .map(KoalaBear::from_u32);
        let hasher = OuterHash::new(outer_perm()).unwrap();
        assert_ne!(hasher.hash_iter(a), hasher.hash_iter(b));
    }

    #[test]
    fn test_p2_compress() {
        type OuterDigestVariable = [Var<<C as Config>::N>; BN254_DIGEST_SIZE];
        let perm = outer_perm();
        let compressor = OuterCompress::new(perm.clone());

        let a: [Bn254; 1] = [Bn254::TWO];
        let b: [Bn254; 1] = [Bn254::TWO];
        let gt = compressor.compress([a, b]);

        let mut builder = Builder::<C>::default();
        let a: OuterDigestVariable = [builder.eval(a[0])];
        let b: OuterDigestVariable = [builder.eval(b[0])];
        let result = KoalaBearPoseidon2Outer::compress(&mut builder, [a, b]);
        builder.assert_var_eq(result[0], gt[0]);

        let mut backend = ConstraintCompiler::<C>::default();
        let constraints = backend.emit(builder.into_operations());
        PlonkBn254Prover::test::<C>(constraints.clone(), OuterWitness::default());
    }
}
