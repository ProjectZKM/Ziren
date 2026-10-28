use p3_field::{
    absorb_radix_bits, max_absorb_injective_limbs, squeeze_field_order_num_limbs, BasedVectorSpace,
    PrimeCharacteristicRing,
};
use p3_koala_bear::KoalaBear;

use crate::CircuitConfig;
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
    /// could not grind — a premise the wrap BaseFold open disproves by grinding
    /// `pow_bits = 22` through the same trait.
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

    /// Absorb the buffered inputs and permute, as the length-tagged duplex
    /// sponge does: the inputs fill the first rate lanes, the remaining rate
    /// lanes are zeroed, and the first capacity lane is raised by the number
    /// absorbed, so that absorbing `[x]` and `[x, 0]` reach different states.
    /// An empty absorb, a squeeze, leaves the rate as the last permutation
    /// left it.
    fn duplexing(&mut self, builder: &mut Builder<C>) {
        let absorbed = self.input_buffer.len();
        assert!(absorbed <= HASH_RATE);
        self.sponge_state[0..absorbed].copy_from_slice(self.input_buffer.as_slice());
        self.input_buffer.clear();
        if absorbed > 0 {
            for lane in self.sponge_state[absorbed..HASH_RATE].iter_mut() {
                *lane = builder.eval(C::F::ZERO);
            }
            self.sponge_state[HASH_RATE] =
                builder.eval(self.sponge_state[HASH_RATE] + C::F::from_u8(absorbed as u8));
        }
        self.sponge_state = builder.poseidon2_permute_v2(self.sponge_state);

        self.output_buffer.clear();
        self.output_buffer.extend_from_slice(&self.sponge_state[..HASH_RATE]);
    }
}

/// The Blake3 ring's transcript in the circuit, over 16-bit limbs.
///
/// Reference: [`zkm_pcs::kb31_blake3::Blake3Challenger`]: the state is a
/// digest, zero at the start, and a buffer of observed limbs; folding
/// hashes the state followed by the buffer into the next state, at the cap
/// and at every squeeze; samples read the state's words in order and an
/// observation discards the words still unread.  An element is observed as
/// the two limbs of its canonical value, a digest as its sixteen limbs; a
/// sampled element is two words reduced into the field, and sampled bits
/// are the low bits of one word.  The buffer length and the words left are
/// program structure, as the host's are a function of the protocol alone.
#[derive(Clone, Debug)]
pub struct Blake3ChallengerVariable<C: Config> {
    state: [Felt<C::F>; crate::blake3_circuit::DIGEST_LIMBS],
    buffer: Vec<Felt<C::F>>,
    words_left: usize,
}

/// Limbs the buffer holds before folding: the host's byte cap, halved.
const BLAKE3_ABSORB_CAP_LIMBS: usize = zkm_pcs::kb31_blake3::ABSORB_CAP_BYTES / 2;

/// Words a squeeze yields.
const BLAKE3_SQUEEZE_WORDS: usize = crate::blake3_circuit::DIGEST_LIMBS / 2;

impl<C: CircuitConfig<F = KoalaBear>> Blake3ChallengerVariable<C> {
    pub fn new(builder: &mut Builder<C>) -> Self {
        Self {
            state: core::array::from_fn(|_| builder.constant(C::F::ZERO)),
            buffer: Vec::new(),
            words_left: 0,
        }
    }

    fn observe_limbs(
        &mut self,
        builder: &mut Builder<C>,
        limbs: impl IntoIterator<Item = Felt<C::F>>,
    ) {
        self.words_left = 0;
        for limb in limbs {
            self.buffer.push(limb);
            if self.buffer.len() == BLAKE3_ABSORB_CAP_LIMBS {
                self.fold(builder);
            }
        }
    }

    fn fold(&mut self, builder: &mut Builder<C>) {
        let buffered = self.buffer.len();
        let input: Vec<Felt<C::F>> =
            self.state.iter().copied().chain(self.buffer.drain(..)).collect();
        self.state = crate::blake3_circuit::hash_limbs(builder, &input);
        if zkm_pcs::kb31_blake3::transcript_trace_enabled() {
            let marker: Felt<C::F> = builder.constant(C::F::from_usize(2 * buffered));
            builder.print_f(marker);
            for limb in self.state {
                builder.print_f(limb);
            }
        }
    }

    fn squeeze(&mut self, builder: &mut Builder<C>) {
        self.fold(builder);
        self.words_left = BLAKE3_SQUEEZE_WORDS;
    }

    /// The next word of the transcript as its two limbs.
    fn next_word(&mut self, builder: &mut Builder<C>) -> [Felt<C::F>; 2] {
        if self.words_left == 0 {
            self.squeeze(builder);
        }
        let at = BLAKE3_SQUEEZE_WORDS - self.words_left;
        self.words_left -= 1;
        [self.state[2 * at], self.state[2 * at + 1]]
    }
}

impl<C: CircuitConfig<F = KoalaBear>> CanCopyChallenger<C> for Blake3ChallengerVariable<C> {
    fn copy(&self, builder: &mut Builder<C>) -> Self {
        Self {
            state: self.state.map(|x| builder.eval(x)),
            buffer: self.buffer.iter().map(|x| builder.eval(*x)).collect(),
            words_left: self.words_left,
        }
    }
}

impl<C: CircuitConfig<F = KoalaBear>> CanObserveVariable<C, Felt<C::F>>
    for Blake3ChallengerVariable<C>
{
    fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        let limbs = crate::blake3_circuit::felt_limbs(builder, value);
        self.observe_limbs(builder, limbs);
    }
}

impl<C: CircuitConfig<F = KoalaBear>>
    CanObserveVariable<C, [Felt<C::F>; crate::blake3_circuit::DIGEST_LIMBS]>
    for Blake3ChallengerVariable<C>
{
    fn observe(
        &mut self,
        builder: &mut Builder<C>,
        digest: [Felt<C::F>; crate::blake3_circuit::DIGEST_LIMBS],
    ) {
        self.observe_limbs(builder, digest);
    }
}

impl<C: CircuitConfig<F = KoalaBear>> CanSampleVariable<C, Felt<C::F>>
    for Blake3ChallengerVariable<C>
{
    fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        let low = self.next_word(builder);
        let high = self.next_word(builder);
        let weights = [1u64, 1 << 16, 1 << 32, 1 << 48].map(C::F::from_u64);
        builder.eval(
            low[0] * weights[0] + low[1] * weights[1] + high[0] * weights[2] + high[1] * weights[3],
        )
    }
}

impl<C: CircuitConfig<F = KoalaBear, Bit = Felt<KoalaBear>>> CanSampleBitsVariable<C, Felt<C::F>>
    for Blake3ChallengerVariable<C>
{
    fn sample_bits(&mut self, builder: &mut Builder<C>, nb_bits: usize) -> Vec<Felt<C::F>> {
        assert!(nb_bits <= 32, "a word carries at most 32 bits");
        let [low, high] = self.next_word(builder);
        let mut bits = builder.num2bits_v2_f(low, crate::blake3_circuit::LIMB_BITS);
        if nb_bits > crate::blake3_circuit::LIMB_BITS {
            bits.extend(builder.num2bits_v2_f(high, crate::blake3_circuit::LIMB_BITS));
        }
        bits.truncate(nb_bits);
        bits
    }
}

impl<C: CircuitConfig<F = KoalaBear, Bit = Felt<KoalaBear>>> FieldChallengerVariable<C, Felt<C::F>>
    for Blake3ChallengerVariable<C>
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
        for bit in self.sample_bits(builder, nb_bits) {
            builder.assert_felt_eq(bit, C::F::ZERO);
        }
    }

    /// Fold the buffer into the state without squeezing.
    fn duplexing(&mut self, builder: &mut Builder<C>) {
        self.fold(builder);
    }
}

#[derive(Clone)]
/// The outer ring's transcript in the circuit.
///
/// Reference: [`p3_challenger::MultiField32Challenger`]: observed felts are
/// packed `absorb_num_f_elms` to a native lane in radix `2^absorb_radix_bits`,
/// every absorb raises the first capacity lane by the number of felts (or
/// digests) it carried, and each sampled felt is one base-`F::ORDER` limb of
/// a rate lane.
pub struct MultiField32ChallengerVariable<C: Config> {
    sponge_state: [Var<C::N>; OUTER_MULTI_FIELD_CHALLENGER_WIDTH],
    /// Felts observed since the last absorb.
    input_buffer: Vec<Felt<C::F>>,
    /// Rate lanes of the last permutation not yet split into felts.
    output_buffer: Vec<Var<C::N>>,
    /// Felts split from the rate lanes, popped by `sample`.
    f_squeeze_buffer: Vec<Felt<C::F>>,
    /// Felts packed into one native lane on absorb.
    absorb_num_f_elms: usize,
    /// Felts split from one native lane on squeeze.
    squeeze_num_f_elms: usize,
}

impl<C: Config> MultiField32ChallengerVariable<C> {
    pub fn new(builder: &mut Builder<C>) -> Self {
        MultiField32ChallengerVariable::<C> {
            sponge_state: core::array::from_fn(|_| builder.eval(C::N::ZERO)),
            input_buffer: vec![],
            output_buffer: vec![],
            f_squeeze_buffer: vec![],
            absorb_num_f_elms: max_absorb_injective_limbs::<C::F, C::N>(),
            squeeze_num_f_elms: squeeze_field_order_num_limbs::<C::N, C::F>(),
        }
    }

    /// Reference: `MultiField32Challenger::flush_f_if_non_empty`.
    fn flush_f_if_non_empty(&mut self, builder: &mut Builder<C>) {
        if self.input_buffer.is_empty() {
            return;
        }
        let tag = self.input_buffer.len();
        assert!(tag <= self.absorb_num_f_elms * OUTER_MULTI_FIELD_CHALLENGER_RATE);
        let packed: Vec<Var<C::N>> = self
            .input_buffer
            .chunks(self.absorb_num_f_elms)
            .map(|chunk| reduce_packed(builder, chunk))
            .collect();
        self.input_buffer.clear();
        self.absorb_rate_padded_with_tag(builder, &packed, tag);
    }

    /// Reference: `DuplexChallenger::absorb_rate_padded_with_tag`: `values`
    /// fill the first rate lanes, the remaining rate lanes are zeroed, the
    /// first capacity lane is raised by `tag`, and the state is permuted.
    fn absorb_rate_padded_with_tag(
        &mut self,
        builder: &mut Builder<C>,
        values: &[Var<C::N>],
        tag: usize,
    ) {
        assert!(values.len() <= OUTER_MULTI_FIELD_CHALLENGER_RATE);
        for (lane, value) in self.sponge_state.iter_mut().zip(values) {
            *lane = builder.eval(*value);
        }
        for lane in &mut self.sponge_state[values.len()..OUTER_MULTI_FIELD_CHALLENGER_RATE] {
            *lane = builder.eval(C::N::ZERO);
        }
        let capacity = self.sponge_state[OUTER_MULTI_FIELD_CHALLENGER_RATE];
        self.sponge_state[OUTER_MULTI_FIELD_CHALLENGER_RATE] =
            builder.eval(capacity + C::N::from_usize(tag));
        self.permute(builder);
    }

    /// Permute the state and hold its rate lanes for the next squeeze.
    fn permute(&mut self, builder: &mut Builder<C>) {
        builder.push_op(DslIr::CircuitPoseidon2Permute(self.sponge_state));
        self.output_buffer = self.sponge_state[..OUTER_MULTI_FIELD_CHALLENGER_RATE]
            .iter()
            .map(|lane| builder.eval(*lane))
            .collect();
        self.f_squeeze_buffer.clear();
    }

    /// Reference: `MultiField32Challenger::refill_f_squeeze_from_inner`.
    fn refill_f_squeeze(&mut self, builder: &mut Builder<C>) {
        self.f_squeeze_buffer.clear();
        for lane in core::mem::take(&mut self.output_buffer) {
            self.f_squeeze_buffer
                .extend(builder.var2felt_limbs_circuit(lane, self.squeeze_num_f_elms));
        }
    }

    /// Absorb the buffered felts, or permute the state when there are none.
    pub fn duplexing(&mut self, builder: &mut Builder<C>) {
        if self.input_buffer.is_empty() {
            self.permute(builder);
        } else {
            self.flush_f_if_non_empty(builder);
        }
    }

    pub fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        self.output_buffer.clear();
        self.f_squeeze_buffer.clear();

        self.input_buffer.push(value);
        if self.input_buffer.len() == self.absorb_num_f_elms * OUTER_MULTI_FIELD_CHALLENGER_RATE {
            self.flush_f_if_non_empty(builder);
        }
    }

    /// Reference: `CanObserve<Hash<F, PF, N>> for MultiField32Challenger`: a
    /// digest is absorbed as native lanes, after any pending felts.
    pub fn observe_commitment(
        &mut self,
        builder: &mut Builder<C>,
        value: [Var<C::N>; OUTER_MULTI_FIELD_CHALLENGER_DIGEST_SIZE],
    ) {
        self.output_buffer.clear();
        self.f_squeeze_buffer.clear();
        self.flush_f_if_non_empty(builder);
        for chunk in value.chunks(OUTER_MULTI_FIELD_CHALLENGER_RATE) {
            self.absorb_rate_padded_with_tag(builder, chunk, chunk.len());
        }
    }

    pub fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        self.flush_f_if_non_empty(builder);
        if self.f_squeeze_buffer.is_empty() {
            if self.output_buffer.is_empty() {
                self.permute(builder);
            }
            self.refill_f_squeeze(builder);
        }

        self.f_squeeze_buffer.pop().expect("output buffer should be non-empty")
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
            f_squeeze_buffer,
            absorb_num_f_elms,
            squeeze_num_f_elms,
        } = self;
        let sponge_state = sponge_state.map(|x| builder.eval(x));
        let output_buffer = output_buffer.iter().map(|x| builder.eval(*x)).collect();
        let mut copy_felts = |v: &Vec<Felt<C::F>>| v.iter().map(|x| builder.eval(*x)).collect();
        MultiField32ChallengerVariable::<C> {
            sponge_state,
            input_buffer: copy_felts(input_buffer),
            output_buffer,
            f_squeeze_buffer: copy_felts(f_squeeze_buffer),
            absorb_num_f_elms: *absorb_num_f_elms,
            squeeze_num_f_elms: *squeeze_num_f_elms,
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

/// Reference: [`p3_field::reduce_packed`] at the absorb radix of `C::F`: the
/// canonical values of `vals` as the digits of one native lane.
pub fn reduce_packed<C: Config>(builder: &mut Builder<C>, vals: &[Felt<C::F>]) -> Var<C::N> {
    pack_limbs(builder, vals, C::N::ZERO)
}

/// Reference: [`p3_field::reduce_packed_shifted`]: as [`reduce_packed`], with
/// every digit raised by one so that a trailing zero changes the lane.
pub fn reduce_packed_shifted<C: Config>(
    builder: &mut Builder<C>,
    vals: &[Felt<C::F>],
) -> Var<C::N> {
    pack_limbs(builder, vals, C::N::ONE)
}

fn pack_limbs<C: Config>(builder: &mut Builder<C>, vals: &[Felt<C::F>], offset: C::N) -> Var<C::N> {
    let base = C::N::from_u64(1u64 << absorb_radix_bits::<C::F>());
    let mut power = C::N::ONE;
    let result: Var<C::N> = builder.eval(C::N::ZERO);
    for val in vals.iter() {
        let val = builder.felt2var_circuit(*val);
        builder.assign(result, result + val * power + offset * power);
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
        challenger::{CanCopyChallenger, MultiField32ChallengerVariable},
        hash::{FieldHasherVariable, BN254_DIGEST_SIZE},
        utils::tests::run_test_recursion,
    };
    use p3_bn254_fr::Bn254;
    use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger};
    use p3_field::PrimeCharacteristicRing;
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
