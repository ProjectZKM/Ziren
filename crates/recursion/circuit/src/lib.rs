//! Copied from [`zkm_recursion_program`].

#[cfg(all(feature = "bn254", feature = "bls12381"))]
compile_error!("features `bn254` and `bls12381` are mutually exclusive");
#[cfg(not(any(feature = "bn254", feature = "bls12381")))]
compile_error!("either feature `bn254` or `bls12381` must be enabled");

use challenger::{
    CanCopyChallenger, CanObserveVariable, DuplexChallengerVariable, FieldChallengerVariable,
    MultiField32ChallengerVariable, SpongeChallengerShape,
};
use hash::{FieldHasherVariable, Poseidon2KoalaBearHasherVariable};
use itertools::izip;
#[cfg(feature = "bls12381")]
use p3_bls12381_fr::Bls12381Fr as FR;
#[cfg(feature = "bn254")]
use p3_bn254_fr::Bn254Fr as FR;
use p3_field::FieldAlgebra;
use p3_matrix::dense::RowMajorMatrix;
use std::iter::{repeat, zip};
use zkm_recursion_compiler::{
    circuit::CircuitV2Builder,
    config::{InnerConfig, OuterConfig},
    ir::{Builder, Config, DslIr, Ext, Felt, SymbolicFelt, Var, Variable},
};

mod types;

pub mod challenger;
pub mod constraints;
pub mod domain;
pub mod fri;
pub mod hash;
pub mod machine;
pub mod merkle_tree;
pub mod stark;
pub(crate) mod utils;
pub mod witness;

pub use types::*;
use zkm_stark::{
    koala_bear_poseidon2::{KoalaBearPoseidon2, ValMmcs},
    StarkGenericConfig,
};

use p3_challenger::{CanObserve, CanSample, FieldChallenger, GrindingChallenger};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_dft::Radix2DitParallel;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use zkm_recursion_core::{
    air::RecursionPublicValues,
    stark::{KoalaBearPoseidon2Outer, OuterValMmcs},
    D,
};

use p3_koala_bear::KoalaBear;
use utils::{felt_bytes_to_bn254_var, felts_to_bn254_var, words_to_bytes};

type EF = <KoalaBearPoseidon2 as StarkGenericConfig>::Challenge;

pub type PcsConfig<C> = FriConfig<
    ExtensionMmcs<
        <C as StarkGenericConfig>::Val,
        <C as StarkGenericConfig>::Challenge,
        <C as KoalaBearFriConfig>::ValMmcs,
    >,
>;

pub type Digest<C, SC> = <SC as FieldHasherVariable<C>>::DigestVariable;

pub type FriMmcs<C> = ExtensionMmcs<KoalaBear, EF, <C as KoalaBearFriConfig>::ValMmcs>;

pub trait KoalaBearFriConfig:
    StarkGenericConfig<
    Val = KoalaBear,
    Challenge = EF,
    Challenger = Self::FriChallenger,
    Pcs = TwoAdicFriPcs<
        KoalaBear,
        Radix2DitParallel<KoalaBear>,
        Self::ValMmcs,
        ExtensionMmcs<KoalaBear, EF, Self::ValMmcs>,
    >,
>
{
    type ValMmcs: Mmcs<KoalaBear, ProverData<RowMajorMatrix<KoalaBear>> = Self::RowMajorProverData>
        + Send
        + Sync;
    type RowMajorProverData: Clone + Send + Sync;
    type FriChallenger: CanObserve<<Self::ValMmcs as Mmcs<KoalaBear>>::Commitment>
        + CanSample<EF>
        + GrindingChallenger<Witness = KoalaBear>
        + FieldChallenger<KoalaBear>;

    fn fri_config(&self) -> &FriConfig<FriMmcs<Self>>;

    fn challenger_shape(challenger: &Self::FriChallenger) -> SpongeChallengerShape;
}

pub trait KoalaBearFriConfigVariable<C: CircuitConfig<F = KoalaBear>>:
    KoalaBearFriConfig + FieldHasherVariable<C> + Poseidon2KoalaBearHasherVariable<C>
{
    type FriChallengerVariable: FieldChallengerVariable<C, <C as CircuitConfig>::Bit>
        + CanObserveVariable<C, <Self as FieldHasherVariable<C>>::DigestVariable>
        + CanCopyChallenger<C>;

    /// Get a new challenger corresponding to the given config.
    fn challenger_variable(&self, builder: &mut Builder<C>) -> Self::FriChallengerVariable;

    fn commit_recursion_public_values(
        builder: &mut Builder<C>,
        public_values: RecursionPublicValues<Felt<C::F>>,
    );
}

pub trait CircuitConfig: Config {
    type Bit: Copy + Variable<Self>;

    fn read_bit(builder: &mut Builder<Self>) -> Self::Bit;

    fn read_felt(builder: &mut Builder<Self>) -> Felt<Self::F>;

    fn read_ext(builder: &mut Builder<Self>) -> Ext<Self::F, Self::EF>;

    fn assert_bit_zero(builder: &mut Builder<Self>, bit: Self::Bit);

    fn assert_bit_one(builder: &mut Builder<Self>, bit: Self::Bit);

    fn ext2felt(
        builder: &mut Builder<Self>,
        ext: Ext<<Self as Config>::F, <Self as Config>::EF>,
    ) -> [Felt<<Self as Config>::F>; D];

    fn exp_reverse_bits(
        builder: &mut Builder<Self>,
        input: Felt<<Self as Config>::F>,
        power_bits: Vec<Self::Bit>,
    ) -> Felt<<Self as Config>::F>;

    /// Exponentiates a felt x to a list of bits in little endian. Uses precomputed powers
    /// of x.
    fn exp_f_bits_precomputed(
        builder: &mut Builder<Self>,
        power_bits: &[Self::Bit],
        two_adic_powers_of_x: &[Felt<Self::F>],
    ) -> Felt<Self::F>;

    fn batch_fri(
        builder: &mut Builder<Self>,
        alpha_pows: Vec<Ext<Self::F, Self::EF>>,
        p_at_zs: Vec<Ext<Self::F, Self::EF>>,
        p_at_xs: Vec<Felt<Self::F>>,
    ) -> Ext<Self::F, Self::EF>;

    fn num2bits(
        builder: &mut Builder<Self>,
        num: Felt<<Self as Config>::F>,
        num_bits: usize,
    ) -> Vec<Self::Bit>;

    fn bits2num(
        builder: &mut Builder<Self>,
        bits: impl IntoIterator<Item = Self::Bit>,
    ) -> Felt<<Self as Config>::F>;

    #[allow(clippy::type_complexity)]
    fn select_chain_f(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Felt<<Self as Config>::F>> + Clone,
        second: impl IntoIterator<Item = Felt<<Self as Config>::F>> + Clone,
    ) -> Vec<Felt<<Self as Config>::F>>;

    #[allow(clippy::type_complexity)]
    fn select_chain_ef(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Ext<<Self as Config>::F, <Self as Config>::EF>> + Clone,
        second: impl IntoIterator<Item = Ext<<Self as Config>::F, <Self as Config>::EF>> + Clone,
    ) -> Vec<Ext<<Self as Config>::F, <Self as Config>::EF>>;

    fn range_check_felt(builder: &mut Builder<Self>, value: Felt<Self::F>, num_bits: usize) {
        let bits = Self::num2bits(builder, value, 31);
        for bit in bits.into_iter().skip(num_bits) {
            Self::assert_bit_zero(builder, bit);
        }
    }
}

impl CircuitConfig for InnerConfig {
    type Bit = Felt<<Self as Config>::F>;

    fn assert_bit_zero(builder: &mut Builder<Self>, bit: Self::Bit) {
        builder.assert_felt_eq(bit, Self::F::ZERO);
    }

    fn assert_bit_one(builder: &mut Builder<Self>, bit: Self::Bit) {
        builder.assert_felt_eq(bit, Self::F::ONE);
    }

    fn read_bit(builder: &mut Builder<Self>) -> Self::Bit {
        builder.hint_felt_v2()
    }

    fn read_felt(builder: &mut Builder<Self>) -> Felt<Self::F> {
        builder.hint_felt_v2()
    }

    fn read_ext(builder: &mut Builder<Self>) -> Ext<Self::F, Self::EF> {
        builder.hint_ext_v2()
    }

    fn ext2felt(
        builder: &mut Builder<Self>,
        ext: Ext<<Self as Config>::F, <Self as Config>::EF>,
    ) -> [Felt<<Self as Config>::F>; D] {
        builder.ext2felt_v2(ext)
    }

    fn exp_reverse_bits(
        builder: &mut Builder<Self>,
        input: Felt<<Self as Config>::F>,
        power_bits: Vec<Felt<<Self as Config>::F>>,
    ) -> Felt<<Self as Config>::F> {
        builder.exp_reverse_bits_v2(input, power_bits)
    }

    fn batch_fri(
        builder: &mut Builder<Self>,
        alpha_pows: Vec<Ext<<Self as Config>::F, <Self as Config>::EF>>,
        p_at_zs: Vec<Ext<<Self as Config>::F, <Self as Config>::EF>>,
        p_at_xs: Vec<Felt<<Self as Config>::F>>,
    ) -> Ext<<Self as Config>::F, <Self as Config>::EF> {
        builder.batch_fri_v2(alpha_pows, p_at_zs, p_at_xs)
    }

    fn num2bits(
        builder: &mut Builder<Self>,
        num: Felt<<Self as Config>::F>,
        num_bits: usize,
    ) -> Vec<Felt<<Self as Config>::F>> {
        builder.num2bits_v2_f(num, num_bits)
    }

    fn bits2num(
        builder: &mut Builder<Self>,
        bits: impl IntoIterator<Item = Felt<<Self as Config>::F>>,
    ) -> Felt<<Self as Config>::F> {
        builder.bits2num_v2_f(bits)
    }

    fn select_chain_f(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Felt<<Self as Config>::F>> + Clone,
        second: impl IntoIterator<Item = Felt<<Self as Config>::F>> + Clone,
    ) -> Vec<Felt<<Self as Config>::F>> {
        let one: Felt<_> = builder.constant(Self::F::ONE);
        let shouldnt_swap: Felt<_> = builder.eval(one - should_swap);

        let id_branch = first.clone().into_iter().chain(second.clone());
        let swap_branch = second.into_iter().chain(first);
        zip(zip(id_branch, swap_branch), zip(repeat(shouldnt_swap), repeat(should_swap)))
            .map(|((id_v, sw_v), (id_c, sw_c))| builder.eval(id_v * id_c + sw_v * sw_c))
            .collect()
    }

    fn select_chain_ef(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Ext<<Self as Config>::F, <Self as Config>::EF>> + Clone,
        second: impl IntoIterator<Item = Ext<<Self as Config>::F, <Self as Config>::EF>> + Clone,
    ) -> Vec<Ext<<Self as Config>::F, <Self as Config>::EF>> {
        let one: Felt<_> = builder.constant(Self::F::ONE);
        let shouldnt_swap: Felt<_> = builder.eval(one - should_swap);

        let id_branch = first.clone().into_iter().chain(second.clone());
        let swap_branch = second.into_iter().chain(first);
        zip(zip(id_branch, swap_branch), zip(repeat(shouldnt_swap), repeat(should_swap)))
            .map(|((id_v, sw_v), (id_c, sw_c))| builder.eval(id_v * id_c + sw_v * sw_c))
            .collect()
    }

    fn exp_f_bits_precomputed(
        builder: &mut Builder<Self>,
        power_bits: &[Self::Bit],
        two_adic_powers_of_x: &[Felt<Self::F>],
    ) -> Felt<Self::F> {
        Self::exp_reverse_bits(
            builder,
            two_adic_powers_of_x[0],
            power_bits.iter().rev().copied().collect(),
        )
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WrapConfig;

impl Config for WrapConfig {
    type F = <InnerConfig as Config>::F;
    type EF = <InnerConfig as Config>::EF;
    type N = <InnerConfig as Config>::N;
}

impl CircuitConfig for WrapConfig {
    type Bit = <InnerConfig as CircuitConfig>::Bit;

    fn assert_bit_zero(builder: &mut Builder<Self>, bit: Self::Bit) {
        builder.assert_felt_eq(bit, Self::F::ZERO);
    }

    fn assert_bit_one(builder: &mut Builder<Self>, bit: Self::Bit) {
        builder.assert_felt_eq(bit, Self::F::ONE);
    }

    fn read_bit(builder: &mut Builder<Self>) -> Self::Bit {
        builder.hint_felt_v2()
    }

    fn read_felt(builder: &mut Builder<Self>) -> Felt<Self::F> {
        builder.hint_felt_v2()
    }

    fn read_ext(builder: &mut Builder<Self>) -> Ext<Self::F, Self::EF> {
        builder.hint_ext_v2()
    }

    fn ext2felt(
        builder: &mut Builder<Self>,
        ext: Ext<<Self as Config>::F, <Self as Config>::EF>,
    ) -> [Felt<<Self as Config>::F>; D] {
        builder.ext2felt_v2(ext)
    }

    fn exp_reverse_bits(
        builder: &mut Builder<Self>,
        input: Felt<<Self as Config>::F>,
        power_bits: Vec<Felt<<Self as Config>::F>>,
    ) -> Felt<<Self as Config>::F> {
        // builder.exp_reverse_bits_v2(input, power_bits)
        let mut result = builder.constant(Self::F::ONE);
        let mut power_f = input;
        let bit_len = power_bits.len();

        for i in 1..=bit_len {
            let index = bit_len - i;
            let bit = power_bits[index];
            let prod: Felt<_> = builder.eval(result * power_f);
            result = builder.eval(bit * prod + (SymbolicFelt::ONE - bit) * result);
            power_f = builder.eval(power_f * power_f);
        }
        result
    }

    fn batch_fri(
        builder: &mut Builder<Self>,
        alpha_pows: Vec<Ext<<Self as Config>::F, <Self as Config>::EF>>,
        p_at_zs: Vec<Ext<<Self as Config>::F, <Self as Config>::EF>>,
        p_at_xs: Vec<Felt<<Self as Config>::F>>,
    ) -> Ext<<Self as Config>::F, <Self as Config>::EF> {
        builder.batch_fri_v2(alpha_pows, p_at_zs, p_at_xs)
    }

    fn num2bits(
        builder: &mut Builder<Self>,
        num: Felt<<Self as Config>::F>,
        num_bits: usize,
    ) -> Vec<Felt<<Self as Config>::F>> {
        builder.num2bits_v2_f(num, num_bits)
    }

    fn bits2num(
        builder: &mut Builder<Self>,
        bits: impl IntoIterator<Item = Felt<<Self as Config>::F>>,
    ) -> Felt<<Self as Config>::F> {
        builder.bits2num_v2_f(bits)
    }

    fn select_chain_f(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Felt<<Self as Config>::F>> + Clone,
        second: impl IntoIterator<Item = Felt<<Self as Config>::F>> + Clone,
    ) -> Vec<Felt<<Self as Config>::F>> {
        let one: Felt<_> = builder.constant(Self::F::ONE);
        let shouldnt_swap: Felt<_> = builder.eval(one - should_swap);

        let id_branch = first.clone().into_iter().chain(second.clone());
        let swap_branch = second.into_iter().chain(first);
        zip(zip(id_branch, swap_branch), zip(repeat(shouldnt_swap), repeat(should_swap)))
            .map(|((id_v, sw_v), (id_c, sw_c))| builder.eval(id_v * id_c + sw_v * sw_c))
            .collect()
    }

    fn select_chain_ef(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Ext<<Self as Config>::F, <Self as Config>::EF>> + Clone,
        second: impl IntoIterator<Item = Ext<<Self as Config>::F, <Self as Config>::EF>> + Clone,
    ) -> Vec<Ext<<Self as Config>::F, <Self as Config>::EF>> {
        let one: Felt<_> = builder.constant(Self::F::ONE);
        let shouldnt_swap: Felt<_> = builder.eval(one - should_swap);

        let id_branch = first.clone().into_iter().chain(second.clone());
        let swap_branch = second.into_iter().chain(first);
        zip(zip(id_branch, swap_branch), zip(repeat(shouldnt_swap), repeat(should_swap)))
            .map(|((id_v, sw_v), (id_c, sw_c))| builder.eval(id_v * id_c + sw_v * sw_c))
            .collect()
    }

    fn exp_f_bits_precomputed(
        builder: &mut Builder<Self>,
        power_bits: &[Self::Bit],
        two_adic_powers_of_x: &[Felt<Self::F>],
    ) -> Felt<Self::F> {
        Self::exp_reverse_bits(
            builder,
            two_adic_powers_of_x[0],
            power_bits.iter().rev().copied().collect(),
        )
    }
}

impl CircuitConfig for OuterConfig {
    type Bit = Var<<Self as Config>::N>;

    fn assert_bit_zero(builder: &mut Builder<Self>, bit: Self::Bit) {
        builder.assert_var_eq(bit, Self::N::ZERO);
    }

    fn assert_bit_one(builder: &mut Builder<Self>, bit: Self::Bit) {
        builder.assert_var_eq(bit, Self::N::ONE);
    }

    fn read_bit(builder: &mut Builder<Self>) -> Self::Bit {
        builder.witness_var()
    }

    fn read_felt(builder: &mut Builder<Self>) -> Felt<Self::F> {
        builder.witness_felt()
    }

    fn read_ext(builder: &mut Builder<Self>) -> Ext<Self::F, Self::EF> {
        builder.witness_ext()
    }

    fn ext2felt(
        builder: &mut Builder<Self>,
        ext: Ext<<Self as Config>::F, <Self as Config>::EF>,
    ) -> [Felt<<Self as Config>::F>; D] {
        let felts = core::array::from_fn(|_| builder.uninit());
        builder.push_op(DslIr::CircuitExt2Felt(felts, ext));
        felts
    }

    fn exp_reverse_bits(
        builder: &mut Builder<Self>,
        input: Felt<<Self as Config>::F>,
        power_bits: Vec<Var<<Self as Config>::N>>,
    ) -> Felt<<Self as Config>::F> {
        let mut result = builder.constant(Self::F::ONE);
        let power_f = input;
        let bit_len = power_bits.len();

        for i in 1..=bit_len {
            let index = bit_len - i;
            let bit = power_bits[index];
            let prod = builder.eval(result * power_f);
            result = builder.select_f(bit, prod, result);
            builder.assign(power_f, power_f * power_f);
        }
        result
    }

    fn batch_fri(
        builder: &mut Builder<Self>,
        alpha_pows: Vec<Ext<<Self as Config>::F, <Self as Config>::EF>>,
        p_at_zs: Vec<Ext<<Self as Config>::F, <Self as Config>::EF>>,
        p_at_xs: Vec<Felt<<Self as Config>::F>>,
    ) -> Ext<<Self as Config>::F, <Self as Config>::EF> {
        let mut acc: Ext<_, _> = builder.uninit();
        builder.push_op(DslIr::ImmE(acc, <Self as Config>::EF::ZERO));
        for (alpha_pow, p_at_z, p_at_x) in izip!(alpha_pows, p_at_zs, p_at_xs) {
            let temp_1: Ext<_, _> = builder.uninit();
            builder.push_op(DslIr::SubEF(temp_1, p_at_z, p_at_x));
            let temp_2: Ext<_, _> = builder.uninit();
            builder.push_op(DslIr::MulE(temp_2, alpha_pow, temp_1));
            let temp_3: Ext<_, _> = builder.uninit();
            builder.push_op(DslIr::AddE(temp_3, acc, temp_2));
            acc = temp_3;
        }
        acc
    }

    fn num2bits(
        builder: &mut Builder<Self>,
        num: Felt<<Self as Config>::F>,
        num_bits: usize,
    ) -> Vec<Var<<Self as Config>::N>> {
        builder.num2bits_f_circuit(num)[..num_bits].to_vec()
    }

    fn bits2num(
        builder: &mut Builder<Self>,
        bits: impl IntoIterator<Item = Var<<Self as Config>::N>>,
    ) -> Felt<<Self as Config>::F> {
        let result = builder.eval(Self::F::ZERO);
        for (i, bit) in bits.into_iter().enumerate() {
            let to_add: Felt<_> = builder.uninit();
            let pow2 = builder.constant(Self::F::from_canonical_u32(1 << i));
            let zero = builder.constant(Self::F::ZERO);
            builder.push_op(DslIr::CircuitSelectF(bit, pow2, zero, to_add));
            builder.assign(result, result + to_add);
        }
        result
    }

    fn select_chain_f(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Felt<<Self as Config>::F>> + Clone,
        second: impl IntoIterator<Item = Felt<<Self as Config>::F>> + Clone,
    ) -> Vec<Felt<<Self as Config>::F>> {
        let id_branch = first.clone().into_iter().chain(second.clone());
        let swap_branch = second.into_iter().chain(first);
        zip(id_branch, swap_branch)
            .map(|(id_v, sw_v): (Felt<_>, Felt<_>)| -> Felt<_> {
                let result: Felt<_> = builder.uninit();
                builder.push_op(DslIr::CircuitSelectF(should_swap, sw_v, id_v, result));
                result
            })
            .collect()
    }

    fn select_chain_ef(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Ext<<Self as Config>::F, <Self as Config>::EF>> + Clone,
        second: impl IntoIterator<Item = Ext<<Self as Config>::F, <Self as Config>::EF>> + Clone,
    ) -> Vec<Ext<<Self as Config>::F, <Self as Config>::EF>> {
        let id_branch = first.clone().into_iter().chain(second.clone());
        let swap_branch = second.into_iter().chain(first);
        zip(id_branch, swap_branch)
            .map(|(id_v, sw_v): (Ext<_, _>, Ext<_, _>)| -> Ext<_, _> {
                let result: Ext<_, _> = builder.uninit();
                builder.push_op(DslIr::CircuitSelectE(should_swap, sw_v, id_v, result));
                result
            })
            .collect()
    }

    fn exp_f_bits_precomputed(
        builder: &mut Builder<Self>,
        power_bits: &[Self::Bit],
        two_adic_powers_of_x: &[Felt<Self::F>],
    ) -> Felt<Self::F> {
        let mut result: Felt<_> = builder.eval(Self::F::ONE);
        let one = builder.constant(Self::F::ONE);
        for (&bit, &power) in power_bits.iter().zip(two_adic_powers_of_x) {
            let multiplier = builder.select_f(bit, power, one);
            result = builder.eval(multiplier * result);
        }
        result
    }
}

impl KoalaBearFriConfig for KoalaBearPoseidon2 {
    type ValMmcs = ValMmcs;
    type FriChallenger = <Self as StarkGenericConfig>::Challenger;
    type RowMajorProverData = <ValMmcs as Mmcs<KoalaBear>>::ProverData<RowMajorMatrix<KoalaBear>>;

    fn fri_config(&self) -> &FriConfig<FriMmcs<Self>> {
        self.pcs().fri_config()
    }

    fn challenger_shape(challenger: &Self::FriChallenger) -> SpongeChallengerShape {
        SpongeChallengerShape {
            input_buffer_len: challenger.input_buffer.len(),
            output_buffer_len: challenger.output_buffer.len(),
        }
    }
}

impl KoalaBearFriConfig for KoalaBearPoseidon2Outer {
    type ValMmcs = OuterValMmcs;
    type FriChallenger = <Self as StarkGenericConfig>::Challenger;

    type RowMajorProverData =
        <OuterValMmcs as Mmcs<KoalaBear>>::ProverData<RowMajorMatrix<KoalaBear>>;

    fn fri_config(&self) -> &FriConfig<FriMmcs<Self>> {
        self.pcs().fri_config()
    }

    fn challenger_shape(_challenger: &Self::FriChallenger) -> SpongeChallengerShape {
        unimplemented!("Shape not supported for outer fri challenger");
    }
}

impl<C: CircuitConfig<F = KoalaBear, Bit = Felt<KoalaBear>>> KoalaBearFriConfigVariable<C>
    for KoalaBearPoseidon2
{
    type FriChallengerVariable = DuplexChallengerVariable<C>;

    fn challenger_variable(&self, builder: &mut Builder<C>) -> Self::FriChallengerVariable {
        DuplexChallengerVariable::new(builder)
    }

    fn commit_recursion_public_values(
        builder: &mut Builder<C>,
        public_values: RecursionPublicValues<Felt<<C>::F>>,
    ) {
        builder.commit_public_values_v2(public_values);
    }
}

impl<C: CircuitConfig<F = KoalaBear, N = FR, Bit = Var<FR>>> KoalaBearFriConfigVariable<C>
    for KoalaBearPoseidon2Outer
{
    type FriChallengerVariable = MultiField32ChallengerVariable<C>;

    fn challenger_variable(&self, builder: &mut Builder<C>) -> Self::FriChallengerVariable {
        MultiField32ChallengerVariable::new(builder)
    }

    fn commit_recursion_public_values(
        builder: &mut Builder<C>,
        public_values: RecursionPublicValues<Felt<<C>::F>>,
    ) {
        let committed_values_digest_bytes_felts: [Felt<_>; 32] =
            words_to_bytes(&public_values.committed_value_digest).try_into().unwrap();
        let committed_values_digest_bytes: Var<_> =
            felt_bytes_to_bn254_var(builder, &committed_values_digest_bytes_felts);
        builder.commit_committed_values_digest_circuit(committed_values_digest_bytes);

        let vkey_hash = felts_to_bn254_var(builder, &public_values.zkm_vk_digest);
        builder.commit_vkey_hash_circuit(vkey_hash);
    }
}
