//! The cross-shard global challenge in-circuit: the start of the hash chain
//! over the shards' global rounds, one step of one of its lanes, the chain's
//! value as the digest of its lane heads, and the `(α_g, β_g)` a shard's
//! global lookups use, derived from the chain's end.
//!
//! Each function absorbs exactly what its host counterpart in
//! `zkm_pcs::logup_gkr` absorbs, in the same order, on a fresh challenger of
//! the machine's configuration.

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use zkm_pcs::logup_gkr::GLOBAL_CHAIN_LANE_COUNT;
use zkm_recursion_compiler::ir::{Builder, Config, Ext, Felt, SymbolicExt, SymbolicFelt};
use zkm_recursion_core::DIGEST_SIZE;

use crate::{
    challenger::{CanObserveVariable, CanSampleVariable, FieldChallengerVariable},
    logup_gkr::partial_lagrange_symbolic,
    CircuitConfig, KoalaBearFriParametersVariable, VerifyingKeyVariable,
};

/// [`zkm_pcs::logup_gkr::global_lookup_units`] of a global round with
/// `lookups` lookups, a number below `2^lookup_bits`.
pub fn global_lookup_units_variable<C: CircuitConfig<F = KoalaBear>>(
    builder: &mut Builder<C>,
    lookups: Felt<C::F>,
    lookup_bits: usize,
) -> Felt<C::F> {
    assert!(lookup_bits < 31, "the lookups of a global round fit the field");
    let bits = C::num2bits(builder, lookups, lookup_bits);
    let whole_units =
        C::bits2num(builder, bits.into_iter().skip(zkm_pcs::logup_gkr::GLOBAL_LOOKUP_UNIT_BITS));
    builder.eval(whole_units + C::F::ONE)
}

/// Adds the global lookup units `part` to `count` and asserts that the sum
/// is within [`zkm_pcs::logup_gkr::max_global_lookup_units`]. Both must
/// already be within it, so the field adds them without wrapping.
pub fn add_global_lookup_units<C: CircuitConfig<F = KoalaBear>>(
    builder: &mut Builder<C>,
    count: Felt<C::F>,
    part: Felt<C::F>,
) -> Felt<C::F> {
    use p3_field::PrimeField32;
    let max = zkm_pcs::logup_gkr::max_global_lookup_units::<KoalaBear>();
    let bits = (u64::BITS - max.leading_zeros()) as usize;
    assert!(
        2 * max + (1 << bits) < u64::from(KoalaBear::ORDER_U32),
        "the slack below the bound cannot wrap into its own range",
    );
    let sum: Felt<C::F> = builder.eval(count + part);
    let max: Felt<C::F> = builder.constant(C::F::from_u64(max));
    let slack: Felt<C::F> = builder.eval(max - sum);
    C::num2bits(builder, slack, bits);
    sum
}

/// A shard's global challenge: the chain end `h_star` it is derived from, the
/// proof-of-work witness, `α_g`, and the `β_g` table (the eq table of the β
/// seed).
pub struct GlobalChallengeVariable<C: CircuitConfig<F = KoalaBear>> {
    pub h_star: [Felt<C::F>; DIGEST_SIZE],
    pub pow_witness: Felt<C::F>,
    pub alpha: Ext<C::F, C::EF>,
    pub betas: Vec<SymbolicExt<C::F, C::EF>>,
}

impl<C: CircuitConfig<F = KoalaBear>> GlobalChallengeVariable<C> {
    /// `GlobalChallenge::derive`: absorbs the domain and `h_star`, checks the
    /// proof-of-work witness, then samples `α_g` and `beta_seed_dim` seed
    /// elements.
    pub fn derive<SC>(
        builder: &mut Builder<C>,
        config: &SC,
        h_star: [Felt<C::F>; DIGEST_SIZE],
        pow_witness: Felt<C::F>,
        beta_seed_dim: usize,
    ) -> Self
    where
        SC: KoalaBearFriParametersVariable<C>,
    {
        let mut challenger = config.challenger_variable(builder);
        let domain: Felt<C::F> =
            builder.eval(C::F::from_u32(zkm_pcs::logup_gkr::GLOBAL_CHALLENGE_DOMAIN));
        challenger.observe(builder, domain);
        for h in h_star {
            challenger.observe(builder, h);
        }
        challenger.check_witness(builder, zkm_pcs::logup_gkr::global_grinding_bits(), pow_witness);
        let alpha = challenger.sample_ext(builder);
        let seed: Vec<SymbolicExt<C::F, C::EF>> =
            (0..beta_seed_dim).map(|_| challenger.sample_ext(builder).into()).collect();
        let betas = partial_lagrange_symbolic::<C>(&seed);
        Self { h_star, pow_witness, alpha, betas }
    }
}

/// `global_digest`: the head `h_0` every lane of the chain of a proof under
/// `vk` starts at.
pub fn global_digest_variable<C, SC>(
    builder: &mut Builder<C>,
    config: &SC,
    vk: &VerifyingKeyVariable<C, SC>,
) -> [Felt<C::F>; DIGEST_SIZE]
where
    C: CircuitConfig<F = KoalaBear>,
    SC: KoalaBearFriParametersVariable<C, Val = KoalaBear>,
{
    let mut challenger = config.challenger_variable(builder);
    vk.observe_into(builder, &mut challenger);
    let domain: Felt<C::F> = builder.eval(C::F::from_u32(zkm_pcs::logup_gkr::GLOBAL_DIGEST_DOMAIN));
    challenger.observe(builder, domain);
    core::array::from_fn(|_| challenger.sample(builder))
}

/// A shard's global round as the chain absorbs it: the round's commitment
/// and `(name, height)` of each of its chips, in name order.
pub struct GlobalRoundBindingVariable<'a, C: CircuitConfig<F = KoalaBear>> {
    pub commitment: [Felt<C::F>; DIGEST_SIZE],
    pub chips: &'a [(String, Felt<C::F>)],
}

/// `global_chain_step`: a lane's head `h_prev` extended by a shard's global
/// round, `None` for a shard without one.
pub fn global_chain_step_variable<C: CircuitConfig<F = KoalaBear>, SC>(
    builder: &mut Builder<C>,
    config: &SC,
    h_prev: [Felt<C::F>; DIGEST_SIZE],
    round: Option<&GlobalRoundBindingVariable<'_, C>>,
) -> [Felt<C::F>; DIGEST_SIZE]
where
    SC: KoalaBearFriParametersVariable<C>,
{
    let mut challenger = config.challenger_variable(builder);
    let observe_const =
        |builder: &mut Builder<C>, challenger: &mut SC::FriChallengerVariable, v: u64| {
            let felt: Felt<C::F> = builder.eval(C::F::from_u64(v));
            challenger.observe(builder, felt);
        };
    observe_const(builder, &mut challenger, u64::from(zkm_pcs::logup_gkr::GLOBAL_CHAIN_DOMAIN));
    for h in h_prev {
        challenger.observe(builder, h);
    }
    match round {
        None => observe_const(builder, &mut challenger, 0),
        Some(round) => {
            observe_const(builder, &mut challenger, 1);
            for c in round.commitment {
                challenger.observe(builder, c);
            }
            observe_const(builder, &mut challenger, round.chips.len() as u64);
            for (name, height) in round.chips {
                challenger.observe(builder, *height);
                observe_const(builder, &mut challenger, name.len() as u64);
                for byte in name.bytes() {
                    observe_const(builder, &mut challenger, u64::from(byte));
                }
            }
        }
    }
    core::array::from_fn(|_| challenger.sample(builder))
}

/// The heads of the lanes of the global hash chain.
pub type GlobalChainHeadsVariable<C> =
    [[Felt<<C as Config>::F>; DIGEST_SIZE]; GLOBAL_CHAIN_LANE_COUNT];

/// `global_chain_heads_digest`: the value of the chain whose lane heads are
/// `lanes`.
pub fn global_chain_heads_digest_variable<C: CircuitConfig<F = KoalaBear>, SC>(
    builder: &mut Builder<C>,
    config: &SC,
    lanes: &GlobalChainHeadsVariable<C>,
) -> [Felt<C::F>; DIGEST_SIZE]
where
    SC: KoalaBearFriParametersVariable<C>,
{
    let mut challenger = config.challenger_variable(builder);
    let domain: Felt<C::F> =
        builder.eval(C::F::from_u32(zkm_pcs::logup_gkr::GLOBAL_CHAIN_HEADS_DOMAIN));
    challenger.observe(builder, domain);
    for head in lanes {
        for h in head {
            challenger.observe(builder, *h);
        }
    }
    core::array::from_fn(|_| challenger.sample(builder))
}

/// The lane of the global hash chain a prover chose for a global round: one
/// bit for each lane, exactly one of them set. It is built by
/// [`Self::constrain`] only, so every selector in a program is constrained.
pub struct GlobalChainLaneSelectorVariable<C: CircuitConfig<F = KoalaBear>> {
    bits: [Felt<C::F>; GLOBAL_CHAIN_LANE_COUNT],
}

impl<C: CircuitConfig<F = KoalaBear>> GlobalChainLaneSelectorVariable<C> {
    /// The selector of the witnessed `bits`: asserts that each is zero or
    /// one and that they sum to one. There are fewer lanes than the field's
    /// characteristic, so the sum is one only when a single bit is set.
    pub fn constrain(
        builder: &mut Builder<C>,
        bits: [Felt<C::F>; GLOBAL_CHAIN_LANE_COUNT],
    ) -> Self {
        let mut sum: SymbolicFelt<C::F> = SymbolicFelt::ZERO;
        for bit in bits {
            builder.assert_felt_eq(bit * (bit - C::F::ONE), C::F::ZERO);
            sum = sum + bit;
        }
        builder.assert_felt_eq(sum, C::F::ONE);
        Self { bits }
    }

    /// The head of the selected lane of `lanes`.
    pub fn head(
        &self,
        builder: &mut Builder<C>,
        lanes: &GlobalChainHeadsVariable<C>,
    ) -> [Felt<C::F>; DIGEST_SIZE] {
        core::array::from_fn(|j| {
            let head: SymbolicFelt<C::F> =
                self.bits.iter().zip(lanes).map(|(bit, lane)| *bit * lane[j]).sum();
            builder.eval(head)
        })
    }

    /// `lanes` with the head of the selected lane replaced by `head`, and
    /// every other lane as it is.
    pub fn with_head(
        &self,
        builder: &mut Builder<C>,
        lanes: &GlobalChainHeadsVariable<C>,
        head: [Felt<C::F>; DIGEST_SIZE],
    ) -> GlobalChainHeadsVariable<C> {
        core::array::from_fn(|i| {
            core::array::from_fn(|j| {
                builder.eval(lanes[i][j] + self.bits[i] * (head[j] - lanes[i][j]))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use zkm_pcs::{
        koala_bear_poseidon2::KoalaBearPoseidon2,
        logup_gkr::{global_grinding_bits, GlobalChallenge},
        InnerChallenge, InnerVal, StarkGenericConfig,
    };
    use zkm_recursion_compiler::{
        config::InnerConfig,
        ir::{Builder, Ext, ExtConst, Felt},
    };

    use super::{
        global_chain_heads_digest_variable, GlobalChainHeadsVariable,
        GlobalChainLaneSelectorVariable, GlobalChallengeVariable,
    };
    use crate::utils::tests::run_test_recursion;
    use zkm_pcs::logup_gkr::{
        global_chain_heads_digest, GlobalChainHeads, GLOBAL_CHAIN_LANE_COUNT,
    };

    const BETA_SEED_DIM: usize = 2;

    fn host_challenge() -> GlobalChallenge<InnerVal, InnerChallenge> {
        let h_star = core::array::from_fn(|i| InnerVal::from_u32(11 * i as u32 + 3));
        GlobalChallenge::grind(KoalaBearPoseidon2::default().challenger(), h_star, BETA_SEED_DIM)
    }

    /// Derives the challenge in-circuit from `host.h_star` and `witness`, and,
    /// when `compare`, asserts it equals the host's.
    fn derive_in_circuit(
        host: &GlobalChallenge<InnerVal, InnerChallenge>,
        witness: InnerVal,
        compare: bool,
    ) {
        let config = KoalaBearPoseidon2::default();
        let mut builder = Builder::<InnerConfig>::default();
        let h_star: [Felt<InnerVal>; 8] = host.h_star.map(|h| builder.eval(h));
        let witness: Felt<InnerVal> = builder.eval(witness);
        let global = GlobalChallengeVariable::<InnerConfig>::derive(
            &mut builder,
            &config,
            h_star,
            witness,
            BETA_SEED_DIM,
        );
        if compare {
            let alpha: Ext<InnerVal, InnerChallenge> = builder.eval(host.alpha.cons());
            builder.assert_ext_eq(global.alpha, alpha);
            for (beta, expected) in global.betas.iter().zip(&host.betas) {
                let expected: Ext<InnerVal, InnerChallenge> = builder.eval(expected.cons());
                builder.assert_ext_eq(*beta, expected);
            }
        }
        run_test_recursion(builder.into_operations(), std::iter::empty());
    }

    #[test]
    fn the_circuit_derives_the_host_challenge() {
        let host = host_challenge();
        derive_in_circuit(&host, host.pow_witness, true);
    }

    #[test]
    #[should_panic]
    fn the_circuit_rejects_a_failing_proof_of_work() {
        assert!(global_grinding_bits() > 0, "the global challenge is ground");
        let host = host_challenge();
        let below = if host.pow_witness == InnerVal::ZERO {
            InnerVal::ONE
        } else {
            host.pow_witness - InnerVal::ONE
        };
        derive_in_circuit(&host, below, false);
    }

    fn host_chain_heads() -> GlobalChainHeads<InnerVal> {
        core::array::from_fn(|i| {
            core::array::from_fn(|j| InnerVal::from_u32(97 * i as u32 + j as u32 + 5))
        })
    }

    fn chain_heads_in_circuit(
        builder: &mut Builder<InnerConfig>,
        lanes: &GlobalChainHeads<InnerVal>,
    ) -> GlobalChainHeadsVariable<InnerConfig> {
        lanes.map(|head| head.map(|h| builder.eval(h)))
    }

    fn assert_chain_heads_eq(
        builder: &mut Builder<InnerConfig>,
        lanes: &GlobalChainHeadsVariable<InnerConfig>,
        expected: &GlobalChainHeads<InnerVal>,
    ) {
        for (head, expected) in lanes.iter().zip(expected) {
            for (h, e) in head.iter().zip(expected) {
                builder.assert_felt_eq(*h, *e);
            }
        }
    }

    /// Constrains a lane selector of `bits` in-circuit and runs the program.
    fn constrain_selector(bits: [i32; GLOBAL_CHAIN_LANE_COUNT]) {
        let mut builder = Builder::<InnerConfig>::default();
        let bits: [Felt<InnerVal>; GLOBAL_CHAIN_LANE_COUNT] = bits.map(|bit| {
            let magnitude = InnerVal::from_u32(bit.unsigned_abs());
            builder.eval(if bit < 0 { -magnitude } else { magnitude })
        });
        GlobalChainLaneSelectorVariable::<InnerConfig>::constrain(&mut builder, bits);
        run_test_recursion(builder.into_operations(), std::iter::empty());
    }

    #[test]
    fn the_circuit_digests_the_chain_heads_as_the_host_does() {
        let config = KoalaBearPoseidon2::default();
        let lanes = host_chain_heads();
        let mut moved = lanes;
        moved[3][6] += InnerVal::ONE;
        let mut swapped = lanes;
        swapped.swap(1, 2);
        let mut builder = Builder::<InnerConfig>::default();
        for state in [lanes, moved, swapped] {
            let expected = global_chain_heads_digest(config.challenger(), &state);
            let state = chain_heads_in_circuit(&mut builder, &state);
            let digest = global_chain_heads_digest_variable(&mut builder, &config, &state);
            for (d, e) in digest.iter().zip(expected) {
                builder.assert_felt_eq(*d, e);
            }
        }
        run_test_recursion(builder.into_operations(), std::iter::empty());
    }

    #[test]
    fn a_chain_lane_selector_reads_and_replaces_the_head_of_its_lane() {
        let lanes = host_chain_heads();
        let head: [InnerVal; 8] = core::array::from_fn(|j| InnerVal::from_u32(1000 + j as u32));
        let mut builder = Builder::<InnerConfig>::default();
        for lane in [0, 5, GLOBAL_CHAIN_LANE_COUNT - 1] {
            let state = chain_heads_in_circuit(&mut builder, &lanes);
            let bits: [Felt<InnerVal>; GLOBAL_CHAIN_LANE_COUNT] =
                core::array::from_fn(|i| builder.eval(InnerVal::from_bool(i == lane)));
            let selector =
                GlobalChainLaneSelectorVariable::<InnerConfig>::constrain(&mut builder, bits);
            let selected = selector.head(&mut builder, &state);
            for (s, e) in selected.iter().zip(lanes[lane]) {
                builder.assert_felt_eq(*s, e);
            }
            let new_head = head.map(|h| builder.eval(h));
            let replaced = selector.with_head(&mut builder, &state, new_head);
            let mut expected = lanes;
            expected[lane] = head;
            assert_chain_heads_eq(&mut builder, &replaced, &expected);
        }
        run_test_recursion(builder.into_operations(), std::iter::empty());
    }

    #[test]
    #[should_panic]
    fn the_circuit_rejects_a_selector_of_two_chain_lanes() {
        constrain_selector([0, 1, 0, 0, 1, 0, 0, 0]);
    }

    #[test]
    #[should_panic]
    fn the_circuit_rejects_a_selector_of_no_chain_lane() {
        constrain_selector([0; GLOBAL_CHAIN_LANE_COUNT]);
    }

    #[test]
    #[should_panic]
    fn the_circuit_rejects_a_selector_that_is_not_boolean() {
        constrain_selector([2, -1, 0, 0, 0, 0, 0, 0]);
    }
}
