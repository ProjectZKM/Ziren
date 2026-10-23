//! The cross-shard global challenge in-circuit: the start of the hash chain
//! over the shards' global rounds, one step of the chain, and the
//! `(α_g, β_g)` a shard's global lookups use, derived from the chain's end.
//!
//! Each function absorbs exactly what its host counterpart in
//! `zkm_pcs::logup_gkr` absorbs, in the same order, on a fresh challenger of
//! the machine's configuration.

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use zkm_recursion_compiler::ir::{Builder, Ext, Felt, SymbolicExt};
use zkm_recursion_core::DIGEST_SIZE;

use crate::{
    challenger::{CanObserveVariable, CanSampleVariable, FieldChallengerVariable},
    logup_gkr::partial_lagrange_symbolic,
    CircuitConfig, KoalaBearFriParametersVariable, VerifyingKeyVariable,
};

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

/// `global_digest`: the chain start `h_0` of a proof under `vk`.
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

/// `global_chain_step`: `h_prev` extended by a shard's global round, `None`
/// for a shard without one.
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

    use super::GlobalChallengeVariable;
    use crate::utils::tests::run_test_recursion;

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
                builder.assert_ext_eq(beta.clone(), expected);
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
}
