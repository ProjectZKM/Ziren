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

/// A shard's global challenge: the chain end `h_star` it is derived from,
/// `α_g`, and the `β_g` table (the eq table of the β seed).
pub struct GlobalChallengeVariable<C: CircuitConfig<F = KoalaBear>> {
    pub h_star: [Felt<C::F>; DIGEST_SIZE],
    pub alpha: Ext<C::F, C::EF>,
    pub betas: Vec<SymbolicExt<C::F, C::EF>>,
}

impl<C: CircuitConfig<F = KoalaBear>> GlobalChallengeVariable<C> {
    /// `GlobalChallenge::derive`: absorbs the domain and `h_star`, then samples
    /// `α_g` and `beta_seed_dim` seed elements.
    pub fn derive<SC>(
        builder: &mut Builder<C>,
        config: &SC,
        h_star: [Felt<C::F>; DIGEST_SIZE],
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
        let alpha = challenger.sample_ext(builder);
        let seed: Vec<SymbolicExt<C::F, C::EF>> =
            (0..beta_seed_dim).map(|_| challenger.sample_ext(builder).into()).collect();
        let betas = partial_lagrange_symbolic::<C>(&seed);
        Self { h_star, alpha, betas }
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
