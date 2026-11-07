//! The zero-knowledge shrink ring (feature `zk`).
//!
//! The zk shrink is a terminal proof after the compress root, proven on the
//! shrink machine and verified natively; its statement is the application
//! key, the committed-value digest, the exit code and the recursion root
//! (the root digest, see
//! `zkm_recursion_circuit::machine::PublicValuesOutputDigest::ReduceToRoot`).
//!
//! The ring is the inner ring at its own profile index,
//! [`WHIR_PROFILE_ZK_SHRINK`], so that a zk-shrink proof and key are a
//! distinct type from the native shrink's.  Its openings run the
//! zero-knowledge stacked WHIR of [`crate::whir::zk`] under the shrink
//! schedule with a final polynomial one variable larger
//! ([`crate::whir::jagged::WhirProfile::ZkShrink`]):
//! padded stripes, a random stripe, one funnelled claim and salted leaves, so
//! the opening reveals nothing of the committed traces.  The masked
//! sumchecks and the hiding of the trace columns themselves are the later
//! phases' work.

use crate::koala_bear_poseidon2::{KoalaBearPoseidon2Ring, WHIR_PROFILE_ZK_SHRINK};

/// The inner ring under the zk-shrink profile: the zk shrink machine.
pub type KoalaBearPoseidon2ZkShrink = KoalaBearPoseidon2Ring<WHIR_PROFILE_ZK_SHRINK>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::WhirRing,
        koala_bear_poseidon2::{KoalaBearPoseidon2Shrink, WHIR_PROFILE_SHRINK},
        whir::jagged::WhirProfile,
    };

    /// The zk ring's schedule is the shrink schedule over stripes one
    /// variable wider: the same rounds, queries and rates, one more variable
    /// to fold.
    #[test]
    fn zk_shrink_ring_proves_under_the_widened_shrink_schedule() {
        use crate::whir::jagged::{shrink_whir_config, whir_config_for_profile};
        use crate::whir::zk::ZK_PAD_VARS;
        assert_eq!(<KoalaBearPoseidon2ZkShrink as WhirRing>::WHIR_PROFILE, WhirProfile::ZkShrink);
        assert_eq!(<KoalaBearPoseidon2Shrink as WhirRing>::WHIR_PROFILE, WhirProfile::Shrink);
        assert_ne!(WHIR_PROFILE_ZK_SHRINK, WHIR_PROFILE_SHRINK);
        let lsh = crate::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
        let zk = <KoalaBearPoseidon2ZkShrink as WhirRing>::whir_config(lsh);
        assert_eq!(zk, whir_config_for_profile(WhirProfile::ZkShrink, lsh));
        let native = shrink_whir_config(lsh);
        let folds: Vec<usize> = zk.round_parameters.iter().map(|rp| rp.folding_factor).collect();
        let native_folds: Vec<usize> =
            native.round_parameters.iter().map(|rp| rp.folding_factor).collect();
        assert_eq!(folds, native_folds);
        assert_eq!(zk.final_poly_log_degree, native.final_poly_log_degree + ZK_PAD_VARS);
        assert_eq!(folds.iter().sum::<usize>() + zk.final_poly_log_degree, lsh + ZK_PAD_VARS);
        for (z, n) in zk.round_parameters.iter().zip(&native.round_parameters) {
            assert_eq!(
                (z.num_queries, z.log_inv_rate, z.ood_samples),
                (n.num_queries, n.log_inv_rate, n.ood_samples)
            );
        }
        assert_eq!(
            (zk.final_queries, zk.final_pow_bits),
            (native.final_queries, native.final_pow_bits)
        );
        assert!(
            lsh + ZK_PAD_VARS + zk.starting_log_inv_rate
                <= <crate::InnerVal as p3_field::TwoAdicField>::TWO_ADICITY,
            "the first oracle must fit the two-adic subgroup"
        );
    }

    #[test]
    fn zk_shrink_ring_is_a_distinct_type() {
        assert_ne!(
            std::any::TypeId::of::<KoalaBearPoseidon2ZkShrink>(),
            std::any::TypeId::of::<KoalaBearPoseidon2Shrink>()
        );
    }
}
