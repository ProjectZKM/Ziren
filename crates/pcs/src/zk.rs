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
//! schedule ([`crate::whir::jagged::WhirProfile::ZkShrink`]): hiding rows,
//! masked sumchecks and a masked base case, so the opening reveals nothing
//! of the committed traces.

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

    /// The zk ring's schedule is the shrink schedule without the batching
    /// grind and with its query counts raised to the rates the hiding rows
    /// leave: every phase meets the target again, every row has a seed more
    /// than its queries, and the rows fit their oracles.
    #[test]
    fn zk_shrink_ring_proves_under_the_shrink_schedule() {
        use crate::whir::jagged::{
            per_component_target_bits, shrink_whir_config, whir_config_for_profile,
        };
        use crate::whir::zk::{zk_query_phase_bits, zk_stages};
        assert_eq!(<KoalaBearPoseidon2ZkShrink as WhirRing>::WHIR_PROFILE, WhirProfile::ZkShrink);
        assert_eq!(<KoalaBearPoseidon2Shrink as WhirRing>::WHIR_PROFILE, WhirProfile::Shrink);
        assert_ne!(WHIR_PROFILE_ZK_SHRINK, WHIR_PROFILE_SHRINK);
        let lsh = crate::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
        let zk = <KoalaBearPoseidon2ZkShrink as WhirRing>::whir_config(lsh);
        assert_eq!(zk, whir_config_for_profile(WhirProfile::ZkShrink, lsh));
        let native = shrink_whir_config(lsh);
        assert_eq!(zk.batch_pow_bits, 0);
        assert_eq!(zk.final_poly_log_degree, native.final_poly_log_degree);
        for (z, n) in zk.round_parameters.iter().zip(&native.round_parameters) {
            assert_eq!(
                (z.folding_factor, z.log_inv_rate, z.ood_samples, z.queries_pow_bits),
                (n.folding_factor, n.log_inv_rate, n.ood_samples, n.queries_pow_bits)
            );
            assert!(z.num_queries >= n.num_queries);
        }
        assert!(zk.final_queries >= native.final_queries);
        let target = per_component_target_bits();
        for (s, (_, bits)) in zk_query_phase_bits(&zk, lsh).iter().enumerate() {
            assert!(*bits >= target, "phase {s}: {bits} bits");
        }
        let stages = zk_stages(&zk, lsh);
        for (s, stage) in stages.iter().enumerate() {
            assert!(stage.seeds > stage.queries, "stage {s}");
            assert!(stage.coefficients() <= 1usize << stage.domain_log, "stage {s}");
        }
        assert!(
            stages[0].domain_log <= <crate::InnerVal as p3_field::TwoAdicField>::TWO_ADICITY,
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
