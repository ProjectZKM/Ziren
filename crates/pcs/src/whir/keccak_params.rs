//! Terminal-only WHIR schedules. Child core/compress proofs retain their own
//! parameters. The resolved configuration is bound by `terminal_key_digest`.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use super::config::WhirConfig;
use super::jagged::{bits_per_query_johnson, whir_config_for_fold_schedule};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeccakWhirParameters {
    pub folds: Vec<usize>,
    /// Rates of the oracles actually queried, including the final query phase.
    pub queried_log_inv_rates: Vec<usize>,
    pub johnson_m: usize,
    /// Query-only target for solving counts, not a complete PCS/quantum budget.
    pub component_target_bits: f64,
    pub query_grinding_bits: usize,
    pub folding_grinding_bits: usize,
    pub batching_grinding_bits: usize,
    pub ood_samples: usize,
}

impl Default for KeccakWhirParameters {
    fn default() -> Self {
        Self {
            folds: vec![1, 3, 4, 4, 4],
            queried_log_inv_rates: vec![4, 6, 8, 10, 12],
            johnson_m: 3,
            component_target_bits: 106.0,
            query_grinding_bits: 27,
            folding_grinding_bits: 27,
            batching_grinding_bits: 27,
            ood_samples: 2,
        }
    }
}

impl KeccakWhirParameters {
    /// Validate geometry and solve query counts. This is not a complete
    /// soundness validator: an approved schedule must also account for folding,
    /// batching, OOD and the actual stripe count (see the Solidity package parameter model).
    pub fn resolve(&self, lsh: usize) -> Result<WhirConfig, String> {
        let fail = |message: &str| Err(message.to_owned());
        if self.folds.is_empty() || self.folds.len() != self.queried_log_inv_rates.len() {
            return fail("one queried rate is required for each fold, including final queries");
        }
        if self.folds.iter().any(|&f| f == 0 || f > 8) || self.folds.iter().sum::<usize>() >= lsh {
            return fail("folds must be 1..=8 and leave at least one final variable");
        }
        if self.johnson_m == 0 || self.johnson_m > 64 || self.ood_samples < 2 {
            return fail("Johnson m must be 1..=64; retain at least two OOD samples");
        }
        if !self.component_target_bits.is_finite() || self.component_target_bits < 106.0 {
            return fail("terminal component target must not be reduced below 106 bits");
        }
        if [self.query_grinding_bits, self.folding_grinding_bits, self.batching_grinding_bits]
            .into_iter()
            .any(|g| g > 28)
        {
            return fail("base-field grinding witness search is capped at 28 bits");
        }
        let mut remaining = lsh;
        let mut previous_rate = 0;
        for (&fold, &rate) in self.folds.iter().zip(&self.queried_log_inv_rates) {
            if rate == 0 || rate > 24 || rate < previous_rate {
                return fail("queried rates must be positive, nondecreasing and at most 24");
            }
            // DFT batch height is 2^(remaining + rate - fold), not the
            // interleaved matrix's total number of cells 2^(remaining+rate).
            if remaining + rate - fold > 24 {
                return fail("interleaved DFT height exceeds KoalaBear's two-adicity");
            }
            remaining -= fold;
            previous_rate = rate;
        }
        let mut cfg = whir_config_for_fold_schedule(lsh, &self.folds, remaining);
        cfg.starting_log_inv_rate = self.queried_log_inv_rates[0];
        cfg.batch_pow_bits = self.batching_grinding_bits;
        for (i, round) in cfg.round_parameters.iter_mut().enumerate() {
            let queried_rate = self.queried_log_inv_rates[i];
            let bits = bits_per_query_johnson(queried_rate, self.johnson_m);
            if !bits.is_finite() || bits <= 0.0 {
                return fail("Johnson agreement bound must be strictly below one");
            }
            round.num_queries = ((self.component_target_bits - self.query_grinding_bits as f64)
                / bits)
                .ceil() as usize;
            // A non-final fold commits the code queried by the next round.
            // The last fold never commits; repeat its consumed rate there.
            round.log_inv_rate =
                self.queried_log_inv_rates.get(i + 1).copied().unwrap_or(queried_rate);
            round.queries_pow_bits = self.query_grinding_bits;
            round.pow_bits = vec![self.folding_grinding_bits; round.folding_factor];
            round.ood_samples = if i + 1 == self.folds.len() { 0 } else { self.ood_samples };
        }
        cfg.final_queries = cfg.round_parameters.last().unwrap().num_queries;
        cfg.final_pow_bits = self.query_grinding_bits;
        // These shape-template fields are not consumed by stacked WHIR; keep
        // their values consistent with the actual first/last folding grinds.
        cfg.starting_folding_pow_bits = cfg.round_parameters[0].pow_bits.clone();
        cfg.final_folding_pow_bits = cfg.round_parameters.last().unwrap().pow_bits.clone();
        Ok(cfg)
    }
}

/// Version-one terminal schedule. It is fixed by the ring type, shared by
/// commitment, opening, verification, key identity and export. Environment
/// variables and submitted proofs cannot select its parameters.
pub fn keccak_whir_config(lsh: usize) -> WhirConfig {
    KeccakWhirParameters::default().resolve(lsh).expect("valid Keccak WHIR parameters")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_final_rate_drives_final_queries() {
        let p = KeccakWhirParameters {
            folds: vec![2, 6, 6],
            queried_log_inv_rates: vec![3, 6, 9],
            johnson_m: 6,
            query_grinding_bits: 26,
            ..Default::default()
        };
        let cfg = p.resolve(21).unwrap();
        assert_eq!(cfg.final_queries, 19);
        assert_eq!(
            cfg.round_parameters.iter().map(|r| r.num_queries).collect::<Vec<_>>(),
            vec![58, 28, 19]
        );
    }

    #[test]
    fn interleaved_height_allows_rate_four_at_first_fold_one() {
        let p = KeccakWhirParameters::default();
        let cfg = p.resolve(21).unwrap();
        assert_eq!(cfg.final_poly_log_degree, 5);
        assert_eq!(cfg.final_queries, 14);
        assert_eq!(
            cfg.round_parameters.iter().map(|r| r.num_queries).collect::<Vec<_>>(),
            vec![45, 29, 21, 17, 14]
        );
        let mut bad = p;
        bad.queried_log_inv_rates[0] = 5;
        assert!(bad.resolve(21).is_err());
    }

    #[test]
    fn reject_malformed_and_query_target_downgrades() {
        let original = KeccakWhirParameters::default();
        let mut p = original.clone();
        p.component_target_bits = 100.0;
        assert!(p.resolve(21).is_err());
        let mut p = original.clone();
        p.query_grinding_bits = 29;
        assert!(p.resolve(21).is_err());
        let mut p = original.clone();
        p.folds[0] = 0;
        assert!(p.resolve(21).is_err());
        let mut p = original.clone();
        p.queried_log_inv_rates.pop();
        assert!(p.resolve(21).is_err());
        let mut p = original;
        p.ood_samples = 1;
        assert!(p.resolve(21).is_err());
    }
}
