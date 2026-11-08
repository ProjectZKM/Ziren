//! The budgets and the error terms of the zero-knowledge shrink.
//!
//! The zk shard proof hides its witness with committed randomness, and each
//! kind of randomness hides exactly as many values as it has cells.  A
//! [`ZkBudget`] counts, for one WHIR schedule and one shard shape, what the
//! verifier learns against what the prover committed:
//!
//! * **data stripes** — the round-0 queries open `q_0·2^{k_0}` entries of
//!   every stripe's codeword.  The stripe's padding half holds `2^lsh`
//!   uniform cells, and the evaluations of `x^{2^lsh}·r(x)` at distinct
//!   domain points are independent while there are at most `2^lsh` of them
//!   (a Vandermonde block), so the opened entries are uniform: the
//!   interleaved-code argument of Ligero.
//! * **the random stripe `R`** — everything else the verifier learns is a
//!   linear functional of `G = Σ_j γ_j S_j + γ_R R`, which `R` makes
//!   uniform: `R`'s own round-0 rows, its mask region, the folding
//!   messages, the out-of-domain answers, the later-round and final queries
//!   and the final polynomial.  Their count must stay below `R`'s
//!   `2^{lsh+1}` cells.
//! * **random rows** — each main column is opened at two points
//!   ([`COLUMN_EVALUATIONS`]), eight base-field coordinates, and its
//!   [`ZK_RANDOM_ROWS`] random rows give it as many uniform scalars when it
//!   is free in both a pair's sum and difference
//!   ([`crate::shard_level::zk`]).
//! * **salts** — every leaf of the main round and of every folded oracle
//!   hashes [`ZK_SALT_WIDTH`] uniform cells, so a sibling digest on an
//!   authentication path is a random-oracle output on a preimage with
//!   `salt_bits` bits of entropy.
//!
//! [`ZkErrors`] turns the counts into the two numbers the security
//! statement carries: the soundness error the masks add, in units of
//! `1/|EF|`, and the simulation error of the compiled proof in the random
//! oracle model.  The soundcalc census prints both for the production
//! schedule; the tests assert the budgets hold there.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::shard_level::zk::ZK_RANDOM_ROWS;
use crate::whir::config::WhirConfig;
use crate::whir::zk::{region_cells, ZK_PAD_VARS, ZK_SALT_WIDTH};
use crate::zk_mask::{ZkCellLayout, GKR_MASK_DEGREE};

/// `⌊100·log2 p⌋` for KoalaBear, `p = 2^31 − 2^24 + 1`.
pub const BASE_FIELD_CENTIBITS: usize = 3098;
/// Base coefficients of a challenge element.
pub const EF_DIM: usize = 4;
/// Bits of a uniform challenge element, floored.
pub const EF_BITS: usize = floor_bits(EF_DIM);
/// Points at which the shard verifier learns every main column: the
/// LogUp-GKR anchor and the zerocheck's reduced point.
pub const COLUMN_EVALUATIONS: usize = 2;
/// Random-oracle queries the simulation error is quoted at.
pub const LOG_RO_QUERIES: usize = 64;
/// Coefficients each WHIR folding message reveals (degree at most two).
const FOLD_MESSAGE_COEFFS: usize = 3;
/// Degree of an unmasked LogUp-GKR layer sumcheck.
const GKR_PLAIN_DEGREE: usize = 3;

/// `⌊elements · log2 p⌋`: the entropy of that many uniform base cells.
pub const fn floor_bits(elements: usize) -> usize {
    elements * BASE_FIELD_CENTIBITS / 100
}

const fn ceil_log2(n: usize) -> usize {
    n.next_power_of_two().trailing_zeros() as usize
}

/// What the verifier of one zk shard learns against what the prover
/// committed; see the module documentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkBudget {
    /// The jagged layer's stacking height; stripes are padded one variable
    /// wider.
    pub log_stacking_height: usize,
    /// Cells of a padded stripe, `2^{lsh + ZK_PAD_VARS}`; all of `R`'s are
    /// uniform.
    pub stripe_cells: usize,
    /// Uniform cells of a data stripe: its padding.
    pub stripe_random_cells: usize,
    /// Entries of each data stripe the round-0 queries open.
    pub stripe_revealed: usize,
    /// Linear functionals of `R` the verifier learns.
    pub random_stripe_learned: usize,
    /// Cells of the mask region and the cells the shard's layout uses.
    pub mask_cells: usize,
    pub mask_cells_used: usize,
    /// Evaluations of each main column the verifier learns, and the uniform
    /// base-field scalars the random rows give each column.
    pub column_evaluations: usize,
    pub random_row_scalars: usize,
    /// Entropy of a leaf's salt, in bits, and the salted leaves over all
    /// oracles.
    pub salt_bits: usize,
    pub salted_leaves: usize,
}

impl ZkBudget {
    /// The budget of `config` (the zk ring's schedule over `lsh + 1`
    /// variables) for a shard whose masks follow `layout`.
    pub fn for_schedule(config: &WhirConfig, lsh: usize, layout: &ZkCellLayout) -> Self {
        let n = lsh + ZK_PAD_VARS;
        let stripe_cells = 1usize << n;
        let rounds = &config.round_parameters;
        let committed = &rounds[..rounds.len() - 1];
        let folds: Vec<usize> = rounds.iter().map(|r| r.folding_factor).collect();
        let stripe_revealed = rounds[0].num_queries << folds[0];
        let mask_cells = region_cells(stripe_cells);

        let mut learned = stripe_revealed + mask_cells + config.starting_ood_samples;
        learned += folds.iter().sum::<usize>() * FOLD_MESSAGE_COEFFS;
        learned += committed.iter().map(|r| r.ood_samples).sum::<usize>();
        learned +=
            committed.iter().skip(1).map(|r| r.num_queries << r.folding_factor).sum::<usize>();
        learned += config.final_queries << folds[folds.len() - 1];
        learned += 1usize << config.final_poly_log_degree;

        let mut salted_leaves = 1usize << (n - folds[0] + config.starting_log_inv_rate);
        let mut remaining = n;
        for (r, round) in committed.iter().enumerate() {
            remaining -= round.folding_factor;
            salted_leaves += 1usize << (remaining - folds[r + 1] + round.log_inv_rate);
        }

        Self {
            log_stacking_height: lsh,
            stripe_cells,
            stripe_random_cells: stripe_cells - (1usize << lsh),
            stripe_revealed,
            random_stripe_learned: learned,
            mask_cells,
            mask_cells_used: layout.end,
            column_evaluations: COLUMN_EVALUATIONS,
            random_row_scalars: ZK_RANDOM_ROWS,
            salt_bits: floor_bits(ZK_SALT_WIDTH),
            salted_leaves,
        }
    }

    /// The budgets that do not hold, one line each; empty when the shard
    /// proof is hiding.
    pub fn violations(&self) -> Vec<String> {
        let mut out = Vec::new();
        let check = |out: &mut Vec<String>, ok: bool, what: &str, learned: usize, have: usize| {
            if !ok {
                out.push(alloc::format!("{what}: {learned} learned, {have} random"));
            }
        };
        check(
            &mut out,
            self.stripe_revealed <= self.stripe_random_cells,
            "data stripe entries",
            self.stripe_revealed,
            self.stripe_random_cells,
        );
        check(
            &mut out,
            self.random_stripe_learned <= self.stripe_cells,
            "random stripe functionals",
            self.random_stripe_learned,
            self.stripe_cells,
        );
        check(
            &mut out,
            self.mask_cells_used <= self.mask_cells,
            "mask cells",
            self.mask_cells_used,
            self.mask_cells,
        );
        check(
            &mut out,
            self.column_evaluations * EF_DIM <= self.random_row_scalars,
            "column coordinates",
            self.column_evaluations * EF_DIM,
            self.random_row_scalars,
        );
        out
    }

    /// Whether every budget holds.
    pub fn holds(&self) -> bool {
        self.violations().is_empty()
    }
}

impl fmt::Display for ZkBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[zk_shrink.budget]")?;
        writeln!(f, "log_stacking_height = {}", self.log_stacking_height)?;
        writeln!(
            f,
            "stripe_cells = {}   # per padded stripe; all of R's are uniform",
            self.stripe_cells
        )?;
        writeln!(
            f,
            "stripe_random_cells = {}   # a data stripe's padding",
            self.stripe_random_cells
        )?;
        writeln!(
            f,
            "stripe_revealed = {}   # round-0 queries x 2^k0, must not exceed stripe_random_cells",
            self.stripe_revealed
        )?;
        writeln!(
            f,
            "random_stripe_learned = {}   # functionals of R, must not exceed stripe_cells",
            self.random_stripe_learned
        )?;
        writeln!(f, "mask_cells = {}", self.mask_cells)?;
        writeln!(f, "mask_cells_used = {}   # the shard's layout", self.mask_cells_used)?;
        writeln!(f, "column_evaluations = {}", self.column_evaluations)?;
        writeln!(
            f,
            "random_row_scalars = {}   # uniform base summands per column, must cover column_evaluations x 4",
            self.random_row_scalars
        )?;
        writeln!(f, "salt_bits = {}   # entropy of every salted leaf", self.salt_bits)?;
        writeln!(
            f,
            "salted_leaves = {}   # main round and every folded oracle",
            self.salted_leaves
        )?;
        writeln!(f, "holds = {}", self.holds())
    }
}

/// The error terms the zk shrink adds to the security statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkErrors {
    /// Soundness error the masks add, in units of `1/|EF|`: the cube-sum
    /// check of every mask challenge, the two extra degrees of each masked
    /// LogUp-GKR layer round, the whole degree of each merge round, and the
    /// batching of the cell claims into the WHIR claim.
    pub soundness_units: usize,
    /// `−log2` of that error, floored.
    pub soundness_bits: usize,
    /// Cell claims the opening batches.
    pub cell_claims: usize,
    /// `−log2` of the simulation error of the compiled proof at
    /// `2^LOG_RO_QUERIES` random-oracle queries: a simulator that programs
    /// the oracle fails only when a query hits a salted preimage,
    /// `queries · salted_leaves / 2^salt_bits`.
    pub simulation_bits: usize,
}

impl ZkErrors {
    /// The terms for a shard with `num_interaction_variables` whose masks
    /// follow `layout` under `budget`.
    pub fn new(budget: &ZkBudget, layout: &ZkCellLayout, num_interaction_variables: usize) -> Self {
        let merge_rounds = num_interaction_variables + 1;
        let mut units = 2;
        for (k, round) in layout.gkr.iter().enumerate() {
            units += 1;
            units += if k < merge_rounds {
                GKR_MASK_DEGREE * round.variables
            } else {
                (GKR_MASK_DEGREE - GKR_PLAIN_DEGREE) * round.variables
            };
        }
        let cell_claims = layout.gkr.len() + 4;
        units += cell_claims + 2;
        Self {
            soundness_units: units,
            soundness_bits: EF_BITS - ceil_log2(units),
            cell_claims,
            simulation_bits: budget
                .salt_bits
                .saturating_sub(LOG_RO_QUERIES + ceil_log2(budget.salted_leaves)),
        }
    }
}

impl fmt::Display for ZkErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[zk_shrink.errors]")?;
        writeln!(f, "cell_claims = {}", self.cell_claims)?;
        writeln!(f, "mask_soundness_units = {}   # of 1/|EF|", self.soundness_units)?;
        writeln!(f, "mask_soundness_bits = {}", self.soundness_bits)?;
        writeln!(
            f,
            "simulation_bits = {}   # at 2^{LOG_RO_QUERIES} random-oracle queries",
            self.simulation_bits
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT;
    use crate::whir::jagged::zk_shrink_whir_config;
    use crate::zk_mask::ZK_MASK_CELLS;

    /// The production schedule keeps every budget for every shard shape the
    /// mask region admits, with orders of magnitude to spare.
    #[test]
    fn production_schedule_keeps_every_budget() {
        let lsh = DEFAULT_LOG_STACKING_HEIGHT as usize;
        let config = zk_shrink_whir_config(lsh);
        for i in 1..=14 {
            let layout = ZkCellLayout::for_shard(EF_DIM, 22, i);
            let budget = ZkBudget::for_schedule(&config, lsh, &layout);
            assert_eq!(budget.violations(), Vec::<String>::new(), "{budget}");
            assert_eq!(budget.mask_cells, ZK_MASK_CELLS);
            assert!(budget.stripe_revealed * 64 <= budget.stripe_random_cells, "{budget}");
            assert!(budget.random_stripe_learned * 64 <= budget.stripe_cells, "{budget}");
            let errors = ZkErrors::new(&budget, &layout, i);
            assert!(errors.soundness_bits >= 110, "{errors}");
            assert!(errors.simulation_bits >= 150, "{errors}");
        }
    }

    /// A stripe too short for its queries fails the first budget, and the
    /// failure names it.
    #[test]
    fn a_short_stripe_breaks_the_budget() {
        let lsh = 6;
        let mut config =
            crate::whir::jagged::whir_config_for_fold_schedule(lsh + ZK_PAD_VARS, &[3], 4);
        config.round_parameters[0].num_queries = 16;
        let layout = ZkCellLayout::new(EF_DIM, &[]);
        let budget = ZkBudget::for_schedule(&config, lsh, &layout);
        assert!(!budget.holds());
        assert!(budget.violations()[0].starts_with("data stripe entries"), "{budget}");
    }

    #[test]
    fn field_bits_are_floored() {
        assert_eq!(EF_BITS, 123);
        assert_eq!(floor_bits(ZK_SALT_WIDTH), 247);
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(5), 3);
    }
}
