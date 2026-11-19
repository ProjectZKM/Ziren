//! The budgets and the error terms of the zero-knowledge shrink.
//!
//! The zk shard proof hides its witness with committed randomness, and each
//! kind of randomness hides exactly as many values as it has degrees of
//! freedom.  A [`ZkBudget`] counts, for one WHIR schedule and one shard
//! shape, what the verifier learns against what the prover committed
//! ([`crate::whir::zk`] has the opening):
//!
//! * **row seeds** — every row of every hiding oracle starts with `T` uniform
//!   coefficients, and the `t` queries to the oracle open it at `t` distinct
//!   points: the opened values are uniform while `t < T` (a Vandermonde
//!   block), with one coefficient to spare for the unopened leaves.
//! * **stage masks** — each stage's mask polynomial `U` has `2(k + 1)`
//!   extension coefficients and its `k`-variable sumcheck reveals `1 + 2k`
//!   values of it: `µ̃` and two free coefficients a round.
//! * **out-of-domain pads** — the auxiliary block of every folded oracle ends
//!   in uniform entries the out-of-domain answers weigh; one entry a sample
//!   makes the answers uniform.
//! * **the mask region** — the shard's masks fit the region the main round
//!   commits.
//! * **random rows** — each main column is opened at two points
//!   ([`COLUMN_EVALUATIONS`]), eight base-field coordinates, and its
//!   [`ZK_RANDOM_ROWS`] random rows give it as many uniform scalars when it
//!   is free in both a pair's sum and difference
//!   ([`crate::shard_level::zk`]).
//! * **leaf entropy** — no leaf is salted (Appendix B of Chiesa–Fenzi–
//!   Weissenberg, ePrint 2026/391): the spare seed coefficient leaves every
//!   row's value at an unopened point uniform, so an unopened leaf of `K`
//!   base rows keeps `(K − EF_DIM)·log2 p` bits once the folded seeds, an
//!   extension combination of its rows, are known.  The input oracle's
//!   leaves are the main round's stripes side by side, so their entropy
//!   grows with the main stripe count.
//!
//! [`ZkErrors`] turns the counts into the two numbers the security
//! statement carries: the soundness error the masks add, in units of
//! `1/|EF|`, and the simulation error of the compiled proof in the random
//! oracle model.  The soundcalc census prints both for the production
//! schedule; the tests assert the budgets hold there.
//!
//! The counts assume the challenges do not degenerate: a mask challenge of
//! zero, a LogUp-GKR layer challenge in `{0, 1}` or two opening points whose
//! random-row weight matrix is singular would leave a function of the
//! witness in the clear.  The verifier rejects such a transcript
//! ([`crate::shard_level::verifier::JaggedShardVerifyError::DegenerateChallenge`])
//! and an honest prover proves again with fresh randomness, so the
//! rejection costs no simulation error: the simulator draws its challenges
//! from the same non-degenerate set.  An honest prover meets a rejection
//! with probability below `2^-20` per proof (the weight matrices; the zero
//! and `{0, 1}` events are `1/|EF|` each).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::shard_level::zk::ZK_RANDOM_ROWS;
use crate::whir::config::WhirConfig;
use crate::whir::zk::{region_cells, zk_stages, ZkStage, ZK_MASK_COORDS};
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
/// Free coefficients each WHIR folding message reveals: three, less the one
/// the running claim fixes.
const FOLD_MESSAGE_FREE: usize = 2;
/// Degree of an unmasked LogUp-GKR layer sumcheck.
const GKR_PLAIN_DEGREE: usize = 3;

/// `⌊elements · log2 p⌋`: the entropy of that many uniform base cells.
pub const fn floor_bits(elements: usize) -> usize {
    elements * BASE_FIELD_CENTIBITS / 100
}

const fn ceil_log2(n: usize) -> usize {
    n.next_power_of_two().trailing_zeros() as usize
}

/// One stage's counts: its rows' seeds against the queries that open
/// them, its mask's coefficients against what its sumcheck reveals, the
/// out-of-domain pad of its oracle against the samples, and the entropy of
/// an unopened leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StageBudget {
    pub rows: usize,
    pub seeds: usize,
    pub queries: usize,
    pub mask_coefficients: usize,
    pub mask_revealed: usize,
    /// Uniform pad entries of the auxiliary block and the out-of-domain
    /// samples that weigh them; `None` on the input oracle, which has no
    /// out-of-domain answer.
    pub ood_pad: Option<(usize, usize)>,
    /// Base cells of a leaf, and its entropy in bits once the folded seeds
    /// are known.
    pub leaf_cells: usize,
    pub leaf_bits: usize,
    /// Leaves of the oracle.
    pub leaves: usize,
}

/// What the verifier of one zk shard learns against what the prover
/// committed; see the module documentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkBudget {
    /// The jagged layer's stacking height.
    pub log_stacking_height: usize,
    /// Stripes the main round covers: the input oracle's leaves hold one row
    /// block of each.
    pub main_stripes: usize,
    pub stages: Vec<StageBudget>,
    /// Cells of the mask region and the cells the shard's layout uses.
    pub mask_cells: usize,
    pub mask_cells_used: usize,
    /// Evaluations of each main column the verifier learns, and the uniform
    /// base-field scalars the random rows give each column.
    pub column_evaluations: usize,
    pub random_row_scalars: usize,
}

impl ZkBudget {
    /// The budget of `config` (the zk ring's schedule) for a shard whose
    /// masks follow `layout` and whose main round covers `main_stripes`
    /// stripes of height `2^lsh`.
    pub fn for_schedule(
        config: &WhirConfig,
        lsh: usize,
        layout: &ZkCellLayout,
        main_stripes: usize,
    ) -> Self {
        let stages = zk_stages(config, lsh);
        let rounds = &config.round_parameters;
        let stage_budget = |s: usize, stage: &ZkStage| {
            let k = stage.width.trailing_zeros() as usize;
            let (ood_pad, leaf_cells) = if s == 0 {
                (None, main_stripes * stage.width)
            } else {
                let pad = stage.aux * stage.width - ZK_MASK_COORDS * stage.width - stage.carried;
                (Some((pad, rounds[s - 1].ood_samples)), stage.width * EF_DIM)
            };
            StageBudget {
                rows: stage.width,
                seeds: stage.seeds,
                queries: stage.queries,
                mask_coefficients: ZK_MASK_COORDS * (k + 1),
                mask_revealed: 1 + FOLD_MESSAGE_FREE * k,
                ood_pad,
                leaf_cells,
                leaf_bits: floor_bits(leaf_cells.saturating_sub(EF_DIM)),
                leaves: 1usize << stage.domain_log,
            }
        };
        Self {
            log_stacking_height: lsh,
            main_stripes,
            stages: stages.iter().enumerate().map(|(s, st)| stage_budget(s, st)).collect(),
            mask_cells: region_cells(lsh),
            mask_cells_used: layout.end,
            column_evaluations: COLUMN_EVALUATIONS,
            random_row_scalars: ZK_RANDOM_ROWS,
        }
    }

    /// The fewest bits an unopened leaf of any oracle keeps.
    pub fn leaf_bits(&self) -> usize {
        self.stages.iter().map(|s| s.leaf_bits).min().unwrap_or(0)
    }

    /// Leaves over every oracle.
    pub fn leaves(&self) -> usize {
        self.stages.iter().map(|s| s.leaves).sum()
    }

    /// The budgets that do not hold, one line each; empty when the shard
    /// proof is hiding.
    pub fn violations(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut check = |ok: bool, what: String, learned: usize, have: usize| {
            if !ok {
                out.push(alloc::format!("{what}: {learned} learned, {have} random"));
            }
        };
        for (s, st) in self.stages.iter().enumerate() {
            check(
                st.queries < st.seeds,
                alloc::format!("stage {s} row seeds"),
                st.queries,
                st.seeds,
            );
            check(
                st.mask_revealed <= st.mask_coefficients,
                alloc::format!("stage {s} mask coefficients"),
                st.mask_revealed,
                st.mask_coefficients,
            );
            if let Some((pad, samples)) = st.ood_pad {
                check(samples <= pad, alloc::format!("stage {s} out-of-domain pad"), samples, pad);
            }
        }
        check(
            self.mask_cells_used <= self.mask_cells,
            "mask cells".into(),
            self.mask_cells_used,
            self.mask_cells,
        );
        check(
            self.column_evaluations * EF_DIM <= self.random_row_scalars,
            "column coordinates".into(),
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
        writeln!(f, "main_stripes = {}", self.main_stripes)?;
        for (s, st) in self.stages.iter().enumerate() {
            write!(
                f,
                "stage_{s} = {{ rows = {}, seeds = {}, queries = {}, mask_coefficients = {}, mask_revealed = {}, ",
                st.rows, st.seeds, st.queries, st.mask_coefficients, st.mask_revealed
            )?;
            if let Some((pad, samples)) = st.ood_pad {
                write!(f, "ood_pad = {pad}, ood_samples = {samples}, ")?;
            }
            writeln!(
                f,
                "leaf_cells = {}, leaf_bits = {}, leaves = {} }}",
                st.leaf_cells, st.leaf_bits, st.leaves
            )?;
        }
        writeln!(f, "mask_cells = {}", self.mask_cells)?;
        writeln!(f, "mask_cells_used = {}   # the shard's layout", self.mask_cells_used)?;
        writeln!(f, "column_evaluations = {}", self.column_evaluations)?;
        writeln!(
            f,
            "random_row_scalars = {}   # uniform base summands per column, must cover column_evaluations x 4",
            self.random_row_scalars
        )?;
        writeln!(f, "holds = {}", self.holds())
    }
}

/// The error terms the zk shrink adds to the security statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkErrors {
    /// Soundness error the masks add, in units of `1/|EF|`: the cube-sum
    /// check of every mask challenge, the two extra degrees of each masked
    /// LogUp-GKR layer round, the whole degree of each merge round, the
    /// batching of the cell claims into the input claim, each stage's mask
    /// challenge `ε` and the base case's `γ⋆`.
    pub soundness_units: usize,
    /// `−log2` of that error, floored.
    pub soundness_bits: usize,
    /// Cell claims the opening batches.
    pub cell_claims: usize,
    /// `−log2` of the simulation error of the compiled proof at
    /// `2^LOG_RO_QUERIES` random-oracle queries: a simulator that programs
    /// the oracle fails only when a query hits an unopened leaf's preimage,
    /// `queries · leaves / 2^leaf_bits`.
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
        units += cell_claims + budget.stages.len() + 1;
        Self {
            soundness_units: units,
            soundness_bits: EF_BITS - ceil_log2(units),
            cell_claims,
            simulation_bits: budget
                .leaf_bits()
                .saturating_sub(LOG_RO_QUERIES + ceil_log2(budget.leaves())),
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
    /// mask region admits once the main round covers two stripes, with room
    /// to spare.
    #[test]
    fn production_schedule_keeps_every_budget() {
        let lsh = DEFAULT_LOG_STACKING_HEIGHT as usize;
        let config = zk_shrink_whir_config(lsh);
        for i in 1..=14 {
            let layout = ZkCellLayout::for_shard(EF_DIM, 22, i);
            let budget = ZkBudget::for_schedule(&config, lsh, &layout, 2);
            assert_eq!(budget.violations(), Vec::<String>::new(), "{budget}");
            assert_eq!(budget.mask_cells, ZK_MASK_CELLS);
            assert_eq!(budget.stages.len(), config.round_parameters.len());
            let errors = ZkErrors::new(&budget, &layout, i);
            assert!(errors.soundness_bits >= 110, "{errors}");
            assert!(errors.simulation_bits >= 150, "{errors}");
        }
    }

    /// One main stripe of eight rows leaves the input oracle's leaves four
    /// base cells of entropy, too few to simulate against `2^64` queries.
    #[test]
    fn a_single_main_stripe_leaves_thin_leaves() {
        let lsh = DEFAULT_LOG_STACKING_HEIGHT as usize;
        let config = zk_shrink_whir_config(lsh);
        let layout = ZkCellLayout::for_shard(EF_DIM, 22, 8);
        let budget = ZkBudget::for_schedule(&config, lsh, &layout, 1);
        assert_eq!(budget.stages[0].leaf_bits, floor_bits(budget.stages[0].rows - EF_DIM));
        assert!(ZkErrors::new(&budget, &layout, 8).simulation_bits < 64, "{budget}");
    }

    #[test]
    fn field_bits_are_floored() {
        assert_eq!(EF_BITS, 123);
        assert_eq!(floor_bits(8), 247);
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(5), 3);
    }
}
