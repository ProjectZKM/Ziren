//! Chip ordering shared by trace-round commitment, opening and verification.

use std::collections::BTreeSet;

use crate::{air::MachineAir, Chip};

/// Partitions name-ordered shard chips into the trace rounds before the main
/// round and the main round. Indices always refer to the original chip order;
/// within each round that order is preserved. A round that names none of the
/// chips is not committed, so the layout holds nonempty preceding rounds only.
///
/// A shard has at most one preceding round, its global round.
#[derive(Clone, Debug)]
pub struct TraceRoundLayout {
    preceding: Vec<Vec<usize>>,
    main: Vec<usize>,
    in_preceding: Vec<bool>,
}

impl TraceRoundLayout {
    /// The layout of a shard whose only preceding round is the global round.
    pub fn for_chips<F: p3_field::Field, A: MachineAir<F>>(
        chips: &[&Chip<F, A>],
        global_round: Option<&BTreeSet<String>>,
    ) -> Self {
        Self::for_rounds(chips, global_round.as_slice())
    }

    /// The layout whose preceding round `r` holds the chips named in
    /// `rounds[r]`; a chip named in none of them is in the main round, and one
    /// named in several is in the first.
    pub fn for_rounds<F: p3_field::Field, A: MachineAir<F>>(
        chips: &[&Chip<F, A>],
        rounds: &[&BTreeSet<String>],
    ) -> Self {
        let mut preceding = vec![Vec::new(); rounds.len()];
        for (i, chip) in chips.iter().enumerate() {
            let name = chip.name();
            if let Some(r) = rounds.iter().position(|set| set.contains(&name)) {
                preceding[r].push(i);
            }
        }
        Self::from_round_indices(chips.len(), preceding)
    }

    /// Builds the same layout from the global indices retained by a prover.
    pub fn from_global_indices(num_chips: usize, global: &[usize]) -> Self {
        Self::from_round_indices(num_chips, vec![global.to_vec()])
    }

    /// Builds the layout from the chip indices of each preceding round, in
    /// round order. Empty rounds are dropped.
    ///
    /// # Panics
    /// When two rounds hold the same chip.
    pub fn from_round_indices(num_chips: usize, mut preceding: Vec<Vec<usize>>) -> Self {
        preceding.retain(|round| !round.is_empty());
        let mut in_preceding = vec![false; num_chips];
        for &i in preceding.iter().flatten() {
            assert!(!in_preceding[i], "a chip is committed in one trace round");
            in_preceding[i] = true;
        }
        let main = (0..num_chips).filter(|&i| !in_preceding[i]).collect();
        Self { preceding, main, in_preceding }
    }

    /// Whether a trace round precedes the main round.
    pub fn has_global(&self) -> bool {
        !self.preceding.is_empty()
    }

    /// The chip indices of every trace round before the main round, in order.
    pub fn preceding(&self) -> &[Vec<usize>] {
        &self.preceding
    }

    /// The chip indices of a shard's global round, empty without one.
    ///
    /// # Panics
    /// When the layout has several preceding rounds.
    pub fn global_indices(&self) -> &[usize] {
        match self.preceding.as_slice() {
            [] => &[],
            [global] => global,
            _ => panic!("a layout with several preceding rounds has no single global round"),
        }
    }

    pub fn main_indices(&self) -> &[usize] {
        &self.main
    }

    /// Per chip, whether a round before the main round commits it.
    pub fn membership(&self) -> &[bool] {
        &self.in_preceding
    }

    /// Trace-round chip indices in opening order: the preceding rounds, then
    /// the main round.
    pub fn rounds(&self) -> Vec<&[usize]> {
        self.preceding.iter().map(Vec::as_slice).chain([self.main.as_slice()]).collect()
    }
}
