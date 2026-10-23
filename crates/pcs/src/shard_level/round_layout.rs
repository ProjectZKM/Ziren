//! Chip ordering shared by main-round commitment, opening and verification.

use std::collections::BTreeSet;

use crate::{air::MachineAir, Chip};

/// Partitions name-ordered shard chips into the global and local main rounds.
/// Indices always refer to the original chip order; within each round that
/// order is preserved. The global round, when nonempty, precedes the local one.
#[derive(Clone, Debug)]
pub struct MainRoundLayout {
    global: Vec<usize>,
    local: Vec<usize>,
    in_global: Vec<bool>,
}

impl MainRoundLayout {
    pub fn for_chips<F: p3_field::Field, A: MachineAir<F>>(
        chips: &[&Chip<F, A>],
        global_round: Option<&BTreeSet<String>>,
    ) -> Self {
        Self::from_membership(
            chips.iter().map(|chip| global_round.is_some_and(|set| set.contains(&chip.name()))),
        )
    }

    /// Builds the same layout from the global indices retained by a prover.
    pub fn from_global_indices(num_chips: usize, global: &[usize]) -> Self {
        let mut in_global = vec![false; num_chips];
        for &i in global {
            in_global[i] = true;
        }
        Self::from_membership(in_global)
    }

    pub fn from_membership(in_global: impl IntoIterator<Item = bool>) -> Self {
        let in_global: Vec<bool> = in_global.into_iter().collect();
        let (global, local) = (0..in_global.len()).partition(|&i| in_global[i]);
        Self { global, local, in_global }
    }

    pub fn has_global(&self) -> bool {
        !self.global.is_empty()
    }

    pub fn global_indices(&self) -> &[usize] {
        &self.global
    }

    pub fn local_indices(&self) -> &[usize] {
        &self.local
    }

    pub fn membership(&self) -> &[bool] {
        &self.in_global
    }

    /// Main-round chip indices in opening order, including an empty global
    /// slice when the shard has only a local round.
    pub fn rounds(&self) -> [&[usize]; 2] {
        [&self.global, &self.local]
    }
}
