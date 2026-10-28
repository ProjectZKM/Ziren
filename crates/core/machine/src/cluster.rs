//! The chip set a core shard commits.

use std::collections::{BTreeMap, BTreeSet};

use p3_air::BaseAir;
use p3_field::PrimeField32;
use zkm_core_executor::ExecutionRecord;
use zkm_pcs::{
    air::MachineAir,
    stacked_shapes::{build_mips_machine_shape, MachineShape},
};

use crate::mips::MipsAir;

/// The chip clusters of the core machine, with each chip's trace width.
///
/// A core shard commits the smallest cluster that contains every chip it
/// includes. Cluster chips that exist in the machine but lack events in the
/// shard are committed as empty traces, so the committed chip set is determined
/// by the cluster and the machine's chip inventory.
pub struct ShardClusters<F: PrimeField32> {
    airs: Vec<MipsAir<F>>,
    shape: MachineShape,
    widths: BTreeMap<String, usize>,
}

impl<F: PrimeField32> ShardClusters<F> {
    #[must_use]
    pub fn new() -> Self {
        let (airs, _) = MipsAir::<F>::get_airs_and_costs();
        let widths = airs.iter().map(|air| (air.name(), BaseAir::<F>::width(air).max(1))).collect();
        Self { airs, shape: build_mips_machine_shape(), widths }
    }

    /// Maps chip names to trace widths for the smallest cluster that contains
    /// every chip `record` includes, restricted to the machine's chip inventory.
    /// Returns `None` when no cluster contains them.
    #[must_use]
    pub fn cluster_widths(&self, record: &ExecutionRecord) -> Option<BTreeMap<String, usize>> {
        let present: BTreeSet<String> =
            self.airs.iter().filter(|air| air.included(record)).map(MachineAir::name).collect();
        let cluster = self.shape.smallest_cluster(&present)?;
        // The catalog retains names such as `Cpu` that have no AIR in the machine.
        Some(
            cluster
                .iter()
                .filter_map(|name| self.widths.get(name).map(|&width| (name.clone(), width)))
                .collect(),
        )
    }
}

impl<F: PrimeField32> Default for ShardClusters<F> {
    fn default() -> Self {
        Self::new()
    }
}
