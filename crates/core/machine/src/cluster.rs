//! The chip set a core shard commits.

use std::collections::{BTreeMap, BTreeSet};

use p3_air::BaseAir;
use p3_field::PrimeField32;
use zkm_core_executor::ExecutionRecord;
use zkm_pcs::{
    air::MachineAir,
    stacked_shapes::{
        build_mips_machine_shape, is_execution_cluster, MachineShape, FIRST_SHARD_CHIP,
    },
    StarkGenericConfig, StarkMachine,
};

use crate::mips::MipsAir;

/// The chip clusters of the core machine, with each chip's trace width.
///
/// A core shard commits the smallest cluster that contains every chip it
/// includes. Cluster chips that exist in the machine but lack events in the
/// shard are committed as empty traces, so the committed chip set is determined
/// by the cluster and the chips the machine has, with the family of the
/// shard's global round and, in the first shard, the memory image
/// ([`Self::committed_chip_sets`]).
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
    /// every chip `record` includes, restricted to the machine's chip set.
    /// Returns `None` when no cluster contains them.
    ///
    /// The first shard's memory image ([`FIRST_SHARD_CHIP`]) takes no part in
    /// the choice: the first shard commits its cluster and the image.
    #[must_use]
    pub fn cluster_widths(&self, record: &ExecutionRecord) -> Option<BTreeMap<String, usize>> {
        let present: BTreeSet<String> = self
            .airs
            .iter()
            .filter(|air| air.included(record))
            .map(MachineAir::name)
            .filter(|name| name != FIRST_SHARD_CHIP)
            .collect();
        let cluster = self.shape.smallest_cluster(&present)?;
        // The catalog retains names such as `Cpu` that have no AIR in the machine.
        Some(
            cluster
                .iter()
                .filter_map(|name| self.widths.get(name).map(|&width| (name.clone(), width)))
                .collect(),
        )
    }

    /// Every chip set a core shard commits on `machine`: a cluster's chips
    /// with the family of their global round
    /// ([`StarkMachine::global_family`]), and, for the cluster of an
    /// execution shard, the same with the first shard's memory image
    /// ([`FIRST_SHARD_CHIP`]).
    #[must_use]
    pub fn committed_chip_sets<SC>(
        &self,
        machine: &StarkMachine<SC, MipsAir<F>>,
    ) -> BTreeSet<BTreeSet<String>>
    where
        SC: StarkGenericConfig<Val = F>,
    {
        let committed = |mut chips: BTreeSet<String>| {
            let family = machine.global_family(chips.iter().map(String::as_str)).cloned();
            chips.extend(family.unwrap_or_default());
            chips
        };
        let mut sets = BTreeSet::new();
        for cluster in self.shape.chip_clusters.iter() {
            let chips: BTreeSet<String> =
                cluster.iter().filter(|name| self.widths.contains_key(*name)).cloned().collect();
            if is_execution_cluster(cluster) {
                let mut first = chips.clone();
                first.insert(FIRST_SHARD_CHIP.to_string());
                sets.insert(committed(first));
            }
            sets.insert(committed(chips));
        }
        sets
    }
}

impl<F: PrimeField32> Default for ShardClusters<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{io::ZKMStdin, utils::shard_records};
    use p3_koala_bear::KoalaBear;
    use zkm_core_executor::Program;
    use zkm_pcs::{
        koala_bear_poseidon2::KoalaBearPoseidon2, pad_to_cluster, pad_to_global_family, CpuProver,
        MachineProver, ZKMCoreOpts,
    };

    /// Every shard of real executions has a cluster, and the chips a prover
    /// commits for it are one of [`ShardClusters::committed_chip_sets`]: an
    /// execution of one shard, one cut into many shards, and one with
    /// precompile and memory shards.
    #[test]
    fn every_shard_commits_an_enumerated_chip_set() {
        let prover = CpuProver::<KoalaBearPoseidon2, MipsAir<KoalaBear>>::new(MipsAir::machine(
            KoalaBearPoseidon2::new(),
        ));
        let machine = prover.machine();
        let clusters = ShardClusters::<KoalaBear>::new();
        let enumerated = clusters.committed_chip_sets(machine);
        let fibonacci = |n: u32| {
            let mut stdin = ZKMStdin::new();
            stdin.write(&n);
            stdin
        };
        let runs = [
            (test_artifacts::FIBONACCI_ELF, fibonacci(10), ZKMCoreOpts::default()),
            (
                test_artifacts::FIBONACCI_ELF,
                fibonacci(1000),
                ZKMCoreOpts { shard_size: 1 << 10, ..ZKMCoreOpts::default() },
            ),
            (test_artifacts::KECCAK_SPONGE_ELF, ZKMStdin::default(), ZKMCoreOpts::default()),
        ];
        let mut committed = BTreeSet::new();
        for (elf, stdin, opts) in runs {
            let program = Program::from(elf).expect("the guest's program");
            let records = shard_records::<KoalaBearPoseidon2, _>(&prover, &program, &stdin, opts)
                .expect("the execution's shards");
            for record in records.iter() {
                let mut traces = prover.generate_traces(record).expect("the shard's traces");
                let cluster = clusters.cluster_widths(record).expect("a shard without a cluster");
                pad_to_cluster(&mut traces, &cluster);
                pad_to_global_family(machine, &mut traces);
                let chips = traces.keys().cloned().collect::<BTreeSet<_>>();
                assert!(enumerated.contains(&chips), "a shard commits {chips:?}");
                committed.insert(chips);
            }
        }
        let holds = |names: &[&str], lacks: &[&str]| {
            committed.iter().any(|chips| {
                names.iter().all(|name| chips.contains(*name))
                    && !lacks.iter().any(|name| chips.contains(*name))
            })
        };
        assert!(holds(&["MemoryImage", "MemoryGlobalInit"], &[]), "no execution of one shard");
        assert!(holds(&["MemoryImage"], &["MemoryGlobalInit"]), "no first shard of several");
        assert!(holds(&["AddSub"], &["MemoryImage"]), "no later execution shard");
        assert!(holds(&["KeccakSponge"], &["AddSub"]), "no precompile shard");
        assert!(holds(&["MemoryGlobalInit"], &["MemoryLocal"]), "no memory shard");
    }
}
