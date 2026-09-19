use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    ops::{Add, AddAssign},
};

use enum_map::{EnumArray, EnumMap};
use hashbrown::HashMap;

use crate::{events::generate_execution_report, syscalls::SyscallCode, Opcode};

/// An execution report.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReport {
    /// The opcode counts.
    pub opcode_counts: Box<EnumMap<Opcode, u64>>,
    /// The syscall counts.
    pub syscall_counts: Box<EnumMap<SyscallCode, u64>>,
    /// The cycle tracker counts.
    pub cycle_tracker: HashMap<String, u64>,
    /// The unique memory address counts.
    pub touched_memory_addresses: u64,
}

impl ExecutionReport {
    /// Compute the total number of instructions run during the execution.
    #[must_use]
    pub fn total_instruction_count(&self) -> u64 {
        self.opcode_counts.values().sum()
    }

    /// Compute the total number of syscalls made during the execution.
    #[must_use]
    pub fn total_syscall_count(&self) -> u64 {
        self.syscall_counts.values().sum()
    }
}

/// Combines two `HashMap`s together. If a key is in both maps, the values are added together.
fn counts_add_assign<K, V>(lhs: &mut EnumMap<K, V>, rhs: EnumMap<K, V>)
where
    K: EnumArray<V>,
    V: AddAssign,
{
    for (k, v) in rhs {
        lhs[k] += v;
    }
}

impl AddAssign for ExecutionReport {
    fn add_assign(&mut self, rhs: Self) {
        counts_add_assign(&mut self.opcode_counts, *rhs.opcode_counts);
        counts_add_assign(&mut self.syscall_counts, *rhs.syscall_counts);
        self.touched_memory_addresses += rhs.touched_memory_addresses;
        // The proving pipeline aggregates per-shard reports with this operator,
        // so omitting `cycle_tracker` silently discarded every
        // `cycle-tracker-report-*` measurement the guest emitted. A scope's
        // cycles are additive across the shards it spans, which is the same rule
        // the single-report accumulation in `handle_cycle_tracker_command` uses.
        for (name, cycles) in rhs.cycle_tracker {
            *self.cycle_tracker.entry(name).or_insert(0) += cycles;
        }
    }
}

impl Add for ExecutionReport {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl Display for ExecutionReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        writeln!(f, "opcode counts ({} total instructions):", self.total_instruction_count())?;
        for line in generate_execution_report(self.opcode_counts.as_ref()) {
            writeln!(f, "  {line}")?;
        }

        writeln!(f, "syscall counts ({} total syscall instructions):", self.total_syscall_count())?;
        for line in generate_execution_report(self.syscall_counts.as_ref()) {
            writeln!(f, "  {line}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ExecutionReport;

    /// The proving pipeline aggregates per-shard reports with `+=`, and this
    /// operator used to omit `cycle_tracker` entirely, so every
    /// `cycle-tracker-report-*` measurement was silently discarded on the way
    /// out. A scope's cycles are additive across the shards it spans.
    #[test]
    fn aggregation_keeps_scope_measurements() {
        let mut a = ExecutionReport::default();
        a.cycle_tracker.insert("keccak".into(), 100);
        a.cycle_tracker.insert("only_in_a".into(), 7);

        let mut b = ExecutionReport::default();
        b.cycle_tracker.insert("keccak".into(), 250);
        b.cycle_tracker.insert("only_in_b".into(), 9);

        a += b;
        assert_eq!(a.cycle_tracker.get("keccak"), Some(&350), "shared scopes add");
        assert_eq!(a.cycle_tracker.get("only_in_a"), Some(&7), "lhs-only survives");
        assert_eq!(a.cycle_tracker.get("only_in_b"), Some(&9), "rhs-only is carried over");
    }

    #[test]
    fn aggregating_into_an_empty_report_carries_everything() {
        let mut empty = ExecutionReport::default();
        let mut rhs = ExecutionReport::default();
        rhs.cycle_tracker.insert("prologue".into(), 42);
        rhs.touched_memory_addresses = 5;
        empty += rhs;
        assert_eq!(empty.cycle_tracker.get("prologue"), Some(&42));
        assert_eq!(empty.touched_memory_addresses, 5);
    }
}
