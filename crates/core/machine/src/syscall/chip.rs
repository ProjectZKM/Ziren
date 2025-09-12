use core::fmt;
use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_field::{FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::IntoParallelRefIterator;
use p3_maybe_rayon::prelude::ParallelBridge;
use p3_maybe_rayon::prelude::ParallelIterator;

use zkm_core_executor::events::GlobalLookupEvent;
use zkm_core_executor::{events::SyscallEvent, ExecutionRecord, Program};
use zkm_derive::AlignedBorrow;
use zkm_stark::air::AirLookup;
use zkm_stark::air::{LookupScope, MachineAir, ZKMAirBuilder};
use zkm_stark::LookupKind;

use crate::utils::pad_rows_fixed;

/// The number of main trace columns for `SyscallChip`.
pub const NUM_SYSCALL_COLS: usize = size_of::<SyscallCols<u8>>();

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SyscallShardKind {
    Core,
    Precompile,
}

/// A chip that stores the syscall invocations.
pub struct SyscallChip {
    shard_kind: SyscallShardKind,
}

impl SyscallChip {
    pub const fn new(shard_kind: SyscallShardKind) -> Self {
        Self { shard_kind }
    }

    pub const fn core() -> Self {
        Self::new(SyscallShardKind::Core)
    }

    pub const fn precompile() -> Self {
        Self::new(SyscallShardKind::Precompile)
    }

    pub fn shard_kind(&self) -> SyscallShardKind {
        self.shard_kind
    }
}

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct SyscallCols<T: Copy> {
    /// The shard number of the syscall.
    pub shard: T,

    /// The clk of the syscall.
    pub clk: T,

    /// The syscall_id of the syscall.
    pub syscall_id: T,

    /// The arg1.
    pub arg1: T,

    /// The arg2.
    pub arg2: T,

    pub is_real: T,
}

impl<F: PrimeField32> MachineAir<F> for SyscallChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        format!("Syscall{}", self.shard_kind).to_string()
    }

    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        let events = match self.shard_kind {
            SyscallShardKind::Core => &input
                .syscall_events
                .iter()
                .filter(|e| {
                    (e.a_record.prev_value.to_le_bytes()[2] == 1)
                        || (e.a_record.prev_value.to_le_bytes()[1] != 0)
                })
                .copied()
                .collect::<Vec<_>>(),
            SyscallShardKind::Precompile => &input
                .precompile_events
                .all_events()
                .map(|(event, _)| event.to_owned())
                .collect::<Vec<_>>(),
        };

        let events = events
            .iter()
            .map(|event| GlobalLookupEvent {
                message: [event.shard, event.clk, event.syscall_id, event.arg1, event.arg2, 0, 0],
                is_receive: self.shard_kind == SyscallShardKind::Precompile,
                kind: LookupKind::Syscall as u8,
            })
            .collect_vec();
        output.global_lookup_events.extend(events);
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let row_fn = |syscall_event: &SyscallEvent, _: bool| {
            let mut row = [F::ZERO; NUM_SYSCALL_COLS];
            let cols: &mut SyscallCols<F> = row.as_mut_slice().borrow_mut();

            cols.shard = F::from_canonical_u32(syscall_event.shard);
            cols.clk = F::from_canonical_u32(syscall_event.clk);
            cols.syscall_id = F::from_canonical_u32(syscall_event.syscall_id);
            cols.arg1 = F::from_canonical_u32(syscall_event.arg1);
            cols.arg2 = F::from_canonical_u32(syscall_event.arg2);
            cols.is_real = F::ONE;

            row
        };

        let mut rows = match self.shard_kind {
            SyscallShardKind::Core => input
                .syscall_events
                .par_iter()
                .filter(|event| {
                    (event.a_record.prev_value.to_le_bytes()[2] == 1)
                        || (event.a_record.prev_value.to_le_bytes()[1] != 0)
                })
                .map(|event| row_fn(event, false))
                .collect::<Vec<_>>(),
            SyscallShardKind::Precompile => input
                .precompile_events
                .all_events()
                .map(|(event, _)| event)
                .par_bridge()
                .map(|event| row_fn(event, true))
                .collect::<Vec<_>>(),
        };

        // Pad the trace to a power of two depending on the proof shape in `input`.
        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_SYSCALL_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_SYSCALL_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match self.shard_kind {
                SyscallShardKind::Core => {
                    shard
                        .syscall_events
                        .iter()
                        .filter(|e| {
                            (e.a_record.prev_value.to_le_bytes()[2] == 1)
                                || (e.a_record.prev_value.to_le_bytes()[1] != 0)
                        })
                        .take(1)
                        .count()
                        > 0
                }
                SyscallShardKind::Precompile => {
                    !shard.precompile_events.is_empty()
                        && shard.cpu_events.is_empty()
                        && shard.global_memory_initialize_events.is_empty()
                        && shard.global_memory_finalize_events.is_empty()
                }
            }
        }
    }

    fn commit_scope(&self) -> LookupScope {
        LookupScope::Local
    }
}

impl<AB> Air<AB> for SyscallChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SyscallCols<AB::Var> = (*local).borrow();

        builder.assert_eq(
            local.is_real * local.is_real * local.is_real,
            local.is_real * local.is_real * local.is_real,
        );

        match self.shard_kind {
            SyscallShardKind::Core => {
                builder.receive_syscall(
                    local.shard,
                    local.clk,
                    local.syscall_id,
                    local.arg1,
                    local.arg2,
                    local.is_real,
                    LookupScope::Local,
                );

                // Send the lookup to the global table.
                builder.send(
                    AirLookup::new(
                        vec![
                            local.shard.into(),
                            local.clk.into(),
                            local.syscall_id.into(),
                            local.arg1.into(),
                            local.arg2.into(),
                            AB::Expr::ZERO,
                            AB::Expr::ZERO,
                            local.is_real.into() * AB::Expr::ONE,
                            local.is_real.into() * AB::Expr::ZERO,
                            AB::Expr::from_canonical_u8(LookupKind::Syscall as u8),
                        ],
                        local.is_real.into(),
                        LookupKind::Global,
                    ),
                    LookupScope::Local,
                );
            }
            SyscallShardKind::Precompile => {
                builder.send_syscall(
                    local.shard,
                    local.clk,
                    local.syscall_id,
                    local.arg1,
                    local.arg2,
                    local.is_real,
                    LookupScope::Local,
                );

                // Send the lookup to the global table.
                builder.send(
                    AirLookup::new(
                        vec![
                            local.shard.into(),
                            local.clk.into(),
                            local.syscall_id.into(),
                            local.arg1.into(),
                            local.arg2.into(),
                            AB::Expr::ZERO,
                            AB::Expr::ZERO,
                            local.is_real.into() * AB::Expr::ZERO,
                            local.is_real.into() * AB::Expr::ONE,
                            AB::Expr::from_canonical_u8(LookupKind::Syscall as u8),
                        ],
                        local.is_real.into(),
                        LookupKind::Global,
                    ),
                    LookupScope::Local,
                );
            }
        }
    }
}

impl<F> BaseAir<F> for SyscallChip {
    fn width(&self) -> usize {
        NUM_SYSCALL_COLS
    }
}

impl fmt::Display for SyscallShardKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyscallShardKind::Core => write!(f, "Core"),
            SyscallShardKind::Precompile => write!(f, "Precompile"),
        }
    }
}
