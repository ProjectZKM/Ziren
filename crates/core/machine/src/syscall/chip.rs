use core::fmt;
use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use p3_air::{Air, AirBuilder, BaseAir};
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
use zkm_stark::{LookupKind, Word};

use crate::{utils::next_power_of_two, CoreChipError};

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

    /// Full Word bytes for syscall result (op_a_value), used for linux syscall result linkage.
    pub result_word: Word<T>,

    /// Full Word bytes for arg1 (op_b_value), used for linux syscall byte-level matching.
    pub arg1_word: Word<T>,

    /// Full Word bytes for arg2 (op_c_value), used for linux syscall byte-level matching.
    pub arg2_word: Word<T>,

    /// Whether the syscall is a linux syscall.
    pub is_linux: T,

    pub is_real: T,
}

impl<F: PrimeField32> MachineAir<F> for SyscallChip {
    type Record = ExecutionRecord;

    type Program = Program;

    type Error = CoreChipError;

    fn name(&self) -> String {
        format!("Syscall{}", self.shard_kind).to_string()
    }

    fn generate_dependencies(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> Result<(), Self::Error> {
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

        let is_receive = self.shard_kind == SyscallShardKind::Precompile;
        let mut all_events: Vec<GlobalLookupEvent> = Vec::new();
        for event in events.iter() {
            // Existing Syscall global lookup.
            all_events.push(GlobalLookupEvent {
                message: [event.shard, event.clk, event.syscall_id, event.arg1, event.arg2, 0, 0],
                is_receive,
                kind: LookupKind::Syscall as u8,
            });

            // For linux syscalls, emit 3 extra global lookups for byte-level matching.
            let is_linux = event.a_record.prev_value.to_le_bytes()[1] != 0;
            if is_linux {
                let result_bytes = event.a_record.value.to_le_bytes();
                let arg1_bytes = event.arg1.to_le_bytes();
                let arg2_bytes = event.arg2.to_le_bytes();
                // Tag 0: result word bytes.
                all_events.push(GlobalLookupEvent {
                    message: [
                        event.shard, event.clk, 0,
                        result_bytes[0] as u32, result_bytes[1] as u32,
                        result_bytes[2] as u32, result_bytes[3] as u32,
                    ],
                    is_receive,
                    kind: LookupKind::SyscallResult as u8,
                });
                // Tag 1: arg1 word bytes.
                all_events.push(GlobalLookupEvent {
                    message: [
                        event.shard, event.clk, 1,
                        arg1_bytes[0] as u32, arg1_bytes[1] as u32,
                        arg1_bytes[2] as u32, arg1_bytes[3] as u32,
                    ],
                    is_receive,
                    kind: LookupKind::SyscallResult as u8,
                });
                // Tag 2: arg2 word bytes.
                all_events.push(GlobalLookupEvent {
                    message: [
                        event.shard, event.clk, 2,
                        arg2_bytes[0] as u32, arg2_bytes[1] as u32,
                        arg2_bytes[2] as u32, arg2_bytes[3] as u32,
                    ],
                    is_receive,
                    kind: LookupKind::SyscallResult as u8,
                });
            }
        }
        output.global_lookup_events.extend(all_events);
        Ok(())
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let events = match self.shard_kind() {
            SyscallShardKind::Core => &input.syscall_events,
            SyscallShardKind::Precompile => &input
                .precompile_events
                .all_events()
                .map(|(event, _)| event.to_owned())
                .collect::<Vec<_>>(),
        };
        let nb_rows = events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let row_fn = |syscall_event: &SyscallEvent, _: bool| {
            let mut row = [F::ZERO; NUM_SYSCALL_COLS];
            let cols: &mut SyscallCols<F> = row.as_mut_slice().borrow_mut();

            cols.shard = F::from_canonical_u32(syscall_event.shard);
            cols.clk = F::from_canonical_u32(syscall_event.clk);
            cols.syscall_id = F::from_canonical_u32(syscall_event.syscall_id);
            cols.arg1 = F::from_canonical_u32(syscall_event.arg1);
            cols.arg2 = F::from_canonical_u32(syscall_event.arg2);
            let is_linux = syscall_event.a_record.prev_value.to_le_bytes()[1] != 0;
            cols.is_linux = F::from_bool(is_linux);
            if is_linux {
                cols.result_word = syscall_event.a_record.value.into();
                cols.arg1_word = syscall_event.arg1.into();
                cols.arg2_word = syscall_event.arg2.into();
            }
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
        rows.resize(
            <SyscallChip as MachineAir<F>>::num_rows(self, input).unwrap(),
            [F::zero(); NUM_SYSCALL_COLS],
        );

        Ok(RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_SYSCALL_COLS))
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

        builder.assert_bool(local.is_real);
        builder.assert_bool(local.is_linux);
        // is_linux can only be 1 when is_real is 1.
        builder
            .when(AB::Expr::one() - local.is_real)
            .assert_zero(local.is_linux);

        let syscall_result_kind = AB::Expr::from_canonical_u8(LookupKind::SyscallResult as u8);

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

                // Receive SyscallResult from SyscallInstrsChip (local).
                builder.receive_syscall_result(
                    local.shard,
                    local.clk,
                    local.result_word,
                    local.arg1_word,
                    local.arg2_word,
                    local.is_linux,
                    LookupScope::Local,
                );

                // Send the Syscall lookup to the global table.
                builder.send(
                    AirLookup::new(
                        vec![
                            local.shard.into(),
                            local.clk.into(),
                            local.syscall_id.into(),
                            local.arg1.into(),
                            local.arg2.into(),
                            AB::Expr::zero(),
                            AB::Expr::zero(),
                            local.is_real.into() * AB::Expr::one(),
                            local.is_real.into() * AB::Expr::zero(),
                            AB::Expr::from_canonical_u8(LookupKind::Syscall as u8),
                        ],
                        local.is_real.into(),
                        LookupKind::Global,
                    ),
                    LookupScope::Local,
                );

                // Send 3 SyscallResult global lookups for linux syscalls (tag 0=result, 1=arg1, 2=arg2).
                for (tag, word) in [
                    (0u32, &local.result_word),
                    (1u32, &local.arg1_word),
                    (2u32, &local.arg2_word),
                ] {
                    builder.send(
                        AirLookup::new(
                            vec![
                                local.shard.into(),
                                local.clk.into(),
                                AB::Expr::from_canonical_u32(tag),
                                word[0].into(),
                                word[1].into(),
                                word[2].into(),
                                word[3].into(),
                                local.is_linux.into() * AB::Expr::one(),
                                local.is_linux.into() * AB::Expr::zero(),
                                syscall_result_kind.clone(),
                            ],
                            local.is_linux.into(),
                            LookupKind::Global,
                        ),
                        LookupScope::Local,
                    );
                }
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

                // Send SyscallResult to SysLinuxChip (local).
                builder.send_syscall_result(
                    local.shard,
                    local.clk,
                    local.result_word,
                    local.arg1_word,
                    local.arg2_word,
                    local.is_linux,
                    LookupScope::Local,
                );

                // Send the Syscall lookup to the global table.
                builder.send(
                    AirLookup::new(
                        vec![
                            local.shard.into(),
                            local.clk.into(),
                            local.syscall_id.into(),
                            local.arg1.into(),
                            local.arg2.into(),
                            AB::Expr::zero(),
                            AB::Expr::zero(),
                            local.is_real.into() * AB::Expr::zero(),
                            local.is_real.into() * AB::Expr::one(),
                            AB::Expr::from_canonical_u8(LookupKind::Syscall as u8),
                        ],
                        local.is_real.into(),
                        LookupKind::Global,
                    ),
                    LookupScope::Local,
                );

                // Send 3 SyscallResult global lookups for linux syscalls.
                for (tag, word) in [
                    (0u32, &local.result_word),
                    (1u32, &local.arg1_word),
                    (2u32, &local.arg2_word),
                ] {
                    builder.send(
                        AirLookup::new(
                            vec![
                                local.shard.into(),
                                local.clk.into(),
                                AB::Expr::from_canonical_u32(tag),
                                word[0].into(),
                                word[1].into(),
                                word[2].into(),
                                word[3].into(),
                                local.is_linux.into() * AB::Expr::zero(),
                                local.is_linux.into() * AB::Expr::one(),
                                syscall_result_kind.clone(),
                            ],
                            local.is_linux.into(),
                            LookupKind::Global,
                        ),
                        LookupScope::Local,
                    );
                }
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
