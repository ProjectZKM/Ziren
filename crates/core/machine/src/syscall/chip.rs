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

use zkm_core_executor::events::{GlobalLookupEvent, PrecompileEvent};
use zkm_core_executor::{events::SyscallEvent, ExecutionRecord, Program};
use zkm_derive::{AlignedBorrow, PicusAnnotations};
use zkm_stark::air::AirLookup;
use zkm_stark::air::{LookupScope, MachineAir, PicusInfo, ZKMAirBuilder};
use zkm_stark::LookupKind;

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

    /// Pack a u32 result into two half-word values (lo = bytes 0-1, hi = bytes 2-3).
    fn pack_result_halves(result: u32) -> (u32, u32) {
        let rb = result.to_le_bytes();
        (rb[0] as u32 + (rb[1] as u32) * 256, rb[2] as u32 + (rb[3] as u32) * 256)
    }
}

/// The column layout for the chip.
#[derive(AlignedBorrow, PicusAnnotations, Clone, Copy)]
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

    /// Half-word packed result (lo = byte0 + byte1*256, hi = byte2 + byte3*256).
    pub result_lo: T,
    pub result_hi: T,

    /// Half-word packed arg1 (op_b_value).
    pub arg1_lo: T,
    pub arg1_hi: T,

    /// Half-word packed arg2 (op_c_value).
    pub arg2_lo: T,
    pub arg2_hi: T,

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

    fn picus_info(&self) -> PicusInfo {
        SyscallCols::<u8>::picus_info()
    }

    fn generate_dependencies(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> Result<(), Self::Error> {
        let is_receive = self.shard_kind == SyscallShardKind::Precompile;

        let make_global =
            |event: &SyscallEvent, result_lo: u32, result_hi: u32| GlobalLookupEvent {
                message: [
                    event.shard,
                    event.clk,
                    event.syscall_id,
                    event.arg1,
                    event.arg2,
                    result_lo,
                    result_hi,
                ],
                is_receive,
                kind: LookupKind::Syscall as u8,
            };

        // Bug 18 fix: include linux syscall result (as packed half-words) in the
        // global message so results are verified across Core and Precompile shards.
        let events: Vec<GlobalLookupEvent> = match self.shard_kind {
            SyscallShardKind::Core => input
                .syscall_events
                .iter()
                .filter(|e| {
                    (e.a_record.prev_value.to_le_bytes()[2] == 1)
                        || (e.a_record.prev_value.to_le_bytes()[1] != 0)
                })
                .map(|event| {
                    let is_linux = event.a_record.prev_value.to_le_bytes()[1] != 0;
                    let (rlo, rhi) = if is_linux {
                        Self::pack_result_halves(event.a_record.value)
                    } else {
                        (0, 0)
                    };
                    make_global(event, rlo, rhi)
                })
                .collect(),
            SyscallShardKind::Precompile => input
                .precompile_events
                .all_events()
                .map(|(event, precompile)| {
                    let (rlo, rhi) = match precompile {
                        PrecompileEvent::Linux(le) => Self::pack_result_halves(le.v0),
                        _ => (0, 0),
                    };
                    make_global(event, rlo, rhi)
                })
                .collect(),
        };

        output.global_lookup_events.extend(events);
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
        let row_fn = |syscall_event: &SyscallEvent, precompile_event: Option<&PrecompileEvent>| {
            let mut row = [F::ZERO; NUM_SYSCALL_COLS];
            let cols: &mut SyscallCols<F> = row.as_mut_slice().borrow_mut();

            cols.shard = F::from_canonical_u32(syscall_event.shard);
            cols.clk = F::from_canonical_u32(syscall_event.clk);
            cols.syscall_id = F::from_canonical_u32(syscall_event.syscall_id);
            cols.arg1 = F::from_canonical_u32(syscall_event.arg1);
            cols.arg2 = F::from_canonical_u32(syscall_event.arg2);
            // For Core shard, a_record has real prev_value with linux_sys byte.
            // For Precompile shard, a_record is default (prev_value=0), so detect
            // linux from the PrecompileEvent variant instead.
            let is_linux = match precompile_event {
                Some(PrecompileEvent::Linux(_)) => true,
                Some(_) => false,
                None => syscall_event.a_record.prev_value.to_le_bytes()[1] != 0,
            };
            cols.is_linux = F::from_bool(is_linux);
            if is_linux {
                let result = match precompile_event {
                    Some(PrecompileEvent::Linux(linux_event)) => linux_event.v0,
                    _ => syscall_event.a_record.value,
                };
                let rb = result.to_le_bytes();
                cols.result_lo = F::from_canonical_u32(rb[0] as u32 + (rb[1] as u32) * 256);
                cols.result_hi = F::from_canonical_u32(rb[2] as u32 + (rb[3] as u32) * 256);
                let a1b = syscall_event.arg1.to_le_bytes();
                cols.arg1_lo = F::from_canonical_u32(a1b[0] as u32 + (a1b[1] as u32) * 256);
                cols.arg1_hi = F::from_canonical_u32(a1b[2] as u32 + (a1b[3] as u32) * 256);
                let a2b = syscall_event.arg2.to_le_bytes();
                cols.arg2_lo = F::from_canonical_u32(a2b[0] as u32 + (a2b[1] as u32) * 256);
                cols.arg2_hi = F::from_canonical_u32(a2b[2] as u32 + (a2b[3] as u32) * 256);
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
                .map(|event| row_fn(event, None))
                .collect::<Vec<_>>(),
            SyscallShardKind::Precompile => input
                .precompile_events
                .all_events()
                .par_bridge()
                .map(|(event, precompile)| row_fn(event, Some(precompile)))
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
        builder.when(AB::Expr::one() - local.is_real).assert_zero(local.is_linux);
        // Bug 18 fix: result_lo/result_hi must be zero when is_linux is 0, so they
        // can be used directly (degree 1) in the global lookup.
        builder.when_not(local.is_linux).assert_zero(local.result_lo);
        builder.when_not(local.is_linux).assert_zero(local.result_hi);

        // ProjectZKM/Ziren#488:4: Bind reduced arg1/arg2 to packed half-word columns.
        builder.when(local.is_linux).assert_eq(
            local.arg1,
            local.arg1_lo + local.arg1_hi * AB::Expr::from_canonical_u32(65536),
        );
        builder.when(local.is_linux).assert_eq(
            local.arg2,
            local.arg2_lo + local.arg2_hi * AB::Expr::from_canonical_u32(65536),
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

                builder.receive_syscall_result_packed(
                    local.shard,
                    local.clk,
                    local.result_lo,
                    local.result_hi,
                    local.arg1_lo,
                    local.arg1_hi,
                    local.arg2_lo,
                    local.arg2_hi,
                    local.is_linux,
                    LookupScope::Local,
                );

                // Send Syscall lookup to global table.
                // Bug 18 fix: include result_lo/result_hi so syscall results are
                // verified across Core and Precompile shards.
                builder.send(
                    AirLookup::new(
                        vec![
                            local.shard.into(),
                            local.clk.into(),
                            local.syscall_id.into(),
                            local.arg1.into(),
                            local.arg2.into(),
                            local.result_lo.into(),
                            local.result_hi.into(),
                            local.is_real.into() * AB::Expr::one(),
                            local.is_real.into() * AB::Expr::zero(),
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

                builder.send_syscall_result_packed(
                    local.shard,
                    local.clk,
                    local.result_lo,
                    local.result_hi,
                    local.arg1_lo,
                    local.arg1_hi,
                    local.arg2_lo,
                    local.arg2_hi,
                    local.is_linux,
                    LookupScope::Local,
                );

                // Send Syscall lookup to global table (with result for bug 18).
                builder.send(
                    AirLookup::new(
                        vec![
                            local.shard.into(),
                            local.clk.into(),
                            local.syscall_id.into(),
                            local.arg1.into(),
                            local.arg2.into(),
                            local.result_lo.into(),
                            local.result_hi.into(),
                            local.is_real.into() * AB::Expr::zero(),
                            local.is_real.into() * AB::Expr::one(),
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
