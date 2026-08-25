use std::mem::size_of;
use zkm_derive::{AlignedBorrow, PicusAnnotations};
use zkm_pcs::{PicusInfo, Word};

use crate::operations::{AddOperation, KoalaBearWordRangeChecker, LtOperation};

pub const NUM_BRANCH_COLS: usize = size_of::<BranchColumns<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, PicusAnnotations, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BranchColumns<T> {
    /// Program fetch, register access and `(clk, pc)` chaining; live on every
    /// real row (every Branch row is an instruction).
    /// I-type across all six opcodes: `op_b` is a register (the zero-compare
    /// decodes read register 0), `op_c` the branch offset immediate.
    pub frame: crate::frame::ITypeFrameCols<T>,

    /// The current program counter.
    pub pc: T,

    /// The next program counter.
    pub next_pc: Word<T>,
    pub next_pc_range_checker: KoalaBearWordRangeChecker<T>,

    /// The inlined target addition: `target = next_pc + op_c` (the branch
    /// delay-slot target, proven in-row instead of via an AddSub request row).
    pub target_add: AddOperation<T>,

    /// The next next program counter.
    pub next_next_pc: Word<T>,

    /// Range check for next next program counter.
    /// Use it instead of check on target pc since reduced next_next_pc is directly used
    /// and target_pc equals to next_next_pc when it really works(the branch is taken).
    pub next_next_pc_range_checker: KoalaBearWordRangeChecker<T>,


    /// Branch Instructions Selectors.
    #[picus(selector)]
    pub is_beq: T,
    #[picus(selector)]
    pub is_bne: T,
    #[picus(selector)]
    pub is_bltz: T,
    #[picus(selector)]
    pub is_blez: T,
    #[picus(selector)]
    pub is_bgtz: T,
    #[picus(selector)]
    pub is_bgez: T,

    /// The branching column is equal to:
    ///
    /// > is_beq & a_eq_b ||
    /// > is_bne & !a_eq_b ||
    /// > is_bltz & a_lt_0 ||
    /// > is_bgtz & a_gt_0 ||
    /// > is_blez & (a_lt_0  | a_eq_0) ||
    /// > is_bgez & (a_gt_0  | a_eq_0)
    pub is_branching: T,

    /// Whether a is greater than b.
    pub a_gt_b: T,

    /// Whether a is less than b.
    pub a_lt_b: T,

    /// The inlined SIGNED comparison of `op_a` and `op_b` — one gadget yields
    /// lt / eq / gt, replacing the two SLT
    /// request rows the chip used to push onto the `Lt` chip.
    pub compare: LtOperation<T>,
}
