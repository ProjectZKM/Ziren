use core::fmt::{Debug, Display};

use p3_air::VirtualPairCol;
use p3_field::Field;

use crate::air::LookupScope;

/// A lookup or a permutation argument.
#[derive(Clone)]
pub struct Lookup<F: Field> {
    /// The values of the lookup.
    pub values: Vec<VirtualPairCol<F>>,
    /// The multiplicity of the lookup.
    pub multiplicity: VirtualPairCol<F>,
    /// The kind of lookup.
    pub kind: LookupKind,
    /// The scope of the lookup.
    pub scope: LookupScope,
}

/// The type of a lookup argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LookupKind {
    /// Lookup with the memory table, such as read and write.
    Memory = 1,

    /// Lookup with the program table, loading an instruction at a given pc address.
    Program = 2,

    /// Lookup with instruction oracle.
    Instruction = 3,

    /// Lookup with the byte lookup table for byte operations.
    Byte = 4,

    /// Requesting a range check for a given value and range.
    Range = 5,

    /// Lookup with a syscall.
    Syscall = 6,

    /// Lookup with the global table.
    Global = 7,

    /// Lookup connecting syscall result and argument bytes between SyscallInstrsChip,
    /// SyscallChip, and SysLinuxChip.
    SyscallResult = 8,

    /// CPU-state chaining bus (clk, pc).  Each instruction-bearing row
    /// `receive_state`s its current (clk, pc) and `send_state`s the next
    /// (clk', next_pc); the LogUp multiset balance forces consecutive
    /// rows to chain — the local-only replacement for the legacy
    /// `when_transition(local.next_pc == next.pc)` constraints.
    /// Boundary endpoints (initial / final pc, clk) are emitted by the
    /// public-values AIR.  Mirrors SP1 `InteractionKind::State`.
    State = 9,

    /// Running global-digest accumulation chain.  Each `GlobalChip` row
    /// receives `(index, running_digest)` and sends
    /// `(index+1, running_digest + this_point)`; anchored at both ends by
    /// the public-values AIR.  Mirrors SP1 `InteractionKind::GlobalAccumulation`.
    GlobalAccumulation = 10,

    /// Global-memory-init ordering control bus (index, prev_addr, valid).
    /// Mirrors SP1 `InteractionKind::MemoryGlobalInitControl`.
    MemoryGlobalInitControl = 11,

    /// Global-memory-finalize ordering control bus.
    /// Mirrors SP1 `InteractionKind::MemoryGlobalFinalizeControl`.
    MemoryGlobalFinalizeControl = 12,
}

impl LookupKind {
    /// Returns all kinds of lookups.
    #[must_use]
    pub fn all_kinds() -> Vec<LookupKind> {
        vec![
            LookupKind::Memory,
            LookupKind::Program,
            LookupKind::Instruction,
            LookupKind::Byte,
            LookupKind::Range,
            LookupKind::Syscall,
            LookupKind::Global,
            LookupKind::SyscallResult,
            LookupKind::State,
            LookupKind::GlobalAccumulation,
            LookupKind::MemoryGlobalInitControl,
            LookupKind::MemoryGlobalFinalizeControl,
        ]
    }

    /// Whether this kind's multiset is closed by endpoints emitted from
    /// the public-values AIR (rather than balancing entirely within the
    /// trace).  Mirrors SP1 `InteractionKind::appears_in_eval_public_values`.
    #[must_use]
    pub fn appears_in_eval_public_values(&self) -> bool {
        matches!(
            self,
            LookupKind::Byte
                | LookupKind::State
                | LookupKind::GlobalAccumulation
                | LookupKind::MemoryGlobalInitControl
                | LookupKind::MemoryGlobalFinalizeControl
        )
    }
}

impl<F: Field> Lookup<F> {
    /// Create a new lookup.
    pub const fn new(
        values: Vec<VirtualPairCol<F>>,
        multiplicity: VirtualPairCol<F>,
        kind: LookupKind,
        scope: LookupScope,
    ) -> Self {
        Self { values, multiplicity, kind, scope }
    }

    /// The index of the argument in the lookup table.
    pub const fn argument_index(&self) -> usize {
        self.kind as usize
    }
}

impl<F: Field> Debug for Lookup<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lookup")
            .field("kind", &self.kind)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl Display for LookupKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LookupKind::Memory => write!(f, "Memory"),
            LookupKind::Program => write!(f, "Program"),
            LookupKind::Instruction => write!(f, "Instruction"),
            LookupKind::Byte => write!(f, "Byte"),
            LookupKind::Range => write!(f, "Range"),
            LookupKind::Syscall => write!(f, "Syscall"),
            LookupKind::Global => write!(f, "Global"),
            LookupKind::SyscallResult => write!(f, "SyscallResult"),
            LookupKind::State => write!(f, "State"),
            LookupKind::GlobalAccumulation => write!(f, "GlobalAccumulation"),
            LookupKind::MemoryGlobalInitControl => write!(f, "MemoryGlobalInitControl"),
            LookupKind::MemoryGlobalFinalizeControl => write!(f, "MemoryGlobalFinalizeControl"),
        }
    }
}
