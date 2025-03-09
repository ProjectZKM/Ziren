use core::fmt::{Debug, Display};

use p3_air::VirtualPairCol;
use p3_field::Field;

use crate::air::LookupScope;

/// An interaction for a lookup or a permutation argument.
#[derive(Clone)]
pub struct Interaction<F: Field> {
    /// The values of the interaction.
    pub values: Vec<VirtualPairCol<F>>,
    /// The multiplicity of the interaction.
    pub multiplicity: VirtualPairCol<F>,
    /// The kind of interaction.
    pub kind: LookupKind,
    /// The scope of the interaction.
    pub scope: LookupScope,
}

/// The type of interaction for a lookup argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LookupKind {
    /// Interaction with the memory table, such as read and write.
    Memory = 1,

    /// Interaction with the program table, loading an instruction at a given pc address.
    Program = 2,

    /// Interaction with instruction oracle.
    Instruction = 3,

    /// Interaction with the ALU operations.
    Alu = 4,

    /// Interaction with the byte lookup table for byte operations.
    Byte = 5,

    /// Requesting a range check for a given value and range.
    Range = 6,

    /// Interaction with the field op table for field operations.
    Field = 7,

    /// Interaction with a syscall.
    Syscall = 8,

    /// Interaction with the global table.
    Global = 9,
}

impl LookupKind {
    /// Returns all kinds of interactions.
    #[must_use]
    pub fn all_kinds() -> Vec<LookupKind> {
        vec![
            LookupKind::Memory,
            LookupKind::Program,
            LookupKind::Instruction,
            LookupKind::Alu,
            LookupKind::Byte,
            LookupKind::Range,
            LookupKind::Field,
            LookupKind::Syscall,
            LookupKind::Global,
        ]
    }
}

impl<F: Field> Interaction<F> {
    /// Create a new interaction.
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

impl<F: Field> Debug for Interaction<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interaction")
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
            LookupKind::Alu => write!(f, "Alu"),
            LookupKind::Byte => write!(f, "Byte"),
            LookupKind::Range => write!(f, "Range"),
            LookupKind::Field => write!(f, "Field"),
            LookupKind::Syscall => write!(f, "Syscall"),
            LookupKind::Global => write!(f, "Global"),
        }
    }
}
