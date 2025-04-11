mod consistency;
mod global;
mod instructions;
mod local;

pub use consistency::*;
pub use global::*;
pub use instructions::*;
pub use local::*;

/// The type of global/local memory chip that is being initialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryChipType {
    Initialize,
    Finalize,
}
