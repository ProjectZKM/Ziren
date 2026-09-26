//! The memory-instruction chips.
//!
//! These replace the former single `MemoryInstrs` union chip, which carried all
//! 14 memory opcodes in one 79-column table.  Because a jagged commitment pays
//! for `rows x columns`, every `LW` row in that table also paid for the store
//! masking flags, the sign-extension gadget and the unaligned scratch it never
//! used.  The opcodes are now partitioned by access width and direction, each
//! chip embedding [`common::MemoryInstrCommonCols`] plus only what it needs.
//!
//! On top of the split, the effective-address addition `addr = op_b + op_c` is
//! constrained inline (see [`common`]) rather than delegated to the `AddSub`
//! chip over the ALU bus, which removes one 19-cell `AddSub` row per memory
//! instruction, and narrow signed loads sign-extend with byte constraints
//! instead of a `SUB` ALU dependency.

pub mod common;
pub mod load_narrow;
pub mod load_word;
pub mod store_narrow;
pub mod store_word;
pub mod unaligned;

pub use common::{MemoryInstrCommonCols, NUM_MEMORY_INSTR_COMMON_COLS};
pub use load_narrow::{LoadNarrowChip, LoadNarrowColumns, NUM_LOAD_NARROW_COLS};
pub use load_word::{LoadWordChip, LoadWordColumns, NUM_LOAD_WORD_COLS};
pub use store_narrow::{StoreNarrowChip, StoreNarrowColumns, NUM_STORE_NARROW_COLS};
pub use store_word::{StoreWordChip, StoreWordColumns, NUM_STORE_WORD_COLS};
pub use unaligned::{MemoryUnalignedChip, MemoryUnalignedColumns, NUM_MEMORY_UNALIGNED_COLS};
