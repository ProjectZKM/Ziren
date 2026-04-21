//! Stacked shape types for Ziren recursion (task #20).
//!
//! Ports the `CoreProofShape` / `MachineShape` / `SP1RecursionProgramShape`
//! design into Ziren.
//!
//! Tactic chosen (per scoping report at docs/task_22_plan.md): **size-class
//! quantization**.  Instead of enumerating every per-chip log-height
//! combination (~1.25M shapes), we enumerate representative shapes
//! parameterized by
//!
//!   (shard_chips, preprocessed_area, main_area, preprocessed_padding_cols, main_padding_cols)
//!
//! where `area` is measured in stacking-height-multiple cells.  This gives
//! us ~thousands of representative shapes instead of millions, and the
//! recursion verifier accepts any actual trace that fits under a
//! representative's upper bound.
//!
//! ## No ISA/Executor/zkVM-circuit changes
//!
//! This module is purely a *shape enumeration* layer at the recursion
//! boundary.  Ziren's per-chip core proof shape stays unchanged; the
//! row-reduction shapes here serve as the VK-indexing key and the upper-
//! bound contract the recursion circuit verifies against.  No
//! executor/trace-gen/AIR changes.
//!
//! ## Mapping to SP1
//!
//! | Ziren (this module)          | the source                                          |
//! |------------------------------|-----------------------------------------------------|
//! | [`CoreProofShape`]           | `/tmp/sp1/crates/hypercube/src/prover/shard.rs:798` |
//! | [`MachineShape`]             | `/tmp/sp1/crates/hypercube/src/machine.rs:10`       |
//! | [`ZKMRecursionProgramShape`] | `/tmp/sp1/crates/prover/src/shapes.rs:84`           |
//! | [`ZKMNormalizeInputShape`]   | `/tmp/sp1/crates/prover/src/shapes.rs:76`           |

pub mod enumerate;
pub mod types;

pub use enumerate::*;
pub use types::*;
