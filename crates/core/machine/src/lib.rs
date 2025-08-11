#![allow(
    clippy::new_without_default,
    clippy::field_reassign_with_default,
    clippy::unnecessary_cast,
    clippy::cast_abs_to_unsigned,
    clippy::needless_range_loop,
    clippy::type_complexity,
    clippy::unnecessary_unwrap,
    clippy::default_constructed_unit_structs,
    clippy::box_default,
    clippy::assign_op_pattern,
    deprecated,
    incomplete_features
)]
#![warn(unused_extern_crates)]

pub mod air;
pub mod alu;
pub mod bytes;
pub mod control_flow;
pub mod cpu;
pub mod global;
pub mod io;
pub mod memory;
pub mod mips;
pub mod misc;
pub mod operations;
pub mod program;
#[cfg(test)]
pub mod programs;
pub mod shape;
pub mod syscall;
pub mod utils;
pub use cpu::*;
pub use mips::*;

/// The global version for all components of Ziren.
///
/// This string should be updated whenever any step in verifying a Ziren proof changes, including
/// core, recursion, and plonk-bn254. This string is used to download Ziren artifacts and the gnark
/// docker image.
pub const ZKM_CIRCUIT_VERSION: &str = "v1.1.2";

// Re-export the `ZKMReduceProof` struct from zkm_core_machine.
//
// This is done to avoid a circular dependency between zkm_core_machine and zkm_core_executor, and
// enable crates that depend on zkm_core_machine to import the `ZKMReduceProof` type directly.
pub mod reduce {
    pub use zkm_core_executor::ZKMReduceProof;
}
