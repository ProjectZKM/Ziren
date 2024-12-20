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
mod alu;
pub mod bytes;
pub mod mips;
mod operations;
pub mod utils;
pub use mips::*;

/// The global version for all components of ZKM.

///
/// This string should be updated whenever any step in verifying an ZKM proof changes, including
/// core, recursion, and plonk-bn254. This string is used to download ZKM artifacts and the gnark
/// docker image.
pub const ZKM_CIRCUIT_VERSION: &str = "v0.0.1";
