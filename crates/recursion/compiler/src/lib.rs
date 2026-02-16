#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]

extern crate alloc;

#[cfg(all(feature = "bn254", feature = "bls12381"))]
compile_error!("features `bn254` and `bls12381` are mutually exclusive");
#[cfg(not(any(feature = "bn254", feature = "bls12381")))]
compile_error!("either feature `bn254` or `bls12381` must be enabled");

pub mod circuit;
pub mod config;
pub mod constraints;
pub mod ir;

pub mod prelude {
    pub use crate::ir::*;
    pub use zkm_recursion_derive::DslVariable;
}
