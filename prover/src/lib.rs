//! A STARK framework.

#![no_std]

extern crate alloc;

mod config;
mod evaluation_frame;
mod folder;
mod generation;
mod proof;
mod prover;
mod stark;
mod stark_testing;
mod symbolic_builder;
mod symbolic_expression;
mod symbolic_variable;
mod verifier;
mod zerofier_coset;

#[cfg(debug_assertions)]
mod check_constraints;

#[cfg(debug_assertions)]
pub use check_constraints::*;
pub use config::*;
pub use folder::*;
pub use proof::*;
pub use prover::*;
pub use symbolic_builder::*;
pub use symbolic_expression::*;
pub use symbolic_variable::*;
pub use verifier::*;
pub use zerofier_coset::*;
