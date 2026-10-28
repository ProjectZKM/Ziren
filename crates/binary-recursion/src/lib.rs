//! The narrow binary recursion: the binary stage's verifier as a program
//! over `GF(2^128)`, recorded by running Plonky3's own verifier over a
//! value type that records what is done with it.
//!
//! The binary stage proves, over bits, a program that verifies a KoalaBear
//! proof, so its tables emulate KoalaBear arithmetic.  Its own verifier
//! works in `GF(2^128)`, the field the binary stage proves over, so a
//! program verifying it is native: an addition is wiring and a
//! multiplication one operation.  This crate records that program from the
//! verifier itself, so that it agrees with Plonky3 on every step of the
//! transcript by construction.

pub mod bytes;
pub mod challenger;
pub mod config;
pub mod domain;
pub mod fields;
pub mod machine;
pub mod mmcs;
pub mod queries;
pub mod tape;
pub mod traced;

pub use tape::{record, Op, Operand, Tape, F};
pub use traced::Traced;
