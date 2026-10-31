//! Compiles recursion programs into word-level constraint systems.
//!
//! The virtual machine is proven as an AIR; the recursion that compresses
//! its proofs is a fixed straight-line program, which this crate turns into
//! the relations of `p3-word` over 64-bit words: zero, bitwise AND and
//! full-width integer product, each over XORs of shifted words.  KoalaBear
//! arithmetic becomes integer identities on canonical words, Blake3
//! becomes lane additions with free XOR and rotations, and the program's
//! dataflow becomes the operands themselves.

pub mod blake3;
pub mod builder;
pub mod kb;
pub mod lower;
pub mod prove;
pub mod tape;

pub use builder::{Builder, Built, Cost, Val};
pub use lower::{lower, LowerError, Lowered};
