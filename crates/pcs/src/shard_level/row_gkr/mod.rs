//! Row-only LogUp-GKR backend.
//!
//! Halves the row dimension `num_row_variables - 1` times until each
//! layer is a 1-row × `2^num_interaction_variables` table, then
//! interleaves the four `(numerator_0/1, denominator_0/1)` sub-MLEs
//! into a single `2^(num_interaction_variables + 1)` pair so the
//! verifier sees the MLE shape it expects.

pub mod build;
pub mod device_circuit;
pub mod extract;
pub mod first_layer;
pub mod layer;
pub mod round;
pub mod top_level;
pub mod transition;

pub use build::*;
pub use device_circuit::*;
pub use extract::*;
pub use first_layer::*;
pub use layer::*;
pub use round::*;
pub use top_level::*;
pub use transition::*;
