//! Operations implement common operations on sets of columns.
//!
//! They should always implement aim to implement `populate` and `eval` methods. The `populate`
//! method is used to populate the columns with values, while the `eval` method is used to evaluate
//! the constraints.

mod add;
mod add4;
mod add5;
mod adddouble;
mod and;
mod cmp;
pub mod field;
mod fixed_rotate_right;
mod fixed_shift_right;
mod global_accumulation;
mod global_lookup;
mod is_equal_word;
mod is_zero;
mod is_zero_word;
mod koala_bear_range;
mod koala_bear_word;
mod not;
mod or;
pub mod poseidon2;
mod xor;

pub use add::*;
pub use add4::*;
pub use add5::*;
pub use adddouble::*;
pub use and::*;
pub use cmp::*;
pub use fixed_rotate_right::*;
pub use fixed_shift_right::*;
pub use global_accumulation::*;
pub use global_lookup::*;
pub use is_equal_word::*;
pub use is_zero::*;
pub use is_zero_word::*;
pub use koala_bear_range::*;
pub use koala_bear_word::*;
pub use not::*;
pub use or::*;
pub use xor::*;
