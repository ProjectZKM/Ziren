//! Allocators for the Ziren zkVM.
//!
//! The `embedded` allocator takes precedence if enabled.

#[cfg(all(feature = "bump", not(feature = "embedded")))]
mod bump;

#[cfg(feature = "embedded")]
mod embedded;

#[cfg(feature = "embedded")]
pub use embedded::init;
