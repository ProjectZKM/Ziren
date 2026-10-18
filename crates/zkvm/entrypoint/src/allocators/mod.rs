//! Allocators for the Ziren zkVM.
//!
//! The `embedded` allocator takes precedence if enabled.

#[cfg(all(feature = "bump", not(feature = "embedded")))]
mod bump;
#[cfg(all(feature = "bump", not(feature = "embedded")))]
pub(crate) use bump::alloc_untouched;

#[cfg(feature = "embedded")]
mod embedded;

#[cfg(feature = "embedded")]
pub use embedded::init;
