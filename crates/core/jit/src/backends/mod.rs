//! Per-architecture JIT code emitters.
//!
//! Currently only `x86` (Linux x86_64) is supported; other targets
//! fall back to the interpreter at compile time via the cfg gate in
//! [`crate::lib`](crate).

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub mod x86;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub use x86::TranspilerBackend;
