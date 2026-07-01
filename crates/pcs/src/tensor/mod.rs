//! Minimal, backend-generic **tensor** primitives for the Ziren basefold
//! port (#125 INC-6).
//!
//! This is a Ziren-native, dependency-free re-modeling of SP1's
//! `slop`-crate tensor stack (`Backend` / `Buffer` / `Dimensions` /
//! `Tensor`).  We deliberately do **not** vendor SP1's `slop_*` crates —
//! only the ~4 small types [`crate::basefold::Mle`] actually needs are
//! reproduced here, and only the CPU backend is implemented.
//!
//! Layering:
//!   * [`Backend`] / [`CpuBackend`] — the memory-space marker.
//!   * [`Buffer`] — backend-generic linear storage (CPU = thin `Vec<T>`).
//!   * [`Dimensions`] — a 2D `[rows, cols]` row-major shape.
//!   * [`Tensor`] — `Buffer` + `Dimensions`; the storage for `Mle`.
//!
//! The whole point is that `Mle<F, A: Backend = CpuBackend>` becomes
//! backend-generic *without* any change to the CPU proving path: because
//! `A` defaults to `CpuBackend`, every existing `Mle<F>` / `Arc<Mle<F>>`
//! annotation keeps compiling, and the CPU accessors stay zero-copy so
//! the hot loops are byte- and perf-neutral.

mod backend;
mod buffer;
mod dimensions;
#[allow(clippy::module_inception)]
mod tensor;

pub use backend::{Backend, CpuBackend};
pub use buffer::Buffer;
pub use dimensions::Dimensions;
pub use tensor::Tensor;
