//! Backend abstraction for the Ziren-native [`super::Tensor`].
//!
//! A `Backend` names the memory space that a [`super::Buffer`] lives in.
//! Today the only backend is [`CpuBackend`] (host `Vec<T>` storage), but
//! the trait is deliberately shaped so a future `CudaBackend` — wrapping
//! `ziren-gpu`'s device buffers — can implement it without touching the
//! backend-agnostic parts of `Tensor` / `Mle`:
//!
//!   * `Clone + Debug` — a backend handle is a cheap, printable token.
//!   * `Send + Sync + 'static` — buffers cross rayon worker boundaries
//!     (the CPU hot loops fan out with `par_iter`), so both the backend
//!     marker and the buffers it owns must be thread-safe.
//!
//! This mirrors SP1's `slop`-crate `Backend` trait but carries **no**
//! associated-buffer machinery yet: the current CPU accessors are gated
//! on `A = CpuBackend`, so no generic device storage type is required
//! until a real device backend lands.

use core::fmt::Debug;

/// Marker trait for a tensor storage backend (memory space).
pub trait Backend: Clone + Debug + Send + Sync + 'static {}

/// The host / CPU backend: buffers are plain `Vec<T>` storage, byte-
/// identical to using `Vec` directly.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuBackend;

impl Backend for CpuBackend {}
