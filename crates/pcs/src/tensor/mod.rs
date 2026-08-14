//! Backend-generic **tensor** primitives for the Ziren basefold stack.
//!
//! Layering:
//!   * [`Allocator`] / [`AllocError`] — the raw allocate/deallocate contract.
//!   * [`mem`] — [`mem::CopyDirection`] / [`mem::CopyError`] / [`mem::DeviceMemory`],
//!     the device memcpy/memset contract.
//!   * [`Backend`] / [`CpuBackend`] — a memory space = `Allocator + DeviceMemory`
//!     (+ [`GlobalBackend`] / [`HasBackend`] and the `io` cross-backend copy traits).
//!   * [`RawBuffer`] — allocator-backed raw storage (ptr + cap).
//!   * [`Slice`] / [`Init`] — allocator-tagged slice / element views.
//!   * [`Buffer`] — fixed-capacity `RawBuffer` + `len`; the storage for [`crate::basefold::Mle`].
//!   * [`Dimensions`] — a 2D `[rows, cols]` row-major shape (Ziren-specific).
//!   * [`Tensor`] — `Buffer` + `Dimensions` (Ziren-specific).
//!
//! Only the **CPU backend** is implemented here, so the host `zkm-pcs` crate
//! stays device-dependency-free and every existing `Mle<F>` / `Buffer<F>`
//! annotation keeps compiling (the CPU accessors are zero-copy, so the hot
//! loops stay byte- and perf-neutral). `ziren-gpu` implements a `CudaBackend`
//! against the [`Backend`] / [`Allocator`] / [`mem::DeviceMemory`] traits.

mod allocator;
mod backend;
mod buffer;
mod dimensions;
mod init;
pub mod mem;
mod raw_buffer;
mod slice;
#[allow(clippy::module_inception)]
mod tensor;

pub use allocator::*;
pub use backend::*;
pub use buffer::Buffer;
pub use dimensions::Dimensions;
pub use init::Init;
pub use raw_buffer::{RawBuffer, TryReserveError};
pub use slice::Slice;
pub use tensor::Tensor;
