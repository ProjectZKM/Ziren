//! Per-shard device-trace provider trait.
//!
//! Explicit per-shard parameter replaces a process-global snapshot
//! slot: under multi-GPU compress, pool workers prove shards
//! concurrently and would race for the global, with the
//! `(height, width)` check unable to disambiguate same-shape chips
//! across shards — silent cryptographic corruption.
//!
//! Trait is erased over the device-handle type so `zkm-pcs` stays
//! CUDA-agnostic; concrete impls live in `ziren-gpu`.
//!
//! ## Scope: host-consumed methods only
//!
//! SP1-parity: the trait carries ONLY what the host prover actually
//! calls.  Device-side queries with no host consumer (per-chip trace
//! lookup / peek / release-by-name, chip enumeration, canonical chip
//! order, and the commit orientation) live on a `ziren-gpu`-side
//! extension trait instead — every one of their call sites is in
//! `ziren-gpu`, which reaches the concrete provider by downcasting
//! through [`DeviceTraceProvider::as_any`].  Keeping them off this
//! trait stops `zkm-pcs` from carrying a device-shaped API surface it
//! never exercises.

use core::any::Any;

/// Per-shard, per-worker device-trace provider.
pub trait DeviceTraceProvider: Send + Sync {
    /// Erase to `&dyn Any` so `ziren-gpu` consumers holding only a
    /// `&dyn DeviceTraceProvider` can downcast to the concrete
    /// provider and reach the device-only extension methods (per-chip
    /// lookup/peek/release, chip enumeration, chip order, commit
    /// orientation, and the dense / commit-jagged pack accessors).
    /// Implementations return `self`.
    fn as_any(&self) -> &(dyn Any + Send + Sync);
}
