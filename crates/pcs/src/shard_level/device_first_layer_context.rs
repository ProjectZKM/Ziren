//! Per-thread device-first-layer side-channel: the prover thread
//! drains the GPU-resident first-layer artifacts into a TLS handle
//! at scope entry, downstream code on the same thread downcasts the
//! handle to its concrete type. TLS (not a mutex) avoids
//! cross-thread serialization on the hot first-round dispatch path.

use core::any::Any;
use std::sync::Arc;

/// Opaque, cheaply-cloneable handle to a device-resident
/// first-layer trace; downcast to recover the concrete type.
#[derive(Clone)]
pub struct DeviceFirstLayerHandle {
    payload: Arc<dyn Any + Send + Sync>,
}

impl Default for DeviceFirstLayerHandle {
    fn default() -> Self {
        Self { payload: Arc::new(()) }
    }
}

impl DeviceFirstLayerHandle {
    #[must_use]
    pub fn new(payload: Arc<dyn Any + Send + Sync>) -> Self {
        Self { payload }
    }

    #[must_use]
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        (*self.payload).downcast_ref::<T>()
    }

    /// Access the underlying Arc so the caller can extend its
    /// lifetime independently of this handle.
    #[must_use]
    pub fn payload(&self) -> &Arc<dyn Any + Send + Sync> {
        &self.payload
    }
}

impl From<Arc<dyn Any + Send + Sync>> for DeviceFirstLayerHandle {
    fn from(payload: Arc<dyn Any + Send + Sync>) -> Self {
        Self::new(payload)
    }
}

// Generation counter on the Guard defends against nested Guards on
// the same thread: a stale Drop must not clear a newer install, so
// the gen check only clears when the slot still holds this Guard.

thread_local! {
    static CURRENT_HANDLE: std::cell::RefCell<Option<(u64, DeviceFirstLayerHandle)>> =
        const { std::cell::RefCell::new(None) };
}

static GUARD_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Installs a `DeviceFirstLayerHandle` into the per-thread stash
/// for its scope; on Drop clears the stash only when the slot still
/// holds this Guard's generation.
pub struct DeviceFirstLayerGuard {
    gen: u64,
}

impl DeviceFirstLayerGuard {
    #[must_use]
    pub fn new(handle: impl Into<DeviceFirstLayerHandle>) -> Self {
        let handle = handle.into();
        let gen = GUARD_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        CURRENT_HANDLE.with(|c| {
            *c.borrow_mut() = Some((gen, handle));
        });
        Self { gen }
    }
}

impl Drop for DeviceFirstLayerGuard {
    fn drop(&mut self) {
        CURRENT_HANDLE.with(|c| {
            let mut slot = c.borrow_mut();
            if let Some((gen, _)) = slot.as_ref() {
                if *gen == self.gen {
                    *slot = None;
                }
            }
        });
    }
}

/// Clone of the currently-stashed handle for the calling thread.
/// Cheap (Arc bump) and `'static` so the caller can hold it across
/// temporary borrows of the TLS slot.
#[must_use]
pub fn current_device_first_layer() -> Option<DeviceFirstLayerHandle> {
    CURRENT_HANDLE.with(|c| c.borrow().as_ref().map(|(_, h)| h.clone()))
}

// D3c (Option-C divergence): the `FirstRoundProvider` / `DrainProvider` traits
// + `HostFirstRound` / `HostDrain` impls + `drain_via_hook` were REMOVED.  Their
// sole consumer was the runtime-dead GPU fused first-round path
// (`try_first_round_on_gpu`, `enabled = false`), retired in P7 along with the
// `GPU_FIRST_ROUND` hook — so `LogupRoundPolynomial::new` ignored the two
// providers (`_`-prefixed).  The row-GKR first-round is now the host per-chip
// path unconditionally; `prove_shard_logup_gkr_rows` / `prove_gkr_round` no
// longer thread them.  The `DeviceFirstLayerHandle` / `DeviceFirstLayerGuard` /
// `current_device_first_layer` TLS stash above is retained (the GPU first-layer
// generation still installs into it; harmless side channel).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_installs_and_clears_handle() {
        assert!(current_device_first_layer().is_none());

        struct Marker(u32);
        let arc: Arc<dyn Any + Send + Sync> = Arc::new(Marker(42));
        {
            let _g = DeviceFirstLayerGuard::new(arc.clone());
            let got = current_device_first_layer().expect("installed");
            let marker = got.downcast_ref::<Marker>().expect("downcast");
            assert_eq!(marker.0, 42);
        }
        assert!(current_device_first_layer().is_none());
    }

    #[test]
    fn guard_accepts_raw_handle() {
        let handle = DeviceFirstLayerHandle::default();
        let _g = DeviceFirstLayerGuard::new(handle);
        assert!(current_device_first_layer().is_some());
    }

    #[test]
    fn out_of_order_drop_safety() {
        struct First;
        struct Second;

        let first_arc: Arc<dyn Any + Send + Sync> = Arc::new(First);
        let second_arc: Arc<dyn Any + Send + Sync> = Arc::new(Second);

        let g_first = DeviceFirstLayerGuard::new(first_arc);
        let _g_second = DeviceFirstLayerGuard::new(second_arc);

        assert!(current_device_first_layer()
            .unwrap()
            .downcast_ref::<Second>()
            .is_some());

        // Stale Guard's gen no longer matches; Drop must be a no-op.
        drop(g_first);
        assert!(current_device_first_layer()
            .unwrap()
            .downcast_ref::<Second>()
            .is_some());
    }
}
