//! Per-thread device-first-layer side-channel: the prover thread
//! drains the GPU-resident first-layer artifacts into a TLS handle
//! at scope entry, downstream code on the same thread downcasts the
//! handle to its concrete type. TLS (not a mutex) avoids
//! cross-thread serialization on the hot first-round dispatch path.

use core::any::Any;
use std::sync::Arc;

type Ef4 = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;

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

/// Device-resident first-round-prove hook. Real implementation
/// lives in ziren-gpu; absent here.
pub type FirstRoundDeviceHook = fn(
    col_index: &[u32],
    start_indices: &[u32],
    eq_row_chip_offsets: &[u32],
    per_chip_cols: &[u32],
    per_chip_real_n0: &[u32],
    per_chip_real_n1: &[u32],
    per_chip_real_d0: &[u32],
    per_chip_real_d1: &[u32],
    per_chip_pair_offsets: &[u32],
    row_half: u32,
    total_pair_tasks: u32,
    total_one_quadrant_cells: u32,
    eq_row_real: &[Ef4],
    eq_int_real: &[Ef4],
    lambda: Ef4,
    alpha: Ef4,
) -> Option<(Vec<Ef4>, Vec<Ef4>)>;

/// Drain the device-first-layer stash via the registered hook.
#[must_use]
pub fn drain_via_hook() -> Option<DeviceFirstLayerHandle> {
    let drain = REGISTERED_DRAIN_HOOK.get().copied()?;
    let payload = drain()?;
    Some(DeviceFirstLayerHandle::new(payload))
}

#[must_use]
pub fn get_first_round_device_hook() -> Option<FirstRoundDeviceHook> {
    REGISTERED_FIRST_ROUND_HOOK.get().copied()
}

pub type FirstRoundDeviceHookRegistration = FirstRoundDeviceHook;

static REGISTERED_FIRST_ROUND_HOOK: std::sync::OnceLock<FirstRoundDeviceHook> =
    std::sync::OnceLock::new();

pub fn register_first_round_device_hook(
    f: FirstRoundDeviceHook,
) -> Result<(), FirstRoundDeviceHook> {
    REGISTERED_FIRST_ROUND_HOOK.set(f)
}

/// Hook ziren-gpu registers to drain its TLS-stashed device handle.
pub type DrainHook = fn() -> Option<Arc<dyn Any + Send + Sync>>;

static REGISTERED_DRAIN_HOOK: std::sync::OnceLock<DrainHook> = std::sync::OnceLock::new();

pub fn register_drain_hook(f: DrainHook) -> Result<(), DrainHook> {
    REGISTERED_DRAIN_HOOK.set(f)
}

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
