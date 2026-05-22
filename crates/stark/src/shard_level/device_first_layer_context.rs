//! + #308 Phase 3/4: per-thread device-first-layer side-channel
//! API consumed by `row_gkr/round.rs` and by ziren-gpu's
//! `basefold/src/device_first_layer.rs`.
//!
//! Lifecycle:
//! 1. ziren-gpu registers `drain_to_handle` via `register_drain_hook`
//!    at process init.
//! 2. The per-shard prover thread, at the start of `try_first_round_on_gpu`
//!    (see `row_gkr/round.rs:914`), calls `drain_via_hook()` and binds
//!    the returned handle into a `DeviceFirstLayerGuard`.  The Guard's
//!    `new` installs the handle into a thread-local slot; `Drop` clears
//!    it.
//! 3. Downstream code (`current_device_first_layer()`) on the same
//!    thread sees `Some(handle)` and can `.downcast_ref::<T>()` to
//!    recover ziren-gpu's `DeviceFirstLayerArtifacts`.
//!
//! The Handle's payload is the same `Arc<dyn Any + Send + Sync>`
//! ziren-gpu's `drain_to_handle` returns (matching SP1's erased-trait
//! pattern), so `downcast_ref::<T>()` succeeds when `T` is the
//! concrete type ziren-gpu stored in the Arc.

use core::any::Any;
use std::sync::Arc;

type Ef4 = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;

/// Opaque, cheaply-cloneable handle to a device-resident first-layer
/// trace.  Wraps the same `Arc<dyn Any + Send + Sync>` payload
/// ziren-gpu's `drain_to_handle` returns, so consumers can
/// `.downcast_ref::<T>()` to recover their concrete type.
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
    /// Wrap an erased Arc payload.  Used by `drain_via_hook` and by
    /// tests that construct handles directly.
    #[must_use]
    pub fn new(payload: Arc<dyn Any + Send + Sync>) -> Self {
        Self { payload }
    }

    /// Borrow the payload as `T` if the contained value is a `T`.
    #[must_use]
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        (*self.payload).downcast_ref::<T>()
    }

    /// Access the underlying Arc payload (for callers that need to
    /// extend its lifetime independently of this handle).
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

// ────────────────────────────────────────────────────────────────────
// Per-thread TLS stash.
//
// The handle lives in a `thread_local!` `RefCell<Option<...>>`.  The
// Guard installs on `new()` and clears on `Drop`, so the stash is
// strictly bounded to the Guard's scope on the producing thread.
//
// Why TLS (not a process-global mutex):
//   - The per-shard prove worker that calls `drain_via_hook` is the
//     same thread that later runs the first-round dispatch.  Other
//     concurrent shard workers on other GPU pool threads each have
//     their own stash, so there's no cross-shard interference.
//   - Avoids the cross-thread serialization a Mutex would impose on
//     the hot first-round dispatch path.
//
// Why a generation counter on the Guard:
//   - Defends against accidental nested Guards on the same thread.
//     A nested Guard's Drop must not blow away the outer Guard's
//     stash if Drop fires out of order; the gen check on Drop only
//     clears when the running Guard is the one that installed.

thread_local! {
    static CURRENT_HANDLE: std::cell::RefCell<Option<(u64, DeviceFirstLayerHandle)>> =
        const { std::cell::RefCell::new(None) };
}

static GUARD_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Drop-guard that installs a `DeviceFirstLayerHandle` into the
/// per-thread stash for its scope.  When dropped, clears the stash
/// IFF the slot still holds this Guard's generation (defends against
/// nested-Guard out-of-order Drop accidentally clearing a parent).
pub struct DeviceFirstLayerGuard {
    gen: u64,
}

impl DeviceFirstLayerGuard {
    /// Install `handle` into the current thread's stash and return a
    /// Guard whose `Drop` clears it.
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

/// Returns a clone of the currently-stashed device-first-layer handle
/// for the calling thread, if any.  The clone is cheap (single Arc
/// bump) and 'static, so the caller can hold it across temporary
/// borrows of the TLS slot.
#[must_use]
pub fn current_device_first_layer() -> Option<DeviceFirstLayerHandle> {
    CURRENT_HANDLE.with(|c| c.borrow().as_ref().map(|(_, h)| h.clone()))
}

/// Signature of the device-resident first-round-prove hook. Real
/// implementation lives in ziren-gpu; stub here returns `None`.
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
/// Invokes the `DrainHook` registered by ziren-gpu (if any) and
/// wraps the returned `Arc<dyn Any + Send + Sync>` payload in a
/// `DeviceFirstLayerHandle` so consumers can
/// `.downcast_ref::<T>()` to their concrete type.
#[must_use]
pub fn drain_via_hook() -> Option<DeviceFirstLayerHandle> {
    let drain = REGISTERED_DRAIN_HOOK.get().copied()?;
    let payload = drain()?;
    Some(DeviceFirstLayerHandle::new(payload))
}

/// Returns the registered first-round device hook, or `None` if
/// ziren-gpu hasn't called `register_first_round_device_hook` yet.
#[must_use]
pub fn get_first_round_device_hook() -> Option<FirstRoundDeviceHook> {
    REGISTERED_FIRST_ROUND_HOOK.get().copied()
}

/// Hook ziren-gpu registers to install its own first-round device
/// implementation.
pub type FirstRoundDeviceHookRegistration = FirstRoundDeviceHook;

static REGISTERED_FIRST_ROUND_HOOK: std::sync::OnceLock<FirstRoundDeviceHook> =
    std::sync::OnceLock::new();

pub fn register_first_round_device_hook(
    f: FirstRoundDeviceHook,
) -> Result<(), FirstRoundDeviceHook> {
    REGISTERED_FIRST_ROUND_HOOK.set(f)
}

/// Hook ziren-gpu registers to drain its TLS-stashed device handle.
/// Signature matches ziren-gpu's `drain_to_handle`, which returns
/// the erased `Arc<dyn Any + Send + Sync>` so consumers can downcast
/// to their concrete trace type.
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
        // No handle installed by default.
        assert!(current_device_first_layer().is_none());

        // Construct an Arc-wrapped payload and install via Guard.
        struct Marker(u32);
        let arc: Arc<dyn Any + Send + Sync> = Arc::new(Marker(42));
        {
            let _g = DeviceFirstLayerGuard::new(arc.clone());
            let got = current_device_first_layer().expect("installed");
            let marker = got.downcast_ref::<Marker>().expect("downcast");
            assert_eq!(marker.0, 42);
        }
        // After Guard drop, stash is cleared.
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
        // If a stale Guard is dropped after a fresher one installed
        // newer content, the stale Guard's gen no longer matches the
        // slot's gen — Drop must be a no-op so it doesn't clear the
        // newer install.
        struct First;
        struct Second;

        let first_arc: Arc<dyn Any + Send + Sync> = Arc::new(First);
        let second_arc: Arc<dyn Any + Send + Sync> = Arc::new(Second);

        let g_first = DeviceFirstLayerGuard::new(first_arc);
        let _g_second = DeviceFirstLayerGuard::new(second_arc);

        // Slot holds Second now.
        assert!(current_device_first_layer()
            .unwrap()
            .downcast_ref::<Second>()
            .is_some());

        // Drop the stale first Guard explicitly while the second is
        // still alive.  Its gen differs from the slot's gen, so the
        // drop must NOT clear the Second handle.
        drop(g_first);
        assert!(current_device_first_layer()
            .unwrap()
            .downcast_ref::<Second>()
            .is_some());
    }
}
