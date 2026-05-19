//! #316 fixup: stub module for the device-first-layer side-channel API
//! that row_gkr/round.rs references.
//!
//! The original module was never committed to this branch (in-flight
//! work paired with ziren-gpu side channels). The callers here are all
//! gated by env flags (`ZIREN_GPU_DEVICE_FIRST_LAYER_CONSUME`,
//! `ZIREN_GPU_SP1_FIRST_LAYER`) that default OFF, so a stub that
//! always returns `None` is byte-equivalent to the never-taken
//! production path. When upstream lands the real implementation, this
//! file should be replaced wholesale.
//!
//! Callers expect:
//!   - `drain_via_hook() -> Option<DeviceFirstLayerHandle>`
//!   - `DeviceFirstLayerGuard::new(handle)` (constructor)
//!   - `current_device_first_layer() -> Option<&DeviceFirstLayerHandle>`
//!   - `get_first_round_device_hook() -> Option<FirstRoundDeviceHook>`

use core::any::Any;

type Ef4 = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;

/// Opaque handle to a device-resident first-layer trace.
///
/// Wraps an erased payload so ziren-gpu callers can `.downcast_ref::<T>()`
/// to recover their concrete type.  In stub mode the payload is always
/// `()`, so downcasts to anything other than `()` return `None`.
pub struct DeviceFirstLayerHandle {
    payload: Box<dyn Any + Send + Sync>,
}

impl Default for DeviceFirstLayerHandle {
    fn default() -> Self {
        Self { payload: Box::new(()) }
    }
}

impl DeviceFirstLayerHandle {
    /// Borrow the payload as `T` if the contained value is a `T`.
    /// Stub always carries `()` so non-`()` downcasts return `None`.
    #[must_use]
    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.payload.downcast_ref::<T>()
    }
}

/// Drop-guard that releases the device first-layer handle when it
/// leaves scope. In the stub this is a no-op.
pub struct DeviceFirstLayerGuard(#[allow(dead_code)] DeviceFirstLayerHandle);

impl DeviceFirstLayerGuard {
    #[must_use]
    pub fn new(handle: DeviceFirstLayerHandle) -> Self {
        Self(handle)
    }
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

/// Drain the device-first-layer thread-local stash via the registered
/// hook.  Invokes the `DrainHook` registered by ziren-gpu (if any) and
/// wraps the returned `Arc<dyn Any>` payload in a
/// `DeviceFirstLayerHandle` so callers can `.downcast_ref::<Arc<T>>()`.
/// Returns `None` when no drain hook is registered or the hook itself
/// returns `None`.
#[must_use]
pub fn drain_via_hook() -> Option<DeviceFirstLayerHandle> {
    let drain = REGISTERED_DRAIN_HOOK.get().copied()?;
    let payload = drain()?;
    Some(DeviceFirstLayerHandle { payload: Box::new(payload) })
}

/// Returns the currently-stashed device-first-layer handle, if any.
/// Stub always `None` — the TLS-stashing pattern needs a separate
/// orphan-commit port to land; consumers fall back to the
/// drain-on-demand path via `drain_via_hook`.
#[must_use]
pub fn current_device_first_layer() -> Option<&'static DeviceFirstLayerHandle> {
    None
}

/// Returns the registered first-round device hook, or `None` if
/// ziren-gpu hasn't called `register_first_round_device_hook` yet.
#[must_use]
pub fn get_first_round_device_hook() -> Option<FirstRoundDeviceHook> {
    REGISTERED_FIRST_ROUND_HOOK.get().copied()
}

/// Hook ziren-gpu registers to install its own first-round device
/// implementation.  Stub stores the pointer but never calls it
/// (`get_first_round_device_hook` returns `None`).
pub type FirstRoundDeviceHookRegistration = FirstRoundDeviceHook;

static REGISTERED_FIRST_ROUND_HOOK: std::sync::OnceLock<FirstRoundDeviceHook> =
    std::sync::OnceLock::new();

pub fn register_first_round_device_hook(
    f: FirstRoundDeviceHook,
) -> Result<(), FirstRoundDeviceHook> {
    REGISTERED_FIRST_ROUND_HOOK.set(f)
}

/// Hook ziren-gpu registers to drain its TLS-stashed device handle.
/// Signature matches ziren-gpu's `drain_to_handle` which returns
/// the erased `Arc<dyn Any + Send + Sync>` so consumers can downcast
/// to their concrete trace type.  Stub stores the pointer but
/// `drain_via_hook` ignores it.
pub type DrainHook = fn() -> Option<std::sync::Arc<dyn Any + Send + Sync>>;

static REGISTERED_DRAIN_HOOK: std::sync::OnceLock<DrainHook> = std::sync::OnceLock::new();

pub fn register_drain_hook(f: DrainHook) -> Result<(), DrainHook> {
    REGISTERED_DRAIN_HOOK.set(f)
}
