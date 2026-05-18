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

type Ef4 = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;

/// Opaque handle to a device-resident first-layer trace.
pub struct DeviceFirstLayerHandle;

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
/// hook. Stub returns `None`.
#[must_use]
pub fn drain_via_hook() -> Option<DeviceFirstLayerHandle> {
    None
}

/// Returns the currently-stashed device-first-layer handle, if any.
/// Stub always `None`.
#[must_use]
pub fn current_device_first_layer() -> Option<&'static DeviceFirstLayerHandle> {
    None
}

/// Returns the registered first-round device hook. Stub always `None`.
#[must_use]
pub fn get_first_round_device_hook() -> Option<FirstRoundDeviceHook> {
    None
}
