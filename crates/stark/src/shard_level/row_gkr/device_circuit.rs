//! Device-resident LogUp-GKR circuit scaffold (task #368).
//!
//! Direct analogue of SP1's
//! [`LogUpCudaCircuit`](file:///tmp/sp1/sp1-gpu/crates/logup_gkr/src/utils.rs#L151-L161)
//! — a streaming container that yields one circuit layer at a time so
//! the GKR prover can walk the circuit bottom-up without materializing
//! every layer up front on host.
//!
//! ## Why this exists
//!
//! Today's `build_gkr_circuit` + `LogupGkrCpuCircuit` (see
//! [`super::layer`]) eagerly walks every layer transition on host
//! **before** any sumcheck round executes.  Profile data (see
//! `project_359_*` memory notes) shows `flatten_layer` consuming
//! 77% of per-layer cost on fibonacci / 58% on tendermint —
//! eliminating per-call flatten via persistent device-resident layer
//! state is projected to save ~20% wall.
//!
//! The fix mirrors SP1's design exactly: the prover side holds a
//! [`DeviceLogupGkrCircuit`] that stores a `Vec<DeviceCircuitLayer>`
//! plus an optional virtual `FirstLayerVirtual` placeholder.  Each
//! call to [`DeviceLogupGkrCircuit::next`] pops the bottom-most
//! materialized layer, or — when `recompute_first_layer` is on and
//! the materialized stack is empty — generates the FirstLayer on
//! demand from the input data.
//!
//! ## Scope of this scaffold (#368)
//!
//! * Defines the public types: [`DeviceLogupGkrCircuit`],
//!   [`DeviceCircuitLayer`], [`DeviceLayerHandle`],
//!   [`DeviceInputData`].
//! * Defines iterator-style API: [`DeviceLogupGkrCircuit::next`],
//!   [`DeviceLogupGkrCircuit::new`], [`DeviceLogupGkrCircuit::len`].
//! * Stays **device-agnostic**: handles are opaque `Arc<...>`
//!   placeholders.  The stark crate must not depend on ziren-gpu /
//!   cudarc; the actual device payload type is filled in by the GPU
//!   crate via a side-channel registry (matching the
//!   [`super::layer::LayerState::Device`] pattern in #218 Q1 /
//!   #225-#228).
//! * Methods that need device dispatch (e.g. recomputing the first
//!   layer from raw input data) carry `todo!()` bodies and are gated
//!   behind a clear `// hook-point` comment so #371 can wire the V3
//!   hook signature in cleanly.
//!
//! ## Out of scope (#371 — next task)
//!
//! * Plumbing `DeviceLogupGkrCircuit` into [`super::round`] /
//!   [`super::top_level`].  This task only defines the type.
//! * Modifying any existing caller of `LogupGkrCpuCircuit`.
//! * Wiring CUDA dependencies into the stark crate.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_field::{ExtensionField, Field};

/// Opaque handle to a device-resident layer payload.
///
/// The stark crate has no knowledge of the underlying device payload
/// type — that lives in the basefold/GPU crate and is keyed by a
/// `(device_id, circuit_id, handle_id)` triple in the per-process
/// registry (see `crate::basefold_late_binding` for the existing
/// `LayerState::Device` hooks introduced by #218 Q1 / #225-#228).
///
/// `Arc<dyn AnyDeviceHandle>` keeps the type erased while preserving
/// reference-counted ownership across rayon workers; the actual
/// payload is dropped via the registry's pull/release hook when the
/// last `Arc` clone is dropped.
///
/// **#371 hook-point:** When the V3 hook lands, this is the type that
/// will flow into the sumcheck round prover.  The marker trait
/// `AnyDeviceHandle: Any + Send + Sync` keeps the abstraction
/// device-agnostic while letting the GPU side downcast via
/// `Arc::downcast`.
#[derive(Clone)]
pub struct DeviceLayerHandle {
    /// Opaque type-erased payload — populated by the GPU crate's
    /// registry, never inspected on the stark side.
    inner: Arc<dyn AnyDeviceHandle>,
    /// Mirrored shape metadata so callers that only need dimensions
    /// can read them without dereferencing through the registry
    /// (matches the [`super::layer::LayerState::Device`] pattern).
    num_row_variables: usize,
    /// log₂ of (max chip-interaction count rounded up).
    num_interaction_variables: usize,
    /// Multi-GPU scoping ID — keyed per-`build_device_gkr_circuit`
    /// invocation so concurrent shards stay isolated (mirrors the
    /// `LayerState::Device::circuit_id` field added in #230).
    circuit_id: u64,
}

/// Marker trait that any device-side handle payload must implement.
///
/// This lives in the stark crate only as an opaque erased pointer;
/// the GPU crate provides concrete impls keyed in its registry.
pub trait AnyDeviceHandle: core::any::Any + Send + Sync {}

impl DeviceLayerHandle {
    /// Constructor used by the GPU registry when a fresh device
    /// layer is materialized.  Stark-side callers should not invoke
    /// this directly — the GPU crate's hook is the only legal caller.
    #[must_use]
    pub fn new(
        inner: Arc<dyn AnyDeviceHandle>,
        num_row_variables: usize,
        num_interaction_variables: usize,
        circuit_id: u64,
    ) -> Self {
        Self { inner, num_row_variables, num_interaction_variables, circuit_id }
    }

    /// log₂ of row count for the layer this handle points to.
    #[inline]
    #[must_use]
    pub fn num_row_variables(&self) -> usize {
        self.num_row_variables
    }

    /// log₂ of (max chip-interaction count rounded up).
    #[inline]
    #[must_use]
    pub fn num_interaction_variables(&self) -> usize {
        self.num_interaction_variables
    }

    /// Multi-GPU scoping ID (see field doc).
    #[inline]
    #[must_use]
    pub fn circuit_id(&self) -> u64 {
        self.circuit_id
    }

    /// Borrow the opaque payload as `&dyn AnyDeviceHandle` —
    /// callers downcast via `Arc::downcast` on the cloned inner
    /// (the GPU crate owns the concrete type).
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &Arc<dyn AnyDeviceHandle> {
        &self.inner
    }
}

impl core::fmt::Debug for DeviceLayerHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceLayerHandle")
            .field("num_row_variables", &self.num_row_variables)
            .field("num_interaction_variables", &self.num_interaction_variables)
            .field("circuit_id", &self.circuit_id)
            .finish_non_exhaustive()
    }
}

/// Input data needed to regenerate the first layer from raw chips +
/// jagged traces on demand.
///
/// Analogue of SP1's
/// [`GkrInputData`](file:///tmp/sp1/sp1-gpu/crates/logup_gkr/src/utils.rs#L36-L51)
/// — kept type-erased and device-agnostic on the stark side.
///
/// The GPU crate's registry stores the actual chip + trace pointers
/// and looks them up via `circuit_id`.  Stark-side callers only need
/// the shape metadata to dispatch on, so we don't pull the heavy
/// `JaggedTraceMle` / chip-set types in here.
///
/// **#371 hook-point:** The V3 hook will accept a `DeviceInputData`
/// reference and invoke a registered `generate_first_layer_hook`
/// keyed on `circuit_id`.
#[derive(Clone, Debug)]
pub struct DeviceInputData {
    /// Multi-GPU scoping ID (matches [`DeviceLayerHandle::circuit_id`]).
    pub circuit_id: u64,
    /// log₂ of the maximum padded row count across the shard's chips.
    /// `generate_first_layer` reduces this by 1, mirroring SP1's
    /// `num_row_variables = input.num_row_variables - 1` convention.
    pub num_row_variables: u32,
    /// log₂ of (total interaction count rounded up to the next power
    /// of two).
    pub num_interaction_variables: u32,
}

/// A single circuit layer, mirroring SP1's
/// [`GkrCircuitLayer`](file:///tmp/sp1/sp1-gpu/crates/logup_gkr/src/utils.rs#L109-L113).
///
/// Three variants:
/// * [`DeviceCircuitLayer::FirstLayer`] — the bottom-most circuit
///   layer (`num_row_variables == input.num_row_variables - 1` after
///   per-chip jagged-mle assembly).  Holds the row-major denominator
///   / numerator buffers in device memory via the opaque
///   [`DeviceLayerHandle`].
/// * [`DeviceCircuitLayer::Materialized`] — any subsequent layer
///   produced by `gkr_transition`.  Same shape metadata as
///   `FirstLayer`, just at half the row dimension.
/// * [`DeviceCircuitLayer::FirstLayerVirtual`] — a placeholder for
///   the FirstLayer that has NOT yet been materialized.  When
///   `recompute_first_layer == true` we defer generating the
///   FirstLayer until `next()` walks back to it; this avoids holding
///   the heaviest layer (which dominates GPU memory) across every
///   intermediate round.
///
/// The `_phantom` generics are kept identical to the host-side
/// [`super::layer::GkrCircuitLayer`] so call-site signatures (#371)
/// can swap between the two with a single type substitution.
pub enum DeviceCircuitLayer<F: Field, EF: ExtensionField<F>> {
    /// Materialized first layer (the lowest layer of the GKR
    /// circuit, after first-round jagged-mle assembly).
    FirstLayer(DeviceLayerHandle, PhantomData<(F, EF)>),
    /// Materialized intermediate or terminal layer (produced by
    /// `gkr_transition` on the way up).
    Materialized(DeviceLayerHandle, PhantomData<(F, EF)>),
    /// Lazy first-layer placeholder — `next()` will materialize it
    /// from `input_data` on demand.
    FirstLayerVirtual(DeviceInputData, PhantomData<(F, EF)>),
}

impl<F: Field, EF: ExtensionField<F>> DeviceCircuitLayer<F, EF> {
    /// log₂ of row count for this layer.
    ///
    /// For [`Self::FirstLayerVirtual`] this returns
    /// `input.num_row_variables - 1` — matching SP1's convention
    /// that the first-layer generation reduces by 1.
    #[must_use]
    pub fn num_row_variables(&self) -> usize {
        match self {
            Self::FirstLayer(h, _) => h.num_row_variables(),
            Self::Materialized(h, _) => h.num_row_variables(),
            Self::FirstLayerVirtual(d, _) => (d.num_row_variables.saturating_sub(1)) as usize,
        }
    }

    /// log₂ of (max chip-interaction count rounded up).
    #[must_use]
    pub fn num_interaction_variables(&self) -> usize {
        match self {
            Self::FirstLayer(h, _) => h.num_interaction_variables(),
            Self::Materialized(h, _) => h.num_interaction_variables(),
            Self::FirstLayerVirtual(d, _) => d.num_interaction_variables as usize,
        }
    }

    /// Returns the opaque device handle for materialized layers, or
    /// `None` for the lazy [`Self::FirstLayerVirtual`] placeholder.
    #[must_use]
    pub fn as_handle(&self) -> Option<&DeviceLayerHandle> {
        match self {
            Self::FirstLayer(h, _) | Self::Materialized(h, _) => Some(h),
            Self::FirstLayerVirtual(_, _) => None,
        }
    }

    /// `true` for the lazy `FirstLayerVirtual` placeholder; `false`
    /// for materialized layers.
    #[must_use]
    pub fn is_virtual(&self) -> bool {
        matches!(self, Self::FirstLayerVirtual(_, _))
    }
}

impl<F: Field, EF: ExtensionField<F>> core::fmt::Debug for DeviceCircuitLayer<F, EF> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FirstLayer(h, _) => f.debug_tuple("FirstLayer").field(h).finish(),
            Self::Materialized(h, _) => f.debug_tuple("Materialized").field(h).finish(),
            Self::FirstLayerVirtual(d, _) => f.debug_tuple("FirstLayerVirtual").field(d).finish(),
        }
    }
}

/// Device-resident GKR circuit container — analogue of SP1's
/// [`LogUpCudaCircuit`](file:///tmp/sp1/sp1-gpu/crates/logup_gkr/src/utils.rs#L151-L161).
///
/// Holds the full layer stack as a vector that callers pop from the
/// bottom upward via [`Self::next`].  When
/// `num_virtual_layers > 0` and the materialized stack is empty,
/// `next()` will (in a future V3 hook landing — #371) materialize the
/// FirstLayer on demand from `input_data` rather than keeping it in
/// device memory across every intermediate round.
///
/// ## Layer ordering
///
/// `materialized_layers` is stored bottom-up — the terminal layer is
/// at index 0, and the FirstLayer (or its virtual placeholder) is at
/// the END of the vector.  `next()` pops from the back (matches SP1's
/// `materialized_layers.pop()`), so the prover walks bottom-up by
/// reverse iteration.
///
/// ## Iterator semantics
///
/// * Constructed via [`Self::new`] with the full materialized layer
///   stack + optional virtual first-layer placeholder.
/// * Each [`Self::next`] call returns the bottom-most layer, or the
///   regenerated FirstLayer when the stack is exhausted and
///   `num_virtual_layers > 0`.
/// * Returns `None` once both are exhausted.
pub struct DeviceLogupGkrCircuit<F: Field, EF: ExtensionField<F>> {
    /// Materialized layer stack, bottom-up.  `pop()` yields the
    /// terminal first, then intermediate Materialized layers, then
    /// the FirstLayer if it was materialized eagerly.
    pub materialized_layers: Vec<DeviceCircuitLayer<F, EF>>,
    /// Input data needed to regenerate the FirstLayer on demand
    /// (used only when `num_virtual_layers > 0`).
    pub input_data: DeviceInputData,
    /// Number of layers that have NOT yet been materialized — in
    /// practice this is `0` (eager) or `1` (lazy first-layer).
    /// Mirrors SP1's `num_virtual_layers` field.
    pub num_virtual_layers: usize,
    _phantom: PhantomData<(F, EF)>,
}

impl<F: Field, EF: ExtensionField<F>> DeviceLogupGkrCircuit<F, EF> {
    /// Build a new circuit from a fully-materialized layer stack and
    /// optional `num_virtual_layers` (set to `1` when the FirstLayer
    /// is deferred, `0` when it was materialized eagerly).
    #[must_use]
    pub fn new(
        materialized_layers: Vec<DeviceCircuitLayer<F, EF>>,
        input_data: DeviceInputData,
        num_virtual_layers: usize,
    ) -> Self {
        debug_assert!(
            num_virtual_layers <= 1,
            "DeviceLogupGkrCircuit: num_virtual_layers must be 0 or 1, got {num_virtual_layers}"
        );
        Self {
            materialized_layers,
            input_data,
            num_virtual_layers,
            _phantom: PhantomData,
        }
    }

    /// Total number of layers remaining to be yielded by `next()`.
    ///
    /// Equals `materialized_layers.len() + num_virtual_layers`.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.materialized_layers.len() + self.num_virtual_layers
    }

    /// `true` when no layers remain to be yielded.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.materialized_layers.is_empty() && self.num_virtual_layers == 0
    }

    /// Pop the next layer in bottom-up order.
    ///
    /// Behavior mirrors SP1's
    /// [`LogUpCudaCircuit::next`](file:///tmp/sp1/sp1-gpu/crates/logup_gkr/src/tracegen.rs#L168-L186):
    ///
    /// * If `materialized_layers` is non-empty, pop and return the
    ///   bottom-most.
    /// * Else, if `num_virtual_layers > 0`, regenerate the
    ///   FirstLayer from `input_data` (one-shot — decrement counter).
    /// * Else, return `None`.
    ///
    /// ## `#371 hook-point`
    ///
    /// The lazy-regeneration arm currently carries a `todo!()`
    /// because Ziren has no GPU-side `generate_first_layer` hook
    /// registered yet — the V3 hook (#371) will install one keyed on
    /// `input_data.circuit_id`.  Until #371 lands, callers MUST
    /// construct `DeviceLogupGkrCircuit` with `num_virtual_layers ==
    /// 0` (eager materialization) — the iterator pops materialized
    /// entries only.
    pub fn next(&mut self) -> Option<DeviceCircuitLayer<F, EF>> {
        if let Some(layer) = self.materialized_layers.pop() {
            return Some(layer);
        }
        if self.num_virtual_layers == 0 {
            return None;
        }
        // num_virtual_layers > 0 → fall through to lazy first-layer
        // generation.  Currently unimplemented; see #371 hook-point
        // note above.
        debug_assert_eq!(
            self.num_virtual_layers, 1,
            "DeviceLogupGkrCircuit: lazy regeneration only supports a single virtual layer"
        );
        self.num_virtual_layers = 0;
        // hook-point #371: call generate_first_layer_device(&self.input_data)
        // and return Some(DeviceCircuitLayer::FirstLayer(handle, _)).
        let _ = &self.input_data;
        todo!(
            "device-side first-layer regeneration hook (#371) not yet wired; \
             construct DeviceLogupGkrCircuit with num_virtual_layers=0 until then"
        );
    }

    /// Returns the input-data circuit ID — useful for the GPU
    /// registry to scope handles per-`build_device_gkr_circuit`
    /// invocation.
    #[inline]
    #[must_use]
    pub fn circuit_id(&self) -> u64 {
        self.input_data.circuit_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Challenge;
    use p3_koala_bear::KoalaBear;

    type SC = crate::koala_bear_poseidon2::KoalaBearPoseidon2;
    type EF = Challenge<SC>;

    /// Minimal `AnyDeviceHandle` impl for unit tests — carries a tag
    /// the test can downcast to verify identity.
    struct TestHandle {
        tag: u64,
    }
    impl AnyDeviceHandle for TestHandle {}

    fn make_handle(tag: u64, num_row_vars: usize, num_int_vars: usize) -> DeviceLayerHandle {
        DeviceLayerHandle::new(Arc::new(TestHandle { tag }), num_row_vars, num_int_vars, 7)
    }

    /// `next()` walks the materialized stack in bottom-up order and
    /// returns `None` once exhausted.  Mirrors SP1's iteration
    /// pattern.
    #[test]
    fn next_pops_materialized_stack_bottom_up() {
        let input_data = DeviceInputData {
            circuit_id: 7,
            num_row_variables: 4,
            num_interaction_variables: 3,
        };
        // Layers pushed bottom-first: index 0 = terminal (smallest),
        // last index = FirstLayer (largest).  `pop()` yields the
        // last entry first, so we expect FirstLayer first.
        let layers = vec![
            DeviceCircuitLayer::<KoalaBear, EF>::Materialized(make_handle(10, 1, 3), PhantomData),
            DeviceCircuitLayer::<KoalaBear, EF>::Materialized(make_handle(20, 2, 3), PhantomData),
            DeviceCircuitLayer::<KoalaBear, EF>::FirstLayer(make_handle(30, 3, 3), PhantomData),
        ];
        let mut circuit = DeviceLogupGkrCircuit::<KoalaBear, EF>::new(layers, input_data, 0);

        assert_eq!(circuit.len(), 3);
        assert!(!circuit.is_empty());

        let l0 = circuit.next().expect("first layer present");
        assert!(matches!(l0, DeviceCircuitLayer::FirstLayer(_, _)));
        assert_eq!(l0.num_row_variables(), 3);

        let l1 = circuit.next().expect("middle layer present");
        assert!(matches!(l1, DeviceCircuitLayer::Materialized(_, _)));
        assert_eq!(l1.num_row_variables(), 2);

        let l2 = circuit.next().expect("terminal layer present");
        assert!(matches!(l2, DeviceCircuitLayer::Materialized(_, _)));
        assert_eq!(l2.num_row_variables(), 1);

        assert!(circuit.next().is_none());
        assert!(circuit.is_empty());
    }

    /// Constructing with `num_virtual_layers = 0` and an empty stack
    /// yields `None` immediately — the lazy-regen `todo!()` arm
    /// must NOT trigger when the counter is 0.
    #[test]
    fn next_returns_none_when_empty_and_no_virtual_layer() {
        let input_data = DeviceInputData {
            circuit_id: 99,
            num_row_variables: 4,
            num_interaction_variables: 3,
        };
        let mut circuit =
            DeviceLogupGkrCircuit::<KoalaBear, EF>::new(Vec::new(), input_data, 0);
        assert!(circuit.is_empty());
        assert_eq!(circuit.len(), 0);
        assert!(circuit.next().is_none());
        // Repeated calls also yield None.
        assert!(circuit.next().is_none());
    }

    /// `FirstLayerVirtual` placeholder reports the right shape
    /// metadata (input.num_row_variables - 1 / input.num_interaction_variables).
    #[test]
    fn first_layer_virtual_reports_reduced_row_variables() {
        let input = DeviceInputData {
            circuit_id: 1,
            num_row_variables: 5,
            num_interaction_variables: 2,
        };
        let layer = DeviceCircuitLayer::<KoalaBear, EF>::FirstLayerVirtual(input, PhantomData);
        assert!(layer.is_virtual());
        assert_eq!(layer.num_row_variables(), 4);
        assert_eq!(layer.num_interaction_variables(), 2);
        assert!(layer.as_handle().is_none());
    }

    /// `DeviceLayerHandle` plumbs `circuit_id` through unchanged
    /// (multi-GPU isolation, see #230).
    #[test]
    fn handle_carries_circuit_id() {
        let h = make_handle(42, 4, 3);
        assert_eq!(h.circuit_id(), 7);
        assert_eq!(h.num_row_variables(), 4);
        assert_eq!(h.num_interaction_variables(), 3);

        // Downcast the inner Arc<dyn> to recover the original tag.
        let any_ref: &dyn core::any::Any = &**h.inner();
        let test_handle = any_ref.downcast_ref::<TestHandle>().expect("downcast");
        assert_eq!(test_handle.tag, 42);
    }
}
