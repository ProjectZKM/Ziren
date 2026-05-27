//! Layer types for the row-only GKR backend.
//!
//! Each per-chip table is indexed `[row, interaction]` row-major.
//! All chips share `(num_row_variables, num_interaction_variables)`
//! at the layer level; chips with fewer interactions virtually pad
//! with identity fractions `(0, 1)`.

use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_field::{ExtensionField, Field};

/// 2-D table indexed `[row, interaction]` row-major. Only the
/// `num_real_rows` prefix is materialized; readers fill the
/// virtual tail with `0` (numerator) or `1` (denominator).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowMajorTable<F> {
    /// Row-major: `cells[row * num_interactions + col]`, length
    /// `num_real_rows * num_interactions`.
    pub cells: Vec<F>,
    /// log₂ of logical row count.
    pub num_row_variables: usize,
    /// log₂ of `num_interactions.next_power_of_two()`.
    pub num_interaction_variables: usize,
    /// Storage stride (raw per-chip interaction count).
    pub num_interactions: usize,
    /// Number of materialized rows; `<= 1 << num_row_variables`.
    pub num_real_rows: usize,
}

impl<F: Clone> RowMajorTable<F> {
    /// Caller MUST write every cell before any read. `F: Copy` is
    /// sufficient because Copy has no Drop, so leaking on panic is
    /// sound.
    #[must_use]
    pub unsafe fn filled_raw_uninit(
        num_row_variables: usize,
        num_interactions: usize,
    ) -> Self
    where
        F: Copy + p3_field::PrimeCharacteristicRing,
    {
        let total = (1usize << num_row_variables) * num_interactions;
        let num_interaction_variables =
            num_interactions.max(1).next_power_of_two().trailing_zeros() as usize;
        // FLAKE FIX: see round.rs note. Init to ZERO instead of leaking
        // uninit u32 — KoalaBear serde rejects out-of-range bit patterns.
        let cells: Vec<F> = vec![F::ZERO; total];
        Self {
            cells,
            num_row_variables,
            num_interaction_variables,
            num_interactions,
            num_real_rows: 1usize << num_row_variables,
        }
    }

    /// Build a table where storage width equals the virtual padded
    /// width (`num_interactions = 1 << num_interaction_variables`).
    /// Compatibility constructor for callers that previously used the
    /// pow2-storage layout.
    #[must_use]
    pub fn filled(
        num_row_variables: usize,
        num_interaction_variables: usize,
        fill: F,
    ) -> Self {
        let num_interactions = 1usize << num_interaction_variables;
        let total = (1usize << num_row_variables) * num_interactions;
        Self {
            cells: vec![fill; total],
            num_row_variables,
            num_interaction_variables,
            num_interactions,
            num_real_rows: 1usize << num_row_variables,
        }
    }

    /// PaddedMle constructor: build a table whose `cells` array is sized
    /// for `num_real_rows × num_interactions` only — the remaining
    /// `(1 << num_row_variables) - num_real_rows` rows are virtual and
    /// resolve to a per-quadrant identity-fraction value at access time
    /// (`F::ZERO` for numerators, `F::ONE` for denominators).  Mirrors
    /// SP1's `PaddedMle::padded` (see `crate::basefold::padded::PaddedMle`).
    ///
    /// Caller must satisfy:
    ///   * `cells.len() == num_real_rows * num_interactions`
    ///   * `num_real_rows <= (1 << num_row_variables)`
    #[must_use]
    pub fn from_padded_cells(
        cells: Vec<F>,
        num_row_variables: usize,
        num_interactions: usize,
        num_real_rows: usize,
    ) -> Self {
        let num_interaction_variables =
            num_interactions.max(1).next_power_of_two().trailing_zeros() as usize;
        debug_assert!(
            num_interactions == 0 || cells.len() == num_real_rows * num_interactions,
            "from_padded_cells: cells.len() {} != num_real_rows {} * num_interactions {}",
            cells.len(),
            num_real_rows,
            num_interactions,
        );
        debug_assert!(num_real_rows <= (1usize << num_row_variables));
        Self {
            cells,
            num_row_variables,
            num_interaction_variables,
            num_interactions,
            num_real_rows,
        }
    }

    /// Linear `[row, interaction] -> idx` mapping for row-major storage.
    /// Raw indexing — `interaction` must be `< num_interactions`, AND
    /// `row` must address a **materialized** cell (`< num_real_rows`).
    /// Reading virtual rows in `[num_real_rows, 1 << num_row_variables)`
    /// is the caller's responsibility to handle (PaddedMle pattern;
    /// see `crate::basefold::padded::PaddedMle`).
    #[inline]
    #[must_use]
    pub fn idx(&self, row: usize, interaction: usize) -> usize {
        debug_assert!(row < self.num_real_rows, "RowMajorTable::idx: row {} >= num_real_rows {}", row, self.num_real_rows);
        debug_assert!(interaction < self.num_interactions);
        row * self.num_interactions + interaction
    }

    /// Read a cell at `[row, interaction]` — raw indexing
    /// (no virtual padding).  Caller must ensure `row < num_real_rows`.
    #[inline]
    #[must_use]
    pub fn get(&self, row: usize, interaction: usize) -> &F {
        &self.cells[self.idx(row, interaction)]
    }

    /// Mutable cell access — raw indexing.  Caller must ensure
    /// `row < num_real_rows`.
    #[inline]
    pub fn set(&mut self, row: usize, interaction: usize, value: F) {
        let i = self.idx(row, interaction);
        self.cells[i] = value;
    }

    /// log₂ of the total virtual cell count
    /// (`num_row_variables + num_interaction_variables`).
    #[inline]
    #[must_use]
    pub fn num_variables(&self) -> usize {
        self.num_row_variables + self.num_interaction_variables
    }
}

/// A circuit layer with `num_row_variables` and `num_interaction_variables`
/// dimensions, holding the four `numerator_0/1, denominator_0/1` MLE
/// tables — one per chip.
///
/// Port of
/// `LogUpGkrCpuLayer<F, EF>`.
///
/// **Two field params** (`NumF`, `DenF`):  At the first layer the
/// numerators are in the base field `F` (raw multiplicities) while
/// denominators live in `EF` (mixed with `alpha + Σ β·col`).  After
/// the first row-halving fold both halves move to `EF`.  The two
/// parameters let us reuse the same struct for both states.
#[derive(Clone, Debug)]
pub struct LogUpGkrCpuLayer<NumF, DenF> {
    /// Per-chip "even-row" numerators (row index has LSB = 0 after
    /// the previous fold).  In the first layer, these come from
    /// `multiplicity` evaluated on every other row.
    pub numerator_0: Vec<RowMajorTable<NumF>>,
    /// Per-chip "even-row" denominators.
    pub denominator_0: Vec<RowMajorTable<DenF>>,
    /// Per-chip "odd-row" numerators (row index LSB = 1).
    pub numerator_1: Vec<RowMajorTable<NumF>>,
    /// Per-chip "odd-row" denominators.
    pub denominator_1: Vec<RowMajorTable<DenF>>,
    /// log₂ of row count for *this* layer (one less than the layer
    /// below for transition layers).
    pub num_row_variables: usize,
    /// log₂ of interaction count (constant across all layers).
    pub num_interaction_variables: usize,
}

impl<NumF, DenF> LogUpGkrCpuLayer<NumF, DenF> {
    /// Total log-variables = row + interaction (handy for sumcheck
    /// dimension calls).
    #[inline]
    #[must_use]
    pub const fn num_variables(&self) -> usize {
        self.num_row_variables + self.num_interaction_variables
    }
}

/// The terminal interaction-only layer (`num_row_variables == 1`,
/// the singleton row holds the row-reduced fractions).
///
/// Port of
/// `InteractionLayer<F, EF>`.
///
/// At extraction time we interleave the four sub-MLEs to produce
/// the final `circuit_output.numerator/denominator` of length
/// `2^(num_interaction_variables + 1)`.
#[derive(Clone, Debug)]
pub struct InteractionLayer<F, EF> {
    pub numerator_0: Vec<F>,
    pub denominator_0: Vec<EF>,
    pub numerator_1: Vec<F>,
    pub denominator_1: Vec<EF>,
    pub num_interaction_variables: usize,
}

/// Discriminated union over circuit layers — `FirstLayer` keeps
/// numerators in the base field while all subsequent `Layer`s have
/// EF numerators.
///
/// Port of
/// `GkrCircuitLayer<F, EF>`.
#[allow(clippy::large_enum_variant)]
pub enum GkrCircuitLayer<F: Field, EF: ExtensionField<F>> {
    Layer(LogUpGkrCpuLayer<EF, EF>),
    FirstLayer(LogUpGkrCpuLayer<F, EF>),
}

impl<F: Field, EF: ExtensionField<F>> GkrCircuitLayer<F, EF> {
    #[must_use]
    pub const fn num_row_variables(&self) -> usize {
        match self {
            Self::Layer(l) => l.num_row_variables,
            Self::FirstLayer(l) => l.num_row_variables,
        }
    }

    #[must_use]
    pub const fn num_interaction_variables(&self) -> usize {
        match self {
            Self::Layer(l) => l.num_interaction_variables,
            Self::FirstLayer(l) => l.num_interaction_variables,
        }
    }

    /// construct a SHAPE-ONLY proxy carrying just
    /// the dimension metadata (`num_row_variables`,
    /// `num_interaction_variables`), with empty `cells` vectors on
    /// every per-chip [`RowMajorTable`].
    ///
    /// ## When this is sound
    ///
    /// **Only safe to pass to [`prove_gkr_round`] when the V3
    /// dispatch is GUARANTEED to consume the layer from the
    /// device-resident [`crate::shard_level::row_gkr::device_circuit::
    /// LogupTaskScope`]** — i.e. when:
    /// 1. The scope's installed circuit has a layer whose
    ///    `(num_row_variables, num_interaction_variables)` matches
    ///    this proxy's shape (verify via
    ///    `LogupTaskScope::peek_next_layer_shape`).
    /// 2. The V3 hook (`ZIREN_GPU_LOGUP_GKR_DEVICE=1`) is registered
    ///    and accepts this layer's size (no threshold-skip).
    /// 3. The V3 hook reads its inputs from the scope handle (NOT
    ///    from the host `cells` vectors).
    ///
    /// When any of those conditions is violated, the host fallback
    /// path inside `prove_gkr_round` will read the empty `cells`
    /// vectors and panic via the `flatten_layer` shape assertions.
    /// The consumer in `top_level.rs` enforces all three conditions
    /// before constructing a proxy.
    ///
    /// ## SP1 parity
    ///
    /// SP1 has no analog — its consumer never has a host fallback.
    /// This proxy is Ziren-specific scaffolding for the
    /// device-resident consumer migration; the long-term direction
    /// (full ) is to delete the host fallback entirely,
    /// at which point this proxy can be removed in favor of the
    /// existing `DeviceCircuitLayer` enum.
    #[must_use]
    pub fn shape_only_layer_proxy(
        num_row_variables: usize,
        num_interaction_variables: usize,
    ) -> Self {
        let empty_table = RowMajorTable::<EF> {
            cells: Vec::new(),
            num_row_variables,
            num_interaction_variables,
            num_interactions: 0,
            num_real_rows: 0,
        };
        Self::Layer(LogUpGkrCpuLayer {
            numerator_0: vec![empty_table.clone()],
            denominator_0: vec![empty_table.clone()],
            numerator_1: vec![empty_table.clone()],
            denominator_1: vec![empty_table],
            num_row_variables,
            num_interaction_variables,
        })
    }
}

/// Backend-parametrized layer storage — Step 4a scaffolding from
/// Per-layer storage: host-resident `Host(GkrCircuitLayer)` or an
/// opaque `Device` handle into the GPU prover's side-channel
/// registry. `u64` handle keeps device types out of stark.
///
/// `circuit_id` scopes the handle to one `build_gkr_circuit` call so
/// concurrent shards on the same GPU stay isolated; the registry is
/// keyed by `(device_id, circuit_id)`.
#[allow(dead_code)]
pub enum LayerState<F: Field, EF: ExtensionField<F>> {
    Host(GkrCircuitLayer<F, EF>),
    Device {
        circuit_id: u64,
        handle: u64,
        num_row_variables: usize,
        num_interaction_variables: usize,
    },
}

impl<F: Field, EF: ExtensionField<F>> LayerState<F, EF> {
    /// log₂ of row count for this layer (matches
    /// [`GkrCircuitLayer::num_row_variables`]).
    #[inline]
    #[must_use]
    pub fn num_row_variables(&self) -> usize {
        match self {
            Self::Host(layer) => layer.num_row_variables(),
            Self::Device { num_row_variables, .. } => *num_row_variables,
        }
    }

    /// log₂ of (max chip-interaction count rounded up) for this
    /// layer (matches [`GkrCircuitLayer::num_interaction_variables`]).
    #[inline]
    #[must_use]
    pub fn num_interaction_variables(&self) -> usize {
        match self {
            Self::Host(layer) => layer.num_interaction_variables(),
            Self::Device { num_interaction_variables, .. } => *num_interaction_variables,
        }
    }

}

/// Layers indexed top-down: layer 0 is the first / largest;
/// layer N-1 is the terminal interaction-only layer.
pub struct LogupGkrCpuCircuit<F: Field, EF: ExtensionField<F>> {
    pub layers: Vec<LayerState<F, EF>>,
    _phantom: PhantomData<(F, EF)>,
}

impl<F: Field, EF: ExtensionField<F>> LogupGkrCpuCircuit<F, EF> {
    #[must_use]
    pub const fn new(layers: Vec<LayerState<F, EF>>) -> Self {
        Self { layers, _phantom: PhantomData }
    }

    /// Pop the bottom-most (most-reduced) layer.  Used by
    /// `prove_gkr_round` to walk the circuit bottom-up.
    pub fn pop_bottom(&mut self) -> Option<LayerState<F, EF>> {
        self.layers.pop()
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::Challenge;

    type SC = crate::koala_bear_poseidon2::KoalaBearPoseidon2;
    type EF = Challenge<SC>;

    #[test]
    fn row_major_table_filled_has_expected_size() {
        let t: RowMajorTable<KoalaBear> = RowMajorTable::filled(3, 2, KoalaBear::from_u32(7));
        assert_eq!(t.num_row_variables, 3);
        assert_eq!(t.num_interaction_variables, 2);
        assert_eq!(t.num_variables(), 5);
        assert_eq!(t.cells.len(), 8 * 4);
        for c in &t.cells {
            assert_eq!(*c, KoalaBear::from_u32(7));
        }
    }

    #[test]
    fn row_major_table_idx_is_row_major() {
        let mut t: RowMajorTable<KoalaBear> = RowMajorTable::filled(2, 2, KoalaBear::from_u32(0));
        // 4 rows × 4 interactions = 16 cells; row 1 interaction 2 -> idx 6.
        assert_eq!(t.idx(1, 2), 1 * 4 + 2);
        t.set(1, 2, KoalaBear::from_u32(99));
        assert_eq!(*t.get(1, 2), KoalaBear::from_u32(99));
        assert_eq!(t.cells[6], KoalaBear::from_u32(99));
    }

    #[test]
    fn cpu_layer_num_variables_sums_axes() {
        let table: RowMajorTable<EF> = RowMajorTable::filled(4, 3, EF::default());
        let layer = LogUpGkrCpuLayer::<EF, EF> {
            numerator_0: vec![table.clone()],
            denominator_0: vec![table.clone()],
            numerator_1: vec![table.clone()],
            denominator_1: vec![table],
            num_row_variables: 4,
            num_interaction_variables: 3,
        };
        assert_eq!(layer.num_variables(), 7);
    }

    #[test]
    fn gkr_circuit_layer_dispatches_dim_queries() {
        let table_f: RowMajorTable<KoalaBear> = RowMajorTable::filled(2, 2, KoalaBear::from_u32(0));
        let table_ef: RowMajorTable<EF> = RowMajorTable::filled(2, 2, EF::default());
        let first: GkrCircuitLayer<KoalaBear, EF> =
            GkrCircuitLayer::FirstLayer(LogUpGkrCpuLayer {
                numerator_0: vec![table_f.clone()],
                denominator_0: vec![table_ef.clone()],
                numerator_1: vec![table_f],
                denominator_1: vec![table_ef.clone()],
                num_row_variables: 2,
                num_interaction_variables: 2,
            });
        assert_eq!(first.num_row_variables(), 2);
        assert_eq!(first.num_interaction_variables(), 2);

        let mid: GkrCircuitLayer<KoalaBear, EF> = GkrCircuitLayer::Layer(LogUpGkrCpuLayer {
            numerator_0: vec![table_ef.clone()],
            denominator_0: vec![table_ef.clone()],
            numerator_1: vec![table_ef.clone()],
            denominator_1: vec![table_ef],
            num_row_variables: 1,
            num_interaction_variables: 2,
        });
        assert_eq!(mid.num_row_variables(), 1);
        assert_eq!(mid.num_interaction_variables(), 2);
    }

    /// `shape_only_layer_proxy` produces a
    /// `GkrCircuitLayer::Layer` with empty `cells` carrying only
    /// the shape metadata.  Safe to pass to `prove_gkr_round` ONLY
    /// when the V3 dispatch will consume the layer from the
    /// device-resident scope.
    #[test]
    fn shape_only_layer_proxy_carries_metadata_with_empty_cells() {
        let proxy = GkrCircuitLayer::<KoalaBear, EF>::shape_only_layer_proxy(5, 3);
        assert_eq!(proxy.num_row_variables(), 5);
        assert_eq!(proxy.num_interaction_variables(), 3);
        match proxy {
            GkrCircuitLayer::Layer(l) => {
                assert_eq!(l.num_row_variables, 5);
                assert_eq!(l.num_interaction_variables, 3);
                assert!(l.numerator_0[0].cells.is_empty());
                assert!(l.denominator_0[0].cells.is_empty());
                assert!(l.numerator_1[0].cells.is_empty());
                assert!(l.denominator_1[0].cells.is_empty());
                assert_eq!(l.numerator_0[0].num_real_rows, 0);
                assert_eq!(l.numerator_0[0].num_interactions, 0);
            }
            GkrCircuitLayer::FirstLayer(_) => {
                panic!("shape_only_layer_proxy must produce Layer variant");
            }
        }
    }

    #[test]
    fn circuit_pops_bottom_in_lifo_order() {
        let table_ef: RowMajorTable<EF> = RowMajorTable::filled(1, 2, EF::default());
        let make_layer = |rows: usize| {
            LayerState::<KoalaBear, EF>::Host(GkrCircuitLayer::Layer(LogUpGkrCpuLayer {
                numerator_0: vec![table_ef.clone()],
                denominator_0: vec![table_ef.clone()],
                numerator_1: vec![table_ef.clone()],
                denominator_1: vec![table_ef.clone()],
                num_row_variables: rows,
                num_interaction_variables: 2,
            }))
        };
        let mut circuit = LogupGkrCpuCircuit::new(vec![make_layer(3), make_layer(2), make_layer(1)]);
        assert_eq!(circuit.pop_bottom().unwrap().num_row_variables(), 1);
        assert_eq!(circuit.pop_bottom().unwrap().num_row_variables(), 2);
        assert_eq!(circuit.pop_bottom().unwrap().num_row_variables(), 3);
        assert!(circuit.pop_bottom().is_none());
    }
}
