//! Layer types for the row-only GKR backend (task #24, A.2 step 1).
//!
//! Direct port of
//! [`/tmp/sp1/crates/hypercube/src/logup_gkr/cpu.rs:27-73`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/cpu.rs#L27-L73)
//! with the `slop_*` types replaced by Ziren-native containers:
//!
//! | the                          | Ziren equivalent                              |
//! |------------------------------|-----------------------------------------------|
//! | `Vec<PaddedMle<F>>`          | `Vec<RowMajorTable<F>>` (defined below)       |
//! | `Arc<Mle<F>>`                | `Vec<F>` of length `2^num_variables`          |
//! | `slop_multilinear::Point<EF>`| `Vec<EF>`                                     |
//!
//! ## Indexing convention
//!
//! Each per-chip table is indexed `[row, interaction]` row-major.
//! `num_row_variables` = log₂ of row count; `num_interaction_variables`
//! = log₂ of (max chip-interaction count rounded up).  The layer
//! enforces a single shared `(num_row_variables, num_interaction_variables)`
//! across all chips — chips with fewer interactions are padded with
//! identity fractions (`(0, 1)`).
//!
//! ## Why `RowMajorTable` and not `RowMajorMatrix`
//!
//! `p3_matrix::dense::RowMajorMatrix` exists but its API is column-
//! major in a row-major-storage sense (`.row(i)` returns the i-th
//! row's slice).  For GKR's row × interaction folding we need both
//! axes addressable, and the per-cell algorithms are simpler with
//! a thin wrapper that exposes `(row, interaction) -> idx`.

use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_field::{ExtensionField, Field};

/// A 2-D table indexed `[row, interaction]` row-major.
///
/// Storage layout: `cells.len() == (1 << num_row_variables) * num_interactions`.
/// `num_interactions` is the **raw** per-chip column count (not padded
/// to a power of two) — keeping storage small for chips with few
/// interactions while still letting the GKR sumcheck virtually pad to
/// `2^num_interaction_variables` cells via zero/one fill at access
/// time (mirrors SP1's `PaddedMle` pattern; see
/// `/tmp/sp1/crates/hypercube/src/logup_gkr/execution.rs:222-242`).
///
/// `num_interaction_variables` is the log₂ of the per-chip padded width
/// (`num_interactions.next_power_of_two().trailing_zeros()`) — used as
/// metadata for the row-only GKR's per-chip dimension reporting.  The
/// LAYER's `num_interaction_variables` is the global aggregate
/// (computed in `first_layer`) and may exceed any single chip's value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowMajorTable<F> {
    /// Cells in row-major layout: `cells[row * num_interactions + col]`.
    pub cells: Vec<F>,
    /// log₂ of row count.
    pub num_row_variables: usize,
    /// log₂ of `num_interactions.next_power_of_two()` — virtual padded
    /// column dimension for sumcheck purposes.
    pub num_interaction_variables: usize,
    /// Raw per-chip column count (= number of interactions in this
    /// chip's lookup set).  Storage stride.  Always ≤ `1 << num_interaction_variables`.
    pub num_interactions: usize,
}

impl<F: Clone> RowMajorTable<F> {
    /// Build a table of `2^num_row_variables × num_interactions` cells
    /// filled with `fill`.  `num_interaction_variables` is derived as
    /// `log₂(num_interactions.next_power_of_two())`.
    #[must_use]
    pub fn filled_raw(
        num_row_variables: usize,
        num_interactions: usize,
        fill: F,
    ) -> Self {
        let total = (1usize << num_row_variables) * num_interactions;
        let num_interaction_variables =
            num_interactions.max(1).next_power_of_two().trailing_zeros() as usize;
        Self {
            cells: vec![fill; total],
            num_row_variables,
            num_interaction_variables,
            num_interactions,
        }
    }

    /// Same shape as `filled_raw` but skips the per-cell init.  Caller
    /// MUST write every cell of `cells[0..total]` before any read.
    /// Used by hot-path constructors (e.g. `layer_transition`) that
    /// would otherwise spend most of their time in `vec![fill; total]`
    /// before unconditionally overwriting every slot.
    ///
    /// # Safety
    ///
    /// Caller is responsible for initializing all `cells[0..total]`
    /// slots before any read.  `F: Copy` is sufficient because Copy
    /// types have no Drop semantics, so leaking uninitialized memory
    /// on panic is sound.
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
        }
    }

    /// Linear `[row, interaction] -> idx` mapping for row-major storage.
    /// Raw indexing — `interaction` must be `< num_interactions`.
    #[inline]
    #[must_use]
    pub fn idx(&self, row: usize, interaction: usize) -> usize {
        debug_assert!(row < (1 << self.num_row_variables));
        debug_assert!(interaction < self.num_interactions);
        row * self.num_interactions + interaction
    }

    /// Read a cell at `[row, interaction]` — raw indexing
    /// (no virtual padding).
    #[inline]
    #[must_use]
    pub fn get(&self, row: usize, interaction: usize) -> &F {
        &self.cells[self.idx(row, interaction)]
    }

    /// Mutable cell access — raw indexing.
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
/// [`LogUpGkrCpuLayer<F, EF>`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/cpu.rs#L40-L57).
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
/// [`InteractionLayer<F, EF>`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/cpu.rs#L60-L73).
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
/// [`GkrCircuitLayer<F, EF>`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/cpu.rs#L32-L37).
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
}

/// The full GKR circuit — layers indexed top-down (layer 0 = first /
/// largest, layer N-1 = terminal interaction-only).
///
/// Port of
/// [`LogupGkrCpuCircuit<F, EF>`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/cpu.rs#L27-L29).
pub struct LogupGkrCpuCircuit<F: Field, EF: ExtensionField<F>> {
    pub layers: Vec<GkrCircuitLayer<F, EF>>,
    _phantom: PhantomData<(F, EF)>,
}

impl<F: Field, EF: ExtensionField<F>> LogupGkrCpuCircuit<F, EF> {
    #[must_use]
    pub const fn new(layers: Vec<GkrCircuitLayer<F, EF>>) -> Self {
        Self { layers, _phantom: PhantomData }
    }

    /// Pop the bottom-most (most-reduced) layer.  Used by
    /// `prove_gkr_round` to walk the circuit bottom-up.
    pub fn pop_bottom(&mut self) -> Option<GkrCircuitLayer<F, EF>> {
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

    #[test]
    fn circuit_pops_bottom_in_lifo_order() {
        let table_ef: RowMajorTable<EF> = RowMajorTable::filled(1, 2, EF::default());
        let make_layer = |rows: usize| {
            GkrCircuitLayer::<KoalaBear, EF>::Layer(LogUpGkrCpuLayer {
                numerator_0: vec![table_ef.clone()],
                denominator_0: vec![table_ef.clone()],
                numerator_1: vec![table_ef.clone()],
                denominator_1: vec![table_ef.clone()],
                num_row_variables: rows,
                num_interaction_variables: 2,
            })
        };
        let mut circuit = LogupGkrCpuCircuit::new(vec![make_layer(3), make_layer(2), make_layer(1)]);
        assert_eq!(circuit.pop_bottom().unwrap().num_row_variables(), 1);
        assert_eq!(circuit.pop_bottom().unwrap().num_row_variables(), 2);
        assert_eq!(circuit.pop_bottom().unwrap().num_row_variables(), 3);
        assert!(circuit.pop_bottom().is_none());
    }
}
