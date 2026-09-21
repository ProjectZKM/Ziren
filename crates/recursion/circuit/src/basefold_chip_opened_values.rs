//! Per-chip opening data for the BaseFold-pipeline shard verifier.
//!
//! Unlike [`zkm_pcs::ChipOpenedValues`] (the 4-batch FRI shape:
//! preprocessed + main + permutation + quotient, each with `local` +
//! `next` rows), the BaseFold pipeline:
//!
//!   - reduces every chip's polynomial to a single hypercube point
//!     (no `next`-row concept),
//!   - replaces the permutation-phase opening with a sumcheck-based
//!     binding (zerocheck + LogUp-GKR), so no permutation columns,
//!   - folds the quotient terms into the FRI commit, so no quotient
//!     opening,
//!   - carries a per-chip `degree` point (big-endian boolean
//!     coordinates of chip height) used by the zerocheck verifier's
//!     padded-row mask.
//!
//! This module hosts the BaseFold-shape opening type that bundles
//! exactly those fields per chip, instead of parallel slices
//! (`chip_degrees`, `cumulative_sums`, `global_cumulative_sums`).
//!
//! Uses Ziren's recursion-compiler `Felt`/`Ext` types (the
//! in-circuit variant); the corresponding host-side variant lives
//! on the prover side.

use serde::{Deserialize, Serialize};
use zkm_pcs::septic_digest::SepticDigest;
use zkm_recursion_compiler::ir::{Ext, Felt};

/// Single-row variant of [`zkm_pcs::AirOpenedValues`] for the
/// BaseFold pipeline.
///
/// Holds only `local` because the BaseFold reduction collapses
/// every chip's polynomial to a single hypercube point — there is
/// no `next` row to expose to constraint folding.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(bound(serialize = "T: Serialize"))]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct JaggedAirOpenedValues<T> {
    /// Row evaluations at the sumcheck-reduced point.
    pub local: Vec<T>,
}

/// Per-chip opening bundle for the BaseFold pipeline.
///
/// The in-circuit verifier's counterpart of [`zkm_pcs::ChipOpenedValues`],
/// which serves the 4-batch FRI verifier path.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(bound(serialize = "F: Serialize, EF: Serialize"))]
#[serde(bound(deserialize = "F: Deserialize<'de>, EF: Deserialize<'de>"))]
pub struct JaggedChipOpenedValues<F, EF> {
    /// Preprocessed-trace evaluations at the sumcheck point.
    pub preprocessed: JaggedAirOpenedValues<EF>,
    /// Main-trace evaluations at the sumcheck point.
    pub main: JaggedAirOpenedValues<EF>,
    /// Big-endian boolean coordinates of the chip's height.
    /// Used by the zerocheck verifier's padded-row mask via
    /// [`crate::zerocheck::full_geq`].
    pub degree: Vec<EF>,
    /// Per-chip local cumulative sum from the LogUp-GKR sumcheck
    /// output, taken directly from the GKR layer's reduced eval (no
    /// permutation column).
    pub local_cumulative_sum: EF,
    /// Per-chip global cumulative sum digest.  Same source as
    /// `local_cumulative_sum`.
    pub global_cumulative_sum: SepticDigest<F>,
}

/// Per-shard opening bundle: one [`JaggedChipOpenedValues`] per
/// chip, in the same order as the shard's chip list.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(bound(serialize = "F: Serialize, EF: Serialize"))]
#[serde(bound(deserialize = "F: Deserialize<'de>, EF: Deserialize<'de>"))]
pub struct JaggedShardOpenedValues<F, EF> {
    /// Per-chip openings.
    pub chips: Vec<JaggedChipOpenedValues<F, EF>>,
}

/// In-circuit variant — the field types are the recursion-
/// compiler's `Felt` / `Ext` rather than raw base/extension
/// values, so the orchestrator can borrow into them without
/// witnessing.
pub type JaggedChipOpenedValuesVariable<C> = JaggedChipOpenedValues<
    Felt<<C as zkm_recursion_compiler::ir::Config>::F>,
    Ext<
        <C as zkm_recursion_compiler::ir::Config>::F,
        <C as zkm_recursion_compiler::ir::Config>::EF,
    >,
>;

/// In-circuit per-shard opening bundle.
pub type JaggedShardOpenedValuesVariable<C> = JaggedShardOpenedValues<
    Felt<<C as zkm_recursion_compiler::ir::Config>::F>,
    Ext<
        <C as zkm_recursion_compiler::ir::Config>::F,
        <C as zkm_recursion_compiler::ir::Config>::EF,
    >,
>;

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;
    type EF = KoalaBear;

    /// Construction smoke test: the bundle constructs cleanly with
    /// host-side base/extension types.
    #[test]
    fn opening_bundle_constructs() {
        use zkm_pcs::septic_curve::SepticCurve;
        use zkm_pcs::septic_extension::SepticExtension;
        let chip_opening: JaggedChipOpenedValues<F, EF> = JaggedChipOpenedValues {
            preprocessed: JaggedAirOpenedValues { local: vec![EF::ZERO; 2] },
            main: JaggedAirOpenedValues { local: vec![EF::ZERO; 4] },
            degree: vec![EF::ZERO; 5],
            local_cumulative_sum: EF::ZERO,
            global_cumulative_sum: SepticDigest(SepticCurve {
                x: SepticExtension::<F>([F::ZERO; 7]),
                y: SepticExtension::<F>([F::ZERO; 7]),
            }),
        };
        let shard: JaggedShardOpenedValues<F, EF> =
            JaggedShardOpenedValues { chips: vec![chip_opening] };
        assert_eq!(shard.chips.len(), 1);
        assert_eq!(shard.chips[0].main.local.len(), 4);
        assert_eq!(shard.chips[0].degree.len(), 5);
    }
}
