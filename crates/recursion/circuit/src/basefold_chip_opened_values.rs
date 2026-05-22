//! Per-chip opening data for the BaseFold-pipeline shard verifier.
//!
//! The legacy [`zkm_stark::ChipOpenedValues`] was designed for the
//! 4-batch FRI shape (preprocessed + main + permutation + quotient,
//! each with `local` + `next` rows).  The BaseFold pipeline:
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
//! exactly those fields, eliminating the parallel-slice plumbing
//! (`chip_degrees`, `cumulative_sums`, `global_cumulative_sums`)
//! the prior wiring threaded through the orchestrator.
//!
//! # Reference
//!
//! Mirrors SP1's `ChipOpenedValues` (crates/hypercube/src/verifier/proof.rs)
//! shape for the BaseFold pipeline.  Uses Ziren's recursion-
//! compiler `Felt`/`Ext` types (the in-circuit variant); the
//! corresponding host-side variant lives on the prover side.

use serde::{Deserialize, Serialize};
use zkm_recursion_compiler::ir::{Ext, Felt};
use zkm_stark::septic_digest::SepticDigest;

/// Single-row variant of [`zkm_stark::AirOpenedValues`] for the
/// BaseFold pipeline.
///
/// Holds only `local` because the BaseFold reduction collapses
/// every chip's polynomial to a single hypercube point — there is
/// no `next` row to expose to constraint folding.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(bound(serialize = "T: Serialize"))]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct BasefoldAirOpenedValues<T> {
    /// Row evaluations at the sumcheck-reduced point.
    pub local: Vec<T>,
}

/// Per-chip opening bundle for the BaseFold pipeline.
///
/// Replaces the legacy [`zkm_stark::ChipOpenedValues`] for the
/// in-circuit verifier; the legacy type stays in place for the
/// 4-batch FRI verifier path until shim retirement deletes it.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(bound(serialize = "F: Serialize, EF: Serialize"))]
#[serde(bound(deserialize = "F: Deserialize<'de>, EF: Deserialize<'de>"))]
pub struct BasefoldChipOpenedValues<F, EF> {
    /// Preprocessed-trace evaluations at the sumcheck point.
    pub preprocessed: BasefoldAirOpenedValues<EF>,
    /// Main-trace evaluations at the sumcheck point.
    pub main: BasefoldAirOpenedValues<EF>,
    /// Big-endian boolean coordinates of the chip's height.
    /// Used by the zerocheck verifier's padded-row mask via
    /// [`crate::zerocheck::full_geq`].
    pub degree: Vec<EF>,
    /// Per-chip local cumulative sum from the LogUp-GKR sumcheck
    /// output.  In the legacy verifier this was opened from a
    /// permutation column; the BaseFold pipeline emits it
    /// directly from the GKR layer's reduced eval.
    pub local_cumulative_sum: EF,
    /// Per-chip global cumulative sum digest.  Same source as
    /// `local_cumulative_sum`.
    pub global_cumulative_sum: SepticDigest<F>,
}

/// Per-shard opening bundle: one [`BasefoldChipOpenedValues`] per
/// chip, in the same order as the shard's chip list.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(bound(serialize = "F: Serialize, EF: Serialize"))]
#[serde(bound(deserialize = "F: Deserialize<'de>, EF: Deserialize<'de>"))]
pub struct BasefoldShardOpenedValues<F, EF> {
    /// Per-chip openings.
    pub chips: Vec<BasefoldChipOpenedValues<F, EF>>,
}

/// In-circuit variant — the field types are the recursion-
/// compiler's `Felt` / `Ext` rather than raw base/extension
/// values, so the orchestrator can borrow into them without
/// witnessing.
pub type BasefoldChipOpenedValuesVariable<C> = BasefoldChipOpenedValues<
    Felt<<C as zkm_recursion_compiler::ir::Config>::F>,
    Ext<
        <C as zkm_recursion_compiler::ir::Config>::F,
        <C as zkm_recursion_compiler::ir::Config>::EF,
    >,
>;

/// In-circuit per-shard opening bundle.
pub type BasefoldShardOpenedValuesVariable<C> = BasefoldShardOpenedValues<
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
        use zkm_stark::septic_curve::SepticCurve;
        use zkm_stark::septic_extension::SepticExtension;
        let chip_opening: BasefoldChipOpenedValues<F, EF> = BasefoldChipOpenedValues {
            preprocessed: BasefoldAirOpenedValues { local: vec![EF::ZERO; 2] },
            main: BasefoldAirOpenedValues { local: vec![EF::ZERO; 4] },
            degree: vec![EF::ZERO; 5],
            local_cumulative_sum: EF::ZERO,
            global_cumulative_sum: SepticDigest(SepticCurve {
                x: SepticExtension::<F>([F::ZERO; 7]),
                y: SepticExtension::<F>([F::ZERO; 7]),
            }),
        };
        let shard: BasefoldShardOpenedValues<F, EF> =
            BasefoldShardOpenedValues { chips: vec![chip_opening] };
        assert_eq!(shard.chips.len(), 1);
        assert_eq!(shard.chips[0].main.local.len(), 4);
        assert_eq!(shard.chips[0].degree.len(), 5);
    }
}
