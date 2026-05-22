//! Core shape types (the task phase 1 — types only).
//!
//! No construction helpers / enumeration helpers yet; those arrive in
//! phase 2 (`enumerate.rs`).  This phase adds the data types themselves
//! so downstream code (recursion circuit, prover) can pin VK map keys
//! against them.
//!
//! ## Identification strategy: chip names, not `Chip<F, A>`
//!
//! The upstream design uses `BTreeSet<Chip<F, A>>` for `shard_chips`.  Ziren's
//! [`crate::Chip<F, A>`] doesn't implement `Ord`/`Hash` (it wraps an
//! AIR that's only `MachineAir`-bounded), and adding those bounds
//! would ripple through every MIPS chip AIR — out of scope per task
//! "no zkVM circuit changes" constraint.
//!
//! Switching identification to `BTreeSet<String>` (chip names) sidesteps
//! the issue with no information loss: for the purpose of shape-indexed
//! VK lookup we only need to know *which* chips are present, and names
//! uniquely identify chips inside a `StarkMachine`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// The shape of a core shard proof — parameterized by area and padding
/// rather than per-chip heights.  This (plus the prover setup) entirely
/// determines the verifier circuit for that shape.
///
/// Port of `sp1_hypercube::prover::shard::CoreProofShape`,
/// with `shard_chips: BTreeSet<Chip<F, A>>` replaced by
/// `shard_chip_names: BTreeSet<String>` — see module docs.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct CoreProofShape {
    /// Names of the chips included in this shard.
    pub shard_chip_names: BTreeSet<String>,

    /// Total trace-cell count in the preprocessed commit, rounded up
    /// to the nearest `2 ^ log_stacking_height` multiple.
    pub preprocessed_area: usize,

    /// Total trace-cell count in the main commit, rounded up to the
    /// nearest `2 ^ log_stacking_height` multiple.
    pub main_area: usize,

    /// Number of zero-padding columns added to the preprocessed commit
    /// so the total column count aligns to the stacking stripe size.
    pub preprocessed_padding_cols: usize,

    /// Number of zero-padding columns added to the main commit so the
    /// total column count aligns to the stacking stripe size.
    pub main_padding_cols: usize,
}

impl CoreProofShape {
    /// Project this CoreProofShape onto the legacy per-chip
    /// [`crate::shape::OrderedShape`] representation.
    ///
    /// The stacked_shapes representation is an area/padding abstract
    /// upper bound; OrderedShape needs concrete per-chip log_heights.
    /// The mapping distributes `main_area` uniformly across the
    /// chips in `shard_chip_names` and takes the `log₂` of the
    /// resulting per-chip cell count (rounded up to the next power
    /// of two).
    ///
    /// This is deliberately lossy — many CoreProofShapes collapse to
    /// the same OrderedShape, which is the point (the whole reason
    /// stacked_shapes exists is to have fewer representative shapes than
    /// per-chip cartesian).
    #[must_use]
    pub fn to_ordered_shape(&self) -> crate::shape::OrderedShape {
        let num_chips = self.shard_chip_names.len().max(1);
        let main_area = self.main_area.max(1);
        // area is measured in stacking-height multiples; convert to cells.
        let total_cells: u128 =
            (main_area as u128) * (1u128 << consts::LOG_STACKING_HEIGHT);
        let per_chip_cells = (total_cells / num_chips as u128).max(1);
        // ceil(log2(per_chip_cells))
        let log_height: usize = if per_chip_cells.is_power_of_two() {
            per_chip_cells.trailing_zeros() as usize
        } else {
            per_chip_cells.next_power_of_two().trailing_zeros() as usize
        };
        // Cap at CORE_MAX_LOG_ROW_COUNT so we don't emit shapes the
        // recursion verifier won't accept.
        let log_height = log_height.min(consts::CORE_MAX_LOG_ROW_COUNT);

        crate::shape::OrderedShape::from_log2_heights(
            &self
                .shard_chip_names
                .iter()
                .map(|name| (name.clone(), log_height))
                .collect::<Vec<_>>(),
        )
    }
}

/// The shape of the machine — a curated list of "chip clusters": sets
/// of chip-name strings known to co-occur in practice.  Shape
/// enumeration iterates over cluster × area × padding tuples instead of
/// the full cartesian product of per-chip heights (~1.25M) that
/// Ziren's legacy [`crate::shape::CoreShapeConfig`] uses.
///
/// Port of `sp1_hypercube::machine::MachineShape`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineShape {
    /// The chip clusters — curated combinations of chip names that
    /// appear together in real workloads.  Typical count: 8-12 clusters
    /// covering core, each major precompile (Keccak, SHA-256,
    /// Poseidon2, Weierstrass, Uint256), and small/deferred variants.
    pub chip_clusters: Vec<BTreeSet<String>>,
}

impl MachineShape {
    /// A single-cluster shape that contains all the chip names — matches
    /// Ziren's today-default "no curation" behaviour.  Equivalent to
    /// [`MachineShape::all`] in SP1.
    #[must_use]
    pub fn all(chip_names: &[String]) -> Self {
        Self { chip_clusters: vec![chip_names.iter().cloned().collect()] }
    }

    /// Build from an explicit cluster list.
    #[must_use]
    pub const fn new(chip_clusters: Vec<BTreeSet<String>>) -> Self {
        Self { chip_clusters }
    }

    /// Smallest cluster (by chip count) that fully contains `chips`.
    /// Used at prove time to pick the most-restrictive representative
    /// shape for a given actual shard.
    #[must_use]
    pub fn smallest_cluster(&self, chips: &BTreeSet<String>) -> Option<&BTreeSet<String>> {
        self.chip_clusters
            .iter()
            .filter(|cluster| chips.is_subset(cluster))
            .min_by_key(|cluster| cluster.len())
    }
}

/// Single-shard Normalize input shape: one `CoreProofShape` plus the
/// stacking/FRI parameters that affect the recursion circuit shape.
///
/// Port of `sp1_prover::shapes::SP1NormalizeInputShape`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct ZKMNormalizeInputShape {
    pub proof_shapes: Vec<CoreProofShape>,
    pub max_log_row_count: usize,
    pub log_blowup: usize,
    pub log_stacking_height: usize,
}

/// Top-level enum dispatching the four recursion program shapes.
/// Selects which VK index + program body to use for a given inner
/// proof at recursion time.
///
/// Port of `sp1_prover::shapes::SP1RecursionProgramShape`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
pub enum ZKMRecursionProgramShape {
    /// Verifies one core shard proof.  The VK used at the recursion
    /// level is indexed by the inner `CoreProofShape`.
    Normalize(CoreProofShape),
    /// Verifies a batch of Normalize (or lower Compose) outputs.
    /// Specialized per arity so each `Compose(k)` has its own VK.
    Compose { arity: usize },
    /// Deferred branch — batches of completed inner recursions.
    Deferred,
    /// Terminal wrap stage — a single root proof.
    Shrink,
}

/// Configuration constants for the stacked shape layer.  Public so
/// downstream code can pin log_blowup / log_stacking_height against
/// the same values the enumeration uses.
///
/// Mirrors the constants in `sp1_prover::components`:
/// `CORE_LOG_STACKING_HEIGHT = 21`, `CORE_LOG_BLOWUP = 2`.
pub mod consts {
    /// Log2 of the stacking stripe height — every core commit's area
    /// is rounded up to a multiple of `2^LOG_STACKING_HEIGHT`.
    pub const LOG_STACKING_HEIGHT: u32 = 21;

    /// Log2 of the FRI blowup factor used by the core commit.  Must
    /// match the prover's FriParameters (`zkm_stark::zkm_fri_config`).
    pub const LOG_BLOWUP: usize = 1;

    /// Max log-height allowed for any single chip in a shard (the
    /// upper bound that size-class bands are measured against).
    pub const CORE_MAX_LOG_ROW_COUNT: usize = 22;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_shape_smallest_cluster_picks_minimal_fit() {
        let core: BTreeSet<String> =
            ["AddSub", "Cpu", "Program"].iter().map(|s| s.to_string()).collect();
        let core_keccak: BTreeSet<String> = ["AddSub", "Cpu", "Program", "KeccakPermute"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let machine = MachineShape::new(vec![core.clone(), core_keccak.clone()]);

        let needed: BTreeSet<String> =
            ["AddSub", "Cpu"].iter().map(|s| s.to_string()).collect();
        assert_eq!(machine.smallest_cluster(&needed), Some(&core));

        let needed_keccak: BTreeSet<String> =
            ["AddSub", "KeccakPermute"].iter().map(|s| s.to_string()).collect();
        assert_eq!(machine.smallest_cluster(&needed_keccak), Some(&core_keccak));
    }

    #[test]
    fn machine_shape_no_matching_cluster_returns_none() {
        let core: BTreeSet<String> = ["AddSub", "Cpu"].iter().map(|s| s.to_string()).collect();
        let machine = MachineShape::new(vec![core]);
        let needed: BTreeSet<String> =
            ["Sha256Extend"].iter().map(|s| s.to_string()).collect();
        assert_eq!(machine.smallest_cluster(&needed), None);
    }

    #[test]
    fn core_proof_shape_roundtrips_through_rmp() {
        let shape = CoreProofShape {
            shard_chip_names: ["Cpu", "AddSub"].iter().map(|s| s.to_string()).collect(),
            preprocessed_area: 1 << 21,
            main_area: 2 << 21,
            preprocessed_padding_cols: 3,
            main_padding_cols: 5,
        };
        let bytes = rmp_serde::to_vec(&shape).unwrap();
        let back: CoreProofShape = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(shape, back);
    }

    #[test]
    fn to_ordered_shape_distributes_area_uniformly() {
        let shape = CoreProofShape {
            shard_chip_names: ["Cpu", "AddSub"].iter().map(|s| s.to_string()).collect(),
            preprocessed_area: 1,
            main_area: 4, // 4 stacking-height multiples = 4 * 2^21 cells total
            preprocessed_padding_cols: 0,
            main_padding_cols: 0,
        };
        let ordered = shape.to_ordered_shape();
        // 2 chips, main_area=4 → per-chip total = 2 * 2^21 = 2^22 cells.
        // log₂(2^22) = 22 (capped at CORE_MAX_LOG_ROW_COUNT = 22).
        assert_eq!(ordered.inner.len(), 2);
        for (_, log_h) in &ordered.inner {
            assert_eq!(*log_h, 22);
        }
    }

    #[test]
    fn to_ordered_shape_caps_at_max_log_row_count() {
        // Huge area that would overflow CORE_MAX_LOG_ROW_COUNT if
        // uncapped.
        let shape = CoreProofShape {
            shard_chip_names: ["Cpu"].iter().map(|s| s.to_string()).collect(),
            preprocessed_area: 1,
            main_area: 1024, // 1024 * 2^21 = 2^31 cells per chip
            preprocessed_padding_cols: 0,
            main_padding_cols: 0,
        };
        let ordered = shape.to_ordered_shape();
        assert_eq!(ordered.inner.len(), 1);
        assert_eq!(ordered.inner[0].1, consts::CORE_MAX_LOG_ROW_COUNT);
    }

    #[test]
    fn recursion_program_shape_variants_sort_stably() {
        let n = ZKMRecursionProgramShape::Normalize(CoreProofShape {
            shard_chip_names: BTreeSet::new(),
            preprocessed_area: 0,
            main_area: 0,
            preprocessed_padding_cols: 0,
            main_padding_cols: 0,
        });
        let c2 = ZKMRecursionProgramShape::Compose { arity: 2 };
        let c4 = ZKMRecursionProgramShape::Compose { arity: 4 };
        let d = ZKMRecursionProgramShape::Deferred;
        let s = ZKMRecursionProgramShape::Shrink;
        let mut v = vec![s.clone(), c4.clone(), d.clone(), c2.clone(), n.clone()];
        v.sort();
        // Normalize < Compose < Deferred < Shrink by enum discriminant
        // ordering; Compose{2} < Compose{4} within Compose.
        assert_eq!(v, vec![n, c2, c4, d, s]);
    }
}
